use crate::crypto;
use crate::crypto::btls::error::{Result, map_result_zero_is_success};
use crate::crypto::btls::macros::bounded_array;
use crate::crypto::btls::secret::Secret;
use crate::crypto::btls::suite::{CipherSuite, ID};
use crate::crypto::btls::{Error, QuicVersion};
use btls::aead::AeadCtx;
use btls_sys as bffi;
use bytes::BytesMut;
use std::ffi::c_uint;
use std::fmt::{Debug, Formatter};
use std::mem::{MaybeUninit, size_of};
use std::result::Result as StdResult;
use zeroize::Zeroize;

const SAMPLE_LEN: usize = 16; // 128-bits.

/// The maximum key size used by Quic algorithms.
const MAX_KEY_LEN: usize = 32;

/// The maximum nonce size used by Quic algorithms.
const MAX_NONCE_LEN: usize = 12;

/// The maximum tag size used by Quic algorithms.
const MAX_TAG_LEN: usize = 16;

bounded_array! {
    /// A buffer that can fit the largest key supported by Quic.
    pub(crate) struct Key(MAX_KEY_LEN),

    /// A buffer that can fit the largest nonce supported by Quic.
    pub(crate) struct Nonce(MAX_NONCE_LEN),

    /// A buffer that can fit the largest tag supported by Quic.
    pub(crate) struct Tag(MAX_TAG_LEN)
}

/// A pair of keys for bidirectional communication
#[derive(Clone, Debug)]
pub(crate) struct KeyPair<T> {
    /// The key for this side, used for encrypting data.
    pub(crate) local: T,

    /// The key for the other side, used for decrypting data.
    pub(crate) remote: T,
}

impl KeyPair<HeaderKey> {
    #[inline]
    pub(crate) fn as_crypto(&self) -> Result<crypto::KeyPair<Box<dyn crypto::HeaderKey>>> {
        Ok(crypto::KeyPair {
            local: self.local.as_crypto()?,
            remote: self.remote.as_crypto()?,
        })
    }
}

impl KeyPair<PacketKey> {
    #[inline]
    pub(crate) fn into_crypto(self) -> crypto::KeyPair<Box<dyn crypto::PacketKey>> {
        crypto::KeyPair {
            local: Box::new(self.local),
            remote: Box::new(self.remote),
        }
    }
}

/// A complete set of keys for a certain encryption level.
#[derive(Debug)]
pub(crate) struct Keys {
    /// Header protection keys
    pub(crate) header: KeyPair<HeaderKey>,
    /// Packet protection keys
    pub(crate) packet: KeyPair<PacketKey>,
}

impl Keys {
    pub(crate) fn into_crypto(self) -> Result<crypto::Keys> {
        Ok(crypto::Keys {
            header: self.header.as_crypto()?,
            packet: self.packet.into_crypto(),
        })
    }
}

/// Internal header key representation. Supports conversion to [crypto::HeaderKey]
#[derive(Clone, Debug)]
pub(crate) struct HeaderKey {
    suite: &'static CipherSuite,
    key: Key,
}

impl HeaderKey {
    pub(crate) fn new(
        version: QuicVersion,
        suite: &'static CipherSuite,
        secret: &Secret,
    ) -> Result<Self> {
        let mut key = suite.aead.zero_key();
        suite
            .hkdf
            .expand_label(secret.slice(), version.header_key_label(), key.slice_mut())?;

        Ok(Self { suite, key })
    }

    #[inline]
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// Converts to a crypto HeaderKey.
    #[inline]
    pub(crate) fn as_crypto(&self) -> Result<Box<dyn crypto::HeaderKey>> {
        match self.suite.id {
            ID::Aes128GcmSha256 | ID::Aes256GcmSha384 => {
                Ok(Box::new(AesHeaderKey::new(self.key())?))
            }
            ID::Chacha20Poly1305Sha256 => Ok(Box::new(ChaChaHeaderKey::new(self.key())?)),
        }
    }
}

/// Base trait for a crypto header protection keys. Implementation copied from rustls.
trait CryptoHeaderKey: crypto::HeaderKey {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]>;

    #[inline]
    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }

    #[inline]
    fn decrypt_in_place(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.xor_in_place(
            &sample[..self.sample_len()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
            true,
        )
        .unwrap();
    }

    #[inline]
    fn encrypt_in_place(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.xor_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
            false,
        )
        .unwrap();
    }

    #[inline]
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<()> {
        // This implements [Header Protection Application] almost verbatim.

        let mask = self.new_mask(sample).unwrap();

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err(Error::other(format!(
                "packet number too long: {}",
                packet_number.len()
            )));
        }

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

/// A [CryptoHeaderKey] for AES ciphers.
struct AesHeaderKey(bffi::AES_KEY);

impl AesHeaderKey {
    fn new(key: &Key) -> Result<Self> {
        let hpk = unsafe {
            let mut hpk = MaybeUninit::uninit();

            // NOTE: this function breaks the usual return value convention.
            map_result_zero_is_success(bffi::AES_set_encrypt_key(
                key.as_ptr(),
                (key.len() * 8) as c_uint,
                hpk.as_mut_ptr(),
            ))?;

            hpk.assume_init()
        };
        Ok(Self(hpk))
    }
}

impl Drop for AesHeaderKey {
    fn drop(&mut self) {
        self.0.rd_key.zeroize();
        self.0.rounds.zeroize();
    }
}

impl CryptoHeaderKey for AesHeaderKey {
    #[inline]
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::invalid_input(format!(
                "invalid sample length: {}",
                sample.len()
            )));
        }

        let mut encrypted: [u8; SAMPLE_LEN] = [0; SAMPLE_LEN];
        unsafe {
            bffi::AES_encrypt(sample.as_ptr(), encrypted.as_mut_ptr(), &self.0);
        }

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&encrypted[..5]);
        Ok(out)
    }
}

impl crypto::HeaderKey for AesHeaderKey {
    #[inline]
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.decrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.encrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// A [CryptoHeaderKey] for ChaCha ciphers.
struct ChaChaHeaderKey(Key);

impl ChaChaHeaderKey {
    const ZEROS: [u8; 5] = [0; 5];

    fn new(key: &Key) -> Result<Self> {
        Ok(Self(key.clone()))
    }
}

impl CryptoHeaderKey for ChaChaHeaderKey {
    #[inline]
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::invalid_input(format!(
                "sample len invalid: {}",
                sample.len()
            )));
        }

        // Extract the counter and the nonce from the sample.
        // The sample starts with the block counter in little endian
        // (https://www.rfc-editor.org/rfc/rfc9001#section-5.4.4).
        let (counter, nonce) = sample.split_at(size_of::<u32>());
        let counter = u32::from_le_bytes(counter.try_into().unwrap());

        let mut out: [u8; 5] = [0; 5];
        unsafe {
            bffi::CRYPTO_chacha_20(
                out.as_mut_ptr(),
                Self::ZEROS.as_ptr(),
                Self::ZEROS.len(),
                self.0.as_ptr(),
                nonce.as_ptr(),
                counter,
            );
        }

        Ok(out)
    }
}

impl crypto::HeaderKey for ChaChaHeaderKey {
    #[inline]
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.decrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.encrypt_in_place(pn_offset, packet)
    }

    #[inline]
    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// Internal key representation.
#[derive(Debug)]
pub(crate) struct PacketKey {
    aead_key: AeadKey,
    iv: Nonce,
}

impl PacketKey {
    #[inline]
    pub(crate) fn new(
        version: QuicVersion,
        suite: &'static CipherSuite,
        secret: &Secret,
    ) -> Result<Self> {
        let mut key = suite.aead.zero_key();
        suite
            .hkdf
            .expand_label(secret.slice(), version.key_label(), key.slice_mut())?;

        let mut iv = suite.aead.zero_nonce();
        suite
            .hkdf
            .expand_label(secret.slice(), version.iv_label(), iv.slice_mut())?;

        let aead_key = AeadKey::new(suite, &key)?;

        Ok(Self { aead_key, iv })
    }

    #[cfg(test)]
    pub(crate) fn iv(&self) -> &Nonce {
        &self.iv
    }

    #[inline]
    fn nonce_for_packet(&self, packet_number: u64) -> Nonce {
        let mut nonce = self.aead_key.suite.aead.zero_nonce();
        let slice = nonce.slice_mut();
        slice[4..].copy_from_slice(&packet_number.to_be_bytes());
        for (out, inp) in slice.iter_mut().zip(self.iv.slice().iter()) {
            *out ^= inp;
        }
        nonce
    }
}

impl crypto::PacketKey for PacketKey {
    /// Encrypt a QUIC packet in-place.
    fn encrypt(&self, packet_number: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);

        let nonce = self.nonce_for_packet(packet_number);

        self.aead_key
            .seal_in_place(&nonce, payload_tag, header)
            .unwrap();
    }

    /// Decrypt a QUIC packet in-place.
    fn decrypt(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> StdResult<(), crypto::CryptoError> {
        let nonce = self.nonce_for_packet(packet_number);

        let plain_len = self
            .aead_key
            .open_in_place(&nonce, payload.as_mut(), header)?;
        payload.truncate(plain_len);
        Ok(())
    }

    #[inline]
    fn tag_len(&self) -> usize {
        self.aead_key.suite.aead.tag_len
    }

    #[inline]
    fn confidentiality_limit(&self) -> u64 {
        self.aead_key.suite.confidentiality_limit
    }

    #[inline]
    fn integrity_limit(&self) -> u64 {
        self.aead_key.suite.integrity_limit
    }
}

/// An AEAD key whose [AeadCtx] owns the key material.
pub(crate) struct AeadKey {
    suite: &'static CipherSuite,
    // `EVP_AEAD_CTX_seal` and `EVP_AEAD_CTX_open` may run concurrently on one context
    // (https://github.com/google/boringssl/blob/master/include/openssl/aead.h).
    ctx: AeadCtx,
}

impl Debug for AeadKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey")
            .field("suite", self.suite)
            .finish_non_exhaustive()
    }
}

impl AeadKey {
    #[inline]
    pub(crate) fn new(suite: &'static CipherSuite, key: &Key) -> Result<Self> {
        let ctx = suite.aead.new_ctx(key)?;
        Ok(Self { suite, ctx })
    }

    /// Encrypts `data` in place. Its last [tag length](crate::crypto::btls::aead::Aead) bytes
    /// receive the tag.
    #[inline]
    pub(crate) fn seal_in_place(
        &self,
        nonce: &Nonce,
        data: &mut [u8],
        additional_data: &[u8],
    ) -> Result<()> {
        let Some(tag_start) = data.len().checked_sub(self.suite.aead.tag_len) else {
            return Err(Error::invalid_input(format!(
                "buffer too short for the tag: {}",
                data.len()
            )));
        };
        let (payload, tag) = data.split_at_mut(tag_start);
        let tag_len = self
            .ctx
            .seal_in_place(nonce.slice(), payload, tag, additional_data)?
            .len();
        if tag_len != self.suite.aead.tag_len {
            return Err(Error::other(format!("unexpected tag length: {tag_len}")));
        }
        Ok(())
    }

    /// Decrypts `data`, which ends with the tag, in place and returns the plaintext length.
    #[inline]
    pub(crate) fn open_in_place(
        &self,
        nonce: &Nonce,
        data: &mut [u8],
        additional_data: &[u8],
    ) -> StdResult<usize, crypto::CryptoError> {
        let Some(tag_start) = data.len().checked_sub(self.suite.aead.tag_len) else {
            return Err(crypto::CryptoError);
        };
        let (payload, tag) = data.split_at_mut(tag_start);
        self.ctx
            .open_in_place(nonce.slice(), payload, tag, additional_data)
            .map_err(|_| crypto::CryptoError)?;
        Ok(tag_start)
    }
}

impl crypto::AeadKey for AeadKey {
    #[inline]
    fn seal(
        &self,
        data: &mut Vec<u8>,
        additional_data: &[u8],
    ) -> StdResult<(), crypto::CryptoError> {
        data.extend_from_slice(self.suite.aead.zero_tag().slice());
        self.seal_in_place(&self.suite.aead.zero_nonce(), data, additional_data)?;
        Ok(())
    }

    #[inline]
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> StdResult<&'a mut [u8], crypto::CryptoError> {
        let plain_len = self.open_in_place(&self.suite.aead.zero_nonce(), data, additional_data)?;
        Ok(&mut data[..plain_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PacketKey as _;
    use hex_literal::hex;

    /// ChaCha20-Poly1305 short header packet
    /// (https://www.rfc-editor.org/rfc/rfc9001#appendix-A.5).
    #[test]
    fn chacha20_short_header_packet() {
        let suite = CipherSuite::chacha20_poly1305_sha256();
        let secret = Secret::from(&hex!(
            "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
        ));

        // The packet key itself stays inside BoringSSL; the ciphertext below depends on it.
        let packet_key = secret.packet_key(QuicVersion::V1, suite).unwrap();
        assert_eq!(packet_key.iv().slice(), hex!("e0459b3474bdd0e44a41c144"));
        let header_key = secret.header_key(QuicVersion::V1, suite).unwrap();
        assert_eq!(
            header_key.key().slice(),
            hex!("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        );

        let mut packet = hex!("4200bff401").to_vec();
        packet.extend_from_slice(&[0; 16]);
        packet_key.encrypt(654360564, &mut packet, 4);
        let header_key = header_key.as_crypto().unwrap();
        header_key.encrypt(1, &mut packet);
        assert_eq!(packet, hex!("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

        header_key.decrypt(1, &mut packet);
        assert_eq!(packet[..4], hex!("4200bff4"));
    }

    #[test]
    fn debug_omits_key_material() {
        let suite = CipherSuite::aes128_gcm_sha256();
        let secret = Secret::from(&[0xab; 32]);
        let header_key = secret.header_key(QuicVersion::V1, suite).unwrap();
        let packet_key = secret.packet_key(QuicVersion::V1, suite).unwrap();

        assert_eq!(format!("{secret:?}"), "Secret { len: 32, .. }");
        assert_eq!(
            format!("{header_key:?}"),
            "HeaderKey { suite: Aes128GcmSha256, key: Key { len: 16, .. } }"
        );
        assert_eq!(
            format!("{packet_key:?}"),
            "PacketKey { aead_key: AeadKey { suite: Aes128GcmSha256, .. }, iv: Nonce { len: 12, .. } }"
        );
    }
}
