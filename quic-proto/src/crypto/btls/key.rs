use crate::crypto;
use crate::crypto::btls::error::Result;
use crate::crypto::btls::macros::{bounded_array, secret_array};
use crate::crypto::btls::secret::Secret;
use crate::crypto::btls::suite::{CipherSuite, ID};
use crate::crypto::btls::{Error, QuicVersion};
use btls::aead::StatelessAeadCtx;
use btls::aes::{self, AesKey};
use btls::chacha;
use bytes::BytesMut;
use std::fmt::{Debug, Formatter};
use std::mem::size_of;
use std::result::Result as StdResult;

const SAMPLE_LEN: usize = 16; // 128-bits.

/// The maximum key size used by Quic algorithms.
const MAX_KEY_LEN: usize = 32;

/// The maximum nonce size used by Quic algorithms.
const MAX_NONCE_LEN: usize = 12;

/// The maximum tag size used by Quic algorithms.
const MAX_TAG_LEN: usize = 16;

secret_array! {
    /// A buffer that can fit the largest key supported by Quic.
    pub(crate) struct Key(MAX_KEY_LEN)
}

bounded_array! {
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
struct AesHeaderKey(AesKey);

impl AesHeaderKey {
    fn new(key: &Key) -> Result<Self> {
        AesKey::new_encrypt(key.slice())
            .map(Self)
            .map_err(|_| Error::invalid_input(format!("invalid AES key length: {}", key.len())))
    }
}

impl CryptoHeaderKey for AesHeaderKey {
    #[inline]
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        let sample = sample.try_into().map_err(|_| {
            Error::invalid_input(format!("invalid sample length: {}", sample.len()))
        })?;
        let mut encrypted = [0; SAMPLE_LEN];
        aes::encrypt_block(&self.0, sample, &mut encrypted);

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
        let key = self.0.slice().try_into().map_err(|_| {
            Error::invalid_input(format!("invalid ChaCha20 key length: {}", self.0.len()))
        })?;

        // The mask is the keystream, encrypting zeros.
        let mut mask = [0; 5];
        chacha::chacha20(key, nonce.try_into().unwrap(), counter, &mut mask);
        Ok(mask)
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
pub(crate) struct PacketKey {
    aead_key: AeadKey,
    iv: Nonce,
}

impl Debug for PacketKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // The IV is derived from the secret, so leave it out like the key.
        f.debug_struct("PacketKey")
            .field("aead_key", &self.aead_key)
            .finish_non_exhaustive()
    }
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

/// An AEAD key whose context owns the key material.
pub(crate) struct AeadKey {
    suite: &'static CipherSuite,
    ctx: StatelessAeadCtx,
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
    use crate::crypto::btls::secret::Secrets;
    use crate::{ConnectionId, Side};
    use bytes::BytesMut;
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

    /// Initial packets of both sides
    /// (https://www.rfc-editor.org/rfc/rfc9001#appendix-A.1 to A.3).
    #[test]
    fn initial_packets() {
        let dst_cid = ConnectionId::new(&hex!("8394c8f03e515708"));
        let client = Secrets::initial(QuicVersion::V1, &dst_cid, Side::Client).unwrap();
        let server = Secrets::initial(QuicVersion::V1, &dst_cid, Side::Server).unwrap();
        assert_eq!(
            client.local.slice(),
            hex!("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            client.remote.slice(),
            hex!("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );
        assert_eq!(server.local.slice(), client.remote.slice());
        assert_eq!(server.remote.slice(), client.local.slice());

        let client = client.keys().unwrap();
        let server = server.keys().unwrap();
        assert_eq!(
            client.packet.local.iv().slice(),
            hex!("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            client.header.local.key().slice(),
            hex!("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            server.packet.local.iv().slice(),
            hex!("0ac1493ca1905853b0bba03e")
        );
        assert_eq!(
            server.header.local.key().slice(),
            hex!("c206b8d9b9f0f37644430b490eeaa314")
        );

        // The packet keys stay inside BoringSSL; the packets below depend on them.
        let client_header = client.header.as_crypto().unwrap();
        let server_header = server.header.as_crypto().unwrap();

        // The client Initial, with a CRYPTO frame padded to 1162 bytes and packet number 2.
        let mut packet = hex!("c300000001088394c8f03e5157080000449e00000002").to_vec();
        packet.extend_from_slice(&hex!(
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
            "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
            "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
            "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
            "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
            "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
            "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
            "75300901100f088394c8f03e51570806048000ffff"
        ));
        packet.resize(22 + 1162 + 16, 0);
        client.packet.local.encrypt(2, &mut packet, 22);
        client_header.local.encrypt(18, &mut packet);
        assert_eq!(
            packet,
            hex!(
                "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
                "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
                "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
                "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
                "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
                "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
                "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
                "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
                "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
                "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
                "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
                "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
                "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
                "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
                "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
                "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
                "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
                "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
                "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
                "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
                "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
                "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
                "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
                "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
                "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
                "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
                "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
                "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
                "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
                "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
                "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
                "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
                "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
                "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
                "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
                "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
                "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
                "e221af44860018ab0856972e194cd934"
            )
        );

        // The server Initial, with packet number 1, which the client opens.
        let header = hex!("c1000000010008f067a5502a4262b50040750001");
        let payload = hex!(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"
            "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"
            "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
            "020304"
        );
        let mut packet = [&header[..], &payload, &[0; 16]].concat();
        server.packet.local.encrypt(1, &mut packet, header.len());
        server_header.local.encrypt(18, &mut packet);
        assert_eq!(
            packet,
            hex!(
                "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
                "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
                "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
                "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
                "2158407dd074ee"
            )
        );

        client_header.remote.decrypt(18, &mut packet);
        let (protected_header, body) = packet.split_at(header.len());
        assert_eq!(protected_header, header);
        let mut body = BytesMut::from(body);
        client.packet.remote.decrypt(1, &header, &mut body).unwrap();
        assert_eq!(body[..], payload);
    }

    /// A key update of the secret of the ChaCha20-Poly1305 sample
    /// (https://www.rfc-editor.org/rfc/rfc9001#appendix-A.5), and the generations of packet keys
    /// that follow from it.
    #[test]
    fn key_update() {
        let suite = CipherSuite::chacha20_poly1305_sha256();
        let secret = Secret::from(&hex!(
            "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
        ));
        let mut updated = secret.clone();
        updated.update(QuicVersion::V1, suite).unwrap();
        assert_eq!(
            updated.slice(),
            hex!("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        );

        // Each call hands out the current generation and moves on to the next one.
        let mut secrets = Secrets {
            version: QuicVersion::V1,
            suite,
            local: secret.clone(),
            remote: secret,
        };
        let current = secrets.next_packet_keys().unwrap();
        assert_eq!(current.local.iv().slice(), hex!("e0459b3474bdd0e44a41c144"));
        let next = secrets.next_packet_keys().unwrap();
        let expected = updated.packet_key(QuicVersion::V1, suite).unwrap();
        assert_eq!(next.local.iv().slice(), expected.iv().slice());
        assert_eq!(next.remote.iv().slice(), expected.iv().slice());
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
            "PacketKey { aead_key: AeadKey { suite: Aes128GcmSha256, .. }, .. }"
        );
    }
}
