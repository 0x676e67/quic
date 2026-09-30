use crate::crypto;
use crate::crypto::btls::hkdf::DIGEST_BLOCK_LEN;
use btls::hash::hmac_sha256;
use rand::Rng;
use std::result::Result as StdResult;
use zeroize::Zeroizing;

const SIGNATURE_LEN_SHA_256: usize = 32;

/// Implementation of [crypto::HmacKey] using BoringSSL.
pub struct HmacKey {
    key: Zeroizing<Vec<u8>>,
}

impl HmacKey {
    /// Creates a new randomized SHA-256 HMAC key.
    pub fn sha256() -> Self {
        // Create a random key.
        let mut key = Zeroizing::new(vec![0u8; DIGEST_BLOCK_LEN]);
        rand::rng().fill_bytes(&mut key);

        Self { key }
    }
}

impl crypto::HmacKey for HmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let signature = hmac_sha256(&self.key, data).expect("HMAC-SHA256 with a valid key");
        out.copy_from_slice(&signature);
    }

    #[inline]
    fn signature_len(&self) -> usize {
        SIGNATURE_LEN_SHA_256
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> StdResult<(), crypto::CryptoError> {
        if signature.len() != self.signature_len() {
            return Err(crypto::CryptoError {});
        }

        // Sign the data.
        let mut out = [0u8; SIGNATURE_LEN_SHA_256];
        self.sign(data, &mut out);

        // Compare in constant time. The lengths are equal, as `memcmp::eq` requires.
        if btls::memcmp::eq(&out, signature) {
            return Ok(());
        }
        Err(crypto::CryptoError {})
    }
}

#[cfg(test)]
mod tests {
    use super::HmacKey;
    use crate::crypto::HmacKey as _;

    #[test]
    fn verify() {
        let key = HmacKey::sha256();
        let mut signature = [0; 32];
        key.sign(b"data", &mut signature);
        assert!(key.verify(b"data", &signature).is_ok());
        assert!(key.verify(b"other", &signature).is_err());

        signature[31] ^= 1;
        assert!(key.verify(b"data", &signature).is_err());
        assert!(key.verify(b"data", &signature[..31]).is_err());
    }
}
