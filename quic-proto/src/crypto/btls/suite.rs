use crate::crypto::btls::aead::Aead;
use crate::crypto::btls::error::{Error, Result};
use crate::crypto::btls::hkdf::Hkdf;
use btls::ssl::SslCipherRef;
use std::fmt::{Debug, Formatter};
use std::sync::LazyLock;

// AEAD usage limits, in packets (https://www.rfc-editor.org/rfc/rfc9001#section-6.6). Appendix B
// allows larger AES-GCM limits only for packets of at most 2^11 bytes, which path MTU discovery
// may exceed.

// AEAD_AES_128_GCM and AEAD_AES_256_GCM may protect at most 2^23 packets.
const AES_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;

// AEAD_CHACHA20_POLY1305 has a confidentiality limit above the number of possible packets (2^62).
const CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT: u64 = u64::MAX;

// AEAD_AES_128_GCM and AEAD_AES_256_GCM may fail to remove protection from at most 2^52 packets.
const AES_INTEGRITY_LIMIT: u64 = 1 << 52;

// AEAD_CHACHA20_POLY1305 may fail to remove protection from at most 2^36 packets.
const CHACHA20_POLY1305_INTEGRITY_LIMIT: u64 = 1 << 36;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ID {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

#[derive(Eq, PartialEq)]
pub(crate) struct CipherSuite {
    pub(crate) id: ID,
    pub(crate) hkdf: Hkdf,
    pub(crate) aead: &'static Aead,
    pub(crate) confidentiality_limit: u64,
    pub(crate) integrity_limit: u64,
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

static AES128_GCM_SHA256: LazyLock<CipherSuite> = LazyLock::new(|| CipherSuite {
    id: ID::Aes128GcmSha256,
    hkdf: Hkdf::sha256(),
    aead: Aead::aes128_gcm(),
    confidentiality_limit: AES_CONFIDENTIALITY_LIMIT,
    integrity_limit: AES_INTEGRITY_LIMIT,
});

static AES256_GCM_SHA384: LazyLock<CipherSuite> = LazyLock::new(|| CipherSuite {
    id: ID::Aes256GcmSha384,
    hkdf: Hkdf::sha384(),
    aead: Aead::aes256_gcm(),
    confidentiality_limit: AES_CONFIDENTIALITY_LIMIT,
    integrity_limit: AES_INTEGRITY_LIMIT,
});

static CHACHA20_POLY1305_SHA256: LazyLock<CipherSuite> = LazyLock::new(|| CipherSuite {
    id: ID::Chacha20Poly1305Sha256,
    hkdf: Hkdf::sha256(),
    aead: Aead::chacha20_poly1305(),
    confidentiality_limit: CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT,
    integrity_limit: CHACHA20_POLY1305_INTEGRITY_LIMIT,
});

impl CipherSuite {
    #[inline]
    pub(crate) fn aes128_gcm_sha256() -> &'static Self {
        &AES128_GCM_SHA256
    }

    #[inline]
    pub(crate) fn aes256_gcm_sha384() -> &'static Self {
        &AES256_GCM_SHA384
    }

    #[inline]
    pub(crate) fn chacha20_poly1305_sha256() -> &'static Self {
        &CHACHA20_POLY1305_SHA256
    }

    /// Returns the suite of a TLS 1.3 cipher suite, by its IANA number
    /// (<https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4>).
    #[inline]
    pub(crate) fn from_cipher(cipher: &SslCipherRef) -> Result<&'static Self> {
        match cipher.protocol_id() {
            0x1301 => Ok(Self::aes128_gcm_sha256()),
            0x1302 => Ok(Self::aes256_gcm_sha384()),
            0x1303 => Ok(Self::chacha20_poly1305_sha256()),
            id => Err(Error::invalid_input(format!(
                "invalid cipher id: {id:#06x}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The limits of RFC 9001 §6.6, which `PacketKey` reports to the connection.
    #[test]
    fn aead_limits() {
        for (suite, confidentiality, integrity) in [
            (CipherSuite::aes128_gcm_sha256(), 1 << 23, 1 << 52),
            (CipherSuite::aes256_gcm_sha384(), 1 << 23, 1 << 52),
            (CipherSuite::chacha20_poly1305_sha256(), u64::MAX, 1 << 36),
        ] {
            assert_eq!(suite.confidentiality_limit, confidentiality, "{suite:?}");
            assert_eq!(suite.integrity_limit, integrity, "{suite:?}");
        }
    }
}
