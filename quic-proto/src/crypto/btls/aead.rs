use crate::crypto::btls::error::Result;
use crate::crypto::btls::key::{Key, Nonce, Tag};
use btls::aead::{AeadCtx, Algorithm};
use std::sync::LazyLock;

const AES_128_GCM_KEY_LEN: usize = 16;
const AES_256_GCM_KEY_LEN: usize = 32;
const CHACHA20_POLY1305_KEY_LEN: usize = 32;

const AES_GCM_NONCE_LEN: usize = 12;
const POLY1305_NONCE_LEN: usize = 12;

pub(crate) const AES_GCM_TAG_LEN: usize = 16;
const POLY1305_TAG_LEN: usize = 16;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ID {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

/// Wrapper around an BoringSSL EVP_AEAD.
pub(crate) struct Aead {
    alg: Algorithm,
    pub(crate) id: ID,
    pub(crate) key_len: usize,
    pub(crate) tag_len: usize,
    pub(crate) nonce_len: usize,
}

impl PartialEq for Aead {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Aead {}

static AES128_GCM: LazyLock<Aead> = LazyLock::new(|| Aead {
    alg: Algorithm::aes_128_gcm(),
    id: ID::Aes128Gcm,
    key_len: AES_128_GCM_KEY_LEN,
    tag_len: AES_GCM_TAG_LEN,
    nonce_len: AES_GCM_NONCE_LEN,
});

static AES256_GCM: LazyLock<Aead> = LazyLock::new(|| Aead {
    alg: Algorithm::aes_256_gcm(),
    id: ID::Aes256Gcm,
    key_len: AES_256_GCM_KEY_LEN,
    tag_len: AES_GCM_TAG_LEN,
    nonce_len: AES_GCM_NONCE_LEN,
});

static CHACHA20_POLY1305: LazyLock<Aead> = LazyLock::new(|| Aead {
    alg: Algorithm::chacha20_poly1305(),
    id: ID::Chacha20Poly1305,
    key_len: CHACHA20_POLY1305_KEY_LEN,
    tag_len: POLY1305_TAG_LEN,
    nonce_len: POLY1305_NONCE_LEN,
});

impl Aead {
    #[inline]
    pub(crate) fn aes128_gcm() -> &'static Self {
        &AES128_GCM
    }

    #[inline]
    pub(crate) fn aes256_gcm() -> &'static Self {
        &AES256_GCM
    }

    #[inline]
    pub(crate) fn chacha20_poly1305() -> &'static Self {
        &CHACHA20_POLY1305
    }

    /// Creates a new zeroed key of the appropriate length for the AEAD algorithm.
    #[inline]
    pub(crate) fn zero_key(&self) -> Key {
        Key::with_len(self.key_len)
    }

    /// Creates a new zeroed nonce of the appropriate length for the AEAD algorithm.
    #[inline]
    pub(crate) fn zero_nonce(&self) -> Nonce {
        Nonce::with_len(self.nonce_len)
    }

    /// Creates a new zeroed tag of the appropriate length for the AEAD algorithm.
    #[inline]
    pub(crate) fn zero_tag(&self) -> Tag {
        Tag::with_len(self.tag_len)
    }

    /// Creates a context that owns `key`. BoringSSL zeroes the context when it is freed.
    #[inline]
    pub(crate) fn new_ctx(&self, key: &Key) -> Result<AeadCtx> {
        Ok(AeadCtx::new(&self.alg, key.slice(), self.tag_len)?)
    }
}
