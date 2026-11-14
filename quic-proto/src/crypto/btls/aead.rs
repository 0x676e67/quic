use crate::crypto::btls::error::Result;
use crate::crypto::btls::key::{Key, Nonce, Tag};
use btls::aead::{Algorithm, StatelessAeadCtx};
use std::sync::LazyLock;

/// A BoringSSL AEAD, with the lengths it takes and produces.
pub(crate) struct Aead {
    alg: Algorithm,
    pub(crate) key_len: usize,
    pub(crate) tag_len: usize,
    pub(crate) nonce_len: usize,
}

static AES128_GCM: LazyLock<Aead> = LazyLock::new(|| Aead::new(Algorithm::aes_128_gcm()));

static AES256_GCM: LazyLock<Aead> = LazyLock::new(|| Aead::new(Algorithm::aes_256_gcm()));

static CHACHA20_POLY1305: LazyLock<Aead> =
    LazyLock::new(|| Aead::new(Algorithm::chacha20_poly1305()));

impl Aead {
    fn new(alg: Algorithm) -> Self {
        Self {
            key_len: alg.key_length(),
            tag_len: alg.max_tag_len(),
            nonce_len: alg.nonce_len(),
            alg,
        }
    }

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
    pub(crate) fn new_ctx(&self, key: &Key) -> Result<StatelessAeadCtx> {
        Ok(StatelessAeadCtx::new(&self.alg, key.slice(), self.tag_len)?)
    }
}
