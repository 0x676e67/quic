use crate::crypto::btls::error::{Error, Result};
use crate::crypto::btls::hkdf;
use crate::crypto::btls::key::{HeaderKey, KeyPair, Keys, PacketKey};
use crate::crypto::btls::macros::secret_array;
use crate::crypto::btls::suite::CipherSuite;
use crate::crypto::btls::version::QuicVersion;
use crate::{ConnectionId, Side};
use std::mem;

const MAX_SECRET_LEN: usize = hkdf::DIGEST_BLOCK_LEN;

secret_array! {
    /// A buffer that can fit the largest master secret.
    pub(crate) struct Secret(MAX_SECRET_LEN)
}

impl Secret {
    /// Performs an in-place key update.
    #[inline]
    pub(crate) fn update(&mut self, version: QuicVersion, suite: &CipherSuite) -> Result<()> {
        let mut next = Self::with_len(self.len());
        suite
            .hkdf
            .expand_label(self.slice(), version.key_update_label(), next.slice_mut())?;
        *self = next;
        Ok(())
    }

    #[inline]
    pub(crate) fn header_key(
        &self,
        version: QuicVersion,
        suite: &'static CipherSuite,
    ) -> Result<HeaderKey> {
        HeaderKey::new(version, suite, self)
    }

    #[inline]
    pub(crate) fn packet_key(
        &self,
        version: QuicVersion,
        suite: &'static CipherSuite,
    ) -> Result<PacketKey> {
        PacketKey::new(version, suite, self)
    }
}

/// A secret pair for reading (decryption) and writing (encryption).
#[derive(Debug)]
pub(crate) struct Secrets {
    pub(crate) version: QuicVersion,
    pub(crate) suite: &'static CipherSuite,
    pub(crate) local: Secret,
    pub(crate) remote: Secret,
}

impl Secrets {
    /// Creates the Quic initial secrets.
    /// See <https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets>.
    #[inline]
    pub(crate) fn initial(
        version: QuicVersion,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Self> {
        // Initial secrets always use AES-128-GCM and SHA256.
        let suite = CipherSuite::aes128_gcm_sha256();

        // Generate the initial secret.
        let salt = version.initial_salt();
        let mut initial_secret = Secret::with_len(Secret::MAX_LEN);
        let initial_secret_len = suite
            .hkdf
            .extract(salt, dst_cid, initial_secret.slice_mut())?;
        let initial_secret = &initial_secret.slice()[..initial_secret_len];

        // Use the appropriate secret labels for "this" side of the connection.
        const CLIENT_LABEL: &[u8] = b"client in";
        const SERVER_LABEL: &[u8] = b"server in";
        let (local_label, remote_label) = match side {
            Side::Client => (CLIENT_LABEL, SERVER_LABEL),
            Side::Server => (SERVER_LABEL, CLIENT_LABEL),
        };

        let len = suite.hkdf.digest_size();
        let mut local = Secret::with_len(len);
        suite
            .hkdf
            .expand_label(initial_secret, local_label, local.slice_mut())?;

        let mut remote = Secret::with_len(len);
        suite
            .hkdf
            .expand_label(initial_secret, remote_label, remote.slice_mut())?;

        Ok(Self {
            version,
            suite,
            local,
            remote,
        })
    }

    #[inline]
    pub(crate) fn keys(&self) -> Result<Keys> {
        Ok(Keys {
            header: self.header_keys()?,
            packet: self.packet_keys()?,
        })
    }

    #[inline]
    pub(crate) fn header_keys(&self) -> Result<KeyPair<HeaderKey>> {
        Ok(KeyPair {
            local: self.local.header_key(self.version, self.suite)?,
            remote: self.remote.header_key(self.version, self.suite)?,
        })
    }

    #[inline]
    pub(crate) fn packet_keys(&self) -> Result<KeyPair<PacketKey>> {
        Ok(KeyPair {
            local: self.local.packet_key(self.version, self.suite)?,
            remote: self.remote.packet_key(self.version, self.suite)?,
        })
    }

    #[inline]
    pub(crate) fn update(&mut self) -> Result<()> {
        // Update the secrets.
        self.local.update(self.version, self.suite)?;
        self.remote.update(self.version, self.suite)?;
        Ok(())
    }

    #[inline]
    pub(crate) fn next_packet_keys(&mut self) -> Result<KeyPair<PacketKey>> {
        // Get the current keys.
        let keys = self.packet_keys()?;

        // Update the secrets.
        self.update()?;

        Ok(keys)
    }
}

/// Collects the secrets BoringSSL installs for one encryption level, until they are taken to
/// derive the keys of that level. It holds no key material after that.
pub(crate) struct SecretsBuilder {
    version: QuicVersion,
    suite: Option<&'static CipherSuite>,
    local: Slot,
    remote: Slot,
}

impl SecretsBuilder {
    pub(crate) fn new(version: QuicVersion) -> Self {
        Self {
            version,
            suite: None,
            local: Slot::Empty,
            remote: Slot::Empty,
        }
    }

    pub(crate) fn set_suite(&mut self, suite: &'static CipherSuite) -> Result<()> {
        match self.suite {
            Some(prev) if prev != suite => Err(Error::other(format!(
                "cipher suite changed from {prev:?} to {suite:?}"
            ))),
            _ => {
                self.suite = Some(suite);
                Ok(())
            }
        }
    }

    pub(crate) fn set_remote_secret(&mut self, secret: Secret) -> Result<()> {
        self.remote.install(secret)
    }

    pub(crate) fn set_local_secret(&mut self, secret: Secret) -> Result<()> {
        self.local.install(secret)
    }

    /// Takes the secrets once both are installed.
    pub(crate) fn take(&mut self) -> Option<Secrets> {
        let suite = self.suite?;
        if !self.local.is_installed() || !self.remote.is_installed() {
            return None;
        }
        Some(Secrets {
            version: self.version,
            suite,
            local: self.local.take()?,
            remote: self.remote.take()?,
        })
    }

    /// Takes the local secret alone, as a server does with the 1-RTT one before the client
    /// Finished.
    pub(crate) fn take_local(&mut self) -> Option<(&'static CipherSuite, Secret)> {
        Some((self.suite?, self.local.take()?))
    }

    /// Takes the remote secret alone, see [`Self::take_local`].
    pub(crate) fn take_remote(&mut self) -> Option<(&'static CipherSuite, Secret)> {
        Some((self.suite?, self.remote.take()?))
    }

    /// Takes the 0-RTT secret, which only the client writes with and only the server reads with.
    pub(crate) fn take_early(&mut self, side: Side) -> Option<(&'static CipherSuite, Secret)> {
        match side {
            Side::Client => self.take_local(),
            Side::Server => self.take_remote(),
        }
    }
}

/// The secret of one direction of a level. BoringSSL installs each at most once per level
/// (see `SSL_QUIC_METHOD` in `openssl/ssl.h`).
enum Slot {
    Empty,
    Installed(Secret),
    /// The keys were derived, and nothing derives keys from a secret installed later.
    Taken,
}

impl Slot {
    fn install(&mut self, secret: Secret) -> Result<()> {
        match self {
            Self::Empty => {
                *self = Self::Installed(secret);
                Ok(())
            }
            Self::Installed(_) => Err(Error::other("secret installed twice".into())),
            Self::Taken => Err(Error::other(
                "secret installed after the keys were derived".into(),
            )),
        }
    }

    fn is_installed(&self) -> bool {
        matches!(self, Self::Installed(_))
    }

    fn take(&mut self) -> Option<Secret> {
        if !self.is_installed() {
            return None;
        }
        match mem::replace(self, Self::Taken) {
            Self::Installed(secret) => Some(secret),
            _ => None,
        }
    }
}
