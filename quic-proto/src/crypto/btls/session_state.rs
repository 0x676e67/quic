use crate::crypto::btls::error::Result;
use crate::crypto::btls::secret::{Secret, Secrets, SecretsBuilder};
use crate::crypto::btls::suite::CipherSuite;
use crate::crypto::btls::{Error, HandshakeData, QuicVersion, retry};
use crate::{
    ConnectionId, Side, TransportError, TransportErrorCode, crypto,
    transport_parameters::TransportParameters,
};
use btls::ex_data::Index;
use btls::ssl::{
    ErrorCode, NameType, QuicEncryptionLevel, QuicMethod, QuicMethodError, Ssl, SslAlert,
    SslCipherRef, SslRef,
};
use btls::x509::X509;
use std::any::Any;
use std::io::Cursor;
use std::mem;
use std::result::Result as StdResult;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use tracing::trace;

/// A QUIC encryption level, which indexes the per-level state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Level {
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    Application = 3,
}

impl Level {
    pub(crate) const NUM_LEVELS: usize = 4;

    /// Returns the level whose keys the handshake switches to after this one.
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Initial | Self::EarlyData => Self::Handshake,
            Self::Handshake | Self::Application => Self::Application,
        }
    }
}

impl TryFrom<QuicEncryptionLevel> for Level {
    type Error = Error;

    fn try_from(level: QuicEncryptionLevel) -> Result<Self> {
        match level {
            QuicEncryptionLevel::INITIAL => Ok(Self::Initial),
            QuicEncryptionLevel::EARLY_DATA => Ok(Self::EarlyData),
            QuicEncryptionLevel::HANDSHAKE => Ok(Self::Handshake),
            QuicEncryptionLevel::APPLICATION => Ok(Self::Application),
            level => Err(Error::other(format!("unknown encryption level {level:?}"))),
        }
    }
}

impl From<Level> for QuicEncryptionLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::Initial => Self::INITIAL,
            Level::EarlyData => Self::EARLY_DATA,
            Level::Handshake => Self::HANDSHAKE,
            Level::Application => Self::APPLICATION,
        }
    }
}

static QUIC_STATE_INDEX: LazyLock<Option<Index<Ssl, Arc<Mutex<QuicState>>>>> =
    LazyLock::new(|| Ssl::new_ex_index().ok());

pub(crate) struct SessionState {
    pub(crate) ssl: Ssl,
    pub(crate) version: QuicVersion,

    /// Indicates that early data was rejected in the last call to [Self::read_handshake].
    pub(crate) early_data_rejected: bool,

    side: Side,
    /// The state the `SSL_QUIC_METHOD` callbacks write to. It is shared with the ex_data of
    /// `ssl`, so it must not be locked across calls into BoringSSL.
    quic: Arc<Mutex<QuicState>>,
    next_secrets: Option<Secrets>,
    handshaking: bool,
}

impl SessionState {
    pub(crate) fn new(mut ssl: Ssl, side: Side, version: QuicVersion) -> Result<Self> {
        let quic = Arc::new(Mutex::new(QuicState {
            write_level: Level::Initial,
            levels: std::array::from_fn(|_| LevelState::new(version)),
            error: None,
        }));
        let index = QUIC_STATE_INDEX.ok_or_else(|| Error::other("no ex_data index".into()))?;
        ssl.set_ex_data(index, quic.clone());

        Ok(Self {
            ssl,
            version,
            side,
            quic,
            next_secrets: None,
            early_data_rejected: false,
            handshaking: true,
        })
    }

    #[inline]
    pub(crate) fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    #[inline]
    pub(crate) fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let sni_name = if self.side.is_server() {
            self.ssl
                .servername(NameType::HOST_NAME)
                .map(|server_name| server_name.to_string())
        } else {
            // Server name does not apply to the client.
            None
        };

        let alpn_protocol = self.ssl.selected_alpn_protocol().map(Vec::from);

        if sni_name.is_none() && alpn_protocol.is_none() {
            None
        } else {
            Some(Box::new(HandshakeData {
                protocol: alpn_protocol,
                server_name: sni_name,
            }))
        }
    }

    #[inline]
    pub(crate) fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.next_secrets
            .as_mut()
            .map(|secrets| secrets.next_packet_keys().unwrap().into_crypto())
    }

    #[inline]
    pub(crate) fn transport_parameters(
        &self,
    ) -> StdResult<Option<TransportParameters>, TransportError> {
        match self.ssl.peer_quic_transport_params() {
            Some(params) => {
                let params = TransportParameters::read(self.side, &mut Cursor::new(params))?;
                Ok(Some(params))
            }
            None => Ok(None),
        }
    }

    #[inline]
    pub(crate) fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<(), TransportError> {
        let read_level = self.ssl.quic_read_level();
        let provided = self.ssl.provide_quic_data(read_level, plaintext);
        self.check_error()?;
        // The data is always provided at the read level, so it only fails when BoringSSL would
        // buffer more than a flight (https://www.rfc-editor.org/rfc/rfc9000#section-7.5).
        provided.map_err(|e| TransportError::CRYPTO_BUFFER_EXCEEDED(format!("{e}")))?;

        self.advance_handshake()
    }

    #[inline]
    pub(crate) fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        let mut quic = lock(&self.quic);

        // Write all available data at the current write level. Whatever is written here
        // belongs to the level in effect before any switch below.
        let write_level = quic.write_level;
        let write_state = quic.level_state_mut(write_level);
        // The buffer is freed until the level has data again.
        let data = mem::take(&mut write_state.write_buffer);
        if buf.is_empty() {
            *buf = data;
        } else {
            buf.extend_from_slice(&data);
        }

        // Switch to the next level only once BoringSSL has installed both of its secrets.
        // The server only learns the application read secret after the client Finished,
        // so the application keys may become available several calls after the write
        // secret did.
        let next_write_level = write_level.next();
        if next_write_level == write_level {
            return None;
        }
        let mut secrets = quic.level_state_mut(next_write_level).builder.take()?;
        quic.write_level = next_write_level;

        // The secrets are only needed for this derivation, except that the application
        // secrets live on as the next generation for `next_1rtt_keys`.
        let keys = secrets.keys().unwrap().into_crypto().unwrap();
        if next_write_level == Level::Application {
            secrets.update().unwrap();
            self.next_secrets = Some(secrets);
        }

        Some(keys)
    }

    #[inline]
    pub(crate) fn is_valid_retry(
        &self,
        orig_dst_cid: &ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        retry::is_valid_retry(&self.version, orig_dst_cid, header, payload)
    }

    #[inline]
    pub(crate) fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // BoringSSL leaves the leaf out of the chain a server receives, so add it back to return
        // the whole chain, leaf first, on both sides.
        let leaf = match self.side {
            Side::Server => self.ssl.peer_certificate(),
            Side::Client => None,
        };
        let chain = self.ssl.peer_cert_chain().into_iter().flatten();
        let certs: Vec<X509> = leaf
            .into_iter()
            .chain(chain.map(ToOwned::to_owned))
            .collect();
        if certs.is_empty() {
            return None;
        }
        Some(Box::new(certs))
    }

    /// Derives the 0-RTT keys once the secret is installed. The secret is dropped with them,
    /// so the keys are returned once.
    #[inline]
    pub(crate) fn early_crypto(
        &self,
    ) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let mut quic = lock(&self.quic);
        let (suite, early_secret) = quic
            .level_state_mut(Level::EarlyData)
            .builder
            .take_early(self.side)?;
        let header_key = early_secret
            .header_key(self.version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();
        let packet_key = Box::new(early_secret.packet_key(self.version, suite).unwrap());

        Some((header_key, packet_key))
    }

    #[inline]
    pub(crate) fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        let secrets = Secrets::initial(self.version, dcid, side).unwrap();
        secrets.keys().unwrap().into_crypto().unwrap()
    }

    #[inline]
    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> StdResult<(), crypto::ExportKeyingMaterialError> {
        // Exporter labels are ASCII strings (https://www.rfc-editor.org/rfc/rfc5705#section-4).
        let label = std::str::from_utf8(label).map_err(|_| crypto::ExportKeyingMaterialError)?;
        self.ssl
            .export_keying_material(output, label, Some(context))
            .map_err(|_| crypto::ExportKeyingMaterialError)
    }

    #[inline]
    pub(crate) fn advance_handshake(&mut self) -> StdResult<(), TransportError> {
        self.early_data_rejected = false;

        if self.handshaking {
            let result = self.ssl.do_handshake();

            // Update the state of the handshake.
            self.handshaking = !self.ssl.is_init_finished();

            self.check_error()?;
            self.check_ssl_result(result)?;
        }

        if !self.handshaking {
            let result = self.ssl.process_quic_post_handshake();
            self.check_error()?;
            return self.check_ssl_result(result);
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn check_error(&self) -> StdResult<(), TransportError> {
        if let Some(error) = &lock(&self.quic).error {
            return Err(error.clone());
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn check_ssl_result(
        &mut self,
        result: StdResult<(), ErrorCode>,
    ) -> StdResult<(), TransportError> {
        let Err(code) = result else {
            return Ok(());
        };
        match code {
            ErrorCode::WANT_READ => {
                // Not an error - retry when we get more data from the peer.
                trace!("SSL:{code}");
                Ok(())
            }
            ErrorCode::PENDING_SESSION
            | ErrorCode::PENDING_CERTIFICATE
            | ErrorCode::PENDING_TICKET
            | ErrorCode::WANT_X509_LOOKUP
            | ErrorCode::WANT_PRIVATE_KEY_OPERATION
            | ErrorCode::WANT_CERTIFICATE_VERIFY => {
                // An asynchronous callback is pending. The session only advances the handshake
                // when the peer sends more data, and the peer waits for this side, so the
                // handshake would stall until the idle timeout.
                Err(TransportError::new(
                    alert_code(SslAlert::INTERNAL_ERROR),
                    format!("unsupported asynchronous operation: {code}"),
                ))
            }
            ErrorCode::EARLY_DATA_REJECTED => {
                // Reset the state to allow retry with 1-RTT.
                self.ssl.reset_early_data_reject();

                // Indicate that the early data has been rejected for the current handshake.
                self.early_data_rejected = true;
                Ok(())
            }
            _ => {
                // Everything else is fatal. BoringSSL reports failures caused by the peer with
                // an alert, which `check_error` returned, so this one is local.
                let reason = if code == ErrorCode::SSL {
                    // Error occurred within the SSL library. Get details from the ErrorStack.
                    format!("{code}: {:?}", btls::error::ErrorStack::get())
                } else {
                    format!("{code}")
                };

                Err(TransportError::new(
                    alert_code(SslAlert::INTERNAL_ERROR),
                    reason,
                ))
            }
        }
    }
}

/// Returns the QUIC error code that carries a TLS alert
/// (<https://www.rfc-editor.org/rfc/rfc9001#section-4.8>).
fn alert_code(alert: SslAlert) -> TransportErrorCode {
    // Alert descriptions are single bytes on the wire.
    TransportErrorCode::crypto(alert.as_raw() as u8)
}

impl From<SslAlert> for TransportError {
    fn from(alert: SslAlert) -> Self {
        Self::new(alert_code(alert), alert.description().to_owned())
    }
}

/// Locks `quic`, which stays usable if a thread panicked while holding it.
fn lock(quic: &Mutex<QuicState>) -> MutexGuard<'_, QuicState> {
    quic.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The state of the `SSL_QUIC_METHOD` callbacks.
struct QuicState {
    write_level: Level,
    levels: [LevelState; Level::NUM_LEVELS],
    /// The first fatal error of the handshake: a TLS alert, or a failed BoringSSL callback.
    error: Option<TransportError>,
}

// BoringSSL event handlers.
impl QuicState {
    #[inline]
    fn level_state_mut(&mut self, level: Level) -> &mut LevelState {
        &mut self.levels[level as usize]
    }

    /// Callback from BoringSSL that configures the read secret and cipher suite for the given
    /// encryption level. If an error is returned, the handshake is terminated with an error.
    /// This function will be called at most once per encryption level.
    #[inline]
    fn on_set_read_secret(
        &mut self,
        level: Level,
        suite: &'static CipherSuite,
        secret: Secret,
    ) -> Result<()> {
        // Store the secret.
        let builder = &mut self.level_state_mut(level).builder;
        builder.set_suite(suite)?;
        builder.set_remote_secret(secret)
    }

    /// Callback from BoringSSL that configures the write secret and cipher suite for the given
    /// encryption level. If an error is returned, the handshake is terminated with an error.
    /// This function will be called at most once per encryption level.
    #[inline]
    fn on_set_write_secret(
        &mut self,
        level: Level,
        suite: &'static CipherSuite,
        secret: Secret,
    ) -> Result<()> {
        // Store the secret.
        let builder = &mut self.level_state_mut(level).builder;
        builder.set_suite(suite)?;
        builder.set_local_secret(secret)
    }

    /// Callback from BoringSSL that adds handshake data to the current flight at the given
    /// encryption level. If an error is returned, the handshake is terminated with an error.
    #[inline]
    fn on_add_handshake_data(&mut self, level: Level, data: &[u8]) -> Result<()> {
        if level < self.write_level {
            return Err(Error::other(format!(
                "add_handshake_data for previous write level {level:?}"
            )));
        }

        // The data is BoringSSL's own flight, which `write_handshake` hands to the transport.
        self.level_state_mut(level)
            .write_buffer
            .extend_from_slice(data);
        Ok(())
    }

    /// Callback from BoringSSL called when the current flight is complete and should be
    /// written to the transport. Note a flight may contain data at several
    /// encryption levels.
    #[inline]
    fn on_flush_flight(&mut self) -> Result<()> {
        Ok(())
    }

    /// Callback from BoringSSL that sends a fatal alert at the specified encryption level.
    #[inline]
    fn on_send_alert(&mut self, _: Level, alert: SslAlert) -> Result<()> {
        self.error.get_or_insert_with(|| alert.into());
        Ok(())
    }
}

impl QuicState {
    /// Runs `f` on the state of `ssl` for a BoringSSL callback. BoringSSL fails the handshake
    /// without a reason when a callback fails, so the error is kept for
    /// [`SessionState::check_error`].
    fn callback(
        ssl: &SslRef,
        f: impl FnOnce(&mut Self) -> Result<()>,
    ) -> StdResult<(), QuicMethodError> {
        let quic = (*QUIC_STATE_INDEX)
            .and_then(|index| ssl.ex_data(index))
            .ok_or(QuicMethodError)?;
        let mut quic = lock(quic);
        f(&mut quic).map_err(|e| {
            quic.error.get_or_insert_with(|| {
                TransportError::new(alert_code(SslAlert::INTERNAL_ERROR), e.to_string())
            });
            QuicMethodError
        })
    }

    /// Converts the arguments of the secret callbacks.
    fn parse_secret(
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(&'static CipherSuite, Secret)> {
        let suite = CipherSuite::from_cipher(cipher)?;
        if secret.len() > Secret::MAX_LEN {
            return Err(Error::other(format!(
                "secret too long: {} bytes",
                secret.len()
            )));
        }
        Ok((suite, Secret::from(secret)))
    }
}

/// Hands the QUIC callbacks of BoringSSL to the [`QuicState`] of each connection.
pub(crate) struct QuicCallbacks;

impl QuicMethod for QuicCallbacks {
    fn set_read_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> StdResult<(), QuicMethodError> {
        QuicState::callback(ssl, |quic| {
            let (suite, secret) = QuicState::parse_secret(cipher, secret)?;
            quic.on_set_read_secret(level.try_into()?, suite, secret)
        })
    }

    fn set_write_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> StdResult<(), QuicMethodError> {
        QuicState::callback(ssl, |quic| {
            let (suite, secret) = QuicState::parse_secret(cipher, secret)?;
            quic.on_set_write_secret(level.try_into()?, suite, secret)
        })
    }

    fn add_handshake_data(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        data: &[u8],
    ) -> StdResult<(), QuicMethodError> {
        QuicState::callback(ssl, |quic| {
            quic.on_add_handshake_data(level.try_into()?, data)
        })
    }

    fn flush_flight(&self, ssl: &mut SslRef) -> StdResult<(), QuicMethodError> {
        QuicState::callback(ssl, QuicState::on_flush_flight)
    }

    fn send_alert(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        alert: SslAlert,
    ) -> StdResult<(), QuicMethodError> {
        QuicState::callback(ssl, |quic| quic.on_send_alert(level.try_into()?, alert))
    }
}

pub(crate) struct LevelState {
    pub(crate) builder: SecretsBuilder,
    /// Handshake data to write at the level, allocated once there is some.
    pub(crate) write_buffer: Vec<u8>,
}

impl LevelState {
    #[inline]
    fn new(version: QuicVersion) -> Self {
        Self {
            builder: SecretsBuilder::new(version),
            write_buffer: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::ssl::{SslCipher, SslContextBuilder, SslMethod};

    fn session() -> SessionState {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
        builder.set_quic_method(QuicCallbacks).unwrap();
        let ssl = Ssl::new(&builder.build()).unwrap();
        SessionState::new(ssl, Side::Client, QuicVersion::V1).unwrap()
    }

    /// Installs a zero secret the way BoringSSL does, with a cipher suite by its IANA number.
    fn install(
        state: &mut SessionState,
        write: bool,
        level: QuicEncryptionLevel,
        cipher: u16,
    ) -> StdResult<(), QuicMethodError> {
        let cipher = SslCipher::from_value(cipher).unwrap();
        if write {
            QuicCallbacks.set_write_secret(&mut state.ssl, level, &cipher, &[0; 32])
        } else {
            QuicCallbacks.set_read_secret(&mut state.ssl, level, &cipher, &[0; 32])
        }
    }

    const AES_128_GCM_SHA256: u16 = 0x1301;
    const CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    #[test]
    fn callback_error_fails_handshake() {
        let mut state = session();
        let level = QuicEncryptionLevel::HANDSHAKE;

        // One cipher suite for reading, then another one for writing.
        assert!(install(&mut state, false, level, AES_128_GCM_SHA256).is_ok());
        assert!(install(&mut state, true, level, CHACHA20_POLY1305_SHA256).is_err());
        // A later alert does not replace the first error.
        QuicCallbacks
            .send_alert(&mut state.ssl, level, SslAlert::DECODE_ERROR)
            .unwrap();

        let err = state.read_handshake(&[]).unwrap_err();
        assert_eq!(err.code, alert_code(SslAlert::INTERNAL_ERROR));
        assert!(err.reason.contains("cipher suite changed"), "{err}");
        assert!(
            lock(&state.quic)
                .level_state_mut(Level::Handshake)
                .builder
                .take()
                .is_none()
        );
    }

    /// Handshake data is buffered on demand whatever its size, and a peer flight larger than
    /// BoringSSL buffers fails with CRYPTO_BUFFER_EXCEEDED.
    #[test]
    fn handshake_buffers() {
        let mut state = session();
        let unallocated = |state: &SessionState| {
            lock(&state.quic)
                .levels
                .iter()
                .all(|level| level.write_buffer.capacity() == 0)
        };
        assert!(unallocated(&state));

        // Beyond what the peer may send at the level, as a large certificate chain can be.
        let flight = vec![1; 64 * 1024];
        QuicCallbacks
            .add_handshake_data(&mut state.ssl, QuicEncryptionLevel::INITIAL, &flight)
            .unwrap();
        let mut buf = Vec::new();
        assert!(state.write_handshake(&mut buf).is_none());
        assert_eq!(buf, flight);
        assert!(unallocated(&state));

        let err = state.read_handshake(&vec![0; 16 * 1024 + 1]).unwrap_err();
        assert_eq!(err.code, TransportErrorCode::CRYPTO_BUFFER_EXCEEDED);
    }

    /// A local failure has no alert, such as a client without the ALPN that QUIC requires.
    #[test]
    fn local_failure_is_internal_error() {
        let mut state = session();
        state.ssl.set_connect_state();
        let err = state.advance_handshake().unwrap_err();
        assert_eq!(err.code, alert_code(SslAlert::INTERNAL_ERROR));
        assert!(err.reason.contains("NO_APPLICATION_PROTOCOL"), "{err}");
    }

    /// Each secret is dropped once the keys of its level are derived.
    #[test]
    fn secrets_dropped_after_key_derivation() {
        let mut state = session();
        let suite = AES_128_GCM_SHA256;
        let mut buf = Vec::new();

        // The 0-RTT keys come out once.
        install(&mut state, true, QuicEncryptionLevel::EARLY_DATA, suite).unwrap();
        assert!(state.early_crypto().is_some());
        assert!(state.early_crypto().is_none());

        // The handshake keys wait for both secrets, then leave nothing behind.
        install(&mut state, true, QuicEncryptionLevel::HANDSHAKE, suite).unwrap();
        assert!(state.write_handshake(&mut buf).is_none());
        install(&mut state, false, QuicEncryptionLevel::HANDSHAKE, suite).unwrap();
        assert!(state.write_handshake(&mut buf).is_some());
        assert!(
            lock(&state.quic)
                .level_state_mut(Level::Handshake)
                .builder
                .take()
                .is_none()
        );

        // Only the next generation of the application secrets stays, for key updates.
        install(&mut state, true, QuicEncryptionLevel::APPLICATION, suite).unwrap();
        install(&mut state, false, QuicEncryptionLevel::APPLICATION, suite).unwrap();
        assert!(state.write_handshake(&mut buf).is_some());
        assert!(
            lock(&state.quic)
                .level_state_mut(Level::Application)
                .builder
                .take()
                .is_none()
        );
        assert!(state.next_1rtt_keys().is_some());
        assert!(state.write_handshake(&mut buf).is_none());

        // A secret installed after its keys were derived is an error, not a leak.
        assert!(install(&mut state, true, QuicEncryptionLevel::HANDSHAKE, suite).is_err());
        let err = state.read_handshake(&[]).unwrap_err();
        assert!(err.reason.contains("after the keys were derived"), "{err}");
    }
}
