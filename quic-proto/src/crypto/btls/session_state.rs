use crate::crypto::btls::alert::Alert;
use crate::crypto::btls::error::Result;
use crate::crypto::btls::secret::{Secret, Secrets, SecretsBuilder};
use crate::crypto::btls::suite::CipherSuite;
use crate::crypto::btls::{Error, HandshakeData, Level, QuicSsl, QuicVersion, SslError, retry};
use crate::{
    ConnectionId, Side, TransportError, crypto, transport_parameters::TransportParameters,
};
use btls::error::ErrorStack;
use btls::ex_data::Index;
use btls::ssl::{NameType, Ssl, SslRef};
use btls::x509::X509;
use btls_sys as bffi;
use bytes::{Buf, BytesMut};
use foreign_types_shared::ForeignTypeRef;
use std::any::Any;
use std::ffi::c_int;
use std::io::Cursor;
use std::result::Result as StdResult;
use std::slice;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use tracing::{error, trace, warn};

pub(crate) static QUIC_METHOD: bffi::SSL_QUIC_METHOD = bffi::SSL_QUIC_METHOD {
    set_read_secret: Some(QuicState::set_read_secret_callback),
    set_write_secret: Some(QuicState::set_write_secret_callback),
    add_handshake_data: Some(QuicState::add_handshake_data_callback),
    flush_flight: Some(QuicState::flush_flight_callback),
    send_alert: Some(QuicState::send_alert_callback),
};

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
            levels: [
                LevelState::new(version, Level::Initial, &ssl),
                LevelState::new(version, Level::EarlyData, &ssl),
                LevelState::new(version, Level::Handshake, &ssl),
                LevelState::new(version, Level::Application, &ssl),
            ],
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
            .map(|secrets| secrets.next_packet_keys().unwrap().as_crypto().unwrap())
    }

    #[inline]
    pub(crate) fn transport_parameters(
        &self,
    ) -> StdResult<Option<TransportParameters>, TransportError> {
        match self.ssl.get_peer_quic_transport_params() {
            Some(params) => {
                let params = TransportParameters::read(self.side, &mut Cursor::new(params))
                    .map_err(|e| {
                        TransportError::new(
                            Alert::handshake_failure().into(),
                            format!("failed parsing transport params: {e:?}"),
                        )
                    })?;
                Ok(Some(params))
            }
            None => Ok(None),
        }
    }

    #[inline]
    pub(crate) fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<(), TransportError> {
        let read_level = self.ssl.quic_read_level();
        let ssl_err = self.ssl.provide_quic_data(read_level, plaintext);
        self.check_error()?;
        self.check_ssl_error(ssl_err)?;

        self.advance_handshake()
    }

    #[inline]
    pub(crate) fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        let mut quic = lock(&self.quic);

        // Write all available data at the current write level. Whatever is written here
        // belongs to the level in effect before any switch below.
        let write_level = quic.write_level;
        let write_state = quic.level_state_mut(write_level);
        if write_state.write_buffer.has_remaining() {
            buf.extend_from_slice(&write_state.write_buffer);
            write_state.write_buffer.clear();
        }

        // Switch to the next level only once BoringSSL has installed both of its secrets.
        // The server only learns the application read secret after the client Finished,
        // so the application keys may become available several calls after the write
        // secret did.
        let next_write_level = write_level.next();
        if next_write_level == write_level {
            return None;
        }
        let secrets = quic.level_state(next_write_level).builder.build()?;
        quic.write_level = next_write_level;

        if next_write_level == Level::Application {
            // Keep the next application secrets for `next_1rtt_keys`.
            let mut next_app_secrets = secrets;
            next_app_secrets.update().unwrap();
            self.next_secrets = Some(next_app_secrets);
        }

        Some(secrets.keys().unwrap().as_crypto().unwrap())
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

    #[inline]
    pub(crate) fn early_crypto(
        &self,
    ) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let quic = lock(&self.quic);
        let builder = &quic.level_state(Level::EarlyData).builder;
        let version = builder.version;
        let suite = builder.suite?;
        let early_secret = match self.side {
            Side::Client => builder.local_secret?,
            Side::Server => builder.remote_secret?,
        };
        let header_key = early_secret
            .header_key(version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();
        let packet_key = Box::new(early_secret.packet_key(version, suite).unwrap());

        Some((header_key, packet_key))
    }

    #[inline]
    pub(crate) fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        let secrets = Secrets::initial(self.version, dcid, side).unwrap();
        secrets.keys().unwrap().as_crypto().unwrap()
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
            let rc = self.ssl.do_handshake();

            // Update the state of the handshake.
            self.handshaking = self.ssl.is_handshaking();

            self.check_error()?;
            self.check_ssl_error(rc)?;
        }

        if !self.handshaking {
            let ssl_err = self.ssl.process_post_handshake();
            self.check_error()?;
            return self.check_ssl_error(ssl_err);
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
    pub(crate) fn check_ssl_error(&mut self, ssl_err: SslError) -> StdResult<(), TransportError> {
        match ssl_err.value() {
            bffi::SSL_ERROR_NONE => Ok(()),
            bffi::SSL_ERROR_WANT_READ => {
                // Not an error - retry when we get more data from the peer.
                trace!("SSL:{}", ssl_err.get_description());
                Ok(())
            }
            bffi::SSL_ERROR_PENDING_SESSION
            | bffi::SSL_ERROR_PENDING_CERTIFICATE
            | bffi::SSL_ERROR_PENDING_TICKET
            | bffi::SSL_ERROR_WANT_X509_LOOKUP
            | bffi::SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
            | bffi::SSL_ERROR_WANT_CERTIFICATE_VERIFY => {
                // An asynchronous callback is pending. The session only advances the handshake
                // when the peer sends more data, and the peer waits for this side, so the
                // handshake would stall until the idle timeout.
                Err(TransportError::new(
                    Alert::internal_error().into(),
                    format!("unsupported asynchronous operation: {ssl_err}"),
                ))
            }
            bffi::SSL_ERROR_EARLY_DATA_REJECTED => {
                // Reset the state to allow retry with 1-RTT.
                self.ssl.reset_early_rejected_data();

                // Indicate that the early data has been rejected for the current handshake.
                self.early_data_rejected = true;
                Ok(())
            }
            _ => {
                // Everything else is fatal.
                let reason = if ssl_err.value() == bffi::SSL_ERROR_SSL {
                    // Error occurred within the SSL library. Get details from the ErrorStack.
                    format!("{}: {:?}", ssl_err, ErrorStack::get())
                } else {
                    format!("{ssl_err}")
                };

                Err(TransportError::new(
                    Alert::handshake_failure().into(),
                    reason,
                ))
            }
        }
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
    fn level_state(&self, level: Level) -> &LevelState {
        &self.levels[level as usize]
    }

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

        // Make sure we don't exceed the buffer capacity for the level.
        let state = self.level_state_mut(level);
        if state.write_buffer.len() + data.len() > state.write_buffer.capacity() {
            return Err(Error::other(format!(
                "add_handshake_data exceeded buffer capacity for level {level:?}"
            )));
        }

        // Add the message to the level.
        state.write_buffer.extend_from_slice(data);
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
    fn on_send_alert(&mut self, _: Level, alert: Alert) -> Result<()> {
        self.error.get_or_insert_with(|| alert.into());
        Ok(())
    }
}

// Raw callbacks from BoringSSL
impl QuicState {
    /// Runs `f` on the state of `ssl` for a BoringSSL callback. BoringSSL fails the handshake
    /// without a reason when a callback returns 0, so the error is kept for
    /// [`SessionState::check_error`].
    fn callback(ssl: *const bffi::SSL, f: impl FnOnce(&mut Self) -> Result<()>) -> c_int {
        // SAFETY: BoringSSL passes the callbacks the `SSL` they run for.
        let ssl = unsafe { SslRef::from_ptr(ssl.cast_mut()) };
        let Some(quic) = (*QUIC_STATE_INDEX).and_then(|index| ssl.ex_data(index)) else {
            return 0;
        };
        let mut quic = lock(quic);
        match f(&mut quic) {
            Ok(()) => 1,
            Err(e) => {
                quic.error.get_or_insert_with(|| {
                    TransportError::new(Alert::internal_error().into(), e.to_string())
                });
                0
            }
        }
    }

    /// Converts the arguments of the secret callbacks.
    fn parse_secret(
        cipher: *const bffi::SSL_CIPHER,
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

    extern "C" fn set_read_secret_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        cipher: *const bffi::SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
        Self::callback(ssl, |quic| {
            let (suite, secret) = Self::parse_secret(cipher, secret)?;
            quic.on_set_read_secret(level.into(), suite, secret)
        })
    }

    extern "C" fn set_write_secret_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        cipher: *const bffi::SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
        Self::callback(ssl, |quic| {
            let (suite, secret) = Self::parse_secret(cipher, secret)?;
            quic.on_set_write_secret(level.into(), suite, secret)
        })
    }

    extern "C" fn add_handshake_data_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        data: *const u8,
        len: usize,
    ) -> c_int {
        let data = unsafe { slice::from_raw_parts(data, len) };
        Self::callback(ssl, |quic| quic.on_add_handshake_data(level.into(), data))
    }

    extern "C" fn flush_flight_callback(ssl: *mut bffi::SSL) -> c_int {
        Self::callback(ssl, Self::on_flush_flight)
    }

    extern "C" fn send_alert_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        alert: u8,
    ) -> c_int {
        Self::callback(ssl, |quic| {
            quic.on_send_alert(level.into(), Alert::from(alert))
        })
    }
}

impl SessionState {
    /// Callback from BoringSSL to handle (i.e. log) info events.
    fn on_info(ssl: &SslRef, type_: c_int, value: c_int) {
        if type_ & bffi::SSL_CB_LOOP > 0 {
            trace!("SSL:ACCEPT_LOOP:{}", ssl.state_string());
        } else if type_ & bffi::SSL_CB_ALERT > 0 {
            let prefix = if type_ & bffi::SSL_CB_READ > 0 {
                "SSL:ALERT:READ:"
            } else {
                "SSL:ALERT:WRITE:"
            };

            if ((type_ & 0xF0) >> 8) == bffi::SSL3_AL_WARNING {
                warn!("{}{}", prefix, ssl.state_string());
            } else {
                error!("{}{}", prefix, ssl.state_string());
            }
        } else if type_ & bffi::SSL_CB_EXIT > 0 {
            if value == 1 {
                trace!("SSL:ACCEPT_EXIT_OK:{}", ssl.state_string());
            } else {
                // Not necessarily an actual error. It could just require additional
                // data from the other side.
                trace!("SSL:ACCEPT_EXIT_FAIL:{}", ssl.state_string());
            }
        } else if type_ & bffi::SSL_CB_HANDSHAKE_START > 0 {
            trace!("SSL:HANDSHAKE_START:{}", ssl.state_string());
        } else if type_ & bffi::SSL_CB_HANDSHAKE_DONE > 0 {
            trace!("SSL:HANDSHAKE_DONE:{}", ssl.state_string());
        } else {
            warn!("SSL:unknown event type {}:{}", type_, ssl.state_string());
        }
    }

    pub(crate) extern "C" fn info_callback(ssl: *const bffi::SSL, type_: c_int, value: c_int) {
        // SAFETY: BoringSSL passes the callback the `SSL` it runs for.
        let ssl = unsafe { SslRef::from_ptr(ssl.cast_mut()) };
        Self::on_info(ssl, type_, value);
    }
}

pub(crate) struct LevelState {
    pub(crate) builder: SecretsBuilder,
    pub(crate) write_buffer: BytesMut,
}

impl LevelState {
    #[inline]
    fn new(version: QuicVersion, level: Level, ssl: &Ssl) -> Self {
        let capacity = ssl.quic_max_handshake_flight_len(level);

        Self {
            builder: SecretsBuilder::new(version),
            write_buffer: BytesMut::with_capacity(capacity),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportErrorCode;
    use crate::crypto::btls::QuicSslContext;
    use btls::ssl::{SslContextBuilder, SslMethod};
    use foreign_types_shared::ForeignType;

    #[test]
    fn callback_error_fails_handshake() {
        let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap().build();
        ctx.set_quic_method(&QUIC_METHOD).unwrap();
        let ssl = Ssl::new(&ctx).unwrap();
        let mut state = SessionState::new(ssl, Side::Client, QuicVersion::V1).unwrap();
        let ssl = state.ssl.as_ptr();
        let level = bffi::ssl_encryption_level_t::ssl_encryption_handshake;
        let secret = [0; 32];
        let cipher = |value| unsafe { bffi::SSL_get_cipher_by_value(value) };

        // TLS_AES_128_GCM_SHA256 for reading, then TLS_CHACHA20_POLY1305_SHA256 for writing.
        let rc = QuicState::set_read_secret_callback(
            ssl,
            level,
            cipher(0x1301),
            secret.as_ptr(),
            secret.len(),
        );
        assert_eq!(rc, 1);
        let rc = QuicState::set_write_secret_callback(
            ssl,
            level,
            cipher(0x1303),
            secret.as_ptr(),
            secret.len(),
        );
        assert_eq!(rc, 0);
        // A later alert does not replace the first error.
        QuicState::send_alert_callback(ssl, level, bffi::SSL_AD_DECODE_ERROR as u8);

        let err = state.read_handshake(&[]).unwrap_err();
        assert_eq!(
            err.code,
            TransportErrorCode::crypto(bffi::SSL_AD_INTERNAL_ERROR as u8)
        );
        assert!(err.reason.contains("cipher suite changed"), "{err}");
        assert!(
            lock(&state.quic)
                .level_state(Level::Handshake)
                .builder
                .build()
                .is_none()
        );
    }
}
