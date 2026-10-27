use crate::crypto::btls::error::{Error, Result};
use crate::crypto::btls::retry;
use crate::crypto::btls::secret::Secrets;
use crate::crypto::btls::session_state::{QuicCallbacks, SessionState};
use crate::crypto::btls::version::QuicVersion;
use crate::{
    ConnectionId, Side, TransportError, crypto, transport_parameters::TransportParameters,
};
use btls::error::ErrorStack;
use btls::ssl::{Ssl, SslContext, SslContextBuilder, SslRef, SslVersion};
use bytes::{Bytes, BytesMut};
use std::any::Any;
use std::result::Result as StdResult;
use std::sync::Arc;
use tracing::warn;

/// Configures the [Ssl] of each connection, see [`QuicServerConfig::set_ssl_callback`].
type SslCallback = dyn Fn(&mut SslRef) -> StdResult<(), ErrorStack> + Send + Sync;

/// Configuration for a server-side QUIC. Wraps around a BoringSSL [SslContext].
///
/// It is created with [`TryFrom`] from an [SslContextBuilder], which holds the certificates,
/// client verification, the ALPN protocols and every other TLS setting.
///
/// QUIC requires ALPN ([RFC 9001 §8.1](https://www.rfc-editor.org/rfc/rfc9001#section-8.1)), so
/// the builder needs either [`SslContextBuilder::set_alpn_protos`], with which BoringSSL selects
/// the first protocol the client offers that the list contains, or
/// [`SslContextBuilder::set_alpn_select_callback`], such as with
/// [`select_next_proto`](btls::ssl::select_next_proto) to prefer the server's order. Without
/// either, every handshake fails with `NO_APPLICATION_PROTOCOL`.
///
/// 0-RTT is off unless the builder enables it with
/// [`SslContextBuilder::set_early_data_enabled`]. The server then accepts 0-RTT from, and issues,
/// tickets that allow it. Each connection binds them to the transport parameters that 0-RTT
/// depends on, so 0-RTT is rejected once those change.
///
/// The conversion restricts the context to TLS 1.3 and installs the QUIC callbacks, replacing any
/// on the builder. Other callbacks of the builder are kept.
pub struct QuicServerConfig {
    ctx: SslContext,
    ssl_callback: Option<Box<SslCallback>>,
}

impl QuicServerConfig {
    /// Returns the underlying [SslContext] backing all created sessions.
    pub fn ctx(&self) -> &SslContext {
        &self.ctx
    }

    /// Sets a callback that configures the [Ssl] of each connection with the settings that
    /// BoringSSL has no [SslContextBuilder] counterpart for, such as
    /// [`SslRef::add_application_settings`].
    ///
    /// It runs before the ClientHello is read, once the connection has its QUIC transport
    /// parameters and 0-RTT context, which it should leave alone. An error fails the connection
    /// with an `INTERNAL_ERROR` alert.
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef) -> StdResult<(), ErrorStack> + Send + Sync + 'static,
    {
        self.ssl_callback = Some(Box::new(callback));
    }
}

impl TryFrom<SslContextBuilder> for QuicServerConfig {
    type Error = Error;

    fn try_from(mut builder: SslContextBuilder) -> Result<Self> {
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_quic_method(QuicCallbacks)?;

        Ok(Self {
            ctx: builder.build(),
            ssl_callback: None,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: ConnectionId,
    ) -> StdResult<crypto::Keys, crypto::UnsupportedVersion> {
        let version = QuicVersion::parse(version)?;
        let secrets = Secrets::initial(version, &dst_cid, Side::Server).unwrap();
        Ok(secrets.keys().unwrap().into_crypto().unwrap())
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Never called with a version that `initial_keys` rejected.
        let version = QuicVersion::parse(version).unwrap();
        retry::retry_tag(&version, &orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        // Never called with a version that `initial_keys` rejected. The session only fails to
        // start when BoringSSL runs out of memory, which the trait cannot report.
        let version = QuicVersion::parse(version).unwrap();
        Session::new(self, version, params).unwrap()
    }
}

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: SessionState,
    handshake_data_sent: bool,
}

impl Session {
    fn new(
        cfg: Arc<QuicServerConfig>,
        version: QuicVersion,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let mut ssl = Ssl::new(&cfg.ctx)?;

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a server.
        ssl.set_accept_state();

        // Set the transport parameters.
        ssl.set_quic_transport_params(&encode_params(params))?;

        // BoringSSL accepts 0-RTT only under the context of the ticket, so 0-RTT is rejected
        // once the limits that a client remembers change. Without a context, BoringSSL issues
        // no tickets for 0-RTT.
        match params.early_data_context() {
            Ok(context) => ssl.set_quic_early_data_context(&context)?,
            Err(e) => warn!("0-RTT disabled: failed decoding own transport parameters: {e}"),
        }

        // The trait cannot report a failure to start, so the handshake fails on the ClientHello.
        let configured = match &cfg.ssl_callback {
            Some(callback) => callback(&mut ssl),
            None => Ok(()),
        };
        let state = SessionState::new(ssl, Side::Server, version)?;
        if let Err(e) = configured {
            state.fail(format!("SSL callback failed: {e}"));
        }

        Ok(Box::new(Self {
            state,
            handshake_data_sent: false,
        }))
    }
}

impl crypto::Session for Session {
    fn initial_keys(&self, dcid: ConnectionId, side: Side) -> crypto::Keys {
        self.state.initial_keys(&dcid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.state.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.state.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.state.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.state.is_handshaking()
    }

    fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<bool, TransportError> {
        self.state.read_handshake(plaintext)?;

        // Only indicate that handshake data is available once, when the client hello has been
        // processed. QUIC requires ALPN, so a protocol is selected by then.
        if !self.handshake_data_sent && self.state.ssl.selected_alpn_protocol().is_some() {
            self.handshake_data_sent = true;
            return Ok(true);
        }

        Ok(false)
    }

    fn transport_parameters(&self) -> StdResult<Option<TransportParameters>, TransportError> {
        self.state.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.state.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.state.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.state.is_valid_retry(&orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> StdResult<(), crypto::ExportKeyingMaterialError> {
        self.state.export_keying_material(output, label, context)
    }
}

fn encode_params(params: &TransportParameters) -> Bytes {
    let mut out = BytesMut::with_capacity(128);
    params.write(&mut out);
    out.freeze()
}
