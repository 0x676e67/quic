use crate::crypto::btls::alpn::AlpnProtocols;
use crate::crypto::btls::bffi_ext::QuicSsl;
use crate::crypto::btls::error::{Error, Result};
use crate::crypto::btls::secret::Secrets;
use crate::crypto::btls::session_state::{QUIC_METHOD, SessionState};
use crate::crypto::btls::version::QuicVersion;
use crate::crypto::btls::{QuicSslContext, retry};
use crate::{
    ConnectionId, Side, TransportError, crypto, transport_parameters::TransportParameters,
};
use btls::ex_data::Index;
use btls::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslRef, SslVersion};
use btls_sys as bffi;
use bytes::{Bytes, BytesMut};
use foreign_types_shared::ForeignTypeRef;
use std::any::Any;
use std::ffi::{c_int, c_uint, c_void};
use std::result::Result as StdResult;
use std::slice;
use std::sync::Arc;
use std::sync::LazyLock;
use tracing::warn;

/// Configuration for a server-side QUIC. Wraps around a BoringSSL [SslContext].
pub struct Config {
    ctx: SslContext,
    alpn_protocols: AlpnProtocols,
}

impl Config {
    pub fn new() -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;

        // QUIC requires TLS 1.3.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        builder.set_default_verify_paths()?;

        // We build the context early, since we are not allowed to further mutate the context
        // in start_session.
        let mut ctx = builder.build();

        // Disable verification of the client by default.
        ctx.verify_peer(false);

        // By default, enable early data (used for 0-RTT).
        ctx.enable_early_data(true);

        // Configure default ALPN protocols accepted by the server.QUIC requires ALPN be
        // configured (see https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).
        ctx.set_alpn_select_cb(Some(Session::alpn_select_callback));

        // Set the callback for receipt of the Server Name Indication (SNI) extension.
        ctx.set_server_name_cb(Some(Session::server_name_callback));

        // Set callbacks for the SessionState.
        ctx.set_quic_method(&QUIC_METHOD)?;
        ctx.set_info_callback(Some(SessionState::info_callback));

        ctx.set_options(bffi::SSL_OP_CIPHER_SERVER_PREFERENCE as u32);

        Ok(Self {
            ctx,
            alpn_protocols: AlpnProtocols::default(),
        })
    }

    /// Returns the underlying [SslContext] backing all created sessions.
    pub fn ctx(&self) -> &SslContext {
        &self.ctx
    }

    /// Returns the underlying [SslContext] backing all created sessions. Wherever possible use
    /// the provided methods to modify settings rather than accessing this directly.
    ///
    /// Care should be taken to avoid overriding required behavior. In particular, this
    /// configuration will set callbacks for QUIC events, alpn selection, server name,
    /// as well as info and key logging.
    pub fn ctx_mut(&mut self) -> &mut SslContext {
        &mut self.ctx
    }

    /// Sets whether or not the peer certificate should be verified. If `true`, any error
    /// during verification will be fatal. If not called, verification of the client is
    /// disabled by default.
    pub fn verify_peer(&mut self, verify: bool) {
        self.ctx.verify_peer(verify)
    }

    /// Sets the ALPN protocols that will be accepted by the server. QUIC requires that
    /// ALPN be used (see <https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1>).
    ///
    /// If this method is not called, the server will default to accepting "h3".
    pub fn set_alpn(&mut self, alpn_protocols: &[Vec<u8>]) -> Result<()> {
        self.alpn_protocols = alpn_protocols.into();
        Ok(())
    }
}

impl crypto::ServerConfig for Config {
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
        let version = QuicVersion::parse(version).unwrap();
        retry::retry_tag(&version, &orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let version = QuicVersion::parse(version).unwrap();
        Session::new(self, version, params).unwrap()
    }
}

/// The ALPN protocols the server accepts, for the ALPN callback.
static ALPN_INDEX: LazyLock<Option<Index<Ssl, AlpnProtocols>>> =
    LazyLock::new(|| Ssl::new_ex_index().ok());

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: SessionState,
    handshake_data_sent: bool,
}

impl Session {
    fn new(
        cfg: Arc<Config>,
        version: QuicVersion,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let mut ssl = Ssl::new(&cfg.ctx).unwrap();

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a server.
        ssl.set_accept_state();

        // Set the transport parameters.
        ssl.set_quic_transport_params(&encode_params(params))
            .unwrap();

        // BoringSSL accepts 0-RTT only under the context of the ticket, so 0-RTT is rejected
        // once the limits that a client remembers change. Without a context, BoringSSL issues
        // no tickets for 0-RTT.
        match params.early_data_context() {
            Ok(context) => ssl.set_quic_early_data_context(&context)?,
            Err(e) => warn!("0-RTT disabled: failed decoding own transport parameters: {e}"),
        }

        let index = ALPN_INDEX.ok_or_else(|| Error::other("no ex_data index".into()))?;
        ssl.set_ex_data(index, cfg.alpn_protocols.clone());

        Ok(Box::new(Self {
            state: SessionState::new(ssl, Side::Server, version)?,
            handshake_data_sent: false,
        }))
    }
}

// Raw callbacks from BoringSSL
impl Session {
    /// Selects the ALPN protocol from the ones the client offered.
    extern "C" fn alpn_select_callback(
        ssl: *mut bffi::SSL,
        out: *mut *const u8,
        out_len: *mut u8,
        in_: *const u8,
        in_len: c_uint,
        _: *mut c_void,
    ) -> c_int {
        // SAFETY: BoringSSL passes the callback the `SSL` it runs for, the offered protocols,
        // and the output slots for the selected one.
        unsafe {
            let ssl = SslRef::from_ptr(ssl);
            let Some(alpn) = (*ALPN_INDEX).and_then(|index| ssl.ex_data(index)) else {
                return bffi::SSL_TLSEXT_ERR_ALERT_FATAL;
            };
            let protos = slice::from_raw_parts(in_, in_len as _);
            match alpn.select(protos) {
                Ok(proto) => {
                    *out = proto.as_ptr() as _;
                    *out_len = proto.len() as _;
                    bffi::SSL_TLSEXT_ERR_OK
                }
                Err(_) => bffi::SSL_TLSEXT_ERR_ALERT_FATAL,
            }
        }
    }

    /// Acknowledges the Server Name Indication (SNI) extension in the client hello.
    extern "C" fn server_name_callback(_: *mut bffi::SSL, _: *mut c_int, _: *mut c_void) -> c_int {
        // SSL_TLSEXT_ERR_OK causes the server_name extension to be acked in
        // ServerHello.
        bffi::SSL_TLSEXT_ERR_OK
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
