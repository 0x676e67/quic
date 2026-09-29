use crate::crypto::btls::alpn::AlpnProtocols;
use crate::crypto::btls::bffi_ext::QuicSslContext;
use crate::crypto::btls::error::Result;
use crate::crypto::btls::session_state::{QUIC_METHOD, SessionState};
use crate::crypto::btls::version::QuicVersion;
use crate::crypto::btls::{Entry, Error, QuicSsl, QuicSslSession, SessionCache, SimpleCache};
use crate::{
    ConnectError, ConnectionId, Side, TransportError, crypto,
    transport_parameters::TransportParameters,
};
use btls::ex_data::Index;
use btls::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslRef, SslSession, SslVersion};
use btls_sys as bffi;
use bytes::{Bytes, BytesMut};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use std::any::Any;
use std::ffi::c_int;
use std::io::Cursor;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::LazyLock;
use tracing::{trace, warn};

/// Per-session settings that are applied to each new [Ssl] instance at handshake time.
///
/// These settings cannot be baked into the shared [SslContext] because they are either
/// per-connection by nature (ECH GREASE) or use a per-`SSL` API (ALPS).
#[derive(Clone, Default)]
pub struct SessionSettings {
    /// ALPS protocol payloads to advertise via `SSL_add_application_settings`.
    /// Each entry is the raw protocol bytes (e.g. `b"h3"`).
    pub alps_protocols: Vec<Vec<u8>>,
    /// Whether to use the new ALPS codepoint (17613) instead of the old one (17513).
    pub alps_use_new_codepoint: bool,
    /// Whether to enable ECH GREASE on every outgoing ClientHello.
    pub enable_ech_grease: bool,
}

/// Configuration for a client-side QUIC. Wraps around a BoringSSL [SslContext].
pub struct Config {
    ctx: SslContext,
    session_cache: Arc<dyn SessionCache>,
    session_settings: SessionSettings,
}

impl Config {
    /// Creates a new [Config] using a default [SslContextBuilder].
    pub fn new() -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;
        builder.set_default_verify_paths()?;
        Self::from_builder(builder)
    }

    /// Creates a new [Config] from a caller-provided [SslContextBuilder].
    ///
    /// The builder is the right place to configure settings that are only available on
    /// [SslContextBuilder] and not on the finished [SslContext], such as:
    /// - [`SslContextBuilder::set_grease_enabled`]
    /// - [`SslContextBuilder::set_sigalgs_list`]
    /// - [`SslContextBuilder::set_extension_permutation`]
    /// - [`SslContextBuilder::add_certificate_compression_algorithm`]
    ///
    /// Quinn-btls will apply its required QUIC callbacks and defaults on top of whatever
    /// the caller has already configured.
    pub fn from_builder(mut builder: SslContextBuilder) -> Result<Self> {
        // QUIC requires TLS 1.3. Enforce this regardless of what the caller configured.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        let mut ctx = builder.build();

        // By default, enable early data (used for 0-RTT).
        ctx.enable_early_data(true);

        // Set the default ALPN protocols offered by the client. QUIC requires ALPN be configured
        // (see <https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1>).
        ctx.set_alpn_protos(&AlpnProtocols::default().encode())?;

        // Configure session caching.
        ctx.set_session_cache_mode(bffi::SSL_SESS_CACHE_CLIENT | bffi::SSL_SESS_CACHE_NO_INTERNAL);
        ctx.set_new_session_callback(Some(Session::new_session_callback));

        // Set callbacks for the SessionState.
        ctx.set_quic_method(&QUIC_METHOD)?;
        ctx.set_info_callback(Some(SessionState::info_callback));

        // For clients, verification of the server is on by default.
        ctx.verify_peer(true);

        Ok(Self {
            ctx,
            session_cache: Arc::new(SimpleCache::new(256)),
            session_settings: SessionSettings::default(),
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

    /// Returns the [SessionSettings] applied to each new TLS session.
    pub fn session_settings(&self) -> &SessionSettings {
        &self.session_settings
    }

    /// Returns the [SessionSettings] applied to each new TLS session, mutably.
    pub fn session_settings_mut(&mut self) -> &mut SessionSettings {
        &mut self.session_settings
    }

    /// Sets whether or not the peer certificate should be verified. If `true`, any error
    /// during verification will be fatal. If not called, verification of the server is
    /// enabled by default.
    pub fn verify_peer(&mut self, verify: bool) {
        self.ctx.verify_peer(verify)
    }

    /// Gets the [SessionCache] used to cache all client sessions.
    pub fn get_session_cache(&self) -> Arc<dyn SessionCache> {
        self.session_cache.clone()
    }

    /// Sets the [SessionCache] to be shared by all created client sessions.
    pub fn set_session_cache(&mut self, session_cache: Arc<dyn SessionCache>) {
        self.session_cache = session_cache;
    }

    /// Sets the ALPN protocols supported by the client. QUIC requires that
    /// ALPN be used (see <https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1>).
    /// By default, the client will offer "h3".
    pub fn set_alpn(&mut self, alpn_protocols: &[Vec<u8>]) -> Result<()> {
        self.ctx
            .set_alpn_protos(&AlpnProtocols::from(alpn_protocols).encode())?;
        Ok(())
    }
}

impl crypto::ClientConfig for Config {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> StdResult<Box<dyn crypto::Session>, ConnectError> {
        let version = QuicVersion::parse(version).unwrap();

        Ok(Session::new(self, version, server_name, params)
            .map_err(|_| ConnectError::EndpointStopping)?)
    }
}

static TICKET_CACHE_INDEX: LazyLock<Option<Index<Ssl, TicketCache>>> =
    LazyLock::new(|| Ssl::new_ex_index().ok());

/// The [SessionCache] entry of a connection. The new session callback finds it in the ex_data
/// of the [Ssl].
#[derive(Clone)]
struct TicketCache {
    cache: Arc<dyn SessionCache>,
    server_name: Bytes,
}

impl TicketCache {
    /// Caches a new session with the server transport parameters, which 0-RTT needs.
    fn put(&self, ssl: &SslRef, session: SslSession) {
        if !session.early_data_capable() {
            warn!("failed caching session: not early data capable");
            return;
        }

        // Get the server transport parameters.
        let params = match ssl.get_peer_quic_transport_params() {
            Some(params) => {
                match TransportParameters::read(Side::Client, &mut Cursor::new(&params)) {
                    Ok(params) => params,
                    Err(e) => {
                        warn!("failed parsing server transport parameters: {:?}", e);
                        return;
                    }
                }
            }
            None => {
                warn!("failed caching session: server transport parameters are not available");
                return;
            }
        };

        // Encode the session cache entry, including both the session and the server params.
        let entry = Entry { session, params };
        match entry.encode() {
            Ok(value) => self.cache.put(self.server_name.clone(), value),
            Err(e) => {
                warn!("failed caching session: unable to encode entry: {:?}", e);
            }
        }
    }

    fn remove(&self) {
        self.cache.remove(self.server_name.clone());
    }
}

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: SessionState,
    tickets: TicketCache,
    zero_rtt_peer_params: Option<TransportParameters>,
    handshake_data_available: bool,
    handshake_data_sent: bool,
}

impl Session {
    fn new(
        cfg: Arc<Config>,
        version: QuicVersion,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let mut ssl = Ssl::new(&cfg.ctx).unwrap();

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a client.
        ssl.set_connect_state();

        // Configure verification for the server hostname.
        ssl.set_verify_hostname(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;

        // Set the SNI hostname.
        // TODO: should we validate the hostname?
        ssl.set_hostname(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;

        // Set the transport parameters.
        ssl.set_quic_transport_params(&encode_params(params))
            .map_err(|_| ConnectError::EndpointStopping)?;

        // Apply per-session settings.
        let settings = &cfg.session_settings;
        if settings.enable_ech_grease {
            ssl.set_enable_ech_grease(true);
        }
        for proto in &settings.alps_protocols {
            ssl.add_application_settings(proto)
                .map_err(|_| ConnectError::EndpointStopping)?;
        }
        if !settings.alps_protocols.is_empty() {
            ssl.set_alps_use_new_codepoint(settings.alps_use_new_codepoint);
        }

        let tickets = TicketCache {
            cache: cfg.session_cache.clone(),
            server_name: Bytes::copy_from_slice(server_name.as_bytes()),
        };

        // If we have a cached session, use it.
        let mut zero_rtt_peer_params = None;
        if let Some(entry) = tickets.cache.get(tickets.server_name.clone()) {
            match Entry::decode(ssl.ssl_context(), entry) {
                Ok(entry) => {
                    zero_rtt_peer_params = Some(entry.params);
                    match unsafe { ssl.set_session(entry.session.as_ref()) } {
                        Ok(()) => {
                            trace!("attempting resumption (0-RTT) for server: {}.", server_name);
                        }
                        Err(e) => {
                            warn!(
                                "failed setting cached session for server {}: {:?}",
                                server_name, e
                            )
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "failed decoding session entry for server {}: {:?}",
                        server_name, e
                    )
                }
            }
        } else {
            trace!(
                "no cached session found for server: {}. Will continue with 1-RTT.",
                server_name
            );
        }

        let index = TICKET_CACHE_INDEX.ok_or_else(|| Error::other("no ex_data index".into()))?;
        ssl.set_ex_data(index, tickets.clone());

        let mut session = Box::new(Self {
            state: SessionState::new(ssl, Side::Client, version)?,
            tickets,
            zero_rtt_peer_params,
            handshake_data_available: false,
            handshake_data_sent: false,
        });

        // Start the handshake in order to emit the Client Hello on the first
        // call to write_handshake.
        session.state.advance_handshake()?;

        Ok(session)
    }

    /// Handler for the rejection of a 0-RTT attempt. Will continue with 1-RTT.
    fn on_zero_rtt_rejected(&mut self) -> StdResult<(), TransportError> {
        trace!(
            "0-RTT handshake attempted but was rejected by the server: {}",
            SslRef::early_data_reason_string(self.state.ssl.get_early_data_reason())
        );

        self.zero_rtt_peer_params = None;

        // Removed the failed cache entry.
        self.tickets.remove();

        // Now retry advancing the handshake, this time in 1-RTT mode.
        self.state.advance_handshake()
    }

    /// Raw callback from BoringSSL to cache a new session.
    extern "C" fn new_session_callback(
        ssl: *mut bffi::SSL,
        session: *mut bffi::SSL_SESSION,
    ) -> c_int {
        // SAFETY: BoringSSL passes the callback the `SSL` it runs for, and a session whose
        // reference it hands over.
        let ssl = unsafe { SslRef::from_ptr(ssl) };
        let session = unsafe { SslSession::from_ptr(session) };
        if let Some(tickets) = (*TICKET_CACHE_INDEX).and_then(|index| ssl.ex_data(index)) {
            tickets.put(ssl, session);
        }

        // Return 1 to indicate we've taken ownership of the session.
        1
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
        Some(self.state.ssl.early_data_accepted())
    }

    fn is_handshaking(&self) -> bool {
        self.state.is_handshaking()
    }

    fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<bool, TransportError> {
        self.state.read_handshake(plaintext)?;

        if self.state.early_data_rejected {
            self.on_zero_rtt_rejected()?;
        }

        // Only indicate that handshake data is available once.
        // On the client side there is no ALPN callback, so we need to manually check
        // if the ALPN protocol has been selected.
        if !self.handshake_data_sent {
            if self.state.ssl.selected_alpn_protocol().is_some() {
                self.handshake_data_available = true;
            }

            if self.handshake_data_available {
                self.handshake_data_sent = true;
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn transport_parameters(&self) -> StdResult<Option<TransportParameters>, TransportError> {
        match self.state.transport_parameters()? {
            Some(params) => Ok(Some(params)),
            None => {
                if self.state.ssl.in_early_data() {
                    Ok(self.zero_rtt_peer_params.clone())
                } else {
                    Ok(None)
                }
            }
        }
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
