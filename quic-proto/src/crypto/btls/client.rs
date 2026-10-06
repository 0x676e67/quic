use crate::crypto::btls::error::Result;
use crate::crypto::btls::session_cache::Entry;
use crate::crypto::btls::session_state::{QuicCallbacks, SessionState};
use crate::crypto::btls::version::QuicVersion;
use crate::crypto::btls::{Error, SessionCache, SimpleCache};
use crate::{
    ConnectError, ConnectionId, Side, TransportError, crypto,
    transport_parameters::TransportParameters,
};
use btls::error::ErrorStack;
use btls::ex_data::Index;
use btls::ssl::{
    Ssl, SslContext, SslContextBuilder, SslRef, SslSession, SslSessionCacheMode, SslVerifyMode,
    SslVersion,
};
use btls::x509::verify::X509CheckFlags;
use bytes::{Bytes, BytesMut};
use std::any::Any;
use std::io::Cursor;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tracing::{trace, warn};

/// Configures the [Ssl] of each connection, see [`QuicClientConfig::set_ssl_callback`].
type SslCallback = dyn Fn(&mut SslRef, &str) -> StdResult<(), ErrorStack> + Send + Sync;

/// Configuration for a client-side QUIC. Wraps around a BoringSSL [SslContext].
///
/// It is created from an [SslContextBuilder] with [`TryFrom`]. The builder is the place for
/// every TLS setting that BoringSSL keeps on the context, including those that only exist on
/// [SslContextBuilder], such as:
/// - [`SslContextBuilder::set_alpn_protos`], which QUIC requires
///   ([RFC 9001 §8.1](https://www.rfc-editor.org/rfc/rfc9001#section-8.1)): without ALPN
///   protocols, BoringSSL cannot build the ClientHello, so the connection fails to start with
///   [`ConnectError::EndpointStopping`] and the reason is logged
/// - the trust anchors, such as [`SslContextBuilder::set_default_verify_paths`]
/// - [`SslContextBuilder::set_grease_enabled`]
/// - [`SslContextBuilder::set_sigalgs_list`]
/// - [`SslContextBuilder::set_extension_permutation`]
/// - [`SslContextBuilder::add_certificate_compression_algorithm`]
/// - [`SslContextBuilder::set_keylog_callback`]
/// - [`SslContextBuilder::set_early_data_enabled`] to send 0-RTT data with the sessions that
///   allow it; without it, sessions are still resumed, in 1-RTT
///
/// Settings that BoringSSL only has per connection, such as ALPS and ECH, go in
/// [`QuicClientConfig::set_ssl_callback`].
///
/// The conversion restricts the context to TLS 1.3 and installs the QUIC callbacks and the session
/// cache callback, replacing any on the builder. The verification settings and other callbacks of
/// the builder are kept, except that the server is verified if the builder verifies nothing.
pub struct QuicClientConfig {
    ctx: SslContext,
    session_cache: Arc<dyn SessionCache>,
    /// Keeps the sessions of this configuration apart from those of others in a shared
    /// [SessionCache], since a session resumes without authenticating either peer again.
    cache_scope: u64,
    ssl_callback: Option<Box<SslCallback>>,
}

impl QuicClientConfig {
    /// The servers whose sessions the default [SessionCache] keeps.
    const SESSION_CACHE_SERVERS: NonZeroUsize = NonZeroUsize::new(256).unwrap();

    /// Returns the underlying [SslContext] backing all created sessions.
    pub fn ctx(&self) -> &SslContext {
        &self.ctx
    }

    /// Sets a callback that configures the [Ssl] of each connection with the settings that
    /// BoringSSL has no [SslContextBuilder] counterpart for, such as
    /// [`SslRef::add_application_settings`] and [`SslRef::set_enable_ech_grease`]. It receives
    /// the server name, and an error fails the connection like other failures to start it.
    ///
    /// It runs before the ClientHello is built, once the connection has its QUIC transport
    /// parameters, server name and certificate verification, which it should leave alone.
    /// What the handshake then negotiated, such as the server's ALPS settings, is in
    /// [`HandshakeData`](super::HandshakeData).
    ///
    /// A session resumes without authenticating either peer again, and within a configuration
    /// the [SessionCache] keys sessions by server name only. So whatever the callback sets for
    /// verification or client authentication, such as [`SslRef::set_verify`] or
    /// [`SslRef::set_certificate`], must follow from the server name alone, or the cache must be
    /// a [`NoSessionCache`].
    ///
    /// [`NoSessionCache`]: crate::crypto::btls::NoSessionCache
    pub fn set_ssl_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &str) -> StdResult<(), ErrorStack> + Send + Sync + 'static,
    {
        self.ssl_callback = Some(Box::new(callback));
    }

    /// Gets the [SessionCache] used to cache all client sessions.
    pub fn get_session_cache(&self) -> Arc<dyn SessionCache> {
        self.session_cache.clone()
    }

    /// Sets the [SessionCache] to be shared by all created client sessions.
    ///
    /// Other configurations may share the cache, but only resume the sessions they cached
    /// themselves.
    pub fn set_session_cache(&mut self, session_cache: Arc<dyn SessionCache>) {
        self.session_cache = session_cache;
    }
}

impl TryFrom<SslContextBuilder> for QuicClientConfig {
    type Error = Error;

    fn try_from(mut builder: SslContextBuilder) -> Result<Self> {
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        if builder.verify_mode() == SslVerifyMode::NONE {
            builder.set_verify(SslVerifyMode::PEER);
        }
        builder
            .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        builder.set_new_session_callback(Session::on_new_session);
        builder.set_quic_method(QuicCallbacks)?;

        static NEXT_CACHE_SCOPE: AtomicU64 = AtomicU64::new(0);
        Ok(Self {
            ctx: builder.build(),
            session_cache: Arc::new(SimpleCache::new(Self::SESSION_CACHE_SERVERS)),
            cache_scope: NEXT_CACHE_SCOPE.fetch_add(1, Ordering::Relaxed),
            ssl_callback: None,
        })
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> StdResult<Box<dyn crypto::Session>, ConnectError> {
        let version = QuicVersion::parse(version)?;
        // Failures other than an invalid server name become `EndpointStopping`, such as a
        // builder without the ALPN protocols that QUIC requires, so log why.
        let session = Session::new(self, version, server_name, params).inspect_err(|e| {
            if !matches!(e, Error::ConnectError(_)) {
                warn!("failed starting a btls session for {server_name}: {e}");
            }
        })?;
        Ok(session)
    }
}

static TICKET_CACHE_INDEX: LazyLock<Option<Index<Ssl, TicketCache>>> =
    LazyLock::new(|| Ssl::new_ex_index().ok());

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: SessionState,
    zero_rtt_peer_params: Option<TransportParameters>,
    handshake_data_sent: bool,
}

impl Session {
    fn new(
        cfg: Arc<QuicClientConfig>,
        version: QuicVersion,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let mut ssl = Ssl::new(&cfg.ctx)?;

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a client.
        ssl.set_connect_state();

        // Verify the server certificate for the server name, and send it as SNI unless it is
        // an IP address, which SNI does not allow
        // (https://www.rfc-editor.org/rfc/rfc6066#section-3).
        let invalid_name = |_| ConnectError::InvalidServerName(server_name.into());
        let ip = server_name.parse::<IpAddr>().ok();
        set_verify_hostname(&mut ssl, server_name, ip).map_err(invalid_name)?;
        if ip.is_none() {
            ssl.set_hostname(server_name).map_err(invalid_name)?;
        }

        ssl.set_quic_transport_params(&encode_params(params))?;

        if let Some(callback) = &cfg.ssl_callback {
            callback(&mut ssl, server_name)?;
        }

        let key = [&cfg.cache_scope.to_be_bytes()[..], server_name.as_bytes()].concat();
        let tickets = TicketCache {
            cache: cfg.session_cache.clone(),
            key: Bytes::from(key),
        };

        // Resume a cached session. Taking it out of the cache keeps it to this connection, and
        // BoringSSL does not offer it once expired.
        let mut zero_rtt_peer_params = None;
        if let Some(entry) = tickets.cache.take(&tickets.key) {
            match Entry::decode(&entry) {
                Ok(entry) => {
                    zero_rtt_peer_params = Some(entry.params);
                    // SAFETY: The handshake has not started, and the session was cached for
                    // this server name by this configuration, whose verification it passed: the
                    // cache scope keeps out the sessions of other configurations. The SSL
                    // callback must not vary verification or client authentication for a server
                    // name.
                    match unsafe { ssl.set_session(entry.session.as_ref()) } {
                        Ok(()) => {
                            trace!("attempting resumption for server: {}.", server_name);
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
        ssl.set_ex_data(index, tickets);

        let mut session = Box::new(Self {
            state: SessionState::new(ssl, Side::Client, version)?,
            zero_rtt_peer_params,
            handshake_data_sent: false,
        });

        // Start the handshake in order to emit the Client Hello on the first
        // call to write_handshake.
        session
            .state
            .advance_handshake()
            .map_err(|e| Error::other(format!("failed starting the handshake: {e}")))?;

        Ok(session)
    }

    /// Handler for the rejection of a 0-RTT attempt. Will continue with 1-RTT.
    fn on_zero_rtt_rejected(&mut self) -> StdResult<(), TransportError> {
        trace!(
            "0-RTT handshake attempted but was rejected by the server: {}",
            self.state.ssl.early_data_reason()
        );

        // The rejected session left the cache when it was taken, and the other sessions of the
        // server may still resume other connections.
        self.zero_rtt_peer_params = None;

        // Now retry advancing the handshake, this time in 1-RTT mode.
        self.state.advance_handshake()
    }

    /// Caches a new session, for [`SslContextBuilder::set_new_session_callback`].
    fn on_new_session(ssl: &mut SslRef, session: SslSession) {
        if let Some(tickets) = (*TICKET_CACHE_INDEX).and_then(|index| ssl.ex_data(index)) {
            tickets.put(ssl, session);
        }
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

        // Only indicate that handshake data is available once, when the server has selected
        // the ALPN protocol. During 0-RTT, BoringSSL reports the protocol of the session
        // instead, which the server only confirms by accepting 0-RTT, and may replace by
        // rejecting it.
        let ssl = &self.state.ssl;
        let predicted = ssl.in_early_data() && !ssl.early_data_accepted();
        if !self.handshake_data_sent && !predicted && ssl.selected_alpn_protocol().is_some() {
            self.handshake_data_sent = true;
            return Ok(true);
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

/// The [SessionCache] entry of a connection. The new session callback finds it in the ex_data
/// of the [Ssl].
#[derive(Clone)]
struct TicketCache {
    cache: Arc<dyn SessionCache>,
    /// The cache scope of the configuration, followed by the server name.
    key: Bytes,
}

impl TicketCache {
    /// Caches a new session with the server transport parameters, which 0-RTT needs.
    fn put(&self, ssl: &SslRef, session: SslSession) {
        // Get the server transport parameters.
        let params = match ssl.peer_quic_transport_params() {
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
            Ok(value) => self.cache.put(self.key.clone(), value),
            Err(e) => {
                warn!("failed caching session: unable to encode entry: {:?}", e);
            }
        }
    }
}

/// Verifies the server certificate for `ip`, or else for the host name `server_name`.
fn set_verify_hostname(
    ssl: &mut SslRef,
    server_name: &str,
    ip: Option<IpAddr>,
) -> StdResult<(), ErrorStack> {
    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match ip {
        Some(ip) => param.set_ip(ip),
        None => param.set_host(server_name),
    }
}

fn encode_params(params: &TransportParameters) -> Bytes {
    let mut out = BytesMut::with_capacity(128);
    params.write(&mut out);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::ssl::{NameType, SslMethod};
    use crypto::ClientConfig as _;

    #[test]
    fn start_session() {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
        builder.set_alpn_protos(b"\x02h3").unwrap();
        let config = Arc::new(QuicClientConfig::try_from(builder).unwrap());
        let params = TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[1])),
            ..TransportParameters::default()
        };

        // SNI carries host names, but not IP addresses.
        for (server_name, sni) in [
            ("localhost", Some("localhost")),
            ("127.0.0.1", None),
            ("::1", None),
        ] {
            let session =
                Session::new(config.clone(), QuicVersion::V1, server_name, &params).unwrap();
            assert_eq!(session.state.ssl.servername(NameType::HOST_NAME), sni);
        }

        let err = config
            .clone()
            .start_session(0x0bad_0bad, "localhost", &params);
        assert!(matches!(err, Err(ConnectError::UnsupportedVersion)));
        let err = config.start_session(1, "bad\0name", &params);
        assert!(matches!(err, Err(ConnectError::InvalidServerName(_))));

        // Without ALPN protocols, BoringSSL cannot build the ClientHello.
        let config = QuicClientConfig::try_from(SslContextBuilder::new(SslMethod::tls()).unwrap());
        let err = Arc::new(config.unwrap()).start_session(1, "localhost", &params);
        assert!(matches!(err, Err(ConnectError::EndpointStopping)));
    }
}
