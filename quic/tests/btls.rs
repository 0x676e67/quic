//! End-to-end handshakes over the btls crypto backend.

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use proto::{TransportParameterConfig, TransportParameterId, TransportParameterKind};
use quic::{
    ClientConfig, Connection, ConnectionError, Endpoint, ReadError, ReadToEndError, ServerConfig,
    TransportConfig, TransportErrorCode,
    btls::{
        pkey::{PKey, Private},
        ssl::{
            AlpnError, ExtensionType, SslContextBuilder, SslInfoCallbackMode, SslMethod,
            SslVerifyError, SslVerifyMode, select_next_proto,
        },
        x509::X509,
    },
    crypto::btls::{
        HandshakeData, QuicClientConfig, QuicServerConfig, SessionCache, SimpleCache, Zeroizing,
    },
};

#[tokio::test]
async fn handshake_resumption_and_early_data() {
    let pki = Pki::new();
    let leaf = pki.issue("localhost");
    let server_chain = pki.chain(&leaf);
    let server = serve(server_endpoint(&pki, &leaf, false));
    // A second server has its own ticket keys, so it cannot resume the first one's sessions.
    let other_server = serve(server_endpoint(&pki, &leaf, false));
    let cache = Arc::new(RemovalTracker::default());
    let client = client_endpoint_with(client_builder(&pki, None), cache.clone());

    // Full handshake: there is no session to resume yet.
    let connecting = client.connect(server, "localhost").unwrap();
    let conn = connecting
        .into_0rtt()
        .expect_err("no ticket yet")
        .await
        .unwrap();
    let data = conn
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap();
    assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));
    assert_eq!(data.server_name, None);
    assert_eq!(peer_chain(&conn), server_chain);
    check_response(
        &conn,
        b"1-rtt",
        &request(&conn, b"1-rtt").await.unwrap(),
        &[],
    );
    conn.close(0u32.into(), b"done");

    // Resumption with the ticket from above: the server accepts the 0-RTT stream.
    let connecting = client.connect(server, "localhost").unwrap();
    let conn = connecting.into_0rtt().expect("resumable ticket");
    let response = request(&conn, b"0-rtt").await.unwrap();
    check_response(&conn, b"0-rtt", &response, &[]);
    assert_eq!(peer_chain(&conn), server_chain);
    conn.close(0u32.into(), b"done");

    // The other server rejects the 0-RTT stream, and the connection continues in 1-RTT.
    let connecting = client.connect(other_server, "localhost").unwrap();
    let conn = connecting.into_0rtt().expect("resumable ticket");
    assert!(matches!(
        request(&conn, b"0-rtt").await,
        Err(ReadToEndError::Read(ReadError::ZeroRttRejected))
    ));
    let response = request(&conn, b"retry").await.unwrap();
    check_response(&conn, b"retry", &response, &[]);
    conn.close(0u32.into(), b"done");
    // The rejected ticket was used up, and the others of the server stay for other connections.
    assert!(!cache.removed.load(Ordering::Relaxed));

    // An untrusted server rejects the 0-RTT stream too. The client verifies the server
    // certificate only after it resumes the handshake in 1-RTT, and that failure must close
    // the connection with a TLS alert rather than leave it to time out.
    let untrusted = Pki::new();
    let untrusted_server = serve(server_endpoint(
        &untrusted,
        &untrusted.issue("localhost"),
        false,
    ));
    let connecting = client.connect(untrusted_server, "localhost").unwrap();
    let conn = connecting.into_0rtt().expect("resumable ticket");
    let err = conn.closed().await;
    assert!(
        matches!(&err, ConnectionError::TransportError(e) if is_tls_alert(e.code)),
        "{err:?}"
    );

    client.wait_idle().await;
}

#[tokio::test]
async fn early_data_rejected_after_transport_change() {
    // A lower stream limit, configured or only sent on the wire.
    let mut configured = TransportConfig::default();
    configured.max_concurrent_bidi_streams(10u32.into());
    let sent = sending_max_streams_bidi(vec![10]);

    for limited in [configured, sent] {
        let pki = Pki::new();
        let crypto = Arc::new(server_crypto(&pki, &pki.issue("localhost"), false));
        // Both servers share the ticket keys of `crypto`, and only differ in a stream limit.
        let config = ServerConfig::with_crypto(crypto.clone());
        let server = serve(Endpoint::server(config, localhost()).unwrap());
        let mut config = ServerConfig::with_crypto(crypto);
        config.transport_config(Arc::new(limited));
        let limited_server = serve(Endpoint::server(config, localhost()).unwrap());
        let client = client_endpoint(&pki, None);

        let conn = client.connect(server, "localhost").unwrap().await.unwrap();
        request(&conn, b"1-rtt").await.unwrap();
        conn.close(0u32.into(), b"done");

        // The limited server resumes the session, but rejects the 0-RTT stream: the client
        // remembers a higher stream limit than the server now grants.
        let connecting = client.connect(limited_server, "localhost").unwrap();
        let conn = connecting.into_0rtt().expect("resumable ticket");
        assert!(matches!(
            request(&conn, b"0-rtt").await,
            Err(ReadToEndError::Read(ReadError::ZeroRttRejected))
        ));
        let response = request(&conn, b"retry").await.unwrap();
        check_response(&conn, b"retry", &response, &[]);
        conn.close(0u32.into(), b"done");

        // A ticket of the limited server matches its limits, so it accepts 0-RTT.
        let connecting = client.connect(limited_server, "localhost").unwrap();
        let conn = connecting.into_0rtt().expect("resumable ticket");
        let response = request(&conn, b"0-rtt").await.unwrap();
        check_response(&conn, b"0-rtt", &response, &[]);
        conn.close(0u32.into(), b"done");

        client.wait_idle().await;
    }
}

/// A malformed transport parameter fails the connection with TRANSPORT_PARAMETER_ERROR
/// (https://www.rfc-editor.org/rfc/rfc9000#section-7.4).
#[tokio::test]
async fn malformed_transport_parameter() {
    let pki = Pki::new();
    let crypto = server_crypto(&pki, &pki.issue("localhost"), false);
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    // The prefix of a two-byte integer, without its second byte.
    config.transport_config(Arc::new(sending_max_streams_bidi(vec![0x40])));
    let server = serve(Endpoint::server(config, localhost()).unwrap());
    let client = client_endpoint(&pki, None);

    let err = client
        .connect(server, "localhost")
        .unwrap()
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ConnectionError::TransportError(e) if e.code == TransportErrorCode::TRANSPORT_PARAMETER_ERROR),
        "{err:?}"
    );
}

#[tokio::test]
async fn peer_identity_with_client_auth() {
    let pki = Pki::new();
    let server_leaf = pki.issue("localhost");
    let client_leaf = pki.issue("client");
    let server = serve(server_endpoint(&pki, &server_leaf, true));
    let client = client_endpoint(&pki, Some(&client_leaf));

    let conn = client.connect(server, "localhost").unwrap().await.unwrap();
    assert_eq!(peer_chain(&conn), pki.chain(&server_leaf));
    // The server replies with the client chain it sees, which must start with the leaf too.
    let response = request(&conn, b"hello").await.unwrap();
    check_response(
        &conn,
        b"hello",
        &response,
        &pki.chain(&client_leaf).concat(),
    );
    conn.close(0u32.into(), b"done");

    client.wait_idle().await;
}

/// Both sides take their ALPN protocols from the builder, and a server without any fails the
/// handshake, since QUIC requires ALPN (https://www.rfc-editor.org/rfc/rfc9001#section-8.1).
#[tokio::test]
async fn alpn_from_builder() {
    let pki = Pki::new();
    let leaf = pki.issue("localhost");
    let mut builder = client_builder(&pki, None);
    builder.set_alpn_protos(b"\x01a\x01b\x01c").unwrap();
    let client = client_endpoint_with(builder, Arc::new(SimpleCache::new(NonZeroUsize::MIN)));
    let server = |configure: &dyn Fn(&mut SslContextBuilder)| {
        let mut builder = server_builder(&pki, &leaf, false);
        configure(&mut builder);
        let crypto = QuicServerConfig::try_from(builder).unwrap();
        let config = ServerConfig::with_crypto(Arc::new(crypto));
        serve(Endpoint::server(config, localhost()).unwrap())
    };

    // BoringSSL selects by the client's preference from the protocols of the builder, and a
    // selection callback can prefer the server's order instead. The client's first protocol is
    // in neither list, so neither result can come from the client alone.
    let by_list = server(&|builder| builder.set_alpn_protos(b"\x01c\x01b").unwrap());
    let by_callback = server(&|builder| {
        builder.set_alpn_select_callback(|_, offered| {
            select_next_proto(b"\x01c\x01b", offered).ok_or(AlpnError::NOACK)
        })
    });
    for (server, protocol) in [(by_list, b"b"), (by_callback, b"c")] {
        let conn = client.connect(server, "localhost").unwrap().await.unwrap();
        let data = conn.handshake_data().unwrap();
        let data = data.downcast::<HandshakeData>().unwrap();
        assert_eq!(data.protocol.as_deref(), Some(&protocol[..]));
        conn.close(0u32.into(), b"done");
    }

    let without_alpn = server(&|_| {});
    let err = client
        .connect(without_alpn, "localhost")
        .unwrap()
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ConnectionError::ConnectionClosed(close) if close.error_code == TransportErrorCode::crypto(NO_APPLICATION_PROTOCOL)),
        "{err:?}"
    );

    client.wait_idle().await;
}

/// Drafts up to 32 carry the transport parameters in the legacy extension 0xffa5, later ones in
/// the extension 57 (https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-33#section-8.2).
#[tokio::test]
async fn transport_parameters_codepoint() {
    let pki = Pki::new();
    let leaf = pki.issue("localhost");
    // Whether each ClientHello carries the legacy and the standard extension.
    let codepoints = Arc::new(Mutex::new(Vec::new()));
    let mut builder = server_builder(&pki, &leaf, false);
    builder.set_alpn_protos(b"\x02h3").unwrap();
    let seen = codepoints.clone();
    builder.set_select_certificate_callback(move |hello| {
        let legacy = hello.get_extension(ExtensionType::QUIC_TRANSPORT_PARAMETERS_LEGACY);
        let standard = hello.get_extension(ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD);
        seen.lock()
            .unwrap()
            .push((legacy.is_some(), standard.is_some()));
        Ok(())
    });
    let crypto = QuicServerConfig::try_from(builder).unwrap();
    let config = ServerConfig::with_crypto(Arc::new(crypto));
    let server = serve(Endpoint::server(config, localhost()).unwrap());

    let crypto = Arc::new(QuicClientConfig::try_from(client_builder(&pki, None)).unwrap());
    let client = Endpoint::client(localhost()).unwrap();
    // draft-32, draft-33 and version 1.
    for version in [0xff00_0020, 0xff00_0021, 1] {
        let mut config = ClientConfig::new(crypto.clone());
        config.version(version);
        let conn = client
            .connect_with(config, server, "localhost")
            .unwrap()
            .await
            .unwrap();
        conn.close(0u32.into(), b"done");
    }
    assert_eq!(
        *codepoints.lock().unwrap(),
        [(true, false), (false, true), (false, true)]
    );

    client.wait_idle().await;
}

/// 0-RTT needs both sides to enable early data on their builder. Without it on either side, the
/// session still resumes, in 1-RTT.
#[tokio::test]
async fn early_data_from_builder() {
    let pki = Pki::new();
    let leaf = pki.issue("localhost");
    // Whether each handshake resumed a session, as the servers see it.
    let resumed = Arc::new(Mutex::new(Vec::new()));
    let server = |early_data: bool| {
        let mut builder = server_builder(&pki, &leaf, false);
        builder.set_alpn_protos(b"\x02h3").unwrap();
        builder.set_early_data_enabled(early_data);
        let seen = resumed.clone();
        builder.set_info_callback(move |ssl, mode, _| {
            if mode == SslInfoCallbackMode::HANDSHAKE_DONE {
                seen.lock().unwrap().push(ssl.session_reused());
            }
        });
        let crypto = QuicServerConfig::try_from(builder).unwrap();
        let config = ServerConfig::with_crypto(Arc::new(crypto));
        serve(Endpoint::server(config, localhost()).unwrap())
    };

    for (client_early_data, server_early_data) in [(false, true), (true, false)] {
        let server = server(server_early_data);
        let mut builder = client_builder(&pki, None);
        builder.set_early_data_enabled(client_early_data);
        let client = client_endpoint_with(builder, Arc::new(SimpleCache::new(NonZeroUsize::MIN)));

        let conn = client.connect(server, "localhost").unwrap().await.unwrap();
        request(&conn, b"1-rtt").await.unwrap();
        conn.close(0u32.into(), b"done");

        let connecting = client.connect(server, "localhost").unwrap();
        let conn = connecting.into_0rtt().expect_err("no 0-RTT").await.unwrap();
        request(&conn, b"1-rtt").await.unwrap();
        conn.close(0u32.into(), b"done");

        client.wait_idle().await;
    }
    assert_eq!(*resumed.lock().unwrap(), [false, true, false, true]);
}

/// A server flight may exceed the 16 KiB a server itself accepts per level.
#[tokio::test]
async fn large_certificate_chain() {
    let pki = Pki::new();
    let names = ["localhost".to_owned()]
        .into_iter()
        .chain((0..1000).map(|i| format!("padding-{i}.example")));
    let leaf = pki.issue_for(names.collect());
    assert!(leaf.cert.to_der().unwrap().len() > 16 * 1024);
    let server = serve(server_endpoint(&pki, &leaf, false));
    let client = client_endpoint(&pki, None);

    let conn = client.connect(server, "localhost").unwrap().await.unwrap();
    assert_eq!(peer_chain(&conn), pki.chain(&leaf));
    conn.close(0u32.into(), b"done");

    client.wait_idle().await;
}

/// Asynchronous certificate verification needs someone to resume the handshake once it is
/// done, which the session cannot do, so the connection fails instead of stalling.
#[tokio::test]
async fn async_verification_fails_handshake() {
    let pki = Pki::new();
    let server = serve(server_endpoint(&pki, &pki.issue("localhost"), false));
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder.set_custom_verify_callback(SslVerifyMode::PEER, |_| Err(SslVerifyError::Retry));
    builder.set_alpn_protos(b"\x02h3").unwrap();
    let crypto = QuicClientConfig::try_from(builder).unwrap();
    let client = Endpoint::client(localhost()).unwrap();

    let connecting = client
        .connect_with(ClientConfig::new(Arc::new(crypto)), server, "localhost")
        .unwrap();
    let err = connecting.await.unwrap_err();
    assert!(
        matches!(&err, ConnectionError::TransportError(e) if e.code == TransportErrorCode::crypto(INTERNAL_ERROR)),
        "{err:?}"
    );
}

/// A transport configuration that sends `value` as the raw initial_max_streams_bidi parameter.
fn sending_max_streams_bidi(value: Vec<u8>) -> TransportConfig {
    let mut entries: Vec<_> = [
        TransportParameterId::OriginalDestinationConnectionId,
        TransportParameterId::MaxIdleTimeout,
        TransportParameterId::StatelessResetToken,
        TransportParameterId::MaxUdpPayloadSize,
        TransportParameterId::InitialMaxData,
        TransportParameterId::InitialMaxStreamDataBidiLocal,
        TransportParameterId::InitialMaxStreamDataBidiRemote,
        TransportParameterId::InitialMaxStreamDataUni,
        TransportParameterId::InitialMaxStreamsUni,
        TransportParameterId::AckDelayExponent,
        TransportParameterId::MaxAckDelay,
        TransportParameterId::DisableActiveMigration,
        TransportParameterId::ActiveConnectionIdLimit,
        TransportParameterId::InitialSourceConnectionId,
        TransportParameterId::RetrySourceConnectionId,
        TransportParameterId::MaxDatagramFrameSize,
        TransportParameterId::GreaseQuicBit,
    ]
    .map(TransportParameterKind::Known)
    .into();
    entries.push(TransportParameterKind::Custom {
        id: TransportParameterId::InitialMaxStreamsBidi as u64,
        value,
    });
    let mut config = TransportConfig::default();
    config.transport_parameter_config(TransportParameterConfig::new(entries, true));
    config
}

/// The TLS alert for a local failure (https://www.rfc-editor.org/rfc/rfc8446#section-6.2).
const INTERNAL_ERROR: u8 = 80;

/// The TLS alert for an ALPN mismatch (https://www.rfc-editor.org/rfc/rfc7301#section-3.2).
const NO_APPLICATION_PROTOCOL: u8 = 120;

/// Returns whether `code` carries a TLS alert
/// (https://www.rfc-editor.org/rfc/rfc9001#section-4.8).
fn is_tls_alert(code: TransportErrorCode) -> bool {
    (0x100..0x200).contains(&u64::from(code))
}

/// Serves each bidirectional stream with the request, the connection's keying material and
/// the DER of the client certificate chain, if any.
fn serve(endpoint: Endpoint) -> SocketAddr {
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(request) = recv.read_to_end(1024).await else {
                        return;
                    };
                    let mut response = request;
                    response.extend(keying_material(&conn));
                    if conn.peer_identity().is_some() {
                        response.extend(peer_chain(&conn).concat());
                    }
                    send.write_all(&response).await.unwrap();
                    send.finish().unwrap();
                }
            });
        }
    });
    addr
}

async fn request(conn: &Connection, msg: &[u8]) -> Result<Vec<u8>, ReadToEndError> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(msg).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(64 * 1024).await
}

/// Checks a response of [`serve`]: both sides export the same keying material, which depends
/// on the context, and the server saw `client_chain`.
fn check_response(conn: &Connection, msg: &[u8], response: &[u8], client_chain: &[u8]) {
    let (echo, rest) = response.split_at(msg.len());
    assert_eq!(echo, msg);
    let (server_material, server_seen_chain) = rest.split_at(32);
    assert_eq!(server_material, keying_material(conn));
    assert_ne!(server_material[..16], server_material[16..]);
    assert_eq!(server_seen_chain, client_chain);
}

/// Keying material exported with a context, followed by the one exported without.
fn keying_material(conn: &Connection) -> [u8; 32] {
    let mut out = [0; 32];
    let (with_context, without_context) = out.split_at_mut(16);
    conn.export_keying_material(with_context, b"EXPORTER-test", b"context")
        .unwrap();
    conn.export_keying_material(without_context, b"EXPORTER-test", b"")
        .unwrap();
    out
}

fn peer_chain(conn: &Connection) -> Vec<Vec<u8>> {
    conn.peer_identity()
        .unwrap()
        .downcast::<Vec<X509>>()
        .unwrap()
        .iter()
        .map(|cert| cert.to_der().unwrap())
        .collect()
}

fn server_endpoint(pki: &Pki, leaf: &Leaf, client_auth: bool) -> Endpoint {
    let config = ServerConfig::with_crypto(Arc::new(server_crypto(pki, leaf, client_auth)));
    Endpoint::server(config, localhost()).unwrap()
}

/// A server that accepts "h3", which BoringSSL selects from the ALPN protocols of the builder.
fn server_crypto(pki: &Pki, leaf: &Leaf, client_auth: bool) -> QuicServerConfig {
    let mut builder = server_builder(pki, leaf, client_auth);
    builder.set_alpn_protos(b"\x02h3").unwrap();
    QuicServerConfig::try_from(builder).unwrap()
}

/// A server builder that enables 0-RTT, without ALPN protocols.
fn server_builder(pki: &Pki, leaf: &Leaf, client_auth: bool) -> SslContextBuilder {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder.set_early_data_enabled(true);
    builder.set_certificate(&leaf.cert).unwrap();
    builder.add_extra_chain_cert(pki.ca.clone()).unwrap();
    builder.set_private_key(&leaf.key).unwrap();
    if client_auth {
        builder.cert_store_mut().add_cert(pki.ca.clone()).unwrap();
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    builder
}

fn client_endpoint(pki: &Pki, identity: Option<&Leaf>) -> Endpoint {
    let cache = SimpleCache::new(NonZeroUsize::MIN);
    client_endpoint_with(client_builder(pki, identity), Arc::new(cache))
}

/// A client builder that trusts `pki`, offers "h3" and enables 0-RTT. It leaves verification off,
/// which the conversion to [`QuicClientConfig`] turns on.
fn client_builder(pki: &Pki, identity: Option<&Leaf>) -> SslContextBuilder {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder.set_early_data_enabled(true);
    builder.cert_store_mut().add_cert(pki.ca.clone()).unwrap();
    builder.set_alpn_protos(b"\x02h3").unwrap();
    if let Some(leaf) = identity {
        builder.set_certificate(&leaf.cert).unwrap();
        builder.add_extra_chain_cert(pki.ca.clone()).unwrap();
        builder.set_private_key(&leaf.key).unwrap();
    }
    builder
}

fn client_endpoint_with(builder: SslContextBuilder, cache: Arc<dyn SessionCache>) -> Endpoint {
    let mut crypto = QuicClientConfig::try_from(builder).unwrap();
    crypto.set_session_cache(cache);
    let endpoint = Endpoint::client(localhost()).unwrap();
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
    endpoint
}

fn localhost() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

/// A [SimpleCache] that notes whether sessions were removed without being taken.
struct RemovalTracker {
    cache: SimpleCache,
    removed: AtomicBool,
}

impl Default for RemovalTracker {
    fn default() -> Self {
        Self {
            cache: SimpleCache::new(NonZeroUsize::MIN),
            removed: AtomicBool::new(false),
        }
    }
}

impl SessionCache for RemovalTracker {
    fn put(&self, key: bytes::Bytes, value: Zeroizing<Vec<u8>>) {
        self.cache.put(key, value);
    }

    fn take(&self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.cache.take(key)
    }

    fn remove(&self, key: &[u8]) {
        self.removed.store(true, Ordering::Relaxed);
        self.cache.remove(key);
    }

    fn clear(&self) {
        self.removed.store(true, Ordering::Relaxed);
        self.cache.clear();
    }
}

/// A CA that issues the leaf certificates of a test.
struct Pki {
    ca: X509,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = X509::from_der(params.self_signed(&key).unwrap().der()).unwrap();
        Self {
            ca,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn issue(&self, name: &str) -> Leaf {
        self.issue_for(vec![name.into()])
    }

    /// Issues a leaf for `names`, the first of which is its common name.
    fn issue_for(&self, names: Vec<String>) -> Leaf {
        let key = rcgen::KeyPair::generate().unwrap();
        let name = names[0].clone();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        // rcgen's default subject is the CA's, which would make the leaf look self-signed.
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            cert: X509::from_der(cert.der()).unwrap(),
            key: PKey::private_key_from_pem(key.serialize_pem().as_bytes()).unwrap(),
        }
    }

    /// The DER of the chain an endpoint with `leaf` sends, leaf first.
    fn chain(&self, leaf: &Leaf) -> Vec<Vec<u8>> {
        vec![leaf.cert.to_der().unwrap(), self.ca.to_der().unwrap()]
    }
}

struct Leaf {
    cert: X509,
    key: PKey<Private>,
}
