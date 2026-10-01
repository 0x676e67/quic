//! End-to-end handshakes over the btls crypto backend.

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use proto::{TransportParameterConfig, TransportParameterId, TransportParameterKind};
use quic::{
    ClientConfig, Connection, ConnectionError, Endpoint, ReadError, ReadToEndError, ServerConfig,
    TransportConfig, TransportErrorCode,
    btls::{
        pkey::{PKey, Private},
        ssl::{SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode},
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
    let client = client_endpoint_with(&pki, None, cache.clone());

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
    let crypto = QuicClientConfig::from_builder(builder).unwrap();
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

fn server_crypto(pki: &Pki, leaf: &Leaf, client_auth: bool) -> QuicServerConfig {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder.set_certificate(&leaf.cert).unwrap();
    builder.add_extra_chain_cert(pki.ca.clone()).unwrap();
    builder.set_private_key(&leaf.key).unwrap();
    if client_auth {
        builder.cert_store_mut().add_cert(pki.ca.clone()).unwrap();
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    QuicServerConfig::from_builder(builder).unwrap()
}

/// A client that trusts `pki`. Its builder leaves verification off, which `from_builder` turns
/// on, and it offers "h3" through [`QuicClientConfig::set_alpn`].
fn client_endpoint(pki: &Pki, identity: Option<&Leaf>) -> Endpoint {
    let cache = SimpleCache::new(NonZeroUsize::MIN);
    client_endpoint_with(pki, identity, Arc::new(cache))
}

fn client_endpoint_with(
    pki: &Pki,
    identity: Option<&Leaf>,
    cache: Arc<dyn SessionCache>,
) -> Endpoint {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder.cert_store_mut().add_cert(pki.ca.clone()).unwrap();
    if let Some(leaf) = identity {
        builder.set_certificate(&leaf.cert).unwrap();
        builder.add_extra_chain_cert(pki.ca.clone()).unwrap();
        builder.set_private_key(&leaf.key).unwrap();
    }
    let mut crypto = QuicClientConfig::from_builder(builder).unwrap();
    crypto.set_alpn(&[b"h3".to_vec()]).unwrap();
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
