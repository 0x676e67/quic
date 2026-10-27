//! Interoperability of the btls crypto backend with rustls, in both directions and with each
//! TLS 1.3 cipher suite, so that a bug both btls endpoints share cannot go unnoticed.

use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
};

use quic::{
    ClientConfig, Connection, Endpoint, ReadError, ReadToEndError, ServerConfig,
    btls::{
        pkey::PKey,
        ssl::{EarlyDataReason, SslContextBuilder, SslMethod},
        x509::X509,
    },
    crypto::{btls, rustls as quic_rustls},
    rustls::{
        self, RootCertStore, SupportedCipherSuite,
        crypto::{CryptoProvider, ring},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

const GREETING: &[u8] = b"0.5-rtt";

#[tokio::test]
async fn btls_client_rustls_server() {
    let identity = Identity::new();
    for suite in suites() {
        let id = u16::from(suite.suite());
        let server = serve(rustls_server(&identity, suite));
        // Another server, which cannot resume the first one's sessions.
        let other_server = serve(rustls_server(&identity, suite));
        let client = client_endpoint(btls_client(&identity));
        exercise(&client, server, other_server, id, None).await;
    }
}

#[tokio::test]
async fn rustls_client_btls_server() {
    let identity = Identity::new();
    for suite in suites() {
        let id = u16::from(suite.suite());
        let server = serve(btls_server(&identity));
        let other_server = serve(btls_server(&identity));
        let client = client_endpoint(rustls_client(&identity, suite));
        exercise(&client, server, other_server, id, Some(id)).await;
    }
}

/// Runs a full handshake with key updates, 0-RTT that `server` accepts, and 0-RTT that
/// `other_server` rejects. Each connection first passes a Retry, and gets the 0.5-RTT greeting.
///
/// `server_suite` is the cipher suite a btls server must report, and `None` for rustls.
async fn exercise(
    client: &Endpoint,
    server: SocketAddr,
    other_server: SocketAddr,
    suite: u16,
    server_suite: Option<u16>,
) {
    let conn = match client.connect(server, "localhost").unwrap().into_0rtt() {
        Ok(_) => panic!("0-RTT without a session"),
        Err(connecting) => connecting.await.unwrap(),
    };
    check_greeting(&conn).await;
    check_handshake(&conn, suite, false, EarlyDataReason::NO_SESSION_OFFERED);
    for round in 0..3u8 {
        conn.force_key_update();
        let response = request(&conn, &[round]).await.unwrap();
        check_response(&conn, &[round], &response, server_suite);
    }
    conn.close(0u32.into(), b"done");

    let conn = client
        .connect(server, "localhost")
        .unwrap()
        .into_0rtt()
        .expect("resumable session");
    let response = request(&conn, b"0-rtt").await.unwrap();
    check_response(&conn, b"0-rtt", &response, server_suite);
    check_greeting(&conn).await;
    check_handshake(&conn, suite, true, EarlyDataReason::ACCEPTED);
    conn.close(0u32.into(), b"done");

    let conn = client
        .connect(other_server, "localhost")
        .unwrap()
        .into_0rtt()
        .expect("resumable session");
    assert!(matches!(
        request(&conn, b"0-rtt").await,
        Err(ReadToEndError::Read(ReadError::ZeroRttRejected))
    ));
    let response = request(&conn, b"1-rtt").await.unwrap();
    check_response(&conn, b"1-rtt", &response, server_suite);
    check_greeting(&conn).await;
    check_handshake(&conn, suite, false, EarlyDataReason::SESSION_NOT_RESUMED);
    conn.close(0u32.into(), b"done");

    client.wait_idle().await;
}

/// The TLS 1.3 cipher suites.
fn suites() -> [SupportedCipherSuite; 3] {
    [
        ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ]
}

/// Serves each connection after a Retry. It sends the 0.5-RTT greeting on a unidirectional
/// stream, and answers each bidirectional stream with the request, the keying material and the
/// cipher suite that a btls session reports, then updates the keys.
fn serve(config: ServerConfig) -> SocketAddr {
    let endpoint = Endpoint::server(config, localhost()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            if !incoming.remote_address_validated() {
                incoming.retry().unwrap();
                continue;
            }
            let Ok(connecting) = incoming.accept() else {
                continue;
            };
            let Ok(conn) = connecting.into_0rtt() else {
                continue;
            };
            tokio::spawn(async move {
                if let Ok(mut send) = conn.open_uni().await
                    && send.write_all(GREETING).await.is_ok()
                {
                    let _ = send.finish();
                }
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let Ok(mut response) = recv.read_to_end(1024).await else {
                        return;
                    };
                    if conn.authenticated().await.is_err() {
                        return;
                    }
                    response.extend(keying_material(&conn));
                    let suite = btls_data(&conn).and_then(|data| data.cipher_suite);
                    response.extend(suite.unwrap_or_default().to_be_bytes());
                    if send.write_all(&response).await.is_err() {
                        return;
                    }
                    let _ = send.finish();
                    conn.force_key_update();
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
    recv.read_to_end(1024).await
}

/// Checks an answer of [`serve`]: both sides export the same keying material, and a btls server
/// reports `server_suite`.
fn check_response(conn: &Connection, msg: &[u8], response: &[u8], server_suite: Option<u16>) {
    let (echo, rest) = response.split_at(msg.len());
    assert_eq!(echo, msg);
    let (material, suite) = rest.split_at(32);
    assert_eq!(material, keying_material(conn));
    assert_eq!(
        u16::from_be_bytes(suite.try_into().unwrap()),
        server_suite.unwrap_or_default()
    );
}

async fn check_greeting(conn: &Connection) {
    let mut recv = conn.accept_uni().await.unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), GREETING);
}

/// Checks what a btls client reports about the handshake.
fn check_handshake(conn: &Connection, suite: u16, resumed: bool, reason: EarlyDataReason) {
    let Some(data) = btls_data(conn) else { return };
    assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));
    assert_eq!(data.cipher_suite, Some(suite));
    assert_eq!(data.resumed, resumed);
    assert_eq!(data.early_data_reason, reason);
}

fn btls_data(conn: &Connection) -> Option<Box<btls::HandshakeData>> {
    conn.handshake_data()?.downcast().ok()
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

/// A self-signed certificate for "localhost", which both backends trust.
struct Identity {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl Identity {
    fn new() -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        Self {
            cert: identity.cert.der().clone(),
            key: identity.signing_key.serialize_der().into(),
        }
    }
}

/// A rustls provider with only `suite`. The Initial packets use AES-128-GCM regardless.
fn provider(suite: SupportedCipherSuite) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![suite],
        ..ring::default_provider()
    })
}

fn initial_suite() -> rustls::quic::Suite {
    ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(|suite| suite.quic_suite())
        .unwrap()
}

fn rustls_server(identity: &Identity, suite: SupportedCipherSuite) -> ServerConfig {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider(suite))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert.clone()],
            PrivateKeyDer::Pkcs8(identity.key.clone_key()),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = u32::MAX;
    let crypto = quic_rustls::QuicServerConfig::with_initial(Arc::new(tls), initial_suite());
    ServerConfig::with_crypto(Arc::new(crypto.unwrap()))
}

fn rustls_client(identity: &Identity, suite: SupportedCipherSuite) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(identity.cert.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider(suite))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    let crypto = quic_rustls::QuicClientConfig::with_initial(Arc::new(tls), initial_suite());
    ClientConfig::new(Arc::new(crypto.unwrap()))
}

fn btls_server(identity: &Identity) -> ServerConfig {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder
        .set_certificate(&X509::from_der(&identity.cert).unwrap())
        .unwrap();
    let key = PKey::private_key_from_der(identity.key.secret_pkcs8_der()).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.set_alpn_protos(b"\x02h3").unwrap();
    builder.set_early_data_enabled(true);
    let crypto = btls::QuicServerConfig::try_from(builder).unwrap();
    ServerConfig::with_crypto(Arc::new(crypto))
}

fn btls_client(identity: &Identity) -> ClientConfig {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    builder
        .cert_store_mut()
        .add_cert(X509::from_der(&identity.cert).unwrap())
        .unwrap();
    builder.set_alpn_protos(b"\x02h3").unwrap();
    builder.set_early_data_enabled(true);
    let mut crypto = btls::QuicClientConfig::try_from(builder).unwrap();
    crypto.set_session_cache(Arc::new(btls::SimpleCache::new(NonZeroUsize::MIN)));
    ClientConfig::new(Arc::new(crypto))
}

fn client_endpoint(config: ClientConfig) -> Endpoint {
    let endpoint = Endpoint::client(localhost()).unwrap();
    endpoint.set_default_client_config(config);
    endpoint
}

fn localhost() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}
