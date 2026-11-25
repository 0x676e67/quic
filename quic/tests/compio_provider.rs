#![cfg(all(
    feature = "runtime-compio",
    feature = "rustls-ring",
    any(feature = "rustls-aws-lc-rs", feature = "rustls-aws-lc-rs-fips")
))]

use std::time::Duration;

use compio_io::AsyncWriteExt;
use futures_util::join;
use quic::compio::{ClientBuilder, Endpoint, ServerBuilder};

#[compio_macros::test]
async fn built_in_configs_work_with_both_providers_and_no_process_default() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let key = signing_key.serialize_der().try_into().unwrap();
    let server = ServerBuilder::new_with_single_cert(vec![cert.clone()], key)
        .unwrap()
        .build()
        .unwrap();
    let client = ClientBuilder::new_with_empty_roots()
        .with_custom_certificate(cert)
        .unwrap()
        .with_crls(std::iter::empty())
        .unwrap()
        .build()
        .unwrap();
    let _insecure_client = ClientBuilder::new_with_no_server_verification()
        .unwrap()
        .build()
        .unwrap();
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());

    let endpoint = Endpoint::server("127.0.0.1:0", server).await.unwrap();
    endpoint.set_default_client_config(client);
    compio_runtime::time::timeout(Duration::from_secs(3), async {
        join!(
            async {
                let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let (_, request) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(request, b"ping");
                send.write_all(b"pong").await.unwrap();
                send.finish().unwrap();
                let _ = connection.closed().await;

                let incoming = endpoint.wait_incoming().await.unwrap();
                assert!(incoming.await.is_err());
            },
            async {
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .await
                    .unwrap();
                let (mut send, mut recv) = connection.open_bi().unwrap();
                send.write_all(b"ping").await.unwrap();
                send.finish().unwrap();
                let (_, response) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(response, b"pong");
                connection.close(0u32.into(), b"done");

                assert!(
                    endpoint
                        .connect(endpoint.local_addr().unwrap(), "wrong.localhost", None)
                        .unwrap()
                        .await
                        .is_err()
                );
            }
        );
    })
    .await
    .expect("both-provider TLS policy test timed out");
    endpoint.shutdown().await.unwrap();

    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
}
