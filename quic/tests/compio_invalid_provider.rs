#![cfg(all(feature = "runtime-compio", feature = "rustls-ring"))]

use std::sync::Arc;

use quic::compio::ClientBuilder;

#[test]
fn client_convenience_builders_return_an_error_for_a_provider_without_tls13() {
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots.clone()),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();

    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.tls13().is_none());
    provider.install_default().unwrap();

    fn assert_tls13_error(result: Result<ClientBuilder<rustls::ClientConfig>, rustls::Error>) {
        assert!(result.is_err());
    }

    assert_tls13_error(ClientBuilder::new_with_no_server_verification());
    assert_tls13_error(ClientBuilder::new_with_root_certificates(roots));
    assert_tls13_error(ClientBuilder::new_with_webpki_verifier(verifier));
    assert_tls13_error(
        ClientBuilder::new_with_empty_roots()
            .with_custom_certificate(cert.clone())
            .unwrap()
            .with_no_crls(),
    );
    assert_tls13_error(
        ClientBuilder::new_with_empty_roots()
            .with_custom_certificate(cert)
            .unwrap()
            .with_crls(std::iter::empty()),
    );
}
