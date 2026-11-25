use std::{io, sync::Arc};

use compio_net::ToSocketAddrsAsync;
use proto::{
    ClientConfig, ServerConfig,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig},
};

use crate::compio::Endpoint;

/// Use an explicitly installed process provider when present. Otherwise, mirror the crate's
/// provider priority without installing a process-global default as a side effect.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return provider.clone();
    }

    #[cfg(all(
        not(feature = "rustls-ring"),
        any(feature = "rustls-aws-lc-rs", feature = "rustls-aws-lc-rs-fips")
    ))]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "rustls-ring")]
    let provider = rustls::crypto::ring::default_provider();
    Arc::new(provider)
}

fn client_config_builder(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, rustls::Error> {
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
}

fn server_config_builder(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>, rustls::Error> {
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
}

/// Helper to construct an [`Endpoint`] for use with outgoing connections only.
///
/// To get one, call `new_with_xxx` methods.
/// The built-in TLS configuration constructors enable early data. A configuration passed to
/// [`ClientBuilder::new_with_rustls_client_config`] keeps its `enable_early_data` setting.
///
/// [builder]: https://rust-unofficial.github.io/patterns/patterns/creational/builder.html
#[derive(Debug)]
pub struct ClientBuilder<T>(T);

impl ClientBuilder<rustls::RootCertStore> {
    /// Create a builder with an empty [`rustls::RootCertStore`].
    pub fn new_with_empty_roots() -> Self {
        Self(rustls::RootCertStore::empty())
    }

    /// Create a builder with [`rustls_native_certs`].
    #[cfg(feature = "native-certs")]
    pub fn new_with_native_certs() -> io::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        let mut certs = rustls_native_certs::load_native_certs();
        if certs.certs.is_empty() {
            return Err(certs.errors.pop().map_or_else(
                || io::Error::other("the native certificate store is empty"),
                io::Error::other,
            ));
        }
        roots.add_parsable_certificates(certs.certs);
        Ok(Self(roots))
    }

    /// Create a builder with [`webpki_roots`].
    #[cfg(feature = "webpki-roots")]
    pub fn new_with_webpki_roots() -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self(roots)
    }

    /// Add a custom certificate.
    pub fn with_custom_certificate(
        mut self,
        der: rustls::pki_types::CertificateDer<'_>,
    ) -> Result<Self, rustls::Error> {
        self.0.add(der)?;
        Ok(self)
    }

    /// Don't configure revocation.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot configure TLS 1.3.
    pub fn with_no_crls(self) -> Result<ClientBuilder<rustls::ClientConfig>, rustls::Error> {
        ClientBuilder::new_with_root_certificates(self.0)
    }

    /// Verify the revocation state of presented client certificates against the
    /// provided certificate revocation lists (CRLs).
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot configure TLS 1.3 or the
    /// certificate verifier cannot be built. Verifier construction failures are wrapped in
    /// [`rustls::Error::Other`].
    pub fn with_crls(
        self,
        crls: impl IntoIterator<Item = rustls::pki_types::CertificateRevocationListDer<'static>>,
    ) -> Result<ClientBuilder<rustls::ClientConfig>, rustls::Error> {
        let provider = crypto_provider();
        let config_builder = client_config_builder(provider.clone())?;
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(self.0), provider)
                .with_crls(crls)
                .build()
                .map_err(|error| rustls::Error::Other(rustls::OtherError(Arc::new(error))))?;
        Ok(ClientBuilder::new_with_early_data(
            config_builder
                .with_webpki_verifier(verifier)
                .with_no_client_auth(),
        ))
    }
}

impl ClientBuilder<rustls::ClientConfig> {
    /// Create a builder with the provided [`rustls::ClientConfig`], preserving its early-data
    /// setting.
    pub fn new_with_rustls_client_config(client_config: rustls::ClientConfig) -> Self {
        Self(client_config)
    }

    fn new_with_early_data(mut client_config: rustls::ClientConfig) -> Self {
        client_config.enable_early_data = true;
        Self::new_with_rustls_client_config(client_config)
    }

    /// Do not verify the server's certificate. It is vulnerable to MITM
    /// attacks, but convenient for testing.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot configure TLS 1.3.
    pub fn new_with_no_server_verification() -> Result<Self, rustls::Error> {
        let provider = crypto_provider();
        let verifier = Arc::new(verifier::SkipServerVerification::new(&provider));
        Ok(Self::new_with_early_data(
            client_config_builder(provider)?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
        ))
    }

    /// Create a builder with [`rustls_platform_verifier`].
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot configure TLS 1.3 or the platform
    /// verifier cannot be initialized.
    #[cfg(feature = "platform-verifier")]
    pub fn new_with_platform_verifier() -> Result<Self, rustls::Error> {
        use rustls_platform_verifier::BuilderVerifierExt;

        Ok(Self::new_with_early_data(
            client_config_builder(crypto_provider())?
                .with_platform_verifier()?
                .with_no_client_auth(),
        ))
    }

    /// Create a builder with the provided [`rustls::RootCertStore`].
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot configure TLS 1.3.
    pub fn new_with_root_certificates(roots: rustls::RootCertStore) -> Result<Self, rustls::Error> {
        Ok(Self::new_with_early_data(
            client_config_builder(crypto_provider())?
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
    }

    /// Create a builder with a custom [`rustls::client::WebPkiServerVerifier`].
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot configure TLS 1.3.
    pub fn new_with_webpki_verifier(
        verifier: Arc<rustls::client::WebPkiServerVerifier>,
    ) -> Result<Self, rustls::Error> {
        Ok(Self::new_with_early_data(
            client_config_builder(crypto_provider())?
                .with_webpki_verifier(verifier)
                .with_no_client_auth(),
        ))
    }

    /// Set the ALPN protocols to use.
    pub fn with_alpn_protocols(mut self, protocols: &[&str]) -> Self {
        self.0.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    /// Logging key material to a file for debugging. The file's name is given
    /// by the `SSLKEYLOGFILE` environment variable.
    ///
    /// If `SSLKEYLOGFILE` is not set, or such a file cannot be opened or cannot
    /// be written, this does nothing.
    pub fn with_key_log(mut self) -> Self {
        self.0.key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    /// Build a [`ClientConfig`].
    pub fn build(self) -> Result<ClientConfig, NoInitialCipherSuite> {
        Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            self.0,
        )?)))
    }

    /// Create a new [`Endpoint`].
    ///
    /// See [`Endpoint::client`] for more information.
    pub async fn bind(self, addr: impl ToSocketAddrsAsync) -> io::Result<Endpoint> {
        let endpoint = Endpoint::client(addr).await?;
        endpoint.set_default_client_config(
            self.build()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
        Ok(endpoint)
    }
}

/// Helper to construct an [`Endpoint`] for use with incoming connections.
///
/// To get one, call `new_with_xxx` methods.
/// [`ServerBuilder::new_with_single_cert`] enables early data. A configuration passed to
/// [`ServerBuilder::new_with_rustls_server_config`] keeps its `max_early_data_size` setting.
///
/// [builder]: https://rust-unofficial.github.io/patterns/patterns/creational/builder.html
#[derive(Debug)]
pub struct ServerBuilder<T>(T);

impl ServerBuilder<rustls::ServerConfig> {
    /// Create a builder with the provided [`rustls::ServerConfig`], preserving its early-data
    /// setting.
    pub fn new_with_rustls_server_config(server_config: rustls::ServerConfig) -> Self {
        Self(server_config)
    }

    /// Create a builder with a single certificate chain and matching private
    /// key. Using this method gets the same result as calling
    /// [`ServerConfig::with_single_cert`].
    pub fn new_with_single_cert(
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        let mut server_config = server_config_builder(crypto_provider())?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)?;
        server_config.max_early_data_size = u32::MAX;
        Ok(Self::new_with_rustls_server_config(server_config))
    }

    /// Set the ALPN protocols to use.
    pub fn with_alpn_protocols(mut self, protocols: &[&str]) -> Self {
        self.0.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        self
    }

    /// Logging key material to a file for debugging. The file's name is given
    /// by the `SSLKEYLOGFILE` environment variable.
    ///
    /// If `SSLKEYLOGFILE` is not set, or such a file cannot be opened or cannot
    /// be written, this does nothing.
    pub fn with_key_log(mut self) -> Self {
        self.0.key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    /// Build a [`ServerConfig`].
    pub fn build(self) -> Result<ServerConfig, NoInitialCipherSuite> {
        Ok(ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(self.0)?,
        )))
    }

    /// Create a new [`Endpoint`].
    ///
    /// See [`Endpoint::server`] for more information.
    pub async fn bind(self, addr: impl ToSocketAddrsAsync) -> io::Result<Endpoint> {
        let config = self
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Endpoint::server(addr, config).await
    }
}

mod verifier {
    use rustls::{
        DigitallySignedStruct, Error, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    #[derive(Debug)]
    pub(super) struct SkipServerVerification(WebPkiSupportedAlgorithms);

    impl SkipServerVerification {
        pub(super) fn new(provider: &CryptoProvider) -> Self {
            Self(provider.signature_verification_algorithms)
        }
    }

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use compio_io::AsyncWriteExt;
    use futures_util::join;

    use super::*;

    fn certificate() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (
            cert.der().clone(),
            signing_key.serialize_der().try_into().unwrap(),
        )
    }

    fn client_config(cert: rustls::pki_types::CertificateDer<'static>) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        client_config_builder(crypto_provider())
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn server_config(
        cert: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> rustls::ServerConfig {
        server_config_builder(crypto_provider())
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap()
    }

    async fn prime_resumption(endpoint: &Endpoint) {
        join!(
            async {
                let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let (_, request) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(request, b"ticket");
                send.write_all(b"ready").await.unwrap();
                send.finish().unwrap();
                let _ = connection.closed().await;
            },
            async {
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .await
                    .unwrap();
                let (mut send, mut recv) = connection.open_bi().unwrap();
                send.write_all(b"ticket").await.unwrap();
                send.finish().unwrap();
                let (_, response) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(response, b"ready");
                connection.close(0u32.into(), b"done");
            }
        );
    }

    async fn accept_until_closed(endpoint: &Endpoint) {
        let incoming = endpoint.wait_incoming().await.unwrap();
        if let Ok(connection) = incoming.await {
            let _ = connection.closed().await;
        }
    }

    #[compio_macros::test]
    async fn custom_client_early_data_setting_is_preserved() {
        compio_runtime::time::timeout(Duration::from_secs(3), async {
            let (cert, key) = certificate();
            let server = ServerBuilder::new_with_single_cert(vec![cert.clone()], key)
                .unwrap()
                .build()
                .unwrap();
            let client = ClientBuilder::new_with_rustls_client_config(client_config(cert))
                .build()
                .unwrap();
            let endpoint = Endpoint::server("127.0.0.1:0", server).await.unwrap();
            endpoint.set_default_client_config(client);
            prime_resumption(&endpoint).await;

            join!(accept_until_closed(&endpoint), async {
                let connecting = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap();
                let connection = connecting
                    .into_0rtt()
                    .expect_err("custom client configuration disabled early data")
                    .await
                    .unwrap();
                connection.close(0u32.into(), b"done");
            });
            endpoint.shutdown().await.unwrap();
        })
        .await
        .expect("custom client early-data test timed out");
    }

    #[compio_macros::test]
    async fn custom_server_early_data_setting_is_preserved() {
        compio_runtime::time::timeout(Duration::from_secs(3), async {
            let (cert, key) = certificate();
            let mut accepting_tls = server_config(cert.clone(), key);
            accepting_tls.max_early_data_size = u32::MAX;
            let mut rejecting_tls = accepting_tls.clone();
            rejecting_tls.max_early_data_size = 0;
            let accepting = ServerBuilder::new_with_rustls_server_config(accepting_tls)
                .build()
                .unwrap();
            let rejecting = ServerBuilder::new_with_rustls_server_config(rejecting_tls)
                .build()
                .unwrap();
            let client = ClientBuilder::new_with_empty_roots()
                .with_custom_certificate(cert)
                .unwrap()
                .with_no_crls()
                .unwrap()
                .build()
                .unwrap();
            let endpoint = Endpoint::server("127.0.0.1:0", accepting).await.unwrap();
            endpoint.set_default_client_config(client);
            prime_resumption(&endpoint).await;
            endpoint.set_server_config(Some(rejecting));

            join!(accept_until_closed(&endpoint), async {
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .into_0rtt()
                    .expect("the built-in client should attempt early data");
                assert!(!connection.accepted_0rtt().await.unwrap());
                connection.close(0u32.into(), b"done");
            });
            endpoint.shutdown().await.unwrap();
        })
        .await
        .expect("custom server early-data test timed out");
    }
}
