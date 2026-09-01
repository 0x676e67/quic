use std::{io, sync::Arc};

use compio_io::AsyncWriteExt;
use futures_util::join;
use quic::compio::{
    ClientBuilder, ClientConfig as CompioClientConfig, Endpoint, ServerBuilder, ServerConfig,
};
use quic::{EndpointConfig, TransportConfig};

fn config_pair(transport: TransportConfig) -> (ServerConfig, CompioClientConfig) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let key = signing_key.serialize_der().try_into().unwrap();

    let transport = Arc::new(transport);
    let mut server = ServerBuilder::new_with_single_cert(vec![cert.clone()], key)
        .unwrap()
        .build()
        .unwrap();
    server.transport_config(transport.clone());
    let mut client = ClientBuilder::new_with_empty_roots()
        .with_custom_certificate(cert)
        .unwrap()
        .with_no_crls()
        .build()
        .unwrap();
    client.transport_config(transport);
    (server, client)
}

fn compio_config(config: quic::ClientConfig) -> CompioClientConfig {
    config
}

#[compio_macros::test]
async fn loopback_uses_the_local_protocol_state_machine() {
    let mut transport = TransportConfig::default();
    transport.enable_initial_rtt(true);
    let (server_config, client_config) = config_pair(transport);

    // This only compiles when both frontends expose the exact same local quic-proto type.
    let client_config = compio_config(client_config);

    let endpoint = Endpoint::server("127.0.0.1:0", server_config)
        .await
        .unwrap();
    endpoint.set_default_client_config(client_config);

    join!(
        async {
            let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
            connection.handshake_confirmed().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let (_, request) = recv.read_to_end(Vec::new()).await.unwrap();
            assert_eq!(request, b"ping");
            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
        },
        async {
            let connection = endpoint
                .connect(endpoint.local_addr().unwrap(), "localhost", None)
                .unwrap()
                .await
                .unwrap();
            connection.handshake_confirmed().await.unwrap();
            let (mut send, mut recv) = connection.open_bi().unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            let (_, response) = recv.read_to_end(Vec::new()).await.unwrap();
            assert_eq!(response, b"pong");
        }
    );

    endpoint.shutdown().await.unwrap();
}

#[test]
fn endpoint_creation_outside_runtime_returns_an_error() {
    let runtime = compio_runtime::Runtime::new().unwrap();
    let socket = runtime
        .block_on(compio_net::UdpSocket::bind("127.0.0.1:0"))
        .unwrap();

    let error = Endpoint::new(socket, EndpointConfig::default(), None, None).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
}

#[cfg(feature = "runtime-tokio")]
#[test]
fn compio_client_interoperates_with_tokio_server() -> anyhow::Result<()> {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use anyhow::{Context, anyhow, ensure};

    const TIMEOUT: Duration = Duration::from_secs(10);

    let mut transport = TransportConfig::default();
    transport.enable_initial_rtt(true);
    let (server_config, client_config) = config_pair(transport);
    let (address_tx, address_rx) = mpsc::sync_channel::<SocketAddr>(1);

    let server_thread = thread::spawn(move || -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let endpoint = quic::Endpoint::server(
                    server_config,
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                )?;
                address_tx
                    .send(endpoint.local_addr()?)
                    .map_err(|_| anyhow!("Compio client dropped the server address channel"))?;

                let exchange_result = tokio::time::timeout(TIMEOUT, async {
                    let incoming = endpoint
                        .accept()
                        .await
                        .context("Tokio server endpoint closed before accepting the client")?;
                    let connection = incoming.await?;
                    let (mut send, mut recv) = connection.accept_bi().await?;
                    let request = recv.read_to_end(64).await?;
                    ensure!(
                        request == b"ping",
                        "Tokio server received an invalid request"
                    );
                    send.write_all(b"pong").await?;
                    send.finish()?;
                    let _ = send.stopped().await?;
                    anyhow::Ok(())
                })
                .await
                .map_err(|_| anyhow!("Tokio server exchange timed out"))
                .and_then(|result| result);

                endpoint.close(0u32.into(), b"done");
                let idle_result = tokio::time::timeout(TIMEOUT, endpoint.wait_idle())
                    .await
                    .map_err(|_| anyhow!("Tokio server shutdown timed out"));

                idle_result?;
                exchange_result
            })
    });

    let server_addr = match address_rx.recv_timeout(TIMEOUT) {
        Ok(address) => address,
        Err(error) => {
            let server_result = server_thread.join();
            return Err(anyhow!(
                "Tokio server did not publish its address: {error}; server result: {server_result:?}"
            ));
        }
    };

    let runtime = compio_runtime::Runtime::new()?;
    let client_result = runtime.block_on(async move {
        let endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0)).await?;
        endpoint.set_default_client_config(client_config);

        let exchange_result = compio_runtime::time::timeout(TIMEOUT, async {
            let connection = endpoint.connect(server_addr, "localhost", None)?.await?;
            connection.handshake_confirmed().await?;
            let (mut send, mut recv) = connection.open_bi_wait().await?;

            let (write_result, _) = send.write_all(b"ping").await.into();
            write_result?;
            send.finish()?;

            let (read_result, response) = recv.read_to_end(Vec::new()).await.into();
            read_result?;
            ensure!(
                response == b"pong",
                "Compio client received an invalid response"
            );
            let _ = send.stopped().await?;
            anyhow::Ok(())
        })
        .await
        .map_err(|_| anyhow!("Compio client exchange timed out"))
        .and_then(|result| result);

        endpoint.close(0u32.into(), b"done");
        let shutdown_result = compio_runtime::time::timeout(TIMEOUT, endpoint.shutdown())
            .await
            .map_err(|_| anyhow!("Compio client shutdown timed out"))
            .and_then(|result| result.map_err(Into::into));

        shutdown_result?;
        exchange_result
    });

    let server_result = server_thread
        .join()
        .map_err(|_| anyhow!("Tokio server thread panicked"));
    client_result?;
    server_result??;
    Ok(())
}
