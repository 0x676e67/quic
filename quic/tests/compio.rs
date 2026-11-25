use std::{future::Future, io, sync::Arc, time::Duration};

use compio_io::AsyncWriteExt;
use futures_util::join;
use quic::compio::{
    ClientBuilder, ClientConfig as CompioClientConfig, Endpoint, ServerBuilder, ServerConfig,
    crypto::rustls::QuicServerConfig,
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
        .unwrap()
        .build()
        .unwrap();
    client.transport_config(transport);
    (server, client)
}

fn zero_rtt_config_pair(
    transport: TransportConfig,
) -> (ServerConfig, ServerConfig, CompioClientConfig) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = cert.der().clone();
    let key = signing_key.serialize_der().try_into().unwrap();

    let mut accepting_tls =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
    accepting_tls.max_early_data_size = u32::MAX;
    let mut rejecting_tls = accepting_tls.clone();
    rejecting_tls.max_early_data_size = 0;

    let transport = Arc::new(transport);
    let mut accepting =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(accepting_tls).unwrap()));
    accepting.transport_config(transport.clone());
    let mut rejecting =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rejecting_tls).unwrap()));
    rejecting.transport_config(transport.clone());

    let mut client = ClientBuilder::new_with_empty_roots()
        .with_custom_certificate(cert)
        .unwrap()
        .with_no_crls()
        .unwrap()
        .build()
        .unwrap();
    client.transport_config(transport);
    (accepting, rejecting, client)
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
            assert_eq!(
                std::future::poll_fn(|cx| send.poll_stopped(cx))
                    .await
                    .unwrap(),
                None
            );
            let (_, response) = recv.read_to_end(Vec::new()).await.unwrap();
            assert_eq!(response, b"pong");
        }
    );

    endpoint.shutdown().await.unwrap();
}

#[compio_macros::test]
async fn connection_drains_received_streams_and_datagrams_after_peer_closes() {
    let (server_config, client_config) = config_pair(TransportConfig::default());
    let endpoint = Endpoint::server("127.0.0.1:0", server_config)
        .await
        .unwrap();
    endpoint.set_default_client_config(client_config);
    let (received_tx, received_rx) = flume::bounded(1);

    compio_runtime::time::timeout(Duration::from_secs(5), async {
        join!(
            async {
                let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
                let mut send = connection.open_uni().unwrap();
                send.write_all(b"stream").await.unwrap();
                send.finish().unwrap();
                connection.send_datagram(b"one".as_slice().into()).unwrap();
                connection.send_datagram(b"two".as_slice().into()).unwrap();
                assert_eq!(send.stopped().await.unwrap(), None);
                received_rx.recv_async().await.unwrap();
                connection.close(1u32.into(), b"done");
            },
            async {
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .await
                    .unwrap();
                while connection.stats().frame_rx.datagram < 2 {
                    compio_runtime::time::sleep(Duration::from_millis(1)).await;
                }
                received_tx.send_async(()).await.unwrap();
                let close = connection.closed().await;
                assert!(matches!(
                    close,
                    quic::compio::ConnectionError::ApplicationClosed(_)
                ));

                let mut recv = connection.accept_uni().await.unwrap();
                let (_, payload) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(payload, b"stream");
                assert_eq!(connection.accept_uni().await.unwrap_err(), close);

                let mut datagrams = [
                    connection.try_recv_datagram().unwrap().unwrap(),
                    connection.recv_datagram().await.unwrap(),
                ];
                datagrams.sort();
                assert_eq!(&datagrams[0][..], b"one");
                assert_eq!(&datagrams[1][..], b"two");
                assert_eq!(connection.try_recv_datagram().unwrap_err(), close);
                assert_eq!(connection.recv_datagram().await.unwrap_err(), close);
            }
        );
    })
    .await
    .expect("test peer did not deliver queued traffic and close");

    endpoint.shutdown().await.unwrap();
}

#[compio_macros::test]
async fn repeated_polls_register_one_waker_per_connection_wait() {
    use std::task::{Context, Poll, Wake, Waker};

    struct TrackedWake(Waker);

    impl Wake for TrackedWake {
        fn wake(self: Arc<Self>) {
            self.0.wake_by_ref();
        }
    }

    async fn assert_single_registration(wait: impl Future) {
        let mut wait = std::pin::pin!(wait);
        std::future::poll_fn(|cx| {
            let tracked = Arc::new(TrackedWake(cx.waker().clone()));
            let waker = Waker::from(tracked.clone());
            let mut context = Context::from_waker(&waker);
            let initial_references = Arc::strong_count(&tracked);

            for _ in 0..4 {
                assert!(wait.as_mut().poll(&mut context).is_pending());
            }

            assert_eq!(Arc::strong_count(&tracked), initial_references + 1);
            Poll::Ready(())
        })
        .await;
    }

    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_uni_streams(0u32.into())
        .datagram_send_buffer_size(1);
    let (server_config, client_config) = config_pair(transport);
    let endpoint = Endpoint::server("127.0.0.1:0", server_config)
        .await
        .unwrap();
    endpoint.set_default_client_config(client_config);

    compio_runtime::time::timeout(Duration::from_secs(5), async {
        join!(
            async {
                let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
                connection.closed().await;
            },
            async {
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .await
                    .unwrap();
                connection.handshake_confirmed().await.unwrap();

                assert_single_registration(connection.recv_datagram()).await;
                assert_single_registration(connection.accept_uni()).await;
                assert_single_registration(connection.open_uni_wait()).await;
                connection.send_datagram(b"a".as_slice().into()).unwrap();
                assert_single_registration(connection.send_datagram_wait(b"b".as_slice().into()))
                    .await;
                connection.close(0u32.into(), b"done");
            }
        );
    })
    .await
    .unwrap();

    endpoint.shutdown().await.unwrap();
}

#[compio_macros::test]
async fn closed_observers_survive_cancellation_and_run_concurrently() {
    const TIMEOUT: Duration = Duration::from_secs(2);

    let (server_config, client_config) = config_pair(TransportConfig::default());
    let endpoint = Endpoint::server("127.0.0.1:0", server_config)
        .await
        .unwrap();
    endpoint.set_default_client_config(client_config);
    let (ready_tx, ready_rx) = flume::bounded(1);

    compio_runtime::time::timeout(TIMEOUT, async {
        join!(
            async {
                let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
                let mut cancelled = Box::pin(connection.closed());
                struct CancelledObserver;
                impl std::task::Wake for CancelledObserver {
                    fn wake(self: Arc<Self>) {
                        panic!("cancelled closed observer was woken");
                    }
                }
                let observer = Arc::new(CancelledObserver);
                let waker = std::task::Waker::from(observer.clone());
                assert!(
                    cancelled
                        .as_mut()
                        .poll(&mut std::task::Context::from_waker(&waker))
                        .is_pending()
                );
                drop(cancelled);
                drop(waker);
                assert_eq!(Arc::strong_count(&observer), 1);
                ready_tx.send_async(()).await.unwrap();

                let (first, second) = join!(connection.closed(), connection.closed());
                assert_eq!(first, second);
            },
            async {
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .await
                    .unwrap();
                ready_rx.recv_async().await.unwrap();
                connection.close(7u32.into(), b"done");
            }
        );
    })
    .await
    .expect("closed observers did not all complete");

    endpoint.shutdown().await.unwrap();
}

#[compio_macros::test]
async fn rejected_0rtt_handles_do_not_touch_streams_that_reuse_their_id() {
    use futures_util::future::poll_fn;

    const TIMEOUT: Duration = Duration::from_secs(5);

    let mut transport = TransportConfig::default();
    transport.stream_receive_window(8u32.into());
    let (accepting_server, rejecting_server, client_config) = zero_rtt_config_pair(transport);
    let endpoint = Endpoint::server("127.0.0.1:0", accepting_server)
        .await
        .unwrap();
    endpoint.set_default_client_config(client_config);
    let (server_read_tx, server_read_rx) = flume::bounded(1);

    compio_runtime::time::timeout(TIMEOUT, async {
        join!(
            async {
                let first = endpoint.wait_incoming().await.unwrap().await.unwrap();
                let (mut send, mut recv) = first.accept_bi().await.unwrap();
                let (_, request) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(request, b"ticket");
                send.write_all(b"ready").await.unwrap();
                send.finish().unwrap();
                let _ = first.closed().await;

                let second = endpoint.wait_incoming().await.unwrap().await.unwrap();
                server_read_rx.recv_async().await.unwrap();
                let (mut send, mut recv) = second.accept_bi().await.unwrap();
                let (_, request) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(request, [7; 64]);
                send.write_all(request).await.unwrap();
                send.finish().unwrap();
                let _ = second.closed().await;
            },
            async {
                let first = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .await
                    .unwrap();
                let (mut send, mut recv) = first.open_bi().unwrap();
                send.write_all(b"ticket").await.unwrap();
                send.finish().unwrap();
                let (_, response) = recv.read_to_end(Vec::new()).await.unwrap();
                assert_eq!(response, b"ready");
                first.close(0u32.into(), b"done");

                endpoint.set_server_config(Some(rejecting_server));
                let connection = endpoint
                    .connect(endpoint.local_addr().unwrap(), "localhost", None)
                    .unwrap()
                    .into_0rtt()
                    .expect("the client should have received a resumption ticket");
                let (mut rejected_send, mut rejected_recv) = connection.open_bi().unwrap();
                rejected_send.write_all(b"0-rtt").await.unwrap();
                rejected_recv.stop(0u32.into()).unwrap();
                assert!(!connection.accepted_0rtt().await.unwrap());

                let (mut send, mut recv) = connection.open_bi().unwrap();
                assert_eq!(send.id(), rejected_send.id());
                assert_eq!(recv.id(), rejected_recv.id());
                let (registered_tx, registered_rx) = flume::unbounded();
                let write_registered = registered_tx.clone();
                let write_task = compio_runtime::spawn(async move {
                    let mut write = Box::pin(send.write_all(vec![7; 64]));
                    poll_fn(|cx| match write.as_mut().poll(cx) {
                        std::task::Poll::Pending => std::task::Poll::Ready(()),
                        std::task::Poll::Ready(_) => {
                            panic!("the flow-controlled write completed before it could block")
                        }
                    })
                    .await;
                    write_registered.send(()).unwrap();
                    write.as_mut().await.unwrap();
                    drop(write);
                    send.finish().unwrap();
                });
                let read_task = compio_runtime::spawn(async move {
                    let mut read = Box::pin(recv.read_to_end(Vec::new()));
                    poll_fn(|cx| match read.as_mut().poll(cx) {
                        std::task::Poll::Pending => std::task::Poll::Ready(()),
                        std::task::Poll::Ready(_) => {
                            panic!("the response read completed before the server was released")
                        }
                    })
                    .await;
                    registered_tx.send(()).unwrap();
                    let (_, response) = read.as_mut().await.unwrap();
                    response
                });
                registered_rx.recv_async().await.unwrap();
                registered_rx.recv_async().await.unwrap();

                assert!(rejected_send.finish().is_err());
                assert!(rejected_send.set_priority(1).is_err());
                assert!(rejected_send.priority().is_err());
                drop((rejected_send, rejected_recv));
                server_read_tx.send_async(()).await.unwrap();

                write_task.await.unwrap();
                assert_eq!(read_task.await.unwrap(), [7; 64]);
                connection.close(0u32.into(), b"done");
            }
        );
    })
    .await
    .expect("1-RTT streams stalled after rejected 0-RTT handles were dropped");

    endpoint.shutdown().await.unwrap();
}

#[compio_macros::test]
async fn last_stream_reference_implicitly_closes_the_connection() {
    const TIMEOUT: Duration = Duration::from_secs(2);

    let (server_config, client_config) = config_pair(TransportConfig::default());
    let endpoint = Endpoint::server("127.0.0.1:0", server_config)
        .await
        .unwrap();
    endpoint.set_default_client_config(client_config);
    let (server_ready_tx, server_ready_rx) = flume::unbounded();

    compio_runtime::time::timeout(TIMEOUT, async {
        join!(
            async {
                for _ in 0..2 {
                    let connection = endpoint.wait_incoming().await.unwrap().await.unwrap();
                    server_ready_tx.send(()).unwrap();
                    assert!(matches!(
                        connection.closed().await,
                        quic::compio::ConnectionError::ApplicationClosed(_)
                    ));
                }
            },
            async {
                for keep_send_half in [true, false] {
                    let connection = endpoint
                        .connect(endpoint.local_addr().unwrap(), "localhost", None)
                        .unwrap()
                        .await
                        .unwrap();
                    server_ready_rx.recv_async().await.unwrap();
                    let (send, recv) = connection.open_bi().unwrap();
                    if keep_send_half {
                        drop(recv);
                        drop(connection);
                        drop(send);
                    } else {
                        drop(send);
                        drop(connection);
                        drop(recv);
                    }
                }
            }
        );
    })
    .await
    .expect("dropping the last stream reference did not close the connection");

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

            let (read_result, response) = recv
                .read_to_end(Vec::with_capacity(b"pon".len()))
                .await
                .into();
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
