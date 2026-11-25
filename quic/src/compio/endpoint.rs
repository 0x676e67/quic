use std::{
    collections::VecDeque,
    fmt::Debug,
    future::poll_fn,
    io,
    mem::ManuallyDrop,
    net::{SocketAddr, SocketAddrV6},
    ops::Deref,
    pin::pin,
    ptr,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Instant,
};

use compio_buf::{BufResult, bytes::Bytes};
use compio_log::{Instrument, error};
#[cfg(rustls)]
use compio_net::ToSocketAddrsAsync;
use compio_net::UdpSocket;
use compio_runtime::{JoinHandle, Runtime as CompioRuntime};
use flume::{Receiver, Sender, bounded, unbounded};
use futures_util::{FutureExt, StreamExt, future, select, task::AtomicWaker};
use proto::{
    ClientConfig, ConnectError, ConnectionHandle, DatagramEvent, EndpointConfig, EndpointEvent,
    ServerConfig, Transmit, VarInt,
};
use rustc_hash::FxHashMap as HashMap;

use crate::compio::{
    Connecting, ConnectionError, ConnectionEvent, Incoming, RecvMeta, Socket,
    sync::{
        async_flag::{AsyncFlag, AsyncFlagHandle},
        mutex_blocking::Mutex,
        shared::Shared,
    },
};

#[derive(Debug)]
struct EndpointState {
    endpoint: proto::Endpoint,
    default_client_config: Option<ClientConfig>,
    worker: Option<JoinHandle<()>>,
    response_worker: Option<JoinHandle<()>>,
    connections: HashMap<ConnectionHandle, Sender<ConnectionEvent>>,
    close: Option<(VarInt, Bytes)>,
    stopped: bool,
    exit_on_idle: bool,
    incoming: VecDeque<proto::Incoming>,
    incoming_wakers: VecDeque<Waker>,
    stats: EndpointStats,
}

/// Statistics on [Endpoint] activity
#[non_exhaustive]
#[derive(Debug, Default, Copy, Clone)]
pub struct EndpointStats {
    /// Cumulative number of Quic handshakes accepted by this [Endpoint]
    pub accepted_handshakes: u64,
    /// Cumulative number of Quic handshakes sent from this [Endpoint]
    pub outgoing_handshakes: u64,
    /// Cumulative number of Quic handshakes refused on this [Endpoint]
    pub refused_handshakes: u64,
    /// Cumulative number of Quic handshakes ignored on this [Endpoint]
    pub ignored_handshakes: u64,
}

impl EndpointState {
    fn handle_data(&mut self, meta: RecvMeta, buf: &[u8], respond_fn: impl Fn(Vec<u8>, Transmit)) {
        let now = Instant::now();
        let Some(buf) = buf.get(..meta.len) else {
            return;
        };
        let Some(stride) = datagram_stride(meta.len, meta.stride) else {
            return;
        };
        for data in buf.chunks(stride).map(Into::into) {
            let mut resp_buf = Vec::new();
            match self.endpoint.handle(
                now,
                meta.remote,
                meta.local_ip,
                meta.ecn,
                data,
                &mut resp_buf,
            ) {
                Some(DatagramEvent::NewConnection(incoming)) => {
                    if self.close.is_none() {
                        self.incoming.push_back(incoming);
                    } else {
                        let transmit = self.endpoint.refuse(incoming, &mut resp_buf);
                        respond_fn(resp_buf, transmit);
                    }
                }
                Some(DatagramEvent::ConnectionEvent(ch, event)) => {
                    if let Some(connection) = self.connections.get(&ch) {
                        let _ = connection.send(ConnectionEvent::Proto(event));
                    }
                }
                Some(DatagramEvent::Response(transmit)) => respond_fn(resp_buf, transmit),
                None => {}
            }
        }
    }

    fn handle_event(&mut self, ch: ConnectionHandle, event: EndpointEvent) {
        if event.is_drained() {
            self.connections.remove(&ch);
        }
        if let Some(event) = self.endpoint.handle_event(ch, event)
            && let Some(connection) = self.connections.get(&ch)
        {
            let _ = connection.send(ConnectionEvent::Proto(event));
        }
    }

    fn is_idle(&self) -> bool {
        self.connections.is_empty()
    }

    fn poll_incoming(&mut self, cx: &mut Context<'_>) -> Poll<Option<proto::Incoming>> {
        if self.stopped || self.close.is_some() {
            return Poll::Ready(None);
        }
        if let Some(incoming) = self.incoming.pop_front() {
            return Poll::Ready(Some(incoming));
        }
        if !self
            .incoming_wakers
            .iter()
            .any(|waker| waker.will_wake(cx.waker()))
        {
            self.incoming_wakers.push_back(cx.waker().clone());
        }
        Poll::Pending
    }

    fn wake_incoming_waiters(&mut self) {
        self.incoming_wakers.drain(..).for_each(Waker::wake);
    }

    fn new_connection(
        &mut self,
        handle: ConnectionHandle,
        conn: proto::Connection,
        socket: Socket,
        events_tx: Sender<(ConnectionHandle, EndpointEvent)>,
        runtime: &CompioRuntime,
    ) -> Connecting {
        let (tx, rx) = unbounded();
        if let Some((error_code, reason)) = &self.close {
            let _ = tx.send(ConnectionEvent::Close(*error_code, reason.clone()));
        }
        self.connections.insert(handle, tx);
        Connecting::new(handle, conn, socket, events_tx, rx, runtime)
    }
}

impl Drop for EndpointState {
    fn drop(&mut self) {
        for incoming in self.incoming.drain(..) {
            self.endpoint.ignore(incoming);
        }
    }
}

type ChannelPair<T> = (Sender<T>, Receiver<T>);

fn datagram_stride(len: usize, stride: usize) -> Option<usize> {
    (len != 0).then_some(if stride == 0 { len } else { stride.min(len) })
}

fn is_recoverable_recv_error(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::ConnectionReset || crate::endpoint::is_msg_size_err(error) {
        return true;
    }
    #[cfg(windows)]
    if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_PORT_UNREACHABLE as _) {
        return true;
    }
    false
}

#[derive(Debug)]
pub(crate) struct EndpointInner {
    state: Mutex<EndpointState>,
    socket: Socket,
    runtime: CompioRuntime,
    ipv6: bool,
    events: ChannelPair<(ConnectionHandle, EndpointEvent)>,
    responses: ChannelPair<(Vec<u8>, Transmit)>,
    exit: AsyncFlagHandle,
    done: AtomicWaker,
}

impl EndpointInner {
    fn new(
        runtime: CompioRuntime,
        socket: UdpSocket,
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        default_client_config: Option<ClientConfig>,
        exit: AsyncFlagHandle,
    ) -> io::Result<Self> {
        let socket = Socket::new(socket)?;
        let ipv6 = socket.local_addr()?.is_ipv6();
        let allow_mtud = !socket.may_fragment();
        let responses = bounded(64);

        Ok(Self {
            state: Mutex::new(EndpointState {
                endpoint: proto::Endpoint::new(
                    Arc::new(config),
                    server_config.map(Arc::new),
                    allow_mtud,
                ),
                default_client_config,
                worker: None,
                response_worker: None,
                connections: HashMap::default(),
                close: None,
                stopped: false,
                exit_on_idle: false,
                incoming: VecDeque::new(),
                incoming_wakers: VecDeque::new(),
                stats: EndpointStats::default(),
            }),
            socket,
            runtime,
            ipv6,
            events: unbounded(),
            responses,
            exit,
            done: AtomicWaker::new(),
        })
    }

    fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
        config: Option<ClientConfig>,
    ) -> Result<Connecting, ConnectError> {
        let mut state = self.state.lock();

        if state.close.is_some() || state.stopped || state.worker.is_none() {
            return Err(ConnectError::EndpointStopping);
        }
        let config = config
            .or_else(|| state.default_client_config.clone())
            .ok_or(ConnectError::NoDefaultClientConfig)?;
        if remote.is_ipv6() && !self.ipv6 {
            return Err(ConnectError::InvalidRemoteAddress(remote));
        }
        let remote = if self.ipv6 {
            SocketAddr::V6(match remote {
                SocketAddr::V4(addr) => {
                    SocketAddrV6::new(addr.ip().to_ipv6_mapped(), addr.port(), 0, 0)
                }
                SocketAddr::V6(addr) => addr,
            })
        } else {
            remote
        };

        let (handle, conn) = state
            .endpoint
            .connect(Instant::now(), config, remote, server_name)?;
        state.stats.outgoing_handshakes += 1;

        Ok(state.new_connection(
            handle,
            conn,
            self.socket.clone(),
            self.events.0.clone(),
            &self.runtime,
        ))
    }

    fn respond(&self, buf: Vec<u8>, transmit: Transmit) {
        // These packets are stateless replies. Dropping one under sustained pressure is safe
        // because a conforming peer retries the triggering packet.
        let _ = self.responses.0.try_send((buf, transmit));
    }

    pub(crate) fn accept(
        &self,
        incoming: proto::Incoming,
        server_config: Option<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        let mut state = self.state.lock();
        if state.stopped {
            state.stats.ignored_handshakes += 1;
            state.endpoint.ignore(incoming);
            return Err(ConnectionError::endpoint_stopped());
        }
        let mut resp_buf = Vec::new();
        let now = Instant::now();
        match state
            .endpoint
            .accept(incoming, now, &mut resp_buf, server_config.map(Arc::new))
        {
            Ok((handle, conn)) => {
                state.stats.accepted_handshakes += 1;
                Ok(state.new_connection(
                    handle,
                    conn,
                    self.socket.clone(),
                    self.events.0.clone(),
                    &self.runtime,
                ))
            }
            Err(err) => {
                if let Some(transmit) = err.response {
                    self.respond(resp_buf, transmit);
                }
                Err(err.cause.into())
            }
        }
    }

    pub(crate) fn refuse(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock();
        state.stats.refused_handshakes += 1;
        let mut resp_buf = Vec::new();
        let transmit = state.endpoint.refuse(incoming, &mut resp_buf);
        self.respond(resp_buf, transmit);
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn retry(&self, incoming: proto::Incoming) -> Result<(), proto::RetryError> {
        let mut state = self.state.lock();
        let mut resp_buf = Vec::new();
        let transmit = state.endpoint.retry(incoming, &mut resp_buf)?;
        self.respond(resp_buf, transmit);
        Ok(())
    }

    pub(crate) fn ignore(&self, incoming: proto::Incoming) {
        let mut state = self.state.lock();
        state.stats.ignored_handshakes += 1;
        state.endpoint.ignore(incoming);
    }

    async fn run(&self, exit: AsyncFlag) -> io::Result<()> {
        let respond_fn = |buf: Vec<u8>, transmit: Transmit| self.respond(buf, transmit);

        let mut recv_fut = pin!(
            self.socket
                .recv(Vec::with_capacity(
                    self.state
                        .lock()
                        .endpoint
                        .config()
                        .get_max_udp_payload_size()
                        .min(64 * 1024) as usize
                        * self.socket.max_gro_segments(),
                ))
                .fuse()
        );

        let mut event_stream = self.events.1.stream().ready_chunks(100);
        let mut exit = pin!(exit.wait().fuse());

        loop {
            let mut state = select! {
                () = exit => self.state.lock(),
                BufResult(res, recv_buf) = recv_fut => {
                    let mut state = self.state.lock();
                    match res {
                        Ok(meta) => state.handle_data(meta, &recv_buf, respond_fn),
                        Err(e) if is_recoverable_recv_error(&e) => {}
                        Err(e) => break Err(e),
                    }
                    recv_fut.set(self.socket.recv(recv_buf).fuse());
                    state
                },
                events = event_stream.select_next_some() => {
                    let mut state = self.state.lock();
                    for (ch, event) in events {
                        state.handle_event(ch, event);
                    }
                    state
                },
            };

            if state.exit_on_idle && state.is_idle() {
                break Ok(());
            }
            if !state.incoming.is_empty() {
                state.wake_incoming_waiters();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EndpointRef(Shared<EndpointInner>);

#[derive(Debug)]
struct EndpointDriver(EndpointRef);

impl EndpointDriver {
    async fn run(&self, exit: AsyncFlag) -> io::Result<()> {
        self.0.run(exit).await
    }
}

impl Drop for EndpointDriver {
    fn drop(&mut self) {
        let mut state = self.0.state.lock();
        state.stopped = true;
        state.wake_incoming_waiters();
        state.connections.clear();
        if let Some(worker) = state.worker.take() {
            worker.detach();
        }
    }
}

impl EndpointRef {
    fn into_inner(self) -> Shared<EndpointInner> {
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is not dropped here, and we're consuming Self
        unsafe { ptr::read(&this.0) }
    }

    async fn shutdown(self) -> io::Result<()> {
        let (worker, response_worker, idle) = {
            let mut state = self.0.state.lock();
            let idle = state.is_idle();
            if !idle {
                state.exit_on_idle = true;
            }
            (state.worker.take(), state.response_worker.take(), idle)
        };
        if let Some(worker) = worker {
            if idle {
                worker.cancel().await;
            } else {
                _ = worker.await;
            }
        }
        if let Some(worker) = response_worker {
            worker.cancel().await;
        }

        let mut this = Some(self.into_inner());
        let inner = poll_fn(move |cx| {
            let Some(shared) = this.take() else {
                return Poll::Pending;
            };
            let s = match Shared::try_unwrap(shared) {
                Ok(inner) => return Poll::Ready(inner),
                Err(s) => s,
            };

            s.done.register(cx.waker());

            match Shared::try_unwrap(s) {
                Ok(inner) => Poll::Ready(inner),
                Err(s) => {
                    this.replace(s);
                    Poll::Pending
                }
            }
        })
        .await;

        inner.socket.close().await
    }
}

impl Drop for EndpointRef {
    fn drop(&mut self) {
        if Shared::strong_count(&self.0) == 2 {
            // There are actually two cases:
            // 1. User dropped the endpoint but the worker is still running.
            self.0.state.lock().exit_on_idle = true;
            self.0.exit.clone().notify();
            // 2. User is trying to shutdown the socket.
            self.0.done.wake();
        }
    }
}

impl Deref for EndpointRef {
    type Target = EndpointInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A QUIC endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    inner: EndpointRef,
}

impl Endpoint {
    /// Create a QUIC endpoint.
    pub fn new(
        socket: UdpSocket,
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        default_client_config: Option<ClientConfig>,
    ) -> io::Result<Self> {
        let runtime = CompioRuntime::try_current().ok_or_else(|| {
            io::Error::other("a Compio endpoint must be created inside a running Compio runtime")
        })?;
        // With `runtime-compio-sync`, `Shared` is an `Arc`, but the captured Compio runtime keeps
        // the endpoint local to its owner thread. The `Arc` only changes the internal handle
        // primitives; it intentionally does not promise that `Endpoint` itself is `Send`.
        let exit = AsyncFlag::new();
        #[allow(clippy::arc_with_non_send_sync)]
        let inner = EndpointRef(Shared::new(EndpointInner::new(
            runtime,
            socket,
            config,
            server_config,
            default_client_config,
            exit.handle(),
        )?));
        let worker = inner.runtime.spawn({
            let driver = EndpointDriver(inner.clone());
            async move {
                if let Err(e) = driver.run(exit).await {
                    error!("I/O error: {:?}", e);
                }
            }
            .in_current_span()
        });
        let response_worker = inner.runtime.spawn({
            let responses = inner.responses.1.clone();
            let socket = inner.socket.clone();
            async move {
                while let Ok((buf, transmit)) = responses.recv_async().await {
                    socket.send(buf, &transmit).await;
                }
            }
            .in_current_span()
        });
        let mut state = inner.state.lock();
        state.worker = Some(worker);
        state.response_worker = Some(response_worker);
        drop(state);
        Ok(Self { inner })
    }

    /// Helper to construct an endpoint for use with outgoing connections only.
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually
    /// be a wildcard address like `0.0.0.0:0` or `[::]:0`, which allow
    /// communication with any reachable IPv4 or IPv6 address respectively
    /// from an OS-assigned port.
    ///
    /// If an IPv6 address is provided, the socket may dual-stack depending on
    /// the platform, so as to allow communication with both IPv4 and IPv6
    /// addresses. As such, calling this method with the address `[::]:0` is a
    /// reasonable default to maximize the ability to connect to other
    /// address.
    ///
    /// IPv4 client is never dual-stack.
    #[cfg(rustls)]
    pub async fn client(addr: impl ToSocketAddrsAsync) -> io::Result<Self> {
        // TODO: try to enable dual-stack on all platforms, notably Windows
        let socket = UdpSocket::bind(addr).await?;
        Self::new(socket, EndpointConfig::default(), None, None)
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing
    /// connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket
    /// bound to a wildcard IPv6 address on Windows will not by default be
    /// able to communicate with IPv4 addresses. Portable applications
    /// should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(rustls)]
    pub async fn server(addr: impl ToSocketAddrsAsync, config: ServerConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Self::new(socket, EndpointConfig::default(), Some(config), None)
    }

    /// Returns relevant stats from this Endpoint
    pub fn stats(&self) -> EndpointStats {
        self.inner.state.lock().stats
    }

    /// Connect to a remote endpoint.
    ///
    /// Returns [`ConnectError::EndpointStopping`] once this endpoint is closed or its I/O
    /// worker has stopped.
    pub fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
        config: Option<ClientConfig>,
    ) -> Result<Connecting, ConnectError> {
        self.inner.connect(remote, server_name, config)
    }

    /// Set the client configuration used when [`connect`](Self::connect) receives no override.
    pub fn set_default_client_config(&self, config: ClientConfig) {
        self.inner.state.lock().default_client_config = Some(config);
    }

    /// Wait for the next incoming connection attempt from a client.
    ///
    /// Yields [`Incoming`]s, or `None` if the endpoint is
    /// [`close`](Self::close)d or its I/O worker has stopped. [`Incoming`] can be
    /// `await`ed to obtain the final [`Connection`](crate::compio::Connection),
    /// or used to e.g. filter connection attempts or force address validation,
    /// or converted into an intermediate `Connecting` future which can be used
    /// to e.g. send 0.5-RTT data.
    pub async fn wait_incoming(&self) -> Option<Incoming> {
        future::poll_fn(|cx| self.inner.state.lock().poll_incoming(cx))
            .await
            .map(|incoming| Incoming::new(incoming, self.inner.clone()))
    }

    /// Replace the server configuration, affecting new incoming connections
    /// only.
    ///
    /// Useful for e.g. refreshing TLS certificates without disrupting existing
    /// connections.
    pub fn set_server_config(&self, server_config: Option<ServerConfig>) {
        self.inner
            .state
            .lock()
            .endpoint
            .set_server_config(server_config.map(Arc::new))
    }

    /// Get the local `SocketAddr` the underlying socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }

    /// Get the number of connections that are currently open.
    pub fn open_connections(&self) -> usize {
        self.inner.state.lock().endpoint.open_connections()
    }

    /// Close all of this endpoint's connections immediately and cease accepting
    /// new connections.
    ///
    /// See [`Connection::close()`] for details.
    ///
    /// [`Connection::close()`]: crate::compio::Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let reason = Bytes::copy_from_slice(reason);
        let mut state = self.inner.state.lock();
        if state.close.is_some() {
            return;
        }
        state.close = Some((error_code, reason.clone()));
        for conn in state.connections.values() {
            let _ = conn.send(ConnectionEvent::Close(error_code, reason.clone()));
        }
        state.wake_incoming_waiters();
    }

    /// Gracefully shutdown the endpoint.
    ///
    /// Wait for all connections on the endpoint to be cleanly shut down and
    /// close the underlying socket. This will wait for all clones of the
    /// endpoint, all connections and all streams to be dropped before
    /// closing the socket.
    ///
    /// Waiting for this condition before exiting ensures that a good-faith
    /// effort is made to notify peers of recent connection closes, whereas
    /// exiting immediately could force them to wait out the idle timeout
    /// period.
    ///
    /// Does not proactively close existing connections. Consider calling
    /// [`close()`] if that is desired.
    ///
    /// [`close()`]: Endpoint::close
    pub async fn shutdown(self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "rustls-ring")]
    use std::task::Poll;
    use std::{
        future::Future,
        io,
        net::UdpSocket as StdUdpSocket,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
        time::Duration,
    };

    #[cfg(feature = "rustls-ring")]
    use compio_buf::bytes::Bytes;
    use compio_net::UdpSocket;
    use compio_runtime::time::{sleep, timeout};
    use proto::EndpointConfig;
    #[cfg(feature = "rustls-ring")]
    use proto::{ConnectError, TransportErrorCode};

    #[cfg(feature = "rustls-ring")]
    use super::ConnectionEvent;
    use super::{Endpoint, datagram_stride};
    #[cfg(feature = "rustls-ring")]
    use crate::compio::{ClientBuilder, ConnectionError, ServerBuilder, StoppedError};

    #[test]
    fn empty_datagram_has_no_stride() {
        assert_eq!(datagram_stride(0, 0), None);
        assert_eq!(datagram_stride(1200, 0), Some(1200));
        assert_eq!(datagram_stride(2400, 1200), Some(1200));
    }

    #[cfg(windows)]
    #[test]
    fn winsock_message_size_error_does_not_stop_receiving() {
        use windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE;

        let truncated_datagram = io::Error::from_raw_os_error(WSAEMSGSIZE);
        assert!(super::is_recoverable_recv_error(&truncated_datagram));

        let fatal = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(!super::is_recoverable_recv_error(&fatal));
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(feature = "rustls-ring")]
    fn config_pair() -> (proto::ServerConfig, proto::ClientConfig) {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
            .with_no_crls()
            .build()
            .unwrap();
        (server, client)
    }

    #[compio_macros::test]
    #[cfg(feature = "rustls-ring")]
    async fn closed_endpoint_rejects_outgoing_connections() {
        let (_, client_config) = config_pair();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = socket.local_addr().unwrap();
        let endpoint = Endpoint::new(socket, EndpointConfig::default(), None, None).unwrap();

        endpoint.close(0u32.into(), b"closed");

        assert!(matches!(
            endpoint.connect(remote, "localhost", Some(client_config)),
            Err(ConnectError::EndpointStopping)
        ));
        assert!(matches!(
            endpoint.connect(remote, "localhost", None),
            Err(ConnectError::EndpointStopping)
        ));
        assert_eq!(endpoint.stats().outgoing_handshakes, 0);
        endpoint.shutdown().await.unwrap();
    }

    #[compio_macros::test]
    async fn cancelled_waiter_does_not_consume_incoming_wakeup() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint::new(socket, EndpointConfig::default(), None, None).unwrap();
        let cancelled_counter = Arc::new(WakeCounter::default());
        let cancelled_waker = Waker::from(cancelled_counter);
        let mut cancelled = Box::pin(endpoint.wait_incoming());

        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(&cancelled_waker))
                .is_pending()
        );
        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(&cancelled_waker))
                .is_pending()
        );
        assert_eq!(endpoint.inner.state.lock().incoming_wakers.len(), 1);
        drop(cancelled);

        let active_counter = Arc::new(WakeCounter::default());
        let active_waker = Waker::from(active_counter.clone());
        let mut active = Box::pin(endpoint.wait_incoming());
        assert!(
            active
                .as_mut()
                .poll(&mut Context::from_waker(&active_waker))
                .is_pending()
        );

        endpoint.inner.state.lock().wake_incoming_waiters();
        assert_eq!(active_counter.0.load(Ordering::Relaxed), 1);

        drop(active);
        endpoint.shutdown().await.unwrap();
    }

    #[compio_macros::test]
    async fn dropping_last_endpoint_releases_idle_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let endpoint = Endpoint::new(socket, EndpointConfig::default(), None, None).unwrap();

        assert_eq!(
            StdUdpSocket::bind(addr).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        drop(endpoint);

        let rebound = timeout(Duration::from_secs(1), async {
            loop {
                match StdUdpSocket::bind(addr) {
                    Ok(socket) => break Ok(socket),
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => break Err(error),
                }
            }
        })
        .await
        .expect("endpoint worker did not release its UDP socket")
        .unwrap();

        drop(rebound);
    }

    #[compio_macros::test]
    #[cfg(feature = "rustls-ring")]
    async fn endpoint_driver_exit_wakes_waiters_and_rejects_connect() {
        let (_, client_config) = config_pair();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            Endpoint::new(socket, EndpointConfig::default(), None, Some(client_config)).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let wake_counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(wake_counter.clone());
        let mut incoming = Box::pin(endpoint.wait_incoming());
        assert!(
            incoming
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );

        endpoint.inner.state.lock().exit_on_idle = true;
        endpoint.inner.exit.clone().notify();
        timeout(Duration::from_secs(1), async {
            while !endpoint.inner.state.lock().stopped {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("endpoint worker did not mark the endpoint stopped");

        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            incoming.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(None)
        ));
        assert!(matches!(
            endpoint.connect(addr, "localhost", None),
            Err(ConnectError::EndpointStopping)
        ));

        drop(incoming);
        endpoint.shutdown().await.unwrap();
    }

    #[compio_macros::test]
    #[cfg(feature = "rustls-ring")]
    async fn incoming_accept_rejects_after_endpoint_driver_exit() {
        let (server_config, client_config) = config_pair();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint::new(
            socket,
            EndpointConfig::default(),
            Some(server_config),
            Some(client_config),
        )
        .unwrap();
        let connecting = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost", None)
            .unwrap();
        let incoming = timeout(Duration::from_secs(2), endpoint.wait_incoming())
            .await
            .expect("loopback Initial did not reach the endpoint")
            .unwrap();
        let worker = endpoint.inner.state.lock().worker.take().unwrap();

        worker.cancel().await;
        timeout(Duration::from_secs(1), async {
            while !endpoint.inner.state.lock().stopped {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled endpoint worker did not run its cleanup");

        let accept_error = incoming.accept().unwrap_err();
        assert!(matches!(
            accept_error,
            ConnectionError::TransportError(error)
                if error.code == TransportErrorCode::INTERNAL_ERROR
        ));
        assert_eq!(endpoint.stats().ignored_handshakes, 1);
        let connect_error = timeout(Duration::from_secs(1), connecting)
            .await
            .expect("outgoing connection did not observe endpoint shutdown")
            .unwrap_err();
        assert!(matches!(
            connect_error,
            ConnectionError::TransportError(error)
                if error.code == TransportErrorCode::INTERNAL_ERROR
        ));

        endpoint.shutdown().await.unwrap();
    }

    #[compio_macros::test]
    #[cfg(feature = "rustls-ring")]
    async fn cancelling_endpoint_worker_stops_active_connections() {
        let (server_config, client_config) = config_pair();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint::new(
            socket,
            EndpointConfig::default(),
            Some(server_config),
            Some(client_config),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (server_connection, client_connection) = timeout(Duration::from_secs(2), async {
            futures_util::join!(
                async { endpoint.wait_incoming().await.unwrap().await.unwrap() },
                async {
                    endpoint
                        .connect(addr, "localhost", None)
                        .unwrap()
                        .await
                        .unwrap()
                }
            )
        })
        .await
        .expect("loopback connections did not finish handshaking");
        let mut send = client_connection.open_uni().unwrap();
        let stopped_counter = Arc::new(WakeCounter::default());
        let stopped_waker = Waker::from(stopped_counter.clone());
        let mut stopped = Box::pin(send.stopped());
        assert!(
            stopped
                .as_mut()
                .poll(&mut Context::from_waker(&stopped_waker))
                .is_pending()
        );
        let worker = {
            let mut state = endpoint.inner.state.lock();
            state
                .connections
                .values()
                .next()
                .unwrap()
                .send(ConnectionEvent::Close(0u32.into(), Bytes::new()))
                .unwrap();
            state.worker.take().unwrap()
        };

        worker.cancel().await;
        timeout(Duration::from_secs(1), async {
            while !endpoint.inner.state.lock().stopped {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled endpoint worker did not run its cleanup");

        assert!(endpoint.inner.state.lock().stopped);
        let (server_error, client_error) = timeout(Duration::from_secs(1), async {
            futures_util::join!(server_connection.closed(), client_connection.closed())
        })
        .await
        .expect("connections did not observe endpoint shutdown");
        assert!(
            [&server_error, &client_error]
                .into_iter()
                .any(|error| matches!(error, ConnectionError::LocallyClosed))
        );
        assert!([server_error, client_error].into_iter().any(|error| {
            matches!(
                error,
                ConnectionError::TransportError(error)
                    if error.code == TransportErrorCode::INTERNAL_ERROR
            )
        }));
        let stopped_error = timeout(Duration::from_secs(1), stopped)
            .await
            .expect("stopped future did not observe endpoint shutdown")
            .unwrap_err();
        assert!(matches!(stopped_error, StoppedError::ConnectionLost(_)));
        assert!(stopped_counter.0.load(Ordering::Relaxed) >= 1);

        drop(send);
        drop((server_connection, client_connection));
        endpoint.shutdown().await.unwrap();
    }
}
