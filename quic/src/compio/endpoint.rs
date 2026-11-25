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
    ClientConfig, ConnectError, ConnectionError, ConnectionHandle, DatagramEvent, EndpointConfig,
    EndpointEvent, ServerConfig, Transmit, VarInt,
};
use rustc_hash::FxHashMap as HashMap;

use crate::compio::{
    Connecting, ConnectionEvent, Incoming, RecvMeta, Socket,
    sync::{mutex_blocking::Mutex, shared::Shared},
};

#[derive(Debug)]
struct EndpointState {
    endpoint: proto::Endpoint,
    default_client_config: Option<ClientConfig>,
    worker: Option<JoinHandle<()>>,
    response_worker: Option<JoinHandle<()>>,
    connections: HashMap<ConnectionHandle, Sender<ConnectionEvent>>,
    close: Option<(VarInt, Bytes)>,
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
        if self.close.is_none() {
            if let Some(incoming) = self.incoming.pop_front() {
                Poll::Ready(Some(incoming))
            } else {
                if !self
                    .incoming_wakers
                    .iter()
                    .any(|waker| waker.will_wake(cx.waker()))
                {
                    self.incoming_wakers.push_back(cx.waker().clone());
                }
                Poll::Pending
            }
        } else {
            Poll::Ready(None)
        }
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

#[derive(Debug)]
pub(crate) struct EndpointInner {
    state: Mutex<EndpointState>,
    socket: Socket,
    runtime: CompioRuntime,
    ipv6: bool,
    events: ChannelPair<(ConnectionHandle, EndpointEvent)>,
    responses: ChannelPair<(Vec<u8>, Transmit)>,
    done: AtomicWaker,
}

impl EndpointInner {
    fn new(
        runtime: CompioRuntime,
        socket: UdpSocket,
        config: EndpointConfig,
        server_config: Option<ServerConfig>,
        default_client_config: Option<ClientConfig>,
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
            done: AtomicWaker::new(),
        })
    }

    fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
        config: ClientConfig,
    ) -> Result<Connecting, ConnectError> {
        let mut state = self.state.lock();

        if state.worker.is_none() {
            return Err(ConnectError::EndpointStopping);
        }
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
                Err(err.cause)
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

    async fn run(&self) -> io::Result<()> {
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

        loop {
            let mut state = select! {
                BufResult(res, recv_buf) = recv_fut => {
                    let mut state = self.state.lock();
                    match res {
                        Ok(meta) => state.handle_data(meta, &recv_buf, respond_fn),
                        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                        #[cfg(windows)]
                        Err(e) if e.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_PORT_UNREACHABLE as _) => {}
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
            // 1. User is trying to shutdown the socket.
            self.0.done.wake();
            // 2. User dropped the endpoint but the worker is still running.
            self.0.state.lock().exit_on_idle = true;
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
        #[allow(clippy::arc_with_non_send_sync)]
        let inner = EndpointRef(Shared::new(EndpointInner::new(
            runtime,
            socket,
            config,
            server_config,
            default_client_config,
        )?));
        let worker = inner.runtime.spawn({
            let inner = inner.clone();
            async move {
                if let Err(e) = inner.run().await {
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
    pub fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
        config: Option<ClientConfig>,
    ) -> Result<Connecting, ConnectError> {
        let config = config
            .or_else(|| self.inner.state.lock().default_client_config.clone())
            .ok_or(ConnectError::NoDefaultClientConfig)?;

        self.inner.connect(remote, server_name, config)
    }

    /// Set the client configuration used when [`connect`](Self::connect) receives no override.
    pub fn set_default_client_config(&self, config: ClientConfig) {
        self.inner.state.lock().default_client_config = Some(config);
    }

    /// Wait for the next incoming connection attempt from a client.
    ///
    /// Yields [`Incoming`]s, or `None` if the endpoint is
    /// [`close`](Self::close)d. [`Incoming`] can be `await`ed to obtain the
    /// final [`Connection`](crate::compio::Connection), or used to e.g. filter
    /// connection attempts or force address validation, or converted into an
    /// intermediate `Connecting` future which can be used to e.g. send 0.5-RTT
    /// data.
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
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };

    use compio_net::UdpSocket;
    use proto::EndpointConfig;

    use super::{Endpoint, datagram_stride};

    #[test]
    fn empty_datagram_has_no_stride() {
        assert_eq!(datagram_stride(0, 0), None);
        assert_eq!(datagram_stride(1200, 0), Some(1200));
        assert_eq!(datagram_stride(2400, 1200), Some(1200));
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
}
