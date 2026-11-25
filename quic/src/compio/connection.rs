use std::{
    any::Any,
    collections::VecDeque,
    fmt::Debug,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::{Pin, pin},
    sync::atomic::Ordering,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use compio_buf::bytes::Bytes;
use compio_log::Instrument;
use compio_runtime::{JoinHandle, Runtime as CompioRuntime};
use flume::{Receiver, Sender};
use futures_util::{
    FutureExt, StreamExt,
    future::{self, Fuse, FusedFuture, LocalBoxFuture},
    select, stream,
};
use proto::{
    ConnectionHandle, ConnectionStats, Dir, EndpointEvent, Side, StreamEvent, StreamId,
    TransportError, TransportErrorCode, VarInt, congestion::Controller,
};
use rustc_hash::FxHashMap as HashMap;
use thiserror::Error;
use tokio::sync::Notify;

use crate::compio::{
    RecvStream, SendStream, Socket,
    sync::{
        atomic::AtomicUsize,
        mutex_blocking::{Mutex, MutexGuard},
        shared::Shared,
    },
};

#[derive(Debug)]
pub(crate) enum ConnectionEvent {
    Close(VarInt, Bytes),
    Proto(proto::ConnectionEvent),
}

#[derive(Debug)]
pub(crate) struct ConnectionState {
    pub(crate) conn: proto::Connection,
    pub(crate) error: Option<ConnectionError>,
    connected: bool,
    handshake_confirmed: bool,
    worker: Option<JoinHandle<()>>,
    poller: Option<Waker>,
    on_connected: VecDeque<Waker>,
    on_handshake_confirmed: VecDeque<Waker>,
    on_handshake_data: Option<Waker>,
    datagram_received: VecDeque<Waker>,
    datagrams_unblocked: VecDeque<Waker>,
    stream_opened: [VecDeque<Waker>; 2],
    stream_available: [VecDeque<Waker>; 2],
    pub(crate) writable: HashMap<StreamId, Waker>,
    pub(crate) readable: HashMap<StreamId, Waker>,
    pub(crate) stopped: HashMap<StreamId, Waker>,
}

impl ConnectionState {
    fn terminate(&mut self, reason: ConnectionError) {
        self.error = Some(reason);
        self.connected = false;

        if let Some(waker) = self.on_handshake_data.take() {
            waker.wake()
        }
        self.on_connected.drain(..).for_each(Waker::wake);
        self.on_handshake_confirmed.drain(..).for_each(Waker::wake);
        self.datagram_received.drain(..).for_each(Waker::wake);
        self.datagrams_unblocked.drain(..).for_each(Waker::wake);
        for e in &mut self.stream_opened {
            e.drain(..).for_each(Waker::wake);
        }
        for e in &mut self.stream_available {
            e.drain(..).for_each(Waker::wake);
        }
        wake_all_streams(&mut self.writable);
        wake_all_streams(&mut self.readable);
        wake_all_streams(&mut self.stopped);
    }

    fn close(&mut self, error_code: VarInt, reason: Bytes) {
        self.conn.close(Instant::now(), error_code, reason);
        self.terminate(ConnectionError::LocallyClosed);
        self.wake();
    }

    pub(crate) fn wake(&mut self) {
        if let Some(waker) = self.poller.take() {
            waker.wake()
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.conn.crypto_session().handshake_data()
    }

    pub(crate) fn check_0rtt(&self) -> bool {
        self.conn.side().is_server() || self.conn.is_handshaking() || self.conn.accepted_0rtt()
    }
}

fn wake_stream(stream: StreamId, wakers: &mut HashMap<StreamId, Waker>) {
    if let Some(waker) = wakers.remove(&stream) {
        waker.wake();
    }
}

fn register_waker(wakers: &mut VecDeque<Waker>, waker: &Waker) {
    if !wakers.iter().any(|existing| existing.will_wake(waker)) {
        wakers.push_back(waker.clone());
    }
}

fn wake_all_streams(wakers: &mut HashMap<StreamId, Waker>) {
    wakers.drain().for_each(|(_, waker)| waker.wake())
}

#[derive(Debug)]
pub(crate) struct ConnectionInner {
    state: Mutex<ConnectionState>,
    application_refs: AtomicUsize,
    handle: ConnectionHandle,
    socket: Socket,
    events_tx: Sender<(ConnectionHandle, EndpointEvent)>,
    events_rx: Receiver<ConnectionEvent>,
    closed: Notify,
}

impl ConnectionInner {
    fn new(
        handle: ConnectionHandle,
        conn: proto::Connection,
        socket: Socket,
        events_tx: Sender<(ConnectionHandle, EndpointEvent)>,
        events_rx: Receiver<ConnectionEvent>,
    ) -> Self {
        Self {
            state: Mutex::new(ConnectionState {
                conn,
                connected: false,
                handshake_confirmed: false,
                error: None,
                worker: None,
                poller: None,
                on_connected: VecDeque::new(),
                on_handshake_confirmed: VecDeque::new(),
                on_handshake_data: None,
                datagram_received: VecDeque::new(),
                datagrams_unblocked: VecDeque::new(),
                stream_opened: [VecDeque::new(), VecDeque::new()],
                stream_available: [VecDeque::new(), VecDeque::new()],
                writable: HashMap::default(),
                readable: HashMap::default(),
                stopped: HashMap::default(),
            }),
            application_refs: AtomicUsize::new(1),
            handle,
            socket,
            events_tx,
            events_rx,
            closed: Notify::new(),
        }
    }

    #[inline]
    pub(crate) fn state(&self) -> MutexGuard<'_, ConnectionState> {
        self.state.lock()
    }

    #[inline]
    pub(crate) fn try_state(&self) -> Result<MutexGuard<'_, ConnectionState>, ConnectionError> {
        let state = self.state();
        if let Some(error) = &state.error {
            Err(error.clone())
        } else {
            Ok(state)
        }
    }

    async fn run(&self) {
        let mut poller = stream::poll_fn(|cx| {
            let mut state = self.state();
            let ready = state.poller.is_none();
            match &state.poller {
                Some(waker) if waker.will_wake(cx.waker()) => {}
                _ => state.poller = Some(cx.waker().clone()),
            };
            if ready {
                Poll::Ready(Some(()))
            } else {
                Poll::Pending
            }
        })
        .fuse();

        let mut timer = Timer::new();
        let mut event_stream = self.events_rx.stream().ready_chunks(100);
        let mut send_buf = Some(Vec::with_capacity(self.state().conn.current_mtu() as usize));
        let mut transmit_fut = pin!(Fuse::terminated());

        loop {
            let mut state = select! {
                _ = poller.select_next_some() => self.state(),
                _ = timer => {
                    timer.reset(None);
                    let mut state = self.state();
                    state.conn.handle_timeout(Instant::now());
                    state
                }
                events = event_stream.next().fuse() => {
                    let mut state = self.state();
                    let Some(events) = events else {
                        if state.error.is_none() {
                            state.terminate(ConnectionError::endpoint_stopped());
                            self.closed.notify_waiters();
                        }
                        break;
                    };
                    for event in events {
                        match event {
                            ConnectionEvent::Close(error_code, reason) => {
                                state.close(error_code, reason);
                                self.closed.notify_waiters();
                            }
                            ConnectionEvent::Proto(event) => state.conn.handle_event(event),
                        }
                    }
                    state
                },
                buf = transmit_fut => {
                    // The following line is required to avoid "type annotations needed" error
                    let mut buf: Vec<_> = buf;
                    buf.clear();
                    send_buf = Some(buf);
                    self.state()
                },
            };

            if let Some(mut buf) = send_buf.take() {
                if let Some(transmit) = state.conn.poll_transmit(
                    Instant::now(),
                    self.socket.max_gso_segments(),
                    &mut buf,
                ) {
                    transmit_fut.set(async move { self.socket.send(buf, &transmit).await }.fuse())
                } else {
                    send_buf = Some(buf);
                }
            }

            timer.reset(state.conn.poll_timeout());

            while let Some(event) = state.conn.poll_endpoint_events() {
                let _ = self.events_tx.send((self.handle, event));
            }

            while let Some(event) = state.conn.poll() {
                use proto::Event::*;
                match event {
                    HandshakeDataReady => {
                        if let Some(waker) = state.on_handshake_data.take() {
                            waker.wake()
                        }
                    }
                    Connected => {
                        state.connected = true;
                        state.on_connected.drain(..).for_each(Waker::wake);
                        if state.conn.side().is_client() && !state.conn.accepted_0rtt() {
                            // Wake up rejected 0-RTT streams so they can fail immediately with
                            // `ZeroRttRejected` errors.
                            wake_all_streams(&mut state.writable);
                            wake_all_streams(&mut state.readable);
                            wake_all_streams(&mut state.stopped);
                        }
                    }
                    HandshakeConfirmed => {
                        state.handshake_confirmed = true;
                        state.on_handshake_confirmed.drain(..).for_each(Waker::wake);
                    }
                    ConnectionLost { reason } => {
                        state.terminate(reason.into());
                        self.closed.notify_waiters();
                    }
                    Stream(StreamEvent::Readable { id }) => wake_stream(id, &mut state.readable),
                    Stream(StreamEvent::Writable { id }) => wake_stream(id, &mut state.writable),
                    Stream(StreamEvent::Finished { id }) => wake_stream(id, &mut state.stopped),
                    Stream(StreamEvent::Stopped { id, .. }) => {
                        wake_stream(id, &mut state.stopped);
                        wake_stream(id, &mut state.writable);
                    }
                    Stream(StreamEvent::Available { dir }) => state.stream_available[dir as usize]
                        .drain(..)
                        .for_each(Waker::wake),
                    Stream(StreamEvent::Opened { dir }) => state.stream_opened[dir as usize]
                        .drain(..)
                        .for_each(Waker::wake),
                    DatagramReceived => state.datagram_received.drain(..).for_each(Waker::wake),
                    DatagramsUnblocked => state.datagrams_unblocked.drain(..).for_each(Waker::wake),
                    // The Tokio frontend uses this to drive `RemoteAddressWatcher`.
                    // Compio has no watcher yet; `remote_address()` still reads the
                    // current path straight from the state machine.
                    PathUpdated => {}
                    // `proto::Event` is non-exhaustive.
                    _ => {}
                }
            }

            if state.conn.is_drained() {
                break;
            }
        }
    }
}

/// Owns cleanup that must run whether the connection worker completes or is cancelled.
#[derive(Debug)]
struct ConnectionDriver(Shared<ConnectionInner>);

impl ConnectionDriver {
    async fn run(&self) {
        self.0.run().await;
    }
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        let worker = {
            let mut state = self.0.state();
            if state.error.is_none() {
                state.terminate(ConnectionError::endpoint_stopped());
            }
            let worker = state.worker.take();
            drop(state);
            worker
        };

        self.0.closed.notify_waiters();
        if let Some(worker) = worker {
            worker.detach();
        }
    }
}

/// A reference held by an application-facing connection or stream handle.
///
/// The connection worker deliberately holds a plain [`Shared`] reference so the last application
/// handle can close the connection without waiting for the worker to release its own reference.
#[derive(Debug)]
pub(crate) struct ConnectionRef(Shared<ConnectionInner>);

impl ConnectionRef {
    fn new(inner: Shared<ConnectionInner>) -> Self {
        Self(inner)
    }

    fn stable_id(&self) -> usize {
        Shared::as_ptr(&self.0) as usize
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        Shared::ptr_eq(&self.0, &other.0)
    }
}

impl Clone for ConnectionRef {
    fn clone(&self) -> Self {
        self.application_refs.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for ConnectionRef {
    fn drop(&mut self) {
        if self.application_refs.fetch_sub(1, Ordering::Relaxed) > 1 {
            return;
        }

        let mut state = self.state();
        if state.error.is_none() {
            state.close(0u32.into(), Bytes::new());
        }
    }
}

impl std::ops::Deref for ConnectionRef {
    type Target = ConnectionInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

macro_rules! conn_fn {
    () => {
        /// The side of the connection (client or server)
        pub fn side(&self) -> Side {
            self.0.state().conn.side()
        }

        /// The local IP address which was used when the peer established
        /// the connection.
        ///
        /// This can be different from the address the endpoint is bound to, in case
        /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
        ///
        /// This will return `None` for clients, or when the platform does not
        /// expose this information.
        pub fn local_ip(&self) -> Option<IpAddr> {
            self.0.state().conn.local_ip()
        }

        /// The peer's UDP address.
        ///
        /// Will panic if called after `poll` has returned `Ready`.
        pub fn remote_address(&self) -> SocketAddr {
            self.0.state().conn.remote_address()
        }

        /// Current best estimate of this connection's latency (round-trip-time).
        pub fn rtt(&self) -> Duration {
            self.0.state().conn.rtt()
        }

        /// Connection statistics.
        pub fn stats(&self) -> ConnectionStats {
            self.0.state().conn.stats()
        }

        /// Current state of the congestion control algorithm. (For debugging
        /// purposes)
        pub fn congestion_state(&self) -> Box<dyn Controller> {
            self.0.state().conn.congestion_state().clone_box()
        }

        /// Cryptographic identity of the peer.
        pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
            self.0.state().conn.crypto_session().peer_identity()
        }

        /// A stable identifier for this connection
        ///
        /// Peer addresses and connection IDs can change, but this value will remain
        /// fixed for the lifetime of the connection.
        pub fn stable_id(&self) -> usize {
            self.0.stable_id()
        }

        /// Derive keying material from this connection's TLS session secrets.
        ///
        /// When both peers call this method with the same `label` and `context`
        /// arguments and `output` buffers of equal length, they will get the
        /// same sequence of bytes in `output`. These bytes are cryptographically
        /// strong and pseudorandom, and are suitable for use as keying material.
        ///
        /// This function fails if called with an empty `output` or called prior to
        /// the handshake completing.
        ///
        /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
        pub fn export_keying_material(
            &self,
            output: &mut [u8],
            label: &[u8],
            context: &[u8],
        ) -> Result<(), proto::crypto::ExportKeyingMaterialError> {
            self.0
                .state()
                .conn
                .crypto_session()
                .export_keying_material(output, label, context)
        }
    };
}

/// In-progress connection attempt future
#[derive(Debug)]
#[must_use = "futures/streams/sinks do nothing unless you `.await` or poll them"]
pub struct Connecting(ConnectionRef);

impl Connecting {
    conn_fn!();

    pub(crate) fn new(
        handle: ConnectionHandle,
        conn: proto::Connection,
        socket: Socket,
        events_tx: Sender<(ConnectionHandle, EndpointEvent)>,
        events_rx: Receiver<ConnectionEvent>,
        runtime: &CompioRuntime,
    ) -> Self {
        let inner = Shared::new(ConnectionInner::new(
            handle, conn, socket, events_tx, events_rx,
        ));
        let worker = runtime.spawn({
            let driver = ConnectionDriver(inner.clone());
            async move { driver.run().await }.in_current_span()
        });
        inner.state().worker = Some(worker);
        Self(ConnectionRef::new(inner))
    }

    /// Parameters negotiated during the handshake.
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        future::poll_fn(|cx| {
            let mut state = self.0.try_state()?;
            if let Some(data) = state.handshake_data() {
                return Poll::Ready(Ok(data));
            }

            match &state.on_handshake_data {
                Some(waker) if waker.will_wake(cx.waker()) => {}
                _ => state.on_handshake_data = Some(cx.waker().clone()),
            }

            Poll::Pending
        })
        .await
    }

    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened
    /// security.
    ///
    /// Returns `Ok` immediately if the local endpoint is able to attempt
    /// sending 0/0.5-RTT data. If so, the returned [`Connection`] can be used
    /// to send application data without waiting for the rest of the handshake
    /// to complete, at the cost of weakened cryptographic security guarantees.
    /// The [`Connection::accepted_0rtt`] method resolves when the handshake
    /// does complete, at which point subsequently opened streams and written
    /// data will have full cryptographic protection.
    ///
    /// ## Outgoing
    ///
    /// For outgoing connections, the initial attempt to convert to a
    /// [`Connection`] which sends 0-RTT data will proceed if the
    /// [`crypto::ClientConfig`][crate::compio::crypto::ClientConfig] attempts to resume
    /// a previous TLS session. However, **the remote endpoint may not actually
    /// _accept_ the 0-RTT data**--yet still accept the connection attempt in
    /// general. This possibility is conveyed through the
    /// [`Connection::accepted_0rtt`] method--when the handshake completes, it
    /// resolves to true if the 0-RTT data was accepted and false if it was
    /// rejected. If it was rejected, the existence of streams opened and other
    /// application data sent prior to the handshake completing will not be
    /// conveyed to the remote application, and local operations on them will
    /// return `ZeroRttRejected` errors.
    ///
    /// A server may reject 0-RTT data at its discretion, but accepting 0-RTT
    /// data requires the relevant resumption state to be stored in the server,
    /// which servers may limit or lose for various reasons including not
    /// persisting resumption state across server restarts.
    ///
    /// ## Incoming
    ///
    /// For incoming connections, conversion to 0.5-RTT will always fully
    /// succeed. `into_0rtt` will always return `Ok` and
    /// [`Connection::accepted_0rtt`] will always resolve to true.
    ///
    /// ## Security
    ///
    /// On outgoing connections, this enables transmission of 0-RTT data, which
    /// is vulnerable to replay attacks, and should therefore never invoke
    /// non-idempotent operations.
    ///
    /// On incoming connections, this enables transmission of 0.5-RTT data,
    /// which may be sent before TLS client authentication has occurred, and
    /// should therefore not be used to send data for which client
    /// authentication is being used.
    pub fn into_0rtt(self) -> Result<Connection, Self> {
        let is_ok = {
            let state = self.0.state();
            state.conn.has_0rtt() || state.conn.side().is_server()
        };
        if is_ok {
            Ok(Connection(self.0.clone()))
        } else {
            Err(self)
        }
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.0.try_state()?;

        if state.connected {
            return Poll::Ready(Ok(Connection(self.0.clone())));
        }

        register_waker(&mut state.on_connected, cx.waker());

        Poll::Pending
    }
}

/// A QUIC connection.
#[derive(Debug, Clone)]
pub struct Connection(ConnectionRef);

impl Connection {
    conn_fn!();

    /// Wait for the handshake to be confirmed.
    ///
    /// On a client this completes after receiving HANDSHAKE_DONE. On a server it completes after
    /// the peer's TLS Finished message has been processed.
    pub async fn handshake_confirmed(&self) -> Result<(), ConnectionError> {
        future::poll_fn(|cx| {
            let mut state = self.0.try_state()?;
            if state.handshake_confirmed {
                return Poll::Ready(Ok(()));
            }

            register_waker(&mut state.on_handshake_confirmed, cx.waker());

            Poll::Pending
        })
        .await
    }

    /// Update traffic keys spontaneously
    ///
    /// This primarily exists for testing purposes.
    pub fn force_key_update(&self) {
        self.0.state().conn.force_key_update()
    }

    /// Parameters negotiated during the handshake.
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.0.state().handshake_data()
    }

    /// Compute the maximum size of datagrams that may be passed to
    /// [`send_datagram()`](Self::send_datagram).
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled
    /// locally.
    ///
    /// This may change over the lifetime of a connection according to variation
    /// in the path MTU estimate. The peer can also enforce an arbitrarily small
    /// fixed limit, but if the peer's limit is large this is guaranteed to be a
    /// little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.0.state().conn.datagrams().max_size()
    }

    /// Bytes available in the outgoing datagram buffer.
    ///
    /// When greater than zero, calling [`send_datagram()`](Self::send_datagram)
    /// with a datagram of at most this size is guaranteed not to cause older
    /// datagrams to be dropped.
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.0.state().conn.datagrams().send_buffer_space()
    }

    /// Modify the number of remotely initiated unidirectional streams that may
    /// be concurrently open.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are
    /// already open. Large `count`s increase both minimum and worst-case
    /// memory consumption.
    pub fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        let mut state = self.0.state();
        state.conn.set_max_concurrent_streams(Dir::Uni, count);
        // May need to send MAX_STREAMS to make progress
        state.wake();
    }

    /// See [`proto::TransportConfig::send_window()`]
    pub fn set_send_window(&self, send_window: u64) {
        let mut state = self.0.state();
        state.conn.set_send_window(send_window);
        state.wake();
    }

    /// See [`proto::TransportConfig::receive_window()`]
    pub fn set_receive_window(&self, receive_window: VarInt) {
        let mut state = self.0.state();
        state.conn.set_receive_window(receive_window);
        state.wake();
    }

    /// Modify the number of remotely initiated bidirectional streams that may
    /// be concurrently open.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are
    /// already open. Large `count`s increase both minimum and worst-case
    /// memory consumption.
    pub fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        let mut state = self.0.state();
        state.conn.set_max_concurrent_streams(Dir::Bi, count);
        // May need to send MAX_STREAMS to make progress
        state.wake();
    }

    /// Close the connection immediately.
    ///
    /// Pending operations will fail immediately with
    /// [`ConnectionError::LocallyClosed`]. No more data is sent to the peer
    /// and the peer may drop buffered data upon receiving
    /// the CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly
    /// to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to
    /// improve odds that it is preserved in full, it should be kept under
    /// 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all
    /// data is delivered. The only reliable action it can then take is to
    /// close the connection, potentially with a custom error code. The
    /// delivery of the final CONNECTION_CLOSE frame is very likely if both
    /// endpoints stay online long enough, and [`Endpoint::shutdown()`] can
    /// be used to provide sufficient time. Otherwise, the remote peer will
    /// time out the connection, provided that the idle timeout is not
    /// disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the
    /// remote application. It only knows the data is delivered to the QUIC
    /// stack of the remote endpoint. Once the local side sends a
    /// CONNECTION_CLOSE frame in response to calling [`close()`] the remote
    /// endpoint may drop any data it received but is as yet undelivered to
    /// the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`ConnectionError::LocallyClosed`]: ConnectionError::LocallyClosed
    /// [`Endpoint::shutdown()`]: crate::compio::Endpoint::shutdown
    /// [`close()`]: Connection::close
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.0
            .state()
            .close(error_code, Bytes::copy_from_slice(reason));
        self.0.closed.notify_waiters();
    }

    /// Wait for the connection to be closed for any reason.
    ///
    /// This operation is cancel-safe. Multiple callers can wait concurrently.
    pub async fn closed(&self) -> ConnectionError {
        loop {
            let notified = {
                let state = self.0.state();
                if let Some(error) = &state.error {
                    return error.clone();
                }
                // Register for a broadcast before releasing the state lock.
                self.0.closed.notified()
            };
            notified.await;
        }
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.0.try_state().err()
    }

    fn poll_recv_datagram(&self, cx: &mut Context<'_>) -> Poll<Result<Bytes, ConnectionError>> {
        let mut state = self.0.state();
        if let Some(bytes) = state.conn.datagrams().recv() {
            return Poll::Ready(Ok(bytes));
        }
        if let Some(error) = &state.error {
            return Poll::Ready(Err(error.clone()));
        }
        register_waker(&mut state.datagram_received, cx.waker());
        Poll::Pending
    }

    /// Try to receive an application datagram.
    ///
    /// Buffered datagrams remain available after the connection closes. When the queue is
    /// empty, this returns the close reason for a closed connection, or `Ok(None)` otherwise.
    pub fn try_recv_datagram(&self) -> Result<Option<Bytes>, ConnectionError> {
        let mut state = self.0.state();
        if let Some(bytes) = state.conn.datagrams().recv() {
            return Ok(Some(bytes));
        }
        state.error.clone().map_or(Ok(None), Err)
    }

    /// Receive an application datagram.
    ///
    /// Buffered datagrams are delivered before the close reason.
    pub async fn recv_datagram(&self) -> Result<Bytes, ConnectionError> {
        future::poll_fn(|cx| self.poll_recv_datagram(cx)).await
    }

    fn try_send_datagram(
        &self,
        cx: Option<&mut Context<'_>>,
        data: Bytes,
    ) -> Result<(), Result<SendDatagramError, Bytes>> {
        use proto::SendDatagramError::*;
        let mut state = self.0.try_state().map_err(|e| Ok(e.into()))?;
        match state.conn.datagrams().send(data, cx.is_none()) {
            Ok(()) => {}
            Err(UnsupportedByPeer) => return Err(Ok(SendDatagramError::UnsupportedByPeer)),
            Err(Disabled) => return Err(Ok(SendDatagramError::Disabled)),
            Err(TooLarge) => return Err(Ok(SendDatagramError::TooLarge)),
            Err(Blocked(data)) => {
                let Some(cx) = cx else {
                    // `drop_old` was enabled, so the protocol layer should have made room. QUIC
                    // datagrams are unreliable; if that invariant changes, dropping this datagram
                    // is safer than panicking in application code.
                    return Ok(());
                };
                register_waker(&mut state.datagrams_unblocked, cx.waker());
                return Err(Err(data));
            }
        }
        state.wake();
        Ok(())
    }

    /// Transmit `data` as an unreliable, unordered application datagram.
    ///
    /// Application datagrams are a low-level primitive. They may be lost or
    /// delivered out of order, and `data` must both fit inside a single
    /// QUIC packet and be smaller than the maximum dictated by the peer.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        match self.try_send_datagram(None, data) {
            Ok(()) | Err(Err(_)) => Ok(()),
            Err(Ok(error)) => Err(error),
        }
    }

    /// Transmit `data` as an unreliable, unordered application datagram.
    ///
    /// Unlike [`send_datagram()`], this method will wait for buffer space
    /// during congestion conditions, which effectively prioritizes old
    /// datagrams over new datagrams.
    ///
    /// See [`send_datagram()`] for details.
    ///
    /// [`send_datagram()`]: Connection::send_datagram
    pub async fn send_datagram_wait(&self, data: Bytes) -> Result<(), SendDatagramError> {
        let mut data = data;
        future::poll_fn(
            |cx| match self.try_send_datagram(Some(cx), std::mem::take(&mut data)) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(Ok(e)) => Poll::Ready(Err(e)),
                Err(Err(b)) => {
                    data = b;
                    Poll::Pending
                }
            },
        )
        .await
    }

    fn poll_open_stream(
        &self,
        cx: Option<&mut Context<'_>>,
        dir: Dir,
    ) -> Poll<Result<(StreamId, bool), ConnectionError>> {
        let mut state = self.0.try_state()?;
        if let Some(stream) = state.conn.streams().open(dir) {
            Poll::Ready(Ok((
                stream,
                state.conn.side().is_client() && state.conn.is_handshaking(),
            )))
        } else {
            if let Some(cx) = cx {
                register_waker(&mut state.stream_available[dir as usize], cx.waker());
            }
            Poll::Pending
        }
    }

    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open. As a consequence, the peer
    /// won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_uni(&self) -> Result<SendStream, OpenStreamError> {
        if let Poll::Ready((stream, is_0rtt)) = self.poll_open_stream(None, Dir::Uni)? {
            Ok(SendStream::new(self.0.clone(), stream, is_0rtt))
        } else {
            Err(OpenStreamError::StreamsExhausted)
        }
    }

    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Unlike [`open_uni()`], this method will wait for the connection to allow
    /// a new stream to be opened.
    ///
    /// See [`open_uni()`] for details.
    ///
    /// [`open_uni()`]: crate::compio::Connection::open_uni
    pub async fn open_uni_wait(&self) -> Result<SendStream, ConnectionError> {
        let (stream, is_0rtt) =
            future::poll_fn(|cx| self.poll_open_stream(Some(cx), Dir::Uni)).await?;
        Ok(SendStream::new(self.0.clone(), stream, is_0rtt))
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open. As a consequence, the peer
    /// won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_bi(&self) -> Result<(SendStream, RecvStream), OpenStreamError> {
        if let Poll::Ready((stream, is_0rtt)) = self.poll_open_stream(None, Dir::Bi)? {
            Ok((
                SendStream::new(self.0.clone(), stream, is_0rtt),
                RecvStream::new(self.0.clone(), stream, is_0rtt),
            ))
        } else {
            Err(OpenStreamError::StreamsExhausted)
        }
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Unlike [`open_bi()`], this method will wait for the connection to allow
    /// a new stream to be opened.
    ///
    /// See [`open_bi()`] for details.
    ///
    /// [`open_bi()`]: crate::compio::Connection::open_bi
    pub async fn open_bi_wait(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (stream, is_0rtt) =
            future::poll_fn(|cx| self.poll_open_stream(Some(cx), Dir::Bi)).await?;
        Ok((
            SendStream::new(self.0.clone(), stream, is_0rtt),
            RecvStream::new(self.0.clone(), stream, is_0rtt),
        ))
    }

    fn poll_accept_stream(
        &self,
        cx: &mut Context<'_>,
        dir: Dir,
    ) -> Poll<Result<(StreamId, bool), ConnectionError>> {
        let mut state = self.0.state();
        if let Some(stream) = state.conn.streams().accept(dir) {
            state.wake();
            Poll::Ready(Ok((stream, state.conn.is_handshaking())))
        } else if let Some(error) = &state.error {
            Poll::Ready(Err(error.clone()))
        } else {
            register_waker(&mut state.stream_opened[dir as usize], cx.waker());
            Poll::Pending
        }
    }

    /// Accept the next incoming unidirectional stream.
    ///
    /// Already-received streams remain available after the connection closes.
    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        let (stream, is_0rtt) = future::poll_fn(|cx| self.poll_accept_stream(cx, Dir::Uni)).await?;
        Ok(RecvStream::new(self.0.clone(), stream, is_0rtt))
    }

    /// Accept the next incoming bidirectional stream
    ///
    /// Already-received streams remain available after the connection closes.
    ///
    /// **Important Note**: The `Connection` that calls [`open_bi()`] must write
    /// to its [`SendStream`] before the other `Connection` is able to
    /// `accept_bi()`. Calling [`open_bi()`] then waiting on the [`RecvStream`]
    /// without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`accept_bi()`]: crate::compio::Connection::accept_bi
    /// [`open_bi()`]: crate::compio::Connection::open_bi
    /// [`SendStream`]: crate::compio::SendStream
    /// [`RecvStream`]: crate::compio::RecvStream
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (stream, is_0rtt) = future::poll_fn(|cx| self.poll_accept_stream(cx, Dir::Bi)).await?;
        Ok((
            SendStream::new(self.0.clone(), stream, is_0rtt),
            RecvStream::new(self.0.clone(), stream, is_0rtt),
        ))
    }

    /// Wait for the connection to be fully established.
    ///
    /// For clients, the resulting value indicates if 0-RTT was accepted. For
    /// servers, the resulting value is meaningless.
    pub async fn accepted_0rtt(&self) -> Result<bool, ConnectionError> {
        future::poll_fn(|cx| {
            let mut state = self.0.try_state()?;

            if state.connected {
                return Poll::Ready(Ok(state.conn.accepted_0rtt()));
            }

            register_waker(&mut state.on_connected, cx.waker());

            Poll::Pending
        })
        .await
    }

    /// Wait until an incoming connection is proven not to be a replay attack.
    ///
    /// This completes immediately for established 1-RTT connections. For connections obtained
    /// through 0-RTT, it waits until the handshake authenticates the peer's flight.
    pub async fn authenticated(&self) -> Result<(), ConnectionError> {
        future::poll_fn(|cx| {
            let mut state = self.0.try_state()?;
            if state.connected {
                return Poll::Ready(Ok(()));
            }

            register_waker(&mut state.on_connected, cx.waker());

            Poll::Pending
        })
        .await
    }
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl Eq for Connection {}

struct Timer {
    deadline: Option<Instant>,
    fut: Fuse<LocalBoxFuture<'static, ()>>,
}

impl Timer {
    fn new() -> Self {
        Self {
            deadline: None,
            fut: Fuse::terminated(),
        }
    }

    fn reset(&mut self, deadline: Option<Instant>) {
        if let Some(deadline) = deadline {
            if self.deadline.is_none() || self.deadline != Some(deadline) {
                self.fut = compio_runtime::time::sleep_until(deadline)
                    .boxed_local()
                    .fuse();
            }
        } else {
            self.fut = Fuse::terminated();
        }
        self.deadline = deadline;
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.fut.poll_unpin(cx)
    }
}

impl FusedFuture for Timer {
    fn is_terminated(&self) -> bool {
        self.fut.is_terminated()
    }
}

/// Reasons why a connection might be lost
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The peer doesn't implement any supported version
    #[error("peer doesn't implement any supported version")]
    VersionMismatch,
    /// The peer violated the QUIC specification as understood by this
    /// implementation
    #[error(transparent)]
    TransportError(#[from] TransportError),
    /// The peer's QUIC stack aborted the connection automatically
    #[error("aborted by peer: {0}")]
    ConnectionClosed(proto::ConnectionClose),
    /// The peer closed the connection
    #[error("closed by peer: {0}")]
    ApplicationClosed(proto::ApplicationClose),
    /// The peer is unable to continue processing this connection, usually due
    /// to having restarted
    #[error("reset by peer")]
    Reset,
    /// Communication with the peer has lapsed for longer than the negotiated
    /// idle timeout
    ///
    /// If neither side is sending keep-alives, a connection will time out after
    /// a long enough idle period even if the peer is still reachable. See
    /// also [`TransportConfig::max_idle_timeout()`](proto::TransportConfig::max_idle_timeout())
    /// and [`TransportConfig::keep_alive_interval()`](proto::TransportConfig::keep_alive_interval()).
    #[error("timed out")]
    TimedOut,
    /// The local application closed the connection
    #[error("closed")]
    LocallyClosed,
    /// The connection could not be created because not enough of the CID space
    /// is available
    ///
    /// Try using longer connection IDs.
    #[error("CIDs exhausted")]
    CidsExhausted,
}

impl ConnectionError {
    pub(crate) fn endpoint_stopped() -> Self {
        Self::TransportError(TransportError::new(
            TransportErrorCode::INTERNAL_ERROR,
            "endpoint driver future was dropped".to_string(),
        ))
    }
}

impl From<proto::ConnectionError> for ConnectionError {
    fn from(value: proto::ConnectionError) -> Self {
        use proto::ConnectionError::*;

        match value {
            VersionMismatch => Self::VersionMismatch,
            TransportError(e) => Self::TransportError(e),
            ConnectionClosed(e) => Self::ConnectionClosed(e),
            ApplicationClosed(e) => Self::ApplicationClosed(e),
            Reset => Self::Reset,
            TimedOut => Self::TimedOut,
            LocallyClosed => Self::LocallyClosed,
            CidsExhausted => Self::CidsExhausted,
        }
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by
    /// the peer has been exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
}

/// Errors that can arise when trying to open a stream
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum OpenStreamError {
    /// The connection was lost
    #[error("connection lost")]
    ConnectionLost(#[from] ConnectionError),
    /// The streams in the given direction are currently exhausted
    #[error("streams exhausted")]
    StreamsExhausted,
}

#[cfg(feature = "compio-h3")]
pub(crate) mod h3_impl {
    use std::sync::Arc;

    use compio_buf::bytes::Buf;
    use futures_util::ready;
    use h3::{
        error::Code,
        quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, WriteBuf},
    };
    use h3_datagram::{
        datagram::EncodedDatagram,
        quic_traits::{
            DatagramConnectionExt, RecvDatagram, SendDatagram, SendDatagramErrorIncoming,
        },
    };

    use super::*;
    use crate::compio::send_stream::h3_impl::SendStream;

    impl From<ConnectionError> for ConnectionErrorIncoming {
        fn from(e: ConnectionError) -> Self {
            use ConnectionError::*;
            match e {
                ApplicationClosed(e) => Self::ApplicationClose {
                    error_code: e.error_code.into_inner(),
                },
                TimedOut => Self::Timeout,

                e => Self::Undefined(Arc::new(e)),
            }
        }
    }

    impl From<ConnectionError> for StreamErrorIncoming {
        fn from(e: ConnectionError) -> Self {
            Self::ConnectionErrorIncoming {
                connection_error: e.into(),
            }
        }
    }

    impl From<SendDatagramError> for SendDatagramErrorIncoming {
        fn from(e: SendDatagramError) -> Self {
            use SendDatagramError::*;
            match e {
                UnsupportedByPeer | Disabled => Self::NotAvailable,
                TooLarge => Self::TooLarge,
                ConnectionLost(e) => Self::ConnectionError(e.into()),
            }
        }
    }

    impl<B> SendDatagram<B> for Connection
    where
        B: Buf,
    {
        fn send_datagram<T: Into<EncodedDatagram<B>>>(
            &mut self,
            data: T,
        ) -> Result<(), SendDatagramErrorIncoming> {
            let mut buf: EncodedDatagram<B> = data.into();
            let buf = buf.copy_to_bytes(buf.remaining());
            Ok(Self::send_datagram(self, buf)?)
        }
    }

    impl RecvDatagram for Connection {
        type Buffer = Bytes;

        fn poll_incoming_datagram(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::Buffer, ConnectionErrorIncoming>> {
            Poll::Ready(Ok(ready!(self.poll_recv_datagram(cx))?))
        }
    }

    impl<B: Buf> DatagramConnectionExt<B> for Connection {
        type RecvDatagramHandler = Self;
        type SendDatagramHandler = Self;

        fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
            self.clone()
        }

        fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
            self.clone()
        }
    }

    /// Bidirectional stream.
    pub struct BidiStream<B> {
        send: SendStream<B>,
        recv: RecvStream,
    }

    impl<B> BidiStream<B> {
        pub(crate) fn new(conn: ConnectionRef, stream: StreamId, is_0rtt: bool) -> Self {
            Self {
                send: SendStream::new(conn.clone(), stream, is_0rtt),
                recv: RecvStream::new(conn, stream, is_0rtt),
            }
        }
    }

    impl<B> quic::BidiStream<B> for BidiStream<B>
    where
        B: Buf,
    {
        type RecvStream = RecvStream;
        type SendStream = SendStream<B>;

        fn split(self) -> (Self::SendStream, Self::RecvStream) {
            (self.send, self.recv)
        }
    }

    impl<B> quic::RecvStream for BidiStream<B>
    where
        B: Buf,
    {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.recv.poll_data(cx)
        }

        fn stop_sending(&mut self, error_code: u64) {
            self.recv.stop_sending(error_code)
        }

        fn recv_id(&self) -> quic::StreamId {
            self.recv.recv_id()
        }
    }

    impl<B> quic::SendStream<B> for BidiStream<B>
    where
        B: Buf,
    {
        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            self.send.poll_ready(cx)
        }

        fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
            self.send.send_data(data)
        }

        fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            self.send.poll_finish(cx)
        }

        fn reset(&mut self, reset_code: u64) {
            self.send.reset(reset_code)
        }

        fn send_id(&self) -> quic::StreamId {
            self.send.send_id()
        }
    }

    impl<B> quic::SendStreamUnframed<B> for BidiStream<B>
    where
        B: Buf,
    {
        fn poll_send<D: Buf>(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut D,
        ) -> Poll<Result<usize, StreamErrorIncoming>> {
            self.send.poll_send(cx, buf)
        }
    }

    /// Stream opener.
    #[derive(Clone)]
    pub struct OpenStreams(Connection);

    impl<B> quic::OpenStreams<B> for OpenStreams
    where
        B: Buf,
    {
        type BidiStream = BidiStream<B>;
        type SendStream = SendStream<B>;

        fn poll_open_bidi(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
            let (stream, is_0rtt) = ready!(self.0.poll_open_stream(Some(cx), Dir::Bi))?;
            Poll::Ready(Ok(BidiStream::new(self.0.0.clone(), stream, is_0rtt)))
        }

        fn poll_open_send(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
            let (stream, is_0rtt) = ready!(self.0.poll_open_stream(Some(cx), Dir::Uni))?;
            Poll::Ready(Ok(SendStream::new(self.0.0.clone(), stream, is_0rtt)))
        }

        fn close(&mut self, code: Code, reason: &[u8]) {
            self.0.close(
                VarInt::from_u64(code.value()).unwrap_or(VarInt::MAX),
                reason,
            )
        }
    }

    impl<B> quic::OpenStreams<B> for Connection
    where
        B: Buf,
    {
        type BidiStream = BidiStream<B>;
        type SendStream = SendStream<B>;

        fn poll_open_bidi(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
            let (stream, is_0rtt) = ready!(self.poll_open_stream(Some(cx), Dir::Bi))?;
            Poll::Ready(Ok(BidiStream::new(self.0.clone(), stream, is_0rtt)))
        }

        fn poll_open_send(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
            let (stream, is_0rtt) = ready!(self.poll_open_stream(Some(cx), Dir::Uni))?;
            Poll::Ready(Ok(SendStream::new(self.0.clone(), stream, is_0rtt)))
        }

        fn close(&mut self, code: Code, reason: &[u8]) {
            Self::close(
                self,
                VarInt::from_u64(code.value()).unwrap_or(VarInt::MAX),
                reason,
            )
        }
    }

    impl<B> quic::Connection<B> for Connection
    where
        B: Buf,
    {
        type OpenStreams = OpenStreams;
        type RecvStream = RecvStream;

        fn poll_accept_recv(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
            let (stream, is_0rtt) = ready!(self.poll_accept_stream(cx, Dir::Uni))?;
            Poll::Ready(Ok(RecvStream::new(self.0.clone(), stream, is_0rtt)))
        }

        fn poll_accept_bidi(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
            let (stream, is_0rtt) = ready!(self.poll_accept_stream(cx, Dir::Bi))?;
            Poll::Ready(Ok(BidiStream::new(self.0.clone(), stream, is_0rtt)))
        }

        fn opener(&self) -> Self::OpenStreams {
            OpenStreams(self.clone())
        }
    }
}
