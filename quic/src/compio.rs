//! Native completion-I/O support for the Compio runtime.
//!
//! Compio operations own their buffers until completion and its default task model is
//! runtime-local. The endpoint, connection, and stream types in this module therefore remain
//! separate from the readiness-based types at the crate root. Both frontends use the same
//! [`proto`] state machine and configuration types.

#[cfg(feature = "bloom")]
pub use proto::BloomTokenLog;
#[cfg(feature = "btls")]
pub use proto::btls;
pub use proto::{
    AckFrequencyConfig, ApplicationClose, Chunk, ClientConfig, ClosedStream, ConfigError,
    ConnectError, ConnectionClose, ConnectionId, ConnectionIdGenerator, ConnectionStats, Dir,
    EcnCodepoint, EndpointConfig, FrameStats, FrameType, IdleTimeout, InvalidCid,
    MtuDiscoveryConfig, NoneTokenLog, NoneTokenStore, PathStats, ServerConfig, ServerRttStore,
    Side, StdSystemTime, StreamId, TimeSource, TokenLog, TokenMemoryCache, TokenReuseError,
    TokenStore, Transmit, TransportConfig, TransportErrorCode, TransportParameterConfig,
    TransportParameterId, TransportParameterKind, UdpStats, ValidationTokenConfig, VarInt,
    VarIntBoundsExceeded, VersionEntry, VersionInformation, Written, congestion, crypto,
};
#[cfg(feature = "qlog")]
pub use proto::{QlogConfig, QlogStream};

#[cfg(rustls)]
mod builder;
mod connection;
mod endpoint;
mod incoming;
mod recv_stream;
mod send_stream;
mod socket;

#[cfg(rustls)]
pub use builder::{ClientBuilder, ServerBuilder};
pub use connection::{Connecting, Connection, ConnectionError, OpenStreamError, SendDatagramError};
pub use endpoint::{Endpoint, EndpointStats};
pub use incoming::{Incoming, IncomingFuture, RetryError};
#[cfg(feature = "futures-io")]
pub use recv_stream::CompatRecvStream;
pub use recv_stream::{ReadError, ReadExactError, RecvStream, ResetError};
#[cfg(feature = "futures-io")]
pub use send_stream::CompatSendStream;
pub use send_stream::{SendStream, StoppedError, WriteError};

#[cfg(feature = "runtime-compio-sync")]
pub(crate) use synchrony::sync;
#[cfg(not(feature = "runtime-compio-sync"))]
pub(crate) use synchrony::unsync as sync;

pub(crate) use self::{
    connection::{ConnectionEvent, ConnectionRef},
    endpoint::EndpointRef,
    socket::*,
};
