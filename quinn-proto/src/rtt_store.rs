//! Per-server RTT cache used to advertise the `initial_rtt` transport parameter (0x3127) in
//! subsequent connections, matching Chrome's behaviour.

use std::{collections::HashMap, sync::RwLock};

/// Responsible for caching the measured SRTT per server name across connections
///
/// When a QUIC connection closes successfully, the smoothed RTT is stored here. On the next
/// connection to the same server the cached value is read back and advertised via the
/// `initial_rtt` transport parameter (`0x3127`).
///
/// The first connection to a server finds no cached value and therefore omits the TP, which
/// matches Chrome's observed behaviour.
pub trait RttStore: Send + Sync {
    /// Persist the measured SRTT (in microseconds) for `server_name`.
    ///
    /// Called automatically by quinn-proto when a client connection drains after the handshake
    /// has completed.
    fn insert(&self, server_name: &str, rtt_us: u64);

    /// Retrieve the previously stored SRTT (in microseconds) for `server_name`, if any.
    ///
    /// Called automatically by quinn-proto when creating a new outbound connection.
    /// Returning `None` suppresses the `initial_rtt` TP, which is the correct behaviour for a
    /// first connection to a previously-unseen server.
    fn load(&self, server_name: &str) -> Option<u64>;
}

/// Simple in-memory [`RttStore`] that keeps the latest SRTT for each server name.
///
/// This is the default implementation used by [`ClientConfig`](crate::ClientConfig). It caches
/// values only for the lifetime of the process; use a custom [`RttStore`] implementation if you
/// need persistence across process restarts.
#[derive(Default)]
pub struct RttMemoryCache(RwLock<HashMap<Box<str>, u64>>);

impl RttStore for RttMemoryCache {
    #[inline]
    fn insert(&self, server_name: &str, rtt_us: u64) {
        self.0.write().unwrap().insert(server_name.into(), rtt_us);
    }

    #[inline]
    fn load(&self, server_name: &str) -> Option<u64> {
        self.0.read().unwrap().get(server_name).copied()
    }
}
