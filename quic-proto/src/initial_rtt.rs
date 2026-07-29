//! Per-server cache for the `initial_rtt` transport parameter (`0x3127`).

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
    time::Duration,
};

use crate::VarInt;

/// Minimum accepted value for an untrusted initial RTT.
const MIN_INITIAL_RTT: Duration = Duration::from_millis(10);

/// Maximum accepted value for an initial RTT.
const MAX_INITIAL_RTT: Duration = Duration::from_secs(1);

/// Cache for the measured SRTT used to initialize subsequent connections.
///
/// After a client connection with an RTT sample closes, `quic-proto` inserts its final SRTT. When
/// another connection to the same server starts, the cached value initializes the local RTT
/// estimator and is advertised to the server using the `initial_rtt` transport parameter.
///
/// Implementations must be thread-safe and should not panic in [`insert`](Self::insert), which is
/// called while closing a connection.
pub trait InitialRttCache: Send + Sync {
    /// Cache the measured SRTT for `server_name`.
    fn insert(&self, server_name: &str, rtt: Duration);

    /// Get the previously cached SRTT for `server_name`.
    fn get(&self, server_name: &str) -> Option<Duration>;
}

/// In-memory [`InitialRttCache`] that keeps the latest SRTT for each server name.
///
/// Configure this with
/// [`ClientConfig::initial_rtt_cache`](crate::ClientConfig::initial_rtt_cache) to cache values for
/// the lifetime of the process.
#[derive(Default)]
pub struct InitialRttMemoryCache(RwLock<HashMap<Box<str>, Duration>>);

impl InitialRttCache for InitialRttMemoryCache {
    #[inline]
    fn insert(&self, server_name: &str, rtt: Duration) {
        self.0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(server_name.into(), rtt);
    }

    #[inline]
    fn get(&self, server_name: &str) -> Option<Duration> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(server_name)
            .copied()
    }
}

pub(crate) fn encode(rtt: Duration) -> Option<(Duration, VarInt)> {
    let rtt = sanitize(rtt)?;
    let micros = rtt.as_micros() as u32;
    Some((rtt, VarInt::from_u32(micros)))
}

pub(crate) fn decode(value: VarInt) -> Option<Duration> {
    sanitize(Duration::from_micros(value.into_inner()))
}

fn sanitize(rtt: Duration) -> Option<Duration> {
    (!rtt.is_zero()).then(|| rtt.clamp(MIN_INITIAL_RTT, MAX_INITIAL_RTT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rtt_is_clamped_to_bounds() {
        assert_eq!(encode(Duration::ZERO), None);
        assert_eq!(decode(VarInt::from_u32(0)), None);

        let (rtt, encoded) = encode(Duration::from_millis(1)).unwrap();
        assert_eq!(rtt, MIN_INITIAL_RTT);
        assert_eq!(encoded.into_inner(), 10_000);
        assert_eq!(decode(VarInt::from_u32(1)), Some(MIN_INITIAL_RTT));

        let (rtt, encoded) = encode(Duration::from_millis(20)).unwrap();
        assert_eq!(rtt, Duration::from_millis(20));
        assert_eq!(decode(encoded), Some(rtt));

        let (rtt, encoded) = encode(Duration::from_secs(2)).unwrap();
        assert_eq!(rtt, MAX_INITIAL_RTT);
        assert_eq!(encoded.into_inner(), 1_000_000);
        assert_eq!(decode(VarInt::from_u32(2_000_000)), Some(MAX_INITIAL_RTT));
    }

    #[test]
    fn memory_cache_keeps_latest_srtt() {
        let cache = InitialRttMemoryCache::default();
        assert_eq!(cache.get("example.com"), None);

        cache.insert("example.com", Duration::from_millis(20));
        cache.insert("example.com", Duration::from_millis(30));

        assert_eq!(cache.get("example.com"), Some(Duration::from_millis(30)));
    }
}
