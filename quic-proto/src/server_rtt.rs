//! Per-server RTT storage and wire coding for the `initial_rtt` transport parameter (`0x3127`).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use lru_slab::LruSlab;

use crate::VarInt;

const DEFAULT_MAX_SERVER_ENDPOINTS: u32 = 500;

/// Minimum accepted value for an untrusted initial RTT.
const MIN_INITIAL_RTT: Duration = Duration::from_millis(10);

/// Maximum accepted value for an initial RTT.
const MAX_INITIAL_RTT: Duration = Duration::from_secs(1);

/// Storage for measured SRTTs used by subsequent client connections.
///
/// These methods run synchronously on connection lifecycle paths: [`ServerRttStore::get`] is
/// called when opening a client connection, while [`ServerRttStore::insert`] and
/// [`ServerRttStore::remove_if_eq`] are called when it closes. They are not called for individual
/// application requests or when an existing connection is reused.
///
/// Implementations must return promptly, must not panic, and should not perform blocking file,
/// database, or network I/O. A persistent implementation should keep an in-memory front cache and
/// send durable updates through a bounded, non-blocking queue to another execution context. The
/// background writer should preserve per-endpoint ordering or coalesce updates so an older write
/// cannot replace a newer RTT. Data needed by [`ServerRttStore::get`] should be loaded before the
/// store is installed; returning `None` is preferable to blocking while data is loaded.
pub trait ServerRttStore: Send + Sync {
    /// Store the latest measured SRTT for a server endpoint.
    ///
    /// This is called when a client connection closes after obtaining a usable 1-RTT sample.
    /// An existing value for the same server name and port should be replaced.
    fn insert(&self, server_name: &str, server_port: u16, smoothed_rtt: Duration);

    /// Get the latest measured SRTT for a server endpoint.
    ///
    /// This is called once while opening a client connection when the extension is enabled.
    /// Returning `None` makes the connection use its configured initial RTT.
    fn get(&self, server_name: &str, server_port: u16) -> Option<Duration>;

    /// Remove a measured SRTT if it still equals `expected_rtt`.
    ///
    /// This is called after a connection that reused `expected_rtt` closes without a usable RTT
    /// sample. The comparison and removal must be atomic so that a different sample written by a
    /// concurrent connection is preserved. A missing or different value should have no effect.
    fn remove_if_eq(&self, server_name: &str, server_port: u16, expected_rtt: Duration);
}

/// Bounded in-memory [`ServerRttStore`].
///
/// The default capacity is 500 server endpoints.
/// A mutex is used because reads update LRU order, so lookups require exclusive access.
#[derive(Debug)]
pub(crate) struct ServerRttMemoryStore(Mutex<State>);

impl ServerRttMemoryStore {
    /// Construct an empty store for up to `max_server_endpoints` server endpoints.
    fn new(max_server_endpoints: u32) -> Self {
        Self(Mutex::new(State {
            max_server_endpoints,
            lookup: HashMap::new(),
            lru: LruSlab::default(),
        }))
    }
}

impl ServerRttStore for ServerRttMemoryStore {
    #[inline]
    fn insert(&self, server_name: &str, server_port: u16, smoothed_rtt: Duration) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(server_name, server_port, smoothed_rtt);
    }

    #[inline]
    fn get(&self, server_name: &str, server_port: u16) -> Option<Duration> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(server_name, server_port)
    }

    #[inline]
    fn remove_if_eq(&self, server_name: &str, server_port: u16, expected_rtt: Duration) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove_if_eq(server_name, server_port, expected_rtt);
    }
}

impl Default for ServerRttMemoryStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SERVER_ENDPOINTS)
    }
}

/// Mutable state protected by [`ServerRttMemoryStore`]'s mutex.
///
/// Every endpoint in `lookup` points to a live entry in `lru`. Updates and removals must keep both
/// collections in sync while the mutex is held.
#[derive(Debug)]
struct State {
    max_server_endpoints: u32,
    // Maps a borrowed server name and port to the entry owned by `lru` without allocating on reads.
    lookup: HashMap<Arc<str>, HashMap<u16, u32>>,
    // Owns cache entries and updates their recency whenever `get_mut` is called.
    lru: LruSlab<CacheEntry>,
}

impl State {
    /// Insert or replace an endpoint and mark it as most recently used.
    fn insert(&mut self, server_name: &str, server_port: u16, rtt: Duration) {
        // A zero-capacity cache is valid and never allocates storage.
        if self.max_server_endpoints == 0 {
            return;
        }

        // Reuse the lookup key when adding another port for the same server name.
        let server_name = match self.lookup.get_key_value(server_name) {
            Some((stored_server_name, ports)) => {
                if let Some(slab_key) = ports.get(&server_port).copied() {
                    // Updating an existing endpoint also promotes it to most recently used.
                    self.lru.get_mut(slab_key).rtt = rtt;
                    return;
                }
                Arc::clone(stored_server_name)
            }
            None => Arc::<str>::from(server_name),
        };

        if self.lru.len() >= self.max_server_endpoints {
            let Some(slab_key) = self.lru.lru() else {
                return;
            };
            // Remove the lookup index immediately after taking ownership of the evicted entry.
            let evicted = self.lru.remove(slab_key);
            self.remove_lookup(&evicted.server_name, evicted.server_port);
        }

        // The lookup key and slab entry share the same server-name allocation.
        let slab_key = self.lru.insert(CacheEntry {
            server_name: Arc::clone(&server_name),
            server_port,
            rtt,
        });
        self.lookup
            .entry(server_name)
            .or_default()
            .insert(server_port, slab_key);
    }

    /// Return an endpoint's RTT and promote the corresponding slab entry to most recently used.
    fn get(&mut self, server_name: &str, server_port: u16) -> Option<Duration> {
        let slab_key = self.lookup.get(server_name)?.get(&server_port).copied()?;
        Some(self.lru.get_mut(slab_key).rtt)
    }

    /// Remove an endpoint only when its RTT still matches the value read by the caller.
    fn remove_if_eq(&mut self, server_name: &str, server_port: u16, expected_rtt: Duration) {
        let Some(slab_key) = self
            .lookup
            .get(server_name)
            .and_then(|ports| ports.get(&server_port))
            .copied()
        else {
            return;
        };
        if self.lru.peek(slab_key).rtt != expected_rtt {
            return;
        }

        if let Some(slab_key) = self.remove_lookup(server_name, server_port) {
            self.lru.remove(slab_key);
        }
    }

    /// Remove an endpoint from the lookup index while keeping sibling ports intact.
    ///
    /// The returned slab key lets the caller remove the matching owned entry without another
    /// lookup.
    fn remove_lookup(&mut self, server_name: &str, server_port: u16) -> Option<u32> {
        let (slab_key, remove_server_name) = {
            let ports = self.lookup.get_mut(server_name)?;
            let slab_key = ports.remove(&server_port)?;
            (slab_key, ports.is_empty())
        };

        if remove_server_name {
            self.lookup.remove(server_name);
        }
        Some(slab_key)
    }
}

#[derive(Debug)]
struct CacheEntry {
    server_name: Arc<str>,
    server_port: u16,
    rtt: Duration,
}

pub(crate) fn encode(rtt: Duration) -> Option<(Duration, VarInt)> {
    let rtt = sanitize(rtt)?;
    // `sanitize` caps the duration at one second, so this conversion cannot truncate.
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
    fn memory_store_keeps_latest_srtt_per_server_endpoint() {
        let store = ServerRttMemoryStore::default();
        assert_eq!(store.get("example.com", 443), None);

        store.insert("example.com", 443, Duration::from_millis(20));
        store.insert("example.com", 443, Duration::from_millis(30));

        assert_eq!(
            store.get("example.com", 443),
            Some(Duration::from_millis(30))
        );
        assert_eq!(store.get("example.com", 8443), None);
    }

    #[test]
    fn memory_store_evicts_least_recently_used_endpoint() {
        let store = ServerRttMemoryStore::new(2);
        let rtt = Duration::from_millis(20);

        store.insert("first.example", 443, rtt);
        store.insert("second.example", 443, rtt);
        assert_eq!(store.get("first.example", 443), Some(rtt));

        store.insert("third.example", 443, rtt);

        assert_eq!(store.get("first.example", 443), Some(rtt));
        assert_eq!(store.get("second.example", 443), None);
        assert_eq!(store.get("third.example", 443), Some(rtt));
    }

    #[test]
    fn zero_capacity_memory_store_stays_empty() {
        let store = ServerRttMemoryStore::new(0);
        store.insert("example.com", 443, Duration::from_millis(20));
        assert_eq!(store.get("example.com", 443), None);
    }

    #[test]
    fn memory_store_removes_only_the_matching_endpoint_value() {
        let store = ServerRttMemoryStore::default();
        let rtt = Duration::from_millis(20);
        store.insert("example.com", 443, rtt);
        store.insert("example.com", 8443, rtt);

        store.remove_if_eq("example.com", 443, Duration::from_millis(30));
        assert_eq!(store.get("example.com", 443), Some(rtt));

        store.remove_if_eq("example.com", 443, rtt);
        store.remove_if_eq("example.com", 443, rtt);

        assert_eq!(store.get("example.com", 443), None);
        assert_eq!(store.get("example.com", 8443), Some(rtt));
    }

    #[test]
    fn memory_store_preserves_a_different_newer_value_during_stale_removal() {
        let store = ServerRttMemoryStore::default();
        let old_rtt = Duration::from_millis(20);
        let new_rtt = Duration::from_millis(30);
        store.insert("example.com", 443, old_rtt);

        let cached_rtt = store.get("example.com", 443).unwrap();
        store.insert("example.com", 443, new_rtt);
        store.remove_if_eq("example.com", 443, cached_rtt);

        assert_eq!(store.get("example.com", 443), Some(new_rtt));
    }

    #[test]
    fn memory_store_reuses_server_name_allocation_across_ports() {
        let store = ServerRttMemoryStore::default();
        let rtt = Duration::from_millis(20);
        store.insert("example.com", 443, rtt);
        store.insert("example.com", 8443, rtt);

        let mut state = store.0.lock().unwrap();
        let (lookup_name, first_key, second_key) = {
            let (server_name, ports) = state.lookup.get_key_value("example.com").unwrap();
            (Arc::clone(server_name), ports[&443], ports[&8443])
        };
        let first_name = Arc::clone(&state.lru.get_mut(first_key).server_name);
        let second_name = Arc::clone(&state.lru.get_mut(second_key).server_name);

        assert!(Arc::ptr_eq(&lookup_name, &first_name));
        assert!(Arc::ptr_eq(&lookup_name, &second_name));
    }
}
