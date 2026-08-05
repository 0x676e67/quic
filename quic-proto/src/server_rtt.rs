//! Per-server RTT storage used by the `initial_rtt` transport parameter.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use lru_slab::LruSlab;

const DEFAULT_MAX_SERVER_ENDPOINTS: u32 = 500;

/// Cache for measured SRTTs used by subsequent client connections.
///
/// Methods are called synchronously while opening or closing connections. Implementations should
/// avoid blocking and must not panic. Slow persistence should be queued for separate processing.
pub trait ServerRttStore: Send + Sync {
    /// Store the latest measured SRTT for a server endpoint.
    fn insert(&self, server_name: &str, server_port: u16, smoothed_rtt: Duration);

    /// Get the latest measured SRTT for a server endpoint.
    fn get(&self, server_name: &str, server_port: u16) -> Option<Duration>;

    /// Remove the measured SRTT for a server endpoint after a connection fails without a usable
    /// RTT sample.
    fn remove(&self, server_name: &str, server_port: u16);
}

/// Bounded in-memory [`ServerRttStore`].
///
/// The default capacity is 500 server endpoints.
/// A mutex is used because cache hits update LRU order, so lookups require exclusive access.
#[derive(Debug)]
pub struct ServerRttMemoryCache(Mutex<CacheState>);

impl ServerRttMemoryCache {
    /// Construct an empty cache for up to `max_server_endpoints` server endpoints.
    pub fn new(max_server_endpoints: u32) -> Self {
        Self(Mutex::new(CacheState {
            max_server_endpoints,
            lookup: HashMap::new(),
            lru: LruSlab::default(),
        }))
    }
}

impl ServerRttStore for ServerRttMemoryCache {
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
    fn remove(&self, server_name: &str, server_port: u16) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(server_name, server_port);
    }
}

impl Default for ServerRttMemoryCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SERVER_ENDPOINTS)
    }
}

#[derive(Debug)]
struct CacheState {
    max_server_endpoints: u32,
    // Maps a borrowed server name and port to the entry owned by `lru` without allocating on reads.
    lookup: HashMap<Arc<str>, HashMap<u16, u32>>,
    // Owns cache entries and updates their recency whenever `get_mut` is called.
    lru: LruSlab<CacheEntry>,
}

impl CacheState {
    fn insert(&mut self, server_name: &str, server_port: u16, rtt: Duration) {
        if self.max_server_endpoints == 0 {
            return;
        }

        if let Some(slab_key) = self
            .lookup
            .get(server_name)
            .and_then(|ports| ports.get(&server_port))
            .copied()
        {
            // Updating an existing endpoint also promotes it to most recently used.
            self.lru.get_mut(slab_key).rtt = rtt;
            return;
        }

        if self.lru.len() >= self.max_server_endpoints {
            let Some(slab_key) = self.lru.lru() else {
                return;
            };
            let evicted = self.lru.remove(slab_key);
            self.remove_lookup(&evicted.server_name, evicted.server_port);
        }

        let server_name = Arc::<str>::from(server_name);
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

    fn get(&mut self, server_name: &str, server_port: u16) -> Option<Duration> {
        let slab_key = self.lookup.get(server_name)?.get(&server_port).copied()?;
        Some(self.lru.get_mut(slab_key).rtt)
    }

    fn remove(&mut self, server_name: &str, server_port: u16) {
        if let Some(slab_key) = self.remove_lookup(server_name, server_port) {
            self.lru.remove(slab_key);
        }
    }

    /// Remove an endpoint from the lookup index while keeping sibling ports intact.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_keeps_latest_srtt_per_server_endpoint() {
        let cache = ServerRttMemoryCache::default();
        assert_eq!(cache.get("example.com", 443), None);

        cache.insert("example.com", 443, Duration::from_millis(20));
        cache.insert("example.com", 443, Duration::from_millis(30));

        assert_eq!(
            cache.get("example.com", 443),
            Some(Duration::from_millis(30))
        );
        assert_eq!(cache.get("example.com", 8443), None);
    }

    #[test]
    fn cache_evicts_least_recently_used_endpoint() {
        let cache = ServerRttMemoryCache::new(2);
        let rtt = Duration::from_millis(20);

        cache.insert("first.example", 443, rtt);
        cache.insert("second.example", 443, rtt);
        assert_eq!(cache.get("first.example", 443), Some(rtt));

        cache.insert("third.example", 443, rtt);

        assert_eq!(cache.get("first.example", 443), Some(rtt));
        assert_eq!(cache.get("second.example", 443), None);
        assert_eq!(cache.get("third.example", 443), Some(rtt));
    }

    #[test]
    fn zero_capacity_cache_stays_empty() {
        let cache = ServerRttMemoryCache::new(0);
        cache.insert("example.com", 443, Duration::from_millis(20));
        assert_eq!(cache.get("example.com", 443), None);
    }

    #[test]
    fn cache_removes_only_the_selected_endpoint() {
        let cache = ServerRttMemoryCache::default();
        let rtt = Duration::from_millis(20);
        cache.insert("example.com", 443, rtt);
        cache.insert("example.com", 8443, rtt);

        cache.remove("example.com", 443);
        cache.remove("example.com", 443);

        assert_eq!(cache.get("example.com", 443), None);
        assert_eq!(cache.get("example.com", 8443), Some(rtt));
    }
}
