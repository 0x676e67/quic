use crate::crypto::btls::Error;
use crate::crypto::btls::error::Result;
use crate::{Side, transport_parameters::TransportParameters};
use btls::ssl::SslSession;
use bytes::{Buf, BufMut, Bytes};
use lru::LruCache;
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// A client-side session cache for the btls crypto provider.
///
/// Keys are opaque: they combine the server name with the configuration that cached the session,
/// so a cache shared between configurations only resumes a session with the one that verified it.
/// They are meaningless to another process.
///
/// Values are encoded sessions, which hold resumption secrets. A session resumes at most one
/// connection ([RFC 8446 §C.4](https://www.rfc-editor.org/rfc/rfc8446#appendix-C.4)), so
/// [`SessionCache::take`] removes the value it returns.
pub trait SessionCache: Send + Sync {
    /// Adds a session for `key`, next to the ones already cached for it.
    fn put(&self, key: Bytes, value: Zeroizing<Vec<u8>>);

    /// Removes and returns a session for `key`, preferably the newest.
    fn take(&self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>>;

    /// Removes all sessions for `key`.
    fn remove(&self, key: &[u8]);

    /// Removes all sessions.
    fn clear(&self);
}

/// An [SslSession] with the server [TransportParameters] that 0-RTT needs, as a [SessionCache]
/// value.
pub(crate) struct Entry {
    pub(crate) session: SslSession,
    pub(crate) params: TransportParameters,
}

impl Entry {
    /// Encodes the session and the parameters, each with a `u64` length prefix.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let session = Zeroizing::new(self.session.to_der()?);
        let mut params = Vec::new();
        self.params.write(&mut params);

        // Sized up front, so that no copy of the session is left behind by a reallocation.
        let len = 2 * size_of::<u64>() + session.len() + params.len();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.put_u64(session.len() as u64);
        out.put_slice(&session);
        out.put_u64(params.len() as u64);
        out.put_slice(&params);
        Ok(out)
    }

    /// Decodes a value of [Entry::encode].
    pub(crate) fn decode(mut encoded: &[u8]) -> Result<Self> {
        let session = SslSession::from_der(split_len_prefixed(&mut encoded)?)?;
        let mut params = split_len_prefixed(&mut encoded)?;
        let params = TransportParameters::read(Side::Client, &mut params).map_err(|e| {
            Error::invalid_input(format!("failed parsing cached transport parameters: {e:?}"))
        })?;
        Ok(Self { session, params })
    }
}

/// Splits off a value that [Entry::encode] wrote with a `u64` length prefix.
fn split_len_prefixed<'a>(encoded: &mut &'a [u8]) -> Result<&'a [u8]> {
    let truncated = || Error::invalid_input("truncated session cache entry".into());
    if encoded.remaining() < size_of::<u64>() {
        return Err(truncated());
    }
    let len = usize::try_from(encoded.get_u64()).map_err(|_| truncated())?;
    if len > encoded.len() {
        return Err(truncated());
    }
    let (value, rest) = encoded.split_at(len);
    *encoded = rest;
    Ok(value)
}

/// A [SessionCache] that never caches anything.
pub struct NoSessionCache;

impl SessionCache for NoSessionCache {
    fn put(&self, _: Bytes, _: Zeroizing<Vec<u8>>) {}

    fn take(&self, _: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        None
    }

    fn remove(&self, _: &[u8]) {}

    fn clear(&self) {}
}

/// A [SessionCache] that keeps the two newest sessions of each of its most recently used
/// servers, since a server issues two per connection.
pub struct SimpleCache {
    cache: Mutex<LruCache<Bytes, VecDeque<Zeroizing<Vec<u8>>>>>,
}

impl SimpleCache {
    /// The sessions kept per server.
    const SESSIONS_PER_SERVER: usize = 2;

    /// Creates a cache for the sessions of up to `num_servers` servers.
    pub fn new(num_servers: NonZeroUsize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(num_servers)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, LruCache<Bytes, VecDeque<Zeroizing<Vec<u8>>>>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SessionCache for SimpleCache {
    fn put(&self, key: Bytes, value: Zeroizing<Vec<u8>>) {
        let mut cache = self.lock();
        let sessions = cache.get_or_insert_mut(key, VecDeque::new);
        if sessions.len() == Self::SESSIONS_PER_SERVER {
            sessions.pop_front();
        }
        sessions.push_back(value);
    }

    fn take(&self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let mut cache = self.lock();
        let sessions = cache.get_mut(key)?;
        let value = sessions.pop_back();
        if sessions.is_empty() {
            cache.pop(key);
        }
        value
    }

    fn remove(&self, key: &[u8]) {
        self.lock().pop(key);
    }

    fn clear(&self) {
        self.lock().clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_truncated_entry() {
        for encoded in [
            &[][..],
            &[0, 0, 0, 0],
            // A session length longer than the rest of the entry.
            &[0, 0, 0, 0, 0, 0, 0, 3, 1, 2],
            &u64::MAX.to_be_bytes(),
        ] {
            assert!(Entry::decode(encoded).is_err(), "{encoded:?}");
        }
    }

    #[test]
    fn simple_cache_hands_out_each_session_once() {
        let cache = SimpleCache::new(NonZeroUsize::MIN);
        let value = |v: u8| Zeroizing::new(vec![v]);
        let take = |key: &[u8]| cache.take(key).map(|v| v[0]);

        // The newest two sessions of a server are kept, and each is taken once, newest first.
        for v in 1..=3 {
            cache.put(Bytes::from_static(b"a"), value(v));
        }
        assert_eq!(take(b"a"), Some(3));
        assert_eq!(take(b"a"), Some(2));
        assert_eq!(take(b"a"), None);

        // Another server evicts the least recently used one.
        cache.put(Bytes::from_static(b"a"), value(1));
        cache.put(Bytes::from_static(b"b"), value(2));
        assert_eq!(take(b"a"), None);
        assert_eq!(take(b"b"), Some(2));
    }
}
