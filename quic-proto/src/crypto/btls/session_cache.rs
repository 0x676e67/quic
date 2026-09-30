use crate::crypto::btls::Error;
use crate::crypto::btls::error::Result;
use crate::{Side, transport_parameters::TransportParameters};
use btls::ssl::SslSession;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// A client-side Session cache for the BoringSSL crypto provider.
pub trait SessionCache: Send + Sync {
    /// Adds the given value to the session cache.
    fn put(&self, key: Bytes, value: Bytes);

    /// Returns the cached session, if it exists.
    fn get(&self, key: Bytes) -> Option<Bytes>;

    /// Removes the cached session, if it exists.
    fn remove(&self, key: Bytes);

    /// Removes all entries from the cache.
    fn clear(&self);
}

/// A utility for combining an [SslSession] and server [TransportParameters] as a
/// [SessionCache] entry.
pub struct Entry {
    pub session: SslSession,
    pub params: TransportParameters,
}

impl Entry {
    /// Encodes this [Entry] into a [SessionCache] value.
    pub fn encode(&self) -> Result<Bytes> {
        let mut out = BytesMut::with_capacity(2048);

        // Split the buffer in two: the length prefix buffer and the encoded session buffer.
        // This will be O(1) as both will refer to the same underlying buffer.
        let mut encoded = out.split_off(8);

        // Store the session in the second buffer.
        encoded.put_slice(&self.session.to_der()?);

        // Go back and write the length to the first buffer.
        out.put_u64(encoded.len() as u64);

        // Unsplit to merge the two buffers back together. This will be O(1) since
        // the buffers are already contiguous in memory.
        out.unsplit(encoded);

        // Now add the transport parameters.
        out.reserve(128);
        let mut encoded = out.split_off(out.len() + 8);
        self.params.write(&mut encoded);
        out.put_u64(encoded.len() as u64);
        out.unsplit(encoded);

        Ok(out.freeze())
    }

    /// Decodes a [SessionCache] value into an [Entry].
    pub fn decode(mut encoded: Bytes) -> Result<Self> {
        // Decode the session.
        let encoded_session = split_len_prefixed(&mut encoded)?;
        let session = SslSession::from_der(&encoded_session)?;

        // Decode the transport parameters.
        let mut encoded_params = split_len_prefixed(&mut encoded)?;
        let params = TransportParameters::read(Side::Client, &mut encoded_params).map_err(|e| {
            Error::invalid_input(format!("failed parsing cached transport parameters: {e:?}"))
        })?;

        Ok(Self { session, params })
    }
}

/// Splits off a value that [Entry::encode] wrote with a `u64` length prefix.
fn split_len_prefixed(encoded: &mut Bytes) -> Result<Bytes> {
    let truncated = || Error::invalid_input("truncated session cache entry".into());
    if encoded.remaining() < size_of::<u64>() {
        return Err(truncated());
    }
    let len = usize::try_from(encoded.get_u64()).map_err(|_| truncated())?;
    if len > encoded.remaining() {
        return Err(truncated());
    }
    Ok(encoded.split_to(len))
}

/// A [SessionCache] implementation that will never cache anything. Requires no storage.
pub struct NoSessionCache;

impl SessionCache for NoSessionCache {
    fn put(&self, _: Bytes, _: Bytes) {}

    fn get(&self, _: Bytes) -> Option<Bytes> {
        None
    }

    fn remove(&self, _: Bytes) {}

    fn clear(&self) {}
}

pub struct SimpleCache {
    cache: Mutex<LruCache<Bytes, Bytes>>,
}

impl SimpleCache {
    pub fn new(num_entries: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(num_entries).unwrap())),
        }
    }
}

impl SessionCache for SimpleCache {
    fn put(&self, key: Bytes, value: Bytes) {
        let _ = self.cache.lock().unwrap().put(key, value);
    }

    fn get(&self, key: Bytes) -> Option<Bytes> {
        self.cache.lock().unwrap().get(&key).cloned()
    }

    fn remove(&self, key: Bytes) {
        let _ = self.cache.lock().unwrap().pop(&key);
    }

    fn clear(&self) {
        self.cache.lock().unwrap().clear()
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
            let result = Entry::decode(Bytes::copy_from_slice(encoded));
            assert!(result.is_err(), "{encoded:?}");
        }
    }
}
