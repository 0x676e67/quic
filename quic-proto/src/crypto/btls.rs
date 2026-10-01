mod aead;
mod alert;
mod alpn;
mod client;
mod error;
mod handshake_token;
mod hkdf;
mod hmac;
mod key;
mod macros;
mod retry;
mod secret;
mod server;
mod session_cache;
mod session_state;
mod suite;
mod version;

pub use client::{Config as QuicClientConfig, SessionSettings};
pub use error::{Error, Result};
pub use handshake_token::HandshakeTokenKey;
pub use hmac::HmacKey;
pub use server::Config as QuicServerConfig;
pub use session_cache::{NoSessionCache, SessionCache, SimpleCache};
use version::QuicVersion;
/// The wrapper of [SessionCache] values, which zeroes them on drop.
pub use zeroize::Zeroizing;

/// Authentication data for a btls TLS session.
#[derive(Clone, Debug)]
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use.
    pub protocol: Option<Vec<u8>>,

    /// The server name specified by the client, if any.
    ///
    /// Always `None` for outgoing connections.
    pub server_name: Option<String>,
}
