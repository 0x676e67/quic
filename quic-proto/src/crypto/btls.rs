mod aead;
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

use btls::ssl::{EarlyDataReason, SslSignatureAlgorithm};
pub use client::QuicClientConfig;
pub use error::{Error, Result};
pub use handshake_token::HandshakeTokenKey;
pub use hmac::HmacKey;
pub use server::QuicServerConfig;
pub use session_cache::{NoSessionCache, SessionCache, SimpleCache};
use version::QuicVersion;
/// The wrapper of [SessionCache] values, which zeroes them on drop.
pub use zeroize::Zeroizing;

/// What the TLS handshake of a btls session negotiated.
///
/// Each value is read from BoringSSL when [`handshake_data`](crate::crypto::Session::handshake_data)
/// is called, so those that later handshake messages decide, such as the peer's signature
/// algorithm, are only set once the connection is established. For anything else, the info
/// callback of the [`SslContextBuilder`](btls::ssl::SslContextBuilder) sees the
/// [`SslRef`](btls::ssl::SslRef) when the handshake is done.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use.
    pub protocol: Option<Vec<u8>>,

    /// The server name specified by the client, if any.
    ///
    /// Always `None` for outgoing connections.
    pub server_name: Option<String>,

    /// The cipher suite, by its IANA number.
    pub cipher_suite: Option<u16>,

    /// The key exchange group, by its IANA number.
    pub group: Option<u16>,

    /// The algorithm of the peer's CertificateVerify signature, if the peer authenticated with
    /// a certificate. A resumed session keeps the one of the handshake that established it.
    pub peer_signature_algorithm: Option<SslSignatureAlgorithm>,

    /// Whether the handshake resumed a session.
    pub resumed: bool,

    /// Why 0-RTT was or was not used.
    pub early_data_reason: EarlyDataReason,

    /// Whether the server accepted Encrypted Client Hello.
    pub ech_accepted: bool,

    /// The settings that the peer sent with ALPS for the negotiated protocol, if both peers
    /// enabled it with [`SslRef::add_application_settings`](btls::ssl::SslRef::add_application_settings).
    pub peer_application_settings: Option<Vec<u8>>,
}
