use crate::{TransportError, TransportErrorCode};
use btls::ssl::SslAlert;

/// Returns the QUIC error code that carries a TLS alert
/// (<https://www.rfc-editor.org/rfc/rfc9001#section-4.8>).
pub(crate) fn alert_code(alert: SslAlert) -> TransportErrorCode {
    // Alert descriptions are single bytes on the wire.
    TransportErrorCode::crypto(alert.as_raw() as u8)
}

impl From<SslAlert> for TransportError {
    fn from(alert: SslAlert) -> Self {
        Self::new(alert_code(alert), alert.description().to_owned())
    }
}
