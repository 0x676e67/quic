use crate::crypto::btls::error::{BoringResult, br};
use btls::error::ErrorStack;
use btls::ssl::{SslContextBuilder, SslContextRef, SslRef, SslSession, SslVerifyMode};
use btls_sys as bffi;
use bytes::{Buf, BufMut};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use std::ffi::{CStr, c_int};
use std::fmt::{Display, Formatter};
use std::result::Result as StdResult;
use std::{fmt, ptr, slice};

/// The QUIC settings of an [SslContextBuilder] that btls has no safe API for yet.
pub(crate) trait QuicSslContextBuilder {
    /// Installs the QUIC callbacks, which BoringSSL keeps a pointer to.
    fn set_quic_method(&mut self, method: &'static bffi::SSL_QUIC_METHOD) -> BoringResult;
    fn set_early_data_enabled(&mut self, enabled: bool);
    fn verify_mode(&self) -> SslVerifyMode;
}

impl QuicSslContextBuilder for SslContextBuilder {
    fn set_quic_method(&mut self, method: &'static bffi::SSL_QUIC_METHOD) -> BoringResult {
        unsafe { br(bffi::SSL_CTX_set_quic_method(self.as_ptr(), method)) }
    }

    fn set_early_data_enabled(&mut self, enabled: bool) {
        unsafe { bffi::SSL_CTX_set_early_data_enabled(self.as_ptr(), enabled.into()) }
    }

    fn verify_mode(&self) -> SslVerifyMode {
        SslVerifyMode::from_bits_retain(unsafe { bffi::SSL_CTX_get_verify_mode(self.as_ptr()) })
    }
}

/// Provides additional methods to [SslRef] needed for QUIC.
pub trait QuicSsl {
    fn set_connect_state(&mut self);
    fn set_accept_state(&mut self);
    fn set_quic_transport_params(&mut self, params: &[u8]) -> BoringResult;
    fn get_peer_quic_transport_params(&self) -> Option<&[u8]>;
    fn get_error(&self, raw: c_int) -> SslError;
    fn is_handshaking(&self) -> bool;
    fn do_handshake(&mut self) -> SslError;
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> SslError;
    fn quic_max_handshake_flight_len(&self, level: Level) -> usize;
    fn quic_read_level(&self) -> Level;
    fn quic_write_level(&self) -> Level;
    fn process_post_handshake(&mut self) -> SslError;
    fn set_verify_hostname(&mut self, domain: &str) -> BoringResult;

    fn in_early_data(&self) -> bool;
    fn early_data_accepted(&self) -> bool;
    fn set_quic_method(&mut self, method: &'static bffi::SSL_QUIC_METHOD) -> BoringResult;
    fn set_quic_early_data_context(&mut self, value: &[u8]) -> BoringResult;
    fn get_early_data_reason(&self) -> bffi::ssl_early_data_reason_t;
    fn early_data_reason_string(reason: bffi::ssl_early_data_reason_t) -> &'static str;
    fn reset_early_rejected_data(&mut self);
    fn set_quic_use_legacy_codepoint(&mut self, use_legacy: bool);
}

impl QuicSsl for SslRef {
    fn set_connect_state(&mut self) {
        unsafe { bffi::SSL_set_connect_state(self.as_ptr()) }
    }

    fn set_accept_state(&mut self) {
        unsafe { bffi::SSL_set_accept_state(self.as_ptr()) }
    }

    fn set_quic_transport_params(&mut self, params: &[u8]) -> BoringResult {
        unsafe {
            br(bffi::SSL_set_quic_transport_params(
                self.as_ptr(),
                params.as_ptr(),
                params.len(),
            ))
        }
    }

    fn get_peer_quic_transport_params(&self) -> Option<&[u8]> {
        let mut ptr: *const u8 = ptr::null();
        let mut len: usize = 0;

        unsafe {
            bffi::SSL_get_peer_quic_transport_params(self.as_ptr(), &mut ptr, &mut len);

            if len == 0 {
                None
            } else {
                Some(slice::from_raw_parts(ptr, len))
            }
        }
    }

    #[inline]
    fn get_error(&self, raw: c_int) -> SslError {
        unsafe { SslError(bffi::SSL_get_error(self.as_ptr(), raw)) }
    }

    #[inline]
    fn is_handshaking(&self) -> bool {
        unsafe { bffi::SSL_in_init(self.as_ptr()) == 1 }
    }

    #[inline]
    fn do_handshake(&mut self) -> SslError {
        self.get_error(unsafe { bffi::SSL_do_handshake(self.as_ptr()) })
    }

    #[inline]
    fn provide_quic_data(&mut self, level: Level, plaintext: &[u8]) -> SslError {
        unsafe {
            self.get_error(bffi::SSL_provide_quic_data(
                self.as_ptr(),
                level.into(),
                plaintext.as_ptr(),
                plaintext.len(),
            ))
        }
    }

    #[inline]
    fn quic_max_handshake_flight_len(&self, level: Level) -> usize {
        unsafe { bffi::SSL_quic_max_handshake_flight_len(self.as_ptr(), level.into()) }
    }

    #[inline]
    fn quic_read_level(&self) -> Level {
        unsafe { bffi::SSL_quic_read_level(self.as_ptr()).into() }
    }

    #[inline]
    fn quic_write_level(&self) -> Level {
        unsafe { bffi::SSL_quic_write_level(self.as_ptr()).into() }
    }

    #[inline]
    fn process_post_handshake(&mut self) -> SslError {
        self.get_error(unsafe { bffi::SSL_process_quic_post_handshake(self.as_ptr()) })
    }

    fn set_verify_hostname(&mut self, domain: &str) -> BoringResult {
        let param = self.param_mut();
        param.set_hostflags(btls::x509::verify::X509CheckFlags::NO_PARTIAL_WILDCARDS);
        match domain.parse() {
            Ok(ip) => param.set_ip(ip)?,
            Err(_) => param.set_host(domain)?,
        }
        Ok(())
    }

    #[inline]
    fn in_early_data(&self) -> bool {
        unsafe { bffi::SSL_in_early_data(self.as_ptr()) == 1 }
    }

    #[inline]
    fn early_data_accepted(&self) -> bool {
        unsafe { bffi::SSL_early_data_accepted(self.as_ptr()) == 1 }
    }

    fn set_quic_method(&mut self, method: &'static bffi::SSL_QUIC_METHOD) -> BoringResult {
        unsafe { br(bffi::SSL_set_quic_method(self.as_ptr(), method)) }
    }

    fn set_quic_early_data_context(&mut self, value: &[u8]) -> BoringResult {
        unsafe {
            br(bffi::SSL_set_quic_early_data_context(
                self.as_ptr(),
                value.as_ptr(),
                value.len(),
            ))
        }
    }

    fn get_early_data_reason(&self) -> bffi::ssl_early_data_reason_t {
        unsafe { bffi::SSL_get_early_data_reason(self.as_ptr()) }
    }

    fn early_data_reason_string(reason: bffi::ssl_early_data_reason_t) -> &'static str {
        unsafe {
            bffi::SSL_early_data_reason_string(reason)
                .as_ref()
                .map_or("unknown", |reason| CStr::from_ptr(reason).to_str().unwrap())
        }
    }

    #[inline]
    fn reset_early_rejected_data(&mut self) {
        unsafe { bffi::SSL_reset_early_data_reject(self.as_ptr()) }
    }

    fn set_quic_use_legacy_codepoint(&mut self, use_legacy: bool) {
        unsafe { bffi::SSL_set_quic_use_legacy_codepoint(self.as_ptr(), use_legacy as _) }
    }
}

pub trait QuicSslSession {
    fn early_data_capable(&self) -> bool;
    fn copy_without_early_data(&mut self) -> SslSession;
    fn encode<W: BufMut>(&self, out: &mut W) -> BoringResult;
    fn decode<R: Buf>(ctx: &SslContextRef, r: &mut R) -> StdResult<SslSession, ErrorStack>;
}

impl QuicSslSession for SslSession {
    fn early_data_capable(&self) -> bool {
        unsafe { bffi::SSL_SESSION_early_data_capable(self.as_ptr()) == 1 }
    }

    fn copy_without_early_data(&mut self) -> SslSession {
        unsafe { Self::from_ptr(bffi::SSL_SESSION_copy_without_early_data(self.as_ptr())) }
    }

    fn encode<W: BufMut>(&self, out: &mut W) -> BoringResult {
        unsafe {
            let mut buf: *mut u8 = ptr::null_mut();
            let mut len = 0usize;
            br(bffi::SSL_SESSION_to_bytes(
                self.as_ptr(),
                &mut buf,
                &mut len,
            ))?;
            out.put_slice(slice::from_raw_parts(buf, len));
            bffi::OPENSSL_free(buf as _);
            Ok(())
        }
    }

    fn decode<R: Buf>(ctx: &SslContextRef, r: &mut R) -> StdResult<SslSession, ErrorStack> {
        unsafe {
            let in_len = r.remaining();
            let in_ = r.chunk();
            bffi::SSL_SESSION_from_bytes(in_.as_ptr(), in_len, ctx.as_ptr())
                .as_mut()
                .map_or_else(
                    || Err(ErrorStack::get()),
                    |session| Ok(Self::from_ptr(session)),
                )
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Level {
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    Application = 3,
}

impl Level {
    pub const NUM_LEVELS: usize = 4;

    pub fn next(&self) -> Self {
        match self {
            Self::Initial => Self::Handshake,
            Self::EarlyData => Self::Handshake,
            _ => Self::Application,
        }
    }
}

impl From<bffi::ssl_encryption_level_t> for Level {
    fn from(value: bffi::ssl_encryption_level_t) -> Self {
        match value {
            bffi::ssl_encryption_level_t::ssl_encryption_initial => Self::Initial,
            bffi::ssl_encryption_level_t::ssl_encryption_early_data => Self::EarlyData,
            bffi::ssl_encryption_level_t::ssl_encryption_handshake => Self::Handshake,
            bffi::ssl_encryption_level_t::ssl_encryption_application => Self::Application,
            _ => unreachable!(),
        }
    }
}

impl From<Level> for bffi::ssl_encryption_level_t {
    fn from(value: Level) -> Self {
        match value {
            Level::Initial => Self::ssl_encryption_initial,
            Level::EarlyData => Self::ssl_encryption_early_data,
            Level::Handshake => Self::ssl_encryption_handshake,
            Level::Application => Self::ssl_encryption_application,
        }
    }
}

#[derive(Copy, Clone)]
pub struct SslError(c_int);

impl SslError {
    #[inline]
    pub fn value(&self) -> c_int {
        self.0
    }

    #[inline]
    pub fn is_none(&self) -> bool {
        self.0 == bffi::SSL_ERROR_NONE
    }

    #[inline]
    pub fn get_description(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(bffi::SSL_error_description(self.0))
                .to_str()
                .unwrap()
        }
    }
}

impl Display for SslError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SSL_ERROR[{}]: {}", self.0, self.get_description())
    }
}
