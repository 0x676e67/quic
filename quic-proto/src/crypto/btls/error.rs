use crate::{ConnectError, TransportError, crypto};
use btls::error::ErrorStack;
use std::ffi::c_int;
use std::fmt::{Debug, Display, Formatter};
use std::io::ErrorKind;
use std::result::Result as StdResult;
use std::{fmt, io};

// Error conversion:
pub enum Error {
    SslError(ErrorStack),
    IoError(io::Error),
    ConnectError(ConnectError),
    TransportError(TransportError),
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SslError(e) => Debug::fmt(&e, f),
            Self::IoError(e) => Debug::fmt(&e, f),
            Self::ConnectError(e) => Debug::fmt(&e, f),
            Self::TransportError(e) => Debug::fmt(&e, f),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SslError(e) => Display::fmt(&e, f),
            Self::IoError(e) => Display::fmt(&e, f),
            Self::ConnectError(e) => Display::fmt(&e, f),
            Self::TransportError(e) => Display::fmt(&e, f),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub(crate) fn ssl() -> Self {
        Self::SslError(ErrorStack::get())
    }

    pub(crate) fn invalid_input(msg: String) -> Self {
        Self::IoError(io::Error::new(ErrorKind::InvalidInput, msg))
    }

    pub(crate) fn other(msg: String) -> Self {
        Self::IoError(io::Error::other(msg))
    }
}

/// Support conversion to CryptoError.
impl From<Error> for crypto::CryptoError {
    fn from(_: Error) -> Self {
        Self
    }
}

/// Support conversion to ConnectError.
impl From<Error> for ConnectError {
    fn from(e: Error) -> Self {
        match e {
            Error::SslError(_) => Self::EndpointStopping,
            Error::IoError(_) => Self::EndpointStopping,
            Error::ConnectError(e) => e,
            Error::TransportError(_) => Self::EndpointStopping,
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Self::SslError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        Self::ConnectError(e)
    }
}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Self::TransportError(e)
    }
}

/// The main result type for this (crypto boring) module.
pub type Result<T> = StdResult<T, Error>;

/// The result returned by the Cloudflare Boring library API functions.
pub(crate) type BoringResult = StdResult<(), ErrorStack>;

/// Maps BoringSSL ffi return values to the Result type consistent with the Boring APIs.
pub(crate) fn br(bssl_result: c_int) -> BoringResult {
    match bssl_result {
        1 => Ok(()),
        _ => Err(ErrorStack::get()),
    }
}

pub(crate) fn br_zero_is_success(bssl_result: c_int) -> BoringResult {
    match bssl_result {
        0 => Ok(()),
        _ => Err(ErrorStack::get()),
    }
}

/// Maps BoringSSL ffi return values to a Result.
pub(crate) fn map_result(bssl_result: c_int) -> Result<()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(Error::SslError(ErrorStack::get())),
    }
}

/// Maps a result from a Rust callback to a BoringSSL result error code.
pub(crate) fn map_cb_result<T>(result: Result<T>) -> c_int {
    match result {
        Ok(_) => 1,
        _ => 0,
    }
}

/// Like map_result, but for BoringSSL method that break the standard return value convention.
pub(crate) fn map_result_zero_is_success(bssl_result: c_int) -> Result<()> {
    match bssl_result {
        0 => Ok(()),
        _ => Err(Error::SslError(ErrorStack::get())),
    }
}

/// Like map_result, but ensures that the resulting pointer is non-null.
pub(crate) fn map_ptr_result<T>(r: *mut T) -> Result<*mut T> {
    if r.is_null() {
        Err(Error::ssl())
    } else {
        Ok(r)
    }
}
