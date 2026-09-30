use crate::{ConnectError, crypto};
use btls::error::ErrorStack;
use std::fmt::{Debug, Display, Formatter};
use std::io::ErrorKind;
use std::result::Result as StdResult;
use std::{fmt, io};

/// An error of the btls crypto provider.
pub enum Error {
    /// A BoringSSL error.
    SslError(ErrorStack),
    /// An invalid argument, or another failure outside BoringSSL.
    IoError(io::Error),
    /// A failure to start a connection, such as an invalid server name.
    ConnectError(ConnectError),
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SslError(e) => Debug::fmt(&e, f),
            Self::IoError(e) => Debug::fmt(&e, f),
            Self::ConnectError(e) => Debug::fmt(&e, f),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SslError(e) => Display::fmt(&e, f),
            Self::IoError(e) => Display::fmt(&e, f),
            Self::ConnectError(e) => Display::fmt(&e, f),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
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

/// Keeps a [ConnectError], and reports any other failure to start a connection as
/// [`ConnectError::EndpointStopping`].
impl From<Error> for ConnectError {
    fn from(e: Error) -> Self {
        match e {
            Error::ConnectError(e) => e,
            Error::SslError(_) | Error::IoError(_) => Self::EndpointStopping,
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

/// The main result type for this (crypto boring) module.
pub type Result<T> = StdResult<T, Error>;
