#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![allow(clippy::upper_case_acronyms)]

use std::convert;
use std::error;
use std::fmt;
use std::io;

use git2;
#[cfg(feature = "pcre")]
use pcre2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Success = 0,
    NonFatal = 1,
    Fatal = 2,
    ExternalProgramFailed = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NoSuchRevision,
    Conflict,
    GitError,
    PCREError,
    IOError,
    BadPktlineHeader,
    InvalidPacket,
    UnexpectedPacket,
    InvalidLFSOid,
    InvalidInteger,
    ParseError,
    UnknownCommand,
    MissingData,
    ExtraData,
    CorruptData,
    NotAllowed,
    InvalidPath,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    internal: Option<Box<error::Error + Send + Sync>>,
    message: Option<String>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            // Despite the text, this is not a fatal error in our sense. For compatibility with
            // Git, however, we choose to preserve the same wording.
            ErrorKind::NoSuchRevision => write!(f, "fatal: needed a single revision"),
            ErrorKind::Conflict => write!(f, "fatal: conflict"),
            ErrorKind::PCREError => match self.internal {
                Some(ref e) => write!(f, "fatal: invalid regular expression: {}", e),
                None => write!(f, "fatal: invalid regular expression"),
            },
            ErrorKind::IOError => match self.internal {
                Some(ref e) => write!(f, "fatal: I/O error: {}", e),
                None => write!(f, "fatal: unknown I/O error"),
            },
            ErrorKind::GitError => match self.internal {
                Some(ref e) => write!(f, "fatal: {}", e),
                None => write!(f, "fatal: an unknown error occurred"),
            },
            ErrorKind::BadPktlineHeader => write!(f, "malformed or unknown pkt-line header"),
            ErrorKind::InvalidPacket => write!(f, "invalid or malformed packet"),
            ErrorKind::UnexpectedPacket => write!(f, "unexpected packet while parsing"),
            ErrorKind::InvalidLFSOid => write!(f, "invalid or malformed LFS oid"),
            ErrorKind::InvalidInteger => write!(f, "invalid or malformed integer or size value"),
            ErrorKind::ParseError => write!(f, "parse error"),
            ErrorKind::UnknownCommand => write!(f, "unknown command or operation"),
            ErrorKind::MissingData => write!(f, "incomplete or missing data"),
            ErrorKind::ExtraData => write!(f, "extra data"),
            ErrorKind::CorruptData => write!(f, "corrupt data"),
            ErrorKind::NotAllowed => write!(f, "not allowed"),
            ErrorKind::InvalidPath => write!(f, "invalid path"),
        }?;
        if let Some(ref msg) = self.message {
            write!(f, ": {}", msg)?;
        };
        Ok(())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "an unknown error"
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl Error {
    /// Create a new error.
    ///
    /// If this error was caused by another error, specify it as `Some(error)`.
    pub fn new<E: Into<Box<error::Error + Send + Sync>>>(
        kind: ErrorKind,
        error: Option<E>,
    ) -> Self {
        Error {
            kind,
            internal: error.map(|e| e.into()),
            message: None,
        }
    }

    /// Create a new error without wrapping any other error.
    pub fn new_simple(kind: ErrorKind) -> Self {
        Error {
            kind,
            internal: None,
            message: None,
        }
    }

    /// Create a new error without wrapping any other error.
    pub fn from_message<M: Into<String>>(kind: ErrorKind, msg: M) -> Self {
        Error {
            kind,
            internal: None,
            message: Some(msg.into()),
        }
    }

    /// Return the kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Return the kind of this error when converted into an `io::Error`.
    ///
    /// If the internal error is an `io::Error`, returns its kind; otherwise, returns the kind it
    /// would have if it were converted into an `io::Error`.
    pub fn io_kind(&self) -> io::ErrorKind {
        match self.internal {
            Some(ref e) => match e.downcast_ref::<io::Error>() {
                Some(x) => x.kind(),
                None => io::ErrorKind::InvalidData,
            },
            None => io::ErrorKind::InvalidData,
        }
    }

    /// Indicate whether this error is considered fatal.
    ///
    /// An error is fatal if it results in an exit of 2 or higher. A missing revision is not
    /// considered fatal, but other errors are.
    pub fn fatal(&self) -> bool {
        self.exit_status() == ExitStatus::Fatal
    }

    /// Return the exit status for this error.
    pub fn exit_status(&self) -> ExitStatus {
        match self.kind {
            ErrorKind::NoSuchRevision => ExitStatus::NonFatal,
            ErrorKind::Conflict => ExitStatus::NonFatal,
            _ => ExitStatus::Fatal,
        }
    }
}

impl convert::From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        io::Error::new(error.io_kind(), error)
    }
}

impl convert::From<git2::Error> for Error {
    fn from(error: git2::Error) -> Self {
        let kind = match error.code() {
            git2::ErrorCode::NotFound => ErrorKind::NoSuchRevision,
            git2::ErrorCode::Conflict => ErrorKind::Conflict,
            _ => ErrorKind::GitError,
        };
        Error::new(kind, Some(error))
    }
}

#[cfg(feature = "pcre")]
impl convert::From<pcre2::Error> for Error {
    fn from(error: pcre2::Error) -> Self {
        Error::new(ErrorKind::PCREError, Some(error))
    }
}

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::new(ErrorKind::IOError, Some(error))
    }
}
