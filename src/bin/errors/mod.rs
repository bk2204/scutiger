#![allow(unknown_lints)]
#![allow(bare_trait_objects)]

use std::convert;
use std::error;
use std::fmt;
use std::io;

use git2;
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
    GitError,
    PCREError,
    IOError,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    internal: Option<Box<error::Error + Send + Sync>>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            // Despite the text, this is not a fatal error in our sense. For compatibility with
            // Git, however, we choose to preserve the same wording.
            ErrorKind::NoSuchRevision => write!(f, "fatal: needed a single revision"),
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
        }
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
            internal: match error {
                Some(e) => Some(e.into()),
                None => None,
            },
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
            _ => ExitStatus::Fatal,
        }
    }
}

impl convert::From<git2::Error> for Error {
    fn from(error: git2::Error) -> Self {
        let kind = match error.code() {
            git2::ErrorCode::NotFound => ErrorKind::NoSuchRevision,
            _ => ErrorKind::GitError,
        };
        Error::new(kind, Some(error))
    }
}

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
