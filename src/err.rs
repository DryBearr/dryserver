//! A small error type: a message plus a kind that callers can test for
//! (cancelled, missing file, rejected join...). Wrapping adds a prefix to
//! the message and keeps the kind.

use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Other,
    Canceled,
    DeadlineExceeded,
    NotFound,
    Rejected,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Error {
    kind: Kind,
    msg: String,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Error { kind: Kind::Other, msg: msg.into() }
    }

    pub fn with_kind(kind: Kind, msg: impl Into<String>) -> Self {
        Error { kind, msg: msg.into() }
    }

    pub fn canceled() -> Self {
        Error::with_kind(Kind::Canceled, "context canceled")
    }

    pub fn deadline() -> Self {
        Error::with_kind(Kind::DeadlineExceeded, "context deadline exceeded")
    }

    pub fn is(&self, kind: Kind) -> bool {
        self.kind == kind
    }

    pub fn is_canceled(&self) -> bool {
        self.kind == Kind::Canceled
    }

    pub fn is_not_found(&self) -> bool {
        self.kind == Kind::NotFound
    }

    /// Prefixes the message: "prefix: message".
    pub fn wrap(self, prefix: impl fmt::Display) -> Self {
        Error { kind: self.kind, msg: format!("{prefix}: {}", self.msg) }
    }

    /// Joins several errors into one, one message per line. None when the
    /// list is empty.
    pub fn join(errs: Vec<Error>) -> Option<Error> {
        if errs.is_empty() {
            return None;
        }
        let kind = errs[0].kind;
        let msg = errs.iter().map(|e| e.msg.as_str()).collect::<Vec<_>>().join("\n");
        Some(Error { kind, msg })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        let kind = if e.kind() == io::ErrorKind::NotFound { Kind::NotFound } else { Kind::Other };
        Error { kind, msg: os_msg(&e) }
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::new(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::new(s)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::new(e.to_string())
    }
}

/// The OS message of an I/O error in lower case, without "(os error N)".
pub fn os_msg(e: &io::Error) -> String {
    let s = e.to_string();
    let s = match s.find(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    };
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_lowercase().collect::<String>() + c.as_str(),
        None => s,
    }
}

/// Adds a prefix to the error of a result.
pub trait Context<T> {
    fn wrap(self, prefix: impl fmt::Display) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E> {
    fn wrap(self, prefix: impl fmt::Display) -> Result<T> {
        self.map_err(|e| e.into().wrap(prefix))
    }
}

#[macro_export]
macro_rules! errf {
    ($($t:tt)*) => { $crate::err::Error::new(format!($($t)*)) };
}

#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => { return Err($crate::errf!($($t)*)) };
}
