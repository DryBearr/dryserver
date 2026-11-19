//! Cancellation for long-running work: a shared flag plus an optional
//! deadline. Background jobs check it between steps and while sleeping;
//! running commands are killed when it fires.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::err::{Error, Result};

#[derive(Clone, Default)]
pub struct Ctx {
    flag: Arc<AtomicBool>,
    deadline: Option<Instant>,
}

impl Ctx {
    /// A context that is only cancelled by calling cancel.
    pub fn new() -> Self {
        Ctx::default()
    }

    /// A context cancelled by SIGINT or SIGTERM.
    pub fn on_signals() -> Self {
        let ctx = Ctx::new();
        for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            let _ = signal_hook::flag::register(sig, ctx.flag.clone());
        }
        ctx
    }

    /// The same cancellation, with a deadline at most d away.
    pub fn with_timeout(&self, d: Duration) -> Ctx {
        let at = Instant::now() + d;
        let deadline = Some(match self.deadline {
            Some(cur) if cur < at => cur,
            _ => at,
        });
        Ctx { flag: self.flag.clone(), deadline }
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Why the context is done, or None while it is not.
    pub fn err(&self) -> Option<Error> {
        if self.flag.load(Ordering::SeqCst) {
            return Some(Error::canceled());
        }
        match self.deadline {
            Some(d) if Instant::now() >= d => Some(Error::deadline()),
            _ => None,
        }
    }

    pub fn done(&self) -> bool {
        self.err().is_some()
    }

    pub fn check(&self) -> Result<()> {
        match self.err() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Sleeps for d, returning early with the context's error when it is done.
    pub fn sleep(&self, d: Duration) -> Result<()> {
        let end = Instant::now() + d;
        loop {
            self.check()?;
            let now = Instant::now();
            if now >= end {
                return Ok(());
            }
            std::thread::sleep((end - now).min(Duration::from_millis(50)));
        }
    }
}
