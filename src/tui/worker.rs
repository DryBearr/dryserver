//! A screen's slow work on a thread of its own: SSH to the coordinator,
//! HTTPS to Cloudflare. The screen keeps drawing and taking keys while a
//! job runs, and learns the result from a message.
//!
//! Jobs run one at a time, in the order sent: two calls to the
//! coordinator never race each other, and a change asked for during a
//! refresh simply waits for it. Every job gets the worker's Ctx, which the
//! job narrows to its own time limit.
//!
//! Closing the screen drops the worker: the running job is cancelled
//! (its ssh or curl is killed), the jobs still waiting are skipped, and
//! the drop waits a moment for the thread to end. A result that still
//! arrives goes to a closed channel and is dropped there.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::{Doc, dim, err, sel, spinner, theme};
use crate::ctx::Ctx;
use crate::err::{Error, Kind};

/// How long the other side may take to answer.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// A question: the cluster's listing.
    pub read: Duration,
    /// A change: kubectl apply waits for the cluster to take it; a sync
    /// with Cloudflare is a few dozen small requests.
    pub change: Duration,
    /// After this long without an answer the screen says so.
    pub slow: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { read: Duration::from_secs(15), change: Duration::from_secs(60), slow: Duration::from_secs(4) }
    }
}

/// A call that ran out of time says how long it was given.
pub fn timed(e: Error, limit: Duration) -> Error {
    if e.is(Kind::DeadlineExceeded) {
        Error::with_kind(Kind::DeadlineExceeded, format!("the coordinator did not answer within {}s. Is it on?", limit.as_secs()))
    } else {
        e
    }
}

/// What a screen sent its worker and has not heard back about, in the
/// order sent. Each job answers with exactly one message, so the oldest
/// entry is the one that runs.
#[derive(Default)]
pub struct Waiting {
    jobs: VecDeque<Job>,
    /// When the oldest job started.
    since: Option<Instant>,
}

struct Job {
    /// What it does, for the screen: "asking the coordinator".
    label: String,
    /// It changes something (a refresh does not).
    change: bool,
}

impl Waiting {
    pub fn push(&mut self, label: impl Into<String>, change: bool) {
        if self.jobs.is_empty() {
            self.since = Some(Instant::now());
        }
        self.jobs.push_back(Job { label: label.into(), change });
    }

    /// The oldest job answered.
    pub fn pop(&mut self) {
        self.jobs.pop_front();
        self.since = if self.jobs.is_empty() { None } else { Some(Instant::now()) };
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// A job with this label waits or runs.
    pub fn has(&self, label: &str) -> bool {
        self.jobs.iter().any(|j| j.label == label)
    }

    /// The first change that has not answered yet.
    pub fn change(&self) -> Option<&str> {
        self.jobs.iter().find(|j| j.change).map(|j| j.label.as_str())
    }

    /// How long the running job has been running.
    pub fn running_for(&self) -> Duration {
        self.since.map(|t| t.elapsed()).unwrap_or_default()
    }

    /// The busy line: what runs, what waits behind it, and an alarm once
    /// the other side has been silent longer than slow.
    pub fn view(&self, slow: Duration, silent: &str) -> Option<Doc> {
        let first = self.jobs.front()?;
        let mut d = Doc::new();
        d.s("  ").add(sel(spinner())).s(format!(" {}{}", first.label, theme::ellipsis()));
        if self.jobs.len() > 1 {
            let rest: Vec<&str> = self.jobs.iter().skip(1).map(|j| j.label.as_str()).collect();
            d.add(dim(format!("  then {}", rest.join(", "))));
        }
        let t = self.running_for();
        if t >= slow {
            d.s("  ").add(err(format!("{silent} ({}s)", t.as_secs())));
        }
        Some(d)
    }
}

/// How long closing a screen waits for the running job. A cancelled call
/// is killed within milliseconds; this only bounds a job that ignores it.
const STOP_WAIT: Duration = Duration::from_secs(3);

pub struct Worker<J: Send + 'static> {
    jobs: Option<mpsc::Sender<J>>,
    ctx: Ctx,
    /// Closed when the thread ends.
    ended: mpsc::Receiver<()>,
}

impl<J: Send + 'static> Worker<J> {
    /// Starts the thread; run does one job.
    pub fn start(mut run: impl FnMut(&Ctx, J) + Send + 'static) -> Worker<J> {
        let (tx, rx) = mpsc::channel::<J>();
        let (end_tx, ended) = mpsc::channel::<()>();
        let ctx = Ctx::new();
        let c = ctx.clone();
        std::thread::spawn(move || {
            let _end = end_tx;
            while let Ok(job) = rx.recv() {
                if c.done() {
                    break;
                }
                run(&c, job);
            }
        });
        Worker { jobs: Some(tx), ctx, ended }
    }

    /// Queues a job. False when the thread is gone.
    pub fn send(&self, job: J) -> bool {
        self.jobs.as_ref().is_some_and(|t| t.send(job).is_ok())
    }
}

impl<J: Send + 'static> Drop for Worker<J> {
    fn drop(&mut self) {
        self.ctx.cancel();
        self.jobs = None;
        let _ = self.ended.recv_timeout(STOP_WAIT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::time::Instant;

    #[test]
    fn one_at_a_time_in_order() {
        let (tx, rx) = mpsc::channel();
        let busy = Arc::new(AtomicUsize::new(0));
        let b = busy.clone();
        let w = Worker::start(move |_, n: u32| {
            assert_eq!(b.fetch_add(1, SeqCst), 0, "two jobs at once");
            std::thread::sleep(Duration::from_millis(20));
            b.fetch_sub(1, SeqCst);
            let _ = tx.send(n);
        });
        for n in 0..5 {
            assert!(w.send(n));
        }
        let got: Vec<u32> = (0..5).map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn closing_cancels_and_skips_the_rest() {
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        let w = Worker::start(move |ctx, _: ()| {
            r.fetch_add(1, SeqCst);
            let _ = ctx.sleep(Duration::from_secs(30));
        });
        w.send(());
        w.send(());
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        drop(w);
        assert!(start.elapsed() < Duration::from_secs(1), "closing waited {:?}", start.elapsed());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(ran.load(SeqCst), 1, "a job still waiting ran after the close");
    }

    #[test]
    fn an_answer_after_the_close_goes_nowhere() {
        // The screen's channel is gone and the job ignores the cancel:
        // the drop waits at most STOP_WAIT, the late send fails quietly,
        // and the thread still ends.
        let (tx, rx) = mpsc::channel::<u32>();
        let (started, done) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (s, d) = (started.clone(), done.clone());
        let w = Worker::start(move |_, n: u32| {
            s.fetch_add(1, SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            let _ = tx.send(n);
            d.fetch_add(1, SeqCst);
        });
        w.send(1);
        while started.load(SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(rx);
        drop(w);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(done.load(SeqCst), 1);
    }
}
