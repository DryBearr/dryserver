//! Backups: the coordinator's encrypted backups that are on this computer,
//! newest first, and p to pull the newer ones from it.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use super::app::{PlaceScreen, Size};
use super::frame::{self, Back, Focus, Help, Notice, Page, col};
use super::home::{OLD_BACKUP_SECS, age};
use super::theme::{self, Mark};
use super::{Emit, Event, Flow, Key, Seg, dim};
use crate::backup;
use crate::err::Result;
use crate::runner::LineWriter;

/// One backup here.
#[derive(Debug, Clone, PartialEq)]
pub struct Copy {
    pub name: String,
    /// The time in its name: when the coordinator made it.
    pub made: SystemTime,
    pub size: u64,
}

/// The backups in dir, newest first. Only names the coordinator gives its
/// backups count: part files and signatures do not.
pub fn copies(dir: &Path) -> Vec<Copy> {
    let mut out: Vec<Copy> = std::fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let t = backup::parse_name(&name)?;
                    let m = e.metadata().ok().filter(|m| m.is_file())?;
                    Some(Copy { name, made: SystemTime::from(t), size: m.len() })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|c| std::cmp::Reverse(c.made));
    out
}

/// Copies the coordinator's newer backups here, writing a line for each.
pub type Pull = Arc<dyn Fn(&mut (dyn Write + Send)) -> Result<backup::Pulled> + Send + Sync>;

/// The directories a pull writes into now. One pull at a time into each:
/// a pull keeps going after its screen closes, and two would write the
/// same files.
static PULLING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

pub enum Msg {
    Line(String),
    Done(Result<backup::Pulled>),
}

enum State {
    Idle,
    Pulling {
        started: Instant,
        lines: Vec<String>,
    },
    /// The last pull failed, with the error.
    Failed(String),
}

pub struct Backups {
    dir: PathBuf,
    copies: Vec<Copy>,
    /// None: pulling cannot work yet, with what to do instead.
    pull: std::result::Result<Pull, (String, String)>,
    state: State,
    notice: Option<Notice>,
    cursor: usize,
    now: fn() -> SystemTime,
}

impl Backups {
    /// why_not: why a pull cannot work yet (the problem, what to do).
    pub fn new(dir: PathBuf, pull: std::result::Result<Pull, (String, String)>) -> Backups {
        let copies = copies(&dir);
        Backups { dir, copies, pull, state: State::Idle, notice: None, cursor: 0, now: SystemTime::now }
    }

    fn start(&mut self, emit: &Emit<Msg>) {
        let pull = match &self.pull {
            Ok(p) => p.clone(),
            Err((problem, todo)) => {
                self.notice = Some(Notice::bad(format!("{problem} {todo}")));
                return;
            }
        };
        if matches!(self.state, State::Pulling { .. }) {
            return;
        }
        if !PULLING.lock().unwrap_or_else(|e| e.into_inner()).insert(self.dir.clone()) {
            self.notice = Some(Notice::info("A pull from before still runs. Try again in a moment."));
            return;
        }
        self.notice = None;
        self.state = State::Pulling { started: Instant::now(), lines: Vec::new() };
        let (emit, dir) = (emit.clone(), self.dir.clone());
        std::thread::spawn(move || {
            let e = emit.clone();
            let mut w = LineWriter::new(Arc::new(move |l: &str| e(Msg::Line(l.to_string()))));
            let res = pull(&mut w);
            w.finish();
            PULLING.lock().unwrap_or_else(|e| e.into_inner()).remove(&dir);
            emit(Msg::Done(res));
        });
    }

    fn done(&mut self, res: Result<backup::Pulled>) {
        self.copies = copies(&self.dir);
        self.state = State::Idle;
        match res {
            Ok(r) => {
                let mut said = match r.fetched.len() {
                    0 => "Nothing newer on the coordinator: every copy is here.".to_string(),
                    1 => "Pulled 1 new copy.".to_string(),
                    n => format!("Pulled {n} new copies."),
                };
                if !r.removed.is_empty() {
                    said += &format!(
                        " Removed {} older than the {} daily and {} weekly kept.",
                        r.removed.len(),
                        backup::KEEP_DAILY,
                        backup::KEEP_WEEKLY
                    );
                }
                if r.problems.is_empty() {
                    self.notice = Some(Notice::ok(said));
                } else {
                    self.state = State::Failed(format!("Not everything was copied: {}", r.problems.join("; ")));
                }
            }
            Err(e) => self.state = State::Failed(e.to_string()),
        }
    }
}

impl PlaceScreen for Backups {
    type Msg = Msg;

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        match ev {
            Event::Msg(Msg::Line(l)) => {
                if let State::Pulling { lines, .. } = &mut self.state {
                    lines.push(l);
                    let n = lines.len();
                    lines.drain(..n.saturating_sub(50));
                }
            }
            Event::Msg(Msg::Done(res)) => self.done(res),
            Event::Key(k) => {
                self.notice = None;
                match k {
                    Key::Esc => return Flow::Quit,
                    Key::Char('p') => self.start(emit),
                    Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
                    Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.copies.len().saturating_sub(1)),
                    _ => {}
                }
            }
            Event::Tick | Event::Resize(..) | Event::Back(_) => {}
        }
        Flow::Continue
    }

    fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let mut page = Page::new("Backups");
        page.status.add(dim(self.dir.display().to_string()));
        let now = (self.now)();
        let b = &mut page.body;
        b.add(dim("The coordinator backs itself up every night, encrypted to your backup key. The copies here are what you restore from if it is lost."));
        b.nl();
        if let State::Pulling { started, lines } = &self.state {
            frame::section(b, "Pulling from the coordinator", None);
            b.append(frame::progress(size.width, None, "Copying the newer backups", started.elapsed())).nl();
            for l in lines.iter().rev().take(5).rev() {
                b.add(Seg(super::fit(l, size.width.saturating_sub(2)), p.faint())).nl();
            }
        }
        if let State::Failed(e) = &self.state {
            b.nl();
            b.append(frame::card(
                size.width,
                &format!("The pull did not finish: {e}"),
                "The copies already here are kept.",
                Some(("p", "try again")),
            ));
            b.nl();
        }
        if let Err((problem, todo)) = &self.pull {
            b.nl();
            b.append(frame::card(size.width, problem, todo, None));
            b.nl();
        }
        frame::section(b, "On this computer", Some(self.copies.len()));
        if self.copies.is_empty() {
            b.append(frame::empty("No backup on this computer yet. The coordinator makes one every night; p copies them here."));
        }
        let mut focus = None;
        for (i, c) in self.copies.iter().enumerate() {
            let secs = now.duration_since(c.made).map(|d| d.as_secs()).unwrap_or(0);
            let old = i == 0 && secs > OLD_BACKUP_SECS;
            let when = chrono::DateTime::<chrono::Local>::from(c.made).format("%Y-%m-%d %H:%M").to_string();
            let how_old = if old { format!("{} old: pull the newer ones", age(secs)) } else { format!("{} old", age(secs)) };
            if i == self.cursor {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let m = if old { Mark::Bad } else { Mark::Done };
            b.append(frame::row(
                size.width,
                m,
                vec![col(Seg(when, p.text()), 16), col(Seg(crate::disks::human_size(c.size), p.hint()), 9), col(Seg(how_old, p.hint()), 0)],
            ))
            .nl();
        }
        let key = crate::fsx::dir(&self.dir).join(crate::iso::BACKUP_KEY_NAME);
        b.nl().add(dim(format!("Restoring needs {}, the key the build made: keep a copy of it somewhere safe.", key.display())));
        page.focus = focus;
        page.notice = self.notice.clone();
        if !matches!(self.state, State::Pulling { .. }) {
            page.key("p", "pull the newer ones");
        }
        if !self.copies.is_empty() {
            page.key("↑↓", "move");
        }
        page.back = Back::Esc;
        page.help = Some(Help {
            about: "The coordinator makes an encrypted backup of itself every night and keeps the last 7 daily and 4 weekly. \
                    p copies the ones this computer does not have yet, checks each one's signature, and removes copies here \
                    beyond what is kept."
                .into(),
            keys: vec![("p".into(), "pull the newer backups".into()), ("↑↓".into(), "move".into()), ("esc".into(), "back to Home".into())],
        });
        page
    }

    fn busy(&self) -> Option<String> {
        matches!(self.state, State::Pulling { .. }).then(|| "the pull from the coordinator".into())
    }
}

/// A moment, for tests that set the clock.
#[cfg(test)]
fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::collector;

    fn page_text(b: &Backups) -> String {
        b.page(Size { width: 90, rows: 28 }).body.plain()
    }

    #[test]
    fn lists_copies_newest_first() {
        let dir = crate::testutil::TempDir::new();
        let d = dir.join("backups");
        std::fs::create_dir_all(&d).unwrap();
        for (n, size) in [("brain-20261101T030000Z.tar.age", 100), ("brain-20261120T030000Z.tar.age", 2_000_000), ("brain-x.tar.age", 5)] {
            std::fs::write(d.join(n), vec![0u8; size]).unwrap();
        }
        std::fs::write(d.join(".brain-20261121T030000Z.tar.age.part"), "x").unwrap();
        std::fs::write(d.join("brain-20261120T030000Z.tar.age.sig"), "x").unwrap();
        let c = copies(&d);
        assert_eq!(c.len(), 2, "{c:?}");
        assert_eq!(c[0].name, "brain-20261120T030000Z.tar.age");
        assert_eq!(c[0].size, 2_000_000);
        let mut b = Backups::new(d.clone(), Err(("x".into(), "y".into())));
        b.now = || at(1_796_400_000);
        let t = page_text(&b);
        assert!(t.contains("On this computer  2") && t.contains("2.0 MB"), "{t}");
        assert!(t.contains("days old: pull the newer ones"), "{t}");
        // None: what fixes it.
        let b = Backups::new(dir.join("nothing"), Err(("x".into(), "y".into())));
        assert!(page_text(&b).contains("No backup on this computer yet"));
    }

    #[test]
    fn pull_runs_in_the_background() {
        let dir = crate::testutil::TempDir::new();
        let d = dir.join("backups");
        let d2 = d.clone();
        let pull: Pull = Arc::new(move |w| {
            std::fs::create_dir_all(&d2).unwrap();
            std::fs::write(d2.join("brain-20261122T030000Z.tar.age"), "x").unwrap();
            writeln!(w, "pulled brain-20261122T030000Z.tar.age (1 B)").unwrap();
            Ok(backup::Pulled { fetched: vec!["brain-20261122T030000Z.tar.age".into()], ..Default::default() })
        });
        let mut b = Backups::new(d.clone(), Ok(pull));
        let (emit, rx) = collector();
        b.update(Event::Key(Key::Char('p')), &emit);
        assert!(b.busy().is_some() && page_text(&b).contains("Copying the newer backups"));
        // A second p while it runs starts nothing more.
        b.update(Event::Key(Key::Char('p')), &emit);
        for m in rx.iter().take(2) {
            b.update(Event::Msg(m), &emit);
        }
        assert!(b.busy().is_none());
        assert_eq!(b.notice, Some(Notice::ok("Pulled 1 new copy.")));
        assert_eq!(b.copies.len(), 1, "the list is read again");
    }

    #[test]
    fn a_failed_pull_is_a_card() {
        let dir = crate::testutil::TempDir::new();
        let pull: Pull = Arc::new(|_| Err("the coordinator did not answer within 15s. Is it on?".into()));
        let mut b = Backups::new(dir.join("b"), Ok(pull));
        let (emit, rx) = collector();
        b.update(Event::Key(Key::Char('p')), &emit);
        let m = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        b.update(Event::Msg(m), &emit);
        let t = page_text(&b);
        assert!(t.contains("The pull did not finish: the coordinator did not answer") && t.contains(" p  try again"), "{t}");
        // Not possible yet: says what to do, starts nothing.
        let mut b =
            Backups::new(dir.join("b"), Err(("This computer has not met the coordinator yet.".into(), "Open Machines (4) once.".into())));
        b.update(Event::Key(Key::Char('p')), &emit);
        assert!(b.busy().is_none() && b.notice.as_ref().is_some_and(|n| n.text.contains("Open Machines (4)")));
        assert_eq!(b.update(Event::Key(Key::Esc), &emit), Flow::Quit);
    }
}
