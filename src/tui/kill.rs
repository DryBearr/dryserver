//! Kill switch: cuts the coordinator off from every server, over the
//! WiFi/router network and never through the coordinator. sudo asks for a
//! password on each server, so the screen gives the terminal to it and
//! comes back with the result. Lift and status from the same place.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use super::app::{PlaceScreen, Size};
use super::frame::{self, Back, Focus, Help, Notice, Overlay, Page, col};
use super::home::age;
use super::theme::{self, Mark};
use super::{Emit, Event, Flow, Job, Key, Seg, dim, spinner};
use crate::err::Result;
use crate::quarantine::{self, Remote};

/// What quarantine-all does on every server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    /// Cut the coordinator off.
    Cut,
    /// Show what is cut.
    Status,
    /// Lift every cut, onto the coordinator signed last.
    Lift,
    /// Lift after a false alarm: trust the same coordinator again.
    LiftSame,
}

impl Switch {
    fn title(self) -> &'static str {
        match self {
            Switch::Cut => "Kill switch: cutting the coordinator off on every server",
            Switch::Status => "Kill switch: what is cut on every server",
            Switch::Lift => "Kill switch: lifting the cut on every server",
            Switch::LiftSame => "Kill switch: lifting the cut, trusting the same coordinator",
        }
    }
}

/// Runs quarantine-all (on the terminal: sudo asks on each server).
pub type Quarantine = Arc<dyn Fn(Switch) -> Result<()> + Send + Sync>;
/// Writes ~/.ssh/config.d/dryserver from the signed list (ssh-config);
/// says what it wrote.
pub type WriteList = Arc<dyn Fn() -> Result<String> + Send + Sync>;

pub enum Msg {
    Written(Result<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Run(Switch),
    Write,
}

const ACTIONS: [(Action, &str, &str); 5] = [
    (Action::Run(Switch::Cut), "Cut the coordinator off", "every server stops trusting it"),
    (Action::Run(Switch::Status), "Show what is cut", "on every server"),
    (Action::Run(Switch::Lift), "Lift the cut", "trust the coordinator you signed last again"),
    (Action::Run(Switch::LiftSame), "Lift after a false alarm", "trust the same coordinator again: it was not reinstalled"),
    (Action::Write, "Write the server list again", "from the machines you signed; the coordinator must answer"),
];

/// The servers the kill switch reaches, from the server list.
enum List {
    /// Why there is none, in plain words.
    Missing(String),
    Read {
        servers: Vec<Remote>,
        secs: Option<u64>,
    },
}

pub struct Kill {
    path: Option<PathBuf>,
    list: List,
    cursor: usize,
    confirm: Option<Switch>,
    job: Option<Job>,
    /// Given to the terminal; how it ended comes back as Event::Back.
    running: Option<Switch>,
    writing: Option<Instant>,
    notice: Option<Notice>,
    /// The last run did not finish everywhere.
    problem: Option<String>,
    quarantine: Quarantine,
    write_list: WriteList,
}

/// A path under the home directory as "~/...", which is shorter to read.
fn tilde(p: &std::path::Path) -> String {
    match std::env::var_os("HOME").map(PathBuf::from) {
        Some(home) if !home.as_os_str().is_empty() => match p.strip_prefix(&home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => p.display().to_string(),
        },
        _ => p.display().to_string(),
    }
}

fn read_list(path: &Option<PathBuf>) -> List {
    let Some(path) = path else {
        return List::Missing("$HOME is not set, so the server list cannot be found.".into());
    };
    let Ok(conf) = std::fs::read_to_string(path) else {
        return List::Missing(format!("There is no server list on this computer yet ({}).", tilde(path)));
    };
    let servers = quarantine::remotes(&conf);
    if !servers.iter().any(|r| !r.coordinator) {
        return List::Missing(format!("The server list ({}) has no server that can be reached without the coordinator.", tilde(path)));
    }
    let secs =
        std::fs::metadata(path).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok()).map(|d| d.as_secs());
    List::Read { servers, secs }
}

impl Kill {
    pub fn new(path: Option<PathBuf>, quarantine: Quarantine, write_list: WriteList) -> Kill {
        let list = read_list(&path);
        // Without the list only writing it works: start there.
        let cursor = if matches!(list, List::Read { .. }) { 0 } else { ACTIONS.len() - 1 };
        Kill {
            path,
            list,
            cursor,
            confirm: None,
            job: None,
            running: None,
            writing: None,
            notice: None,
            problem: None,
            quarantine,
            write_list,
        }
    }

    fn ready(&self) -> bool {
        matches!(self.list, List::Read { .. })
    }

    fn run(&mut self, c: Switch) {
        let q = self.quarantine.clone();
        self.problem = None;
        self.running = Some(c);
        self.job = Some(Job { title: c.title().into(), run: Box::new(move || q(c)) });
    }

    fn choose(&mut self, emit: &Emit<Msg>) {
        let (a, label, _) = ACTIONS[self.cursor];
        match a {
            Action::Write => {
                if self.writing.is_some() {
                    return;
                }
                self.writing = Some(Instant::now());
                let (w, emit) = (self.write_list.clone(), emit.clone());
                std::thread::spawn(move || emit(Msg::Written(w())));
            }
            Action::Run(_) if !self.ready() => {
                self.notice = Some(Notice::bad(format!("{label}: there is no server list yet. Write it first (the last line).")));
            }
            Action::Run(c @ (Switch::Cut | Switch::LiftSame)) => self.confirm = Some(c),
            Action::Run(c) => self.run(c),
        }
    }

    fn back(&mut self, res: Result<()>) {
        let Some(c) = self.running.take() else { return };
        match res {
            Ok(()) => {
                self.notice = Some(Notice::ok(match c {
                    Switch::Cut => {
                        "Cut off on every server. Next: delete the tunnel in the Cloudflare dashboard, power the coordinator off \
                                 and keep its disk. Reinstall it from the stick before you lift the cut."
                            .to_string()
                    }
                    Switch::Status => "Every server answered; what each one said was shown before you came back.".into(),
                    Switch::Lift | Switch::LiftSame => "Lifted on every server.".into(),
                }));
            }
            Err(e) => self.problem = Some(e.to_string()),
        }
    }
}

impl PlaceScreen for Kill {
    type Msg = Msg;

    fn update(&mut self, ev: Event<Msg>, emit: &Emit<Msg>) -> Flow {
        match ev {
            Event::Back(res) => self.back(res),
            Event::Msg(Msg::Written(res)) => {
                self.writing = None;
                self.list = read_list(&self.path);
                self.notice = Some(match res {
                    Ok(said) => Notice::ok(said),
                    Err(e) => Notice::bad(format!("The server list was not written: {e}")),
                });
            }
            Event::Key(k) => {
                if let Some(c) = self.confirm.take() {
                    if k == Key::Char('y') {
                        self.run(c);
                    } else {
                        self.notice = Some(Notice::info("Nothing was done."));
                    }
                    return Flow::Continue;
                }
                self.notice = None;
                match k {
                    Key::Esc => return Flow::Quit,
                    Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
                    Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(ACTIONS.len() - 1),
                    Key::Enter => self.choose(emit),
                    _ => {}
                }
            }
            Event::Tick | Event::Resize(..) => {}
        }
        Flow::Continue
    }

    fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let mut page = Page::new("Kill switch");
        let b = &mut page.body;
        b.add(Seg("For when you think the coordinator was broken into.".into(), p.text().add_modifier(ratatui::style::Modifier::BOLD)))
            .nl();
        b.add(dim("Every server stops trusting the coordinator and the list it hands out, and drops its way in. dryserver reaches \
             each server over your WiFi/router network, never through the coordinator. sudo asks for your password on each one."))
            .nl();
        if let Some(e) = &self.problem {
            b.nl();
            b.append(frame::card(
                size.width,
                &format!("Not done everywhere: {e}"),
                "The servers named still trust what was cut. Power the coordinator off now, and run this again when they answer.",
                None,
            ));
            b.nl();
        }
        match &self.list {
            List::Missing(why) => {
                b.nl();
                b.append(frame::card(
                    size.width,
                    why,
                    "Write it while the coordinator is still trusted: it names each server and how to reach it without the coordinator.",
                    Some(("enter", "on the last line writes it")),
                ));
                b.nl();
            }
            List::Read { servers, secs } => {
                frame::section(b, "Servers it reaches", Some(servers.len()));
                for r in servers {
                    let what = if r.coordinator { "the coordinator" } else { "over WiFi/router" };
                    b.append(frame::row(
                        size.width,
                        Mark::Blank,
                        vec![
                            col(Seg(r.name.clone(), p.text()), 18),
                            col(Seg(r.addr.clone(), p.hint()), 16),
                            col(Seg(what.into(), p.hint()), 0),
                        ],
                    ))
                    .nl();
                }
                let when = secs.map(|s| format!("written {} ago", age(s))).unwrap_or_else(|| "written at an unknown time".into());
                let path = self.path.as_ref().map(|p| tilde(p)).unwrap_or_default();
                b.add(dim(format!("From {path}, {when}. Servers added since are not in it: write it again after each new one."))).nl();
            }
        }
        frame::section(b, "What to do", None);
        let mut focus = None;
        for (i, (a, label, what)) in ACTIONS.iter().enumerate() {
            let off = matches!(a, Action::Run(_)) && !self.ready();
            if i == self.cursor {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let (m, label_style) = match a {
                _ if off => (Mark::Off, p.faint()),
                Action::Run(Switch::Cut) => (Mark::Blank, p.fg(p.ember).add_modifier(ratatui::style::Modifier::BOLD)),
                _ => (Mark::Blank, p.text()),
            };
            let what = if off { "needs the server list" } else { what };
            let busy = matches!(a, Action::Write) && self.writing.is_some();
            let what = if busy { format!("{} writing{}", spinner(), theme::ellipsis()) } else { what.to_string() };
            b.append(frame::row(size.width, m, vec![col(Seg(label.to_string(), label_style), 28), col(Seg(what, p.hint()), 0)])).nl();
        }
        page.focus = focus;
        page.notice = self.notice.clone();
        if let Some(c) = self.confirm {
            let (question, consequences) = match c {
                Switch::Cut => (
                    "Cut the coordinator off on every server?",
                    vec![
                        "Every server stops trusting it and the member list it hands out.".to_string(),
                        "The terminal asks for your sudo password on each server.".into(),
                        "Lifting it later trusts the coordinator you sign next.".into(),
                    ],
                ),
                _ => (
                    "Lift the cut and trust the same coordinator again?",
                    vec![
                        "Only after a false alarm: a coordinator that was broken into gets its way in back.".to_string(),
                        "The terminal asks for your sudo password on each server.".into(),
                    ],
                ),
            };
            page.overlay = Some(Overlay::Confirm { question: question.into(), consequences });
        }
        page.key("↑↓", "move").key("enter", "choose");
        page.back = Back::Esc;
        page.help = Some(Help {
            about: "The kill switch is for when the coordinator may have been broken into. It cuts the coordinator off on every \
                    server it reaches over the WiFi/router network; sudo asks for your password on each. Lift the cut once the \
                    coordinator is reinstalled from the stick (or, after a false alarm, trust the same one again)."
                .into(),
            keys: vec![("↑↓".into(), "move".into()), ("enter".into(), "choose".into()), ("esc".into(), "back to Home".into())],
        });
        page
    }

    fn job(&mut self) -> Option<Job> {
        self.job.take()
    }

    fn busy(&self) -> Option<String> {
        self.writing.map(|_| "writing the server list".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::collector;
    use std::sync::Mutex;

    const LIST: &str = "Host coord\n  HostName 10.1.0.60\n  User admin\nHost node-a.lan\n  HostName 10.1.0.71\n  User admin\n";

    fn kill(dir: &crate::testutil::TempDir, list: Option<&str>, runs: Arc<Mutex<Vec<Switch>>>, fail: bool) -> Kill {
        let path = dir.join("dryserver");
        if let Some(l) = list {
            std::fs::write(&path, l).unwrap();
        }
        let q: Quarantine = Arc::new(move |c| {
            runs.lock().unwrap().push(c);
            if fail { Err("not done on 1 server(s):\n  node-a: cannot connect over ssh to 10.1.0.71".into()) } else { Ok(()) }
        });
        let p2 = path.clone();
        let w: WriteList = Arc::new(move || {
            std::fs::write(&p2, LIST).unwrap();
            Ok("Wrote the server list (2 servers).".into())
        });
        Kill::new(Some(path), q, w)
    }

    fn keys(k: &mut Kill, ks: &[Key]) -> Option<Job> {
        let (emit, _rx) = collector();
        for key in ks {
            k.update(Event::Key(key.clone()), &emit);
        }
        k.job()
    }

    /// The page's words, the lines joined: a card wraps where it likes.
    fn text(k: &Kill) -> String {
        let _g = theme::force(theme::Tier::True, false);
        k.page(Size { width: 90, rows: 28 }).body.plain().split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn cut_asks_then_hands_the_terminal_over() {
        let dir = crate::testutil::TempDir::new();
        let runs = Arc::new(Mutex::new(Vec::new()));
        let mut k = kill(&dir, Some(LIST), runs.clone(), false);
        let t = text(&k);
        assert!(t.contains("Servers it reaches 2") && t.contains("node-a") && t.contains("10.1.0.71"), "{t}");
        // enter on the cut asks first; a no does nothing.
        assert!(keys(&mut k, &[Key::Enter]).is_none());
        assert!(matches!(k.page(Size { width: 90, rows: 28 }).overlay, Some(Overlay::Confirm { .. })));
        assert!(keys(&mut k, &[Key::Char('n')]).is_none());
        assert!(runs.lock().unwrap().is_empty());
        // A yes gives the terminal to quarantine-all.
        let job = keys(&mut k, &[Key::Enter, Key::Char('y')]).expect("a job");
        assert!(job.title.contains("cutting the coordinator off"));
        (job.run)().unwrap();
        assert_eq!(*runs.lock().unwrap(), vec![Switch::Cut]);
        let (emit, _rx) = collector();
        k.update(Event::Back(Ok(())), &emit);
        assert!(k.notice.as_ref().unwrap().text.contains("delete the tunnel"), "{:?}", k.notice);
        // Status runs at once; lift too; lift trusting the same asks.
        let job = keys(&mut k, &[Key::Down, Key::Enter]).expect("status");
        (job.run)().unwrap();
        k.update(Event::Back(Ok(())), &emit);
        let job = keys(&mut k, &[Key::Down, Key::Enter]).expect("lift");
        (job.run)().unwrap();
        k.update(Event::Back(Ok(())), &emit);
        assert!(keys(&mut k, &[Key::Down, Key::Enter]).is_none(), "lift -same asks first");
        let job = keys(&mut k, &[Key::Char('y')]).expect("lift same");
        (job.run)().unwrap();
        assert_eq!(*runs.lock().unwrap(), vec![Switch::Cut, Switch::Status, Switch::Lift, Switch::LiftSame]);
    }

    #[test]
    fn a_failure_is_a_card() {
        let dir = crate::testutil::TempDir::new();
        let mut k = kill(&dir, Some(LIST), Arc::new(Mutex::new(Vec::new())), true);
        let job = keys(&mut k, &[Key::Down, Key::Enter]).unwrap();
        let res = (job.run)();
        let (emit, _rx) = collector();
        k.update(Event::Back(res), &emit);
        let t = text(&k);
        assert!(t.contains("Not done everywhere: not done on 1 server(s)") && t.contains("Power the coordinator off now"), "{t}");
    }

    #[test]
    fn without_a_server_list_it_writes_one() {
        let dir = crate::testutil::TempDir::new();
        let runs = Arc::new(Mutex::new(Vec::new()));
        let mut k = kill(&dir, None, runs.clone(), false);
        let t = text(&k);
        assert!(t.contains("There is no server list on this computer yet") && t.contains("needs the server list"), "{t}");
        // The cursor starts on the only line that works; the others say
        // what they need.
        assert!(keys(&mut k, &[Key::Up, Key::Enter]).is_none());
        assert!(k.notice.as_ref().unwrap().text.contains("Write it first") && runs.lock().unwrap().is_empty());
        // The last line writes it in the background.
        let (emit, rx) = collector();
        for key in [Key::Down, Key::Down, Key::Enter] {
            k.update(Event::Key(key), &emit);
        }
        assert!(k.busy().is_some());
        let m = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        k.update(Event::Msg(m), &emit);
        assert!(k.ready() && k.busy().is_none());
        assert!(text(&k).contains("Servers it reaches 2"));
        // A list with only the coordinator in it reaches nobody.
        let dir = crate::testutil::TempDir::new();
        let k = kill(&dir, Some("Host coord\n  HostName 10.1.0.60\n"), runs, false);
        assert!(!k.ready() && text(&k).contains("no server that can be reached without the coordinator"));
    }
}
