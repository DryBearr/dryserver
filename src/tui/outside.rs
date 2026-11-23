//! Outside: the ways in from the internet. Each entrance, how it is doing,
//! and the host names that come in through it; enter shows its details
//! and actions (open, sync, take a name over, close), each also on its own
//! key. A sync always shows every change it would make, and makes them
//! only on y.
//!
//! Like Apps, every call runs on the screen's worker thread with a time
//! limit, so the screen never waits for the coordinator or for
//! Cloudflare.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use super::app::{Place, PlaceScreen, Size};
use super::apps::{Failure, LOADING, REFRESH, Step, cards, change_progress, coordinator_status, hang, health_mark, look_line};
use super::frame::{self, Back, Focus, Help, Item, Notice, Overlay, Page, col};
use super::theme::{self, Mark};
use super::worker::{Limits, Waiting, Worker, timed};
use super::{Emit, Event, Flow, Key, Seg};
use crate::apps::{self, Cluster, Overview};
use crate::ctx::Ctx;
use crate::entrance::{self, Entrances, Health, Report, State};
use crate::err::{Error, Kind, Result};

/// The cluster and how each entrance is doing, in the order of the list.
pub type Look = (Overview, Vec<State>);

/// One question to the coordinator, then each entrance's own look at it.
pub fn look(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits) -> Result<Look> {
    let read = ctx.with_timeout(limits.read);
    let o = apps::overview(&read, c).map_err(|e| timed(e, limits.read))?;
    let states = doors.iter().map(|d| d.state(&read, &o)).collect();
    Ok((o, states))
}

/// What the worker answers. Each job ends with exactly one Loaded, Done
/// or Synced, in the order sent; a change sends its steps before that.
pub enum Msg {
    Loaded(Result<Look>),
    /// The change that runs reached a step: what it does now, and how far
    /// it is, 0 to 1.
    Step(String, f64),
    /// An opening or a closing ended.
    Done(Outcome),
    /// A sync ran: for this entrance, dry or not, taking over these names.
    Synced {
        door: usize,
        dry: bool,
        takeover: Vec<String>,
        res: Result<Report>,
    },
}

/// How an opening or a closing ended.
pub struct Outcome {
    notice: Notice,
    failed: Option<Failure>,
}

enum Job {
    Load,
    Open(usize),
    Close(usize),
    /// confirmed: the changes the admin was shown and said y to; a plan
    /// that differs by then makes none of them.
    Sync {
        door: usize,
        dry: bool,
        takeover: Vec<String>,
        confirmed: Option<Vec<String>>,
    },
}

impl Job {
    fn label(&self, doors: &Entrances) -> String {
        let title = |i: &usize| doors.get(*i).map(|d| d.title()).unwrap_or("?");
        match self {
            Job::Load => LOADING.into(),
            Job::Open(i) => format!("opening {}", title(i)),
            Job::Close(i) => format!("closing {}", title(i)),
            Job::Sync { door, dry: true, .. } => format!("looking at {}", title(door)),
            Job::Sync { door, .. } => format!("syncing {}", title(door)),
        }
    }

    /// It changes something (a look does not).
    fn change(&self) -> bool {
        !matches!(self, Job::Load | Job::Sync { dry: true, .. })
    }

    /// What stops half way when the app quits while it runs.
    fn noun(&self, doors: &Entrances) -> String {
        let title = |i: &usize| doors.get(*i).map(|d| d.title()).unwrap_or("?");
        match self {
            Job::Open(i) => format!("the opening of {}", title(i)),
            Job::Close(i) => format!("the closing of {}", title(i)),
            Job::Sync { door, .. } => format!("the sync of {}", title(door)),
            Job::Load => String::new(),
        }
    }
}

fn run(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, job: Job, step: &dyn Fn(String, f64)) -> Msg {
    let change = ctx.with_timeout(limits.change);
    let gone = || Msg::Done(Outcome { notice: Notice::bad("That way in is not there any more."), failed: None });
    match job {
        Job::Load => Msg::Loaded(look(ctx, c, doors, limits)),
        Job::Open(i) => {
            let Some(d) = doors.get(i) else { return gone() };
            step(format!("Giving {} its token", d.title()), 0.3);
            Msg::Done(match d.open(&change, c) {
                Ok(said) => Outcome { notice: Notice::ok(said), failed: None },
                Err(e) => Outcome {
                    notice: Notice::bad(format!("{} was not opened.", d.title())),
                    failed: Some(Failure {
                        problem: format!("{} was not opened: {}", d.title(), timed(e, limits.change)),
                        todo: "Nothing else was changed. o tries again.".into(),
                        key: ("o", "try again"),
                    }),
                },
            })
        }
        Job::Close(i) => {
            let Some(d) = doors.get(i) else { return gone() };
            step(format!("Closing {}", d.title()), 0.3);
            Msg::Done(match d.close(&change, c) {
                Ok(()) => {
                    Outcome { notice: Notice::ok(format!("{} closed. Nothing from outside comes in through it.", d.title())), failed: None }
                }
                Err(e) => Outcome {
                    notice: Notice::bad(format!("{} was not closed.", d.title())),
                    failed: Some(Failure {
                        problem: format!("{} was not closed: {}", d.title(), timed(e, limits.change)),
                        todo: "Part of it may be closed: r shows how it is now, and x tries again.".into(),
                        key: ("r", "look again"),
                    }),
                },
            })
        }
        Job::Sync { door, dry, takeover, confirmed } => {
            let res = (|| {
                let d = doors.get(door).ok_or_else(|| Error::new("no such entrance"))?;
                if !dry {
                    step("Asking the cluster what the apps want".into(), 0.1);
                }
                // What the apps want now, not what the screen saw a while ago.
                let o = apps::overview(&ctx.with_timeout(limits.read), c).map_err(|e| timed(e, limits.read))?;
                let (wants, _) = entrance::wants(&o.apps);
                let mut want = wants.get(d.id()).cloned().unwrap_or_default();
                want.takeover = takeover.clone();
                want.confirmed = confirmed;
                // The admin asked for it: a closed entrance opens.
                want.open = true;
                if !dry {
                    step(format!("Making the changes in {}", d.title()), 0.4);
                }
                d.sync(&change, c, &o, &want, dry).map_err(|e| timed(e, limits.change))
            })();
            Msg::Synced { door, dry, takeover, res }
        }
    }
}

/// A sync's changes waiting for y. Shown whole before y (pgup and pgdn
/// scroll when they do not fit): a sync may replace a token or switch the
/// cluster's tunnel, and the admin must see that.
struct Plan {
    question: String,
    steps: Vec<String>,
    /// The names it leaves alone: something else holds them.
    held: Vec<entrance::Conflict>,
    job: Job,
}

/// What can be done now in a sheet or a confirm.
enum Over {
    /// The selected entrance's details and actions, the cursor on one.
    Sheet(usize),
    /// A question for y, with what happens.
    Confirm { question: String, consequences: Vec<String>, job: Job },
}

pub struct Screen {
    cluster: Arc<dyn Cluster>,
    doors: Entrances,
    limits: Limits,
    worker: Option<Worker<Job>>,
    waiting: Waiting,
    /// The changes waiting or running, as quitting would stop them.
    nouns: VecDeque<String>,
    now: Overview,
    states: Vec<State>,
    seen: Option<Instant>,
    err: Option<Error>,
    cursor: usize,
    over: Option<Over>,
    plan: Option<Plan>,
    notice: Option<Notice>,
    failed: Option<Failure>,
    /// The last sync's report, for the entrance it belongs to.
    report: Option<(usize, bool, Report)>,
    step: Option<Step>,
    last_load: Option<Instant>,
    quit_armed: bool,
    /// Where to go after this screen closes.
    next: Option<Place>,
}

/// An entrance's question, split into the question and what it does.
fn split_question(q: &str) -> (String, Vec<String>) {
    match q.split_once("? ") {
        Some((head, rest)) if !rest.trim().is_empty() => (format!("{head}?"), vec![rest.trim().to_string()]),
        _ => (q.to_string(), Vec::new()),
    }
}

/// The first sentence or line of a message, for a short reason.
fn first_part(e: &str) -> String {
    let line = e.lines().next().unwrap_or("");
    match line.find(". ") {
        Some(i) => line[..i].to_string(),
        None => line.trim_end_matches('.').to_string(),
    }
}

impl Screen {
    pub fn new(cluster: Arc<dyn Cluster>, doors: Entrances) -> Screen {
        Screen {
            cluster,
            doors,
            limits: Limits::default(),
            worker: None,
            waiting: Waiting::default(),
            nouns: VecDeque::new(),
            now: Overview::default(),
            states: Vec::new(),
            seen: None,
            err: None,
            cursor: 0,
            over: None,
            plan: None,
            notice: None,
            failed: None,
            report: None,
            step: None,
            last_load: None,
            quit_armed: false,
            next: None,
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: Limits) -> Screen {
        self.limits = limits;
        self
    }

    fn start(&mut self, emit: &Emit<Msg>) {
        let (c, doors, limits, emit) = (self.cluster.clone(), self.doors.clone(), self.limits, emit.clone());
        self.worker = Some(Worker::start(move |ctx, job| {
            let e = emit.clone();
            let step = move |what: String, pct: f64| e(Msg::Step(what, pct));
            emit(run(ctx, c.as_ref(), &doors, limits, job, &step))
        }));
    }

    fn send(&mut self, job: Job) {
        let (label, noun, change) = (job.label(&self.doors), job.noun(&self.doors), job.change());
        if self.worker.as_ref().is_some_and(|w| w.send(job)) {
            self.waiting.push(label, change);
            if change {
                self.nouns.push_back(noun);
                self.failed = None;
            }
        } else {
            self.notice = Some(Notice::bad("The background worker stopped: go back (esc) and open Outside again."));
        }
    }

    fn load(&mut self) -> bool {
        if self.waiting.has(LOADING) {
            return false;
        }
        self.last_load = Some(Instant::now());
        self.send(Job::Load);
        true
    }

    fn title(&self, i: usize) -> &'static str {
        self.doors.get(i).map(|d| d.title()).unwrap_or("?")
    }

    /// A change ended.
    fn ended(&mut self) {
        self.nouns.pop_front();
        self.step = None;
        self.quit_armed = false;
    }

    fn answer(&mut self, m: Msg) {
        match m {
            Msg::Step(what, pct) => {
                self.step = Some(Step::next(self.step.as_ref(), what, pct));
                return;
            }
            Msg::Loaded(res) => {
                self.waiting.pop();
                match res {
                    Ok((o, states)) => {
                        self.now = o;
                        self.states = states;
                        self.err = None;
                        self.seen = Some(Instant::now());
                    }
                    Err(e) => self.err = Some(e),
                }
            }
            Msg::Done(out) => {
                self.waiting.pop();
                self.ended();
                self.notice = Some(out.notice);
                self.failed = out.failed;
                self.load();
            }
            Msg::Synced { door, dry, takeover, res: Ok(r) } => {
                self.waiting.pop();
                if !dry {
                    self.ended();
                }
                self.failed = None;
                let title = self.title(door);
                if dry && !r.changes.is_empty() {
                    // Every step is shown before y, and y makes exactly
                    // those (confirmed), or nothing.
                    let question = match takeover.as_slice() {
                        [host] => format!("Take {host} over? {title} makes these changes, in order:"),
                        _ => format!("{title}: {}, in order:", r.summary(true)),
                    };
                    let job = Job::Sync { door, dry: false, takeover: takeover.clone(), confirmed: Some(r.changes.clone()) };
                    self.plan = Some(Plan { question, steps: r.changes.clone(), held: r.conflicts.clone(), job });
                    self.over = None;
                    self.notice = None;
                } else {
                    let said = format!("{title}: {}.", r.summary(dry));
                    self.notice = Some(if dry { Notice::info(said) } else { Notice::ok(said) });
                }
                // A takeover's look keeps the last report: said no to, the
                // name is still held, and t still offers it.
                if !dry || takeover.is_empty() {
                    self.report = Some((door, dry, r));
                }
                if !dry {
                    self.load();
                }
            }
            Msg::Synced { door, dry, res: Err(e), .. } => {
                self.waiting.pop();
                let title = self.title(door);
                let (what, todo) = if dry {
                    ("cannot look", "Nothing was changed. s looks again.")
                } else {
                    self.ended();
                    ("not synced", "A sync cut off half way is finished by the next one. s looks again.")
                };
                self.notice = Some(Notice::bad(format!("{title}: {what}.")));
                self.failed = Some(Failure { problem: format!("{title}: {what}: {e}"), todo: todo.into(), key: ("s", "look again") });
                self.report = None;
                if !dry {
                    self.load();
                }
            }
        }
        self.cursor = self.cursor.min(self.doors.len().saturating_sub(1));
    }

    /// The names the entrance i found held by something else, in its last
    /// look.
    fn conflicts(&self, i: usize) -> Vec<entrance::Conflict> {
        match &self.report {
            Some((door, _, r)) if *door == i => r.conflicts.clone(),
            _ => Vec::new(),
        }
    }

    fn host_key(&self) -> bool {
        self.err.as_ref().is_some_and(|e| e.is(Kind::HostKey))
    }

    fn go(&mut self, place: Place, key: &str) -> Flow {
        // Switching closes this screen and its worker: a sync would stop
        // half way.
        if let Some(what) = self.waiting.change() {
            self.notice = Some(Notice::info(format!("Still {what}. {key} goes to {} once that is done.", place.title())));
            return Flow::Continue;
        }
        self.next = Some(place);
        Flow::Quit
    }

    fn ask_open(&mut self) {
        let Some(d) = self.doors.get(self.cursor) else { return };
        match d.open_question(&self.now) {
            Ok(q) => {
                let (question, consequences) = split_question(&q);
                self.over = Some(Over::Confirm { question, consequences, job: Job::Open(self.cursor) });
            }
            Err(e) => self.notice = Some(Notice::info(e.to_string())),
        }
    }

    fn ask_close(&mut self) {
        let title = self.title(self.cursor);
        match self.states.get(self.cursor) {
            None => {
                self.notice = Some(Notice::info(format!("How {title} is doing is not known yet; wait for the coordinator's answer.")));
                return;
            }
            Some(s) if s.health == Health::NotSetUp => {
                self.notice = Some(Notice::info(format!("{title} is not set up; there is nothing to close.")));
                return;
            }
            Some(_) => {}
        }
        // Closing a way in that apps still use leaves them unreachable
        // from outside: say which.
        let id = self.doors.get(self.cursor).map(|d| d.id()).unwrap_or("");
        let users = entrance::users(id, &self.now.apps);
        let mut consequences = vec![if users.is_empty() {
            "No app comes in through it.".to_string()
        } else {
            format!(
                "{} still come{} in through it: nothing from outside reaches {} after that.",
                users.join(", "),
                if users.len() == 1 { "s" } else { "" },
                if users.len() == 1 { "it" } else { "them" }
            )
        }];
        consequences.push("The apps keep running inside the cluster.".into());
        consequences.push("o opens it again from what you saved.".into());
        self.over = Some(Over::Confirm { question: format!("Close {title}?"), consequences, job: Job::Close(self.cursor) });
    }

    fn sync(&mut self, takeover: Vec<String>) {
        let Some(d) = self.doors.get(self.cursor) else { return };
        if !d.ready() {
            self.notice = Some(Notice::info(format!("{} is not set up yet; there is nothing to sync.", d.title())));
            return;
        }
        self.send(Job::Sync { door: self.cursor, dry: true, takeover, confirmed: None });
    }

    fn key(&mut self, k: Key) -> Flow {
        // A paste where a key is expected does nothing.
        if matches!(k, Key::Paste(_)) {
            return Flow::Continue;
        }
        if let Some(plan) = self.plan.take() {
            match k {
                Key::Char('y') => {
                    self.notice = None;
                    self.send(plan.job);
                }
                // Moving is no answer: pgup and pgdn scroll the plan.
                Key::Up | Key::Down | Key::Char('j') | Key::Char('k') => self.plan = Some(plan),
                _ => self.notice = Some(Notice::info("Nothing changed.")),
            }
            return Flow::Continue;
        }
        if let Some(o) = self.over.take() {
            return self.over_key(o, k);
        }
        self.notice = None;
        let armed = std::mem::take(&mut self.quit_armed);
        let title = self.title(self.cursor);
        match k {
            Key::Esc => match self.waiting.change() {
                Some(what) if !armed => {
                    self.notice = Some(Notice::info(format!("Still {what}. esc again goes back to Home, and that stops half way.")));
                    self.quit_armed = true;
                }
                _ => return Flow::Quit,
            },
            Key::Char('a') => return self.go(Place::Apps, "a"),
            Key::Char('m') if self.host_key() => return self.go(Place::Machines, "m"),
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.doors.len().saturating_sub(1)),
            Key::Enter if !self.doors.is_empty() => self.over = Some(Over::Sheet(0)),
            Key::Char('o') => self.ask_open(),
            Key::Char('x') => self.ask_close(),
            Key::Char('s') => self.sync(Vec::new()),
            Key::Char('t') => {
                // A name something else holds: taken over only on the
                // admin's word, one name at a time. A takeover is a whole
                // sync (the name needs the tunnel to serve it), so it
                // looks first and shows every change before y, as s does.
                match self.conflicts(self.cursor).first() {
                    Some(c) => self.sync(vec![c.host.clone()]),
                    None => self.notice = Some(Notice::info(format!("No name of {title} is held by something else (s looks again)."))),
                }
            }
            Key::Char('r') => {
                if self.failed.as_ref().is_some_and(|f| f.key.0 == "r") {
                    self.failed = None;
                }
                if !self.load() {
                    self.notice = Some(Notice::info("Already asking the coordinator."));
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    fn over_key(&mut self, o: Over, k: Key) -> Flow {
        match o {
            Over::Confirm { job, .. } => {
                if k == Key::Char('y') {
                    self.notice = None;
                    self.send(job);
                } else {
                    self.notice = Some(Notice::info("Nothing changed."));
                }
                Flow::Continue
            }
            Over::Sheet(cursor) => {
                let items = self.items(self.cursor);
                let chosen = match k {
                    Key::Up | Key::Char('k') => {
                        self.over = Some(Over::Sheet(cursor.saturating_sub(1)));
                        None
                    }
                    Key::Down | Key::Char('j') => {
                        self.over = Some(Over::Sheet((cursor + 1).min(items.len().saturating_sub(1))));
                        None
                    }
                    Key::Enter => items.get(cursor).map(|i| i.key.clone()),
                    Key::Esc => None,
                    Key::Char(c) if items.iter().any(|i| i.key == c.to_string()) => Some(c.to_string()),
                    _ => {
                        self.over = Some(Over::Sheet(cursor));
                        None
                    }
                };
                // An action is its key: what cannot be done now says why.
                match chosen.and_then(|c| c.chars().next()) {
                    Some(c) => self.key(Key::Char(c)),
                    None => Flow::Continue,
                }
            }
        }
    }

    /// What can be done to entrance i, for its sheet: open, sync, take a
    /// name over, close.
    fn items(&self, i: usize) -> Vec<Item> {
        let Some(d) = self.doors.get(i) else { return Vec::new() };
        let state = self.states.get(i);
        let runs = state.is_some_and(|s| s.health != Health::NotSetUp);
        let item = |key: &str, label: String, why_not: Option<String>| Item { key: key.into(), label, why_not };
        let take = match self.conflicts(i).first() {
            Some(c) => item("t", format!("take {} over from the {}", c.host, c.holder), None),
            None => item("t", "take a name over".into(), Some("no name is held by something else (s looks again)".into())),
        };
        let close_why = match state {
            None => Some("how it is doing is not known yet".to_string()),
            Some(s) if s.health == Health::NotSetUp => Some("not set up: there is nothing to close".to_string()),
            Some(_) => None,
        };
        vec![
            item(
                "o",
                if runs { "give it the saved token again".into() } else { "open it with the saved token".into() },
                d.open_question(&self.now).err().map(|e| first_part(&e.to_string())),
            ),
            item("s", "sync: show every change it needs, then ask".into(), (!d.ready()).then(|| "not set up yet".to_string())),
            take,
            item("x", "close it".into(), close_why),
        ]
    }

    /// The names that come in through entrance i: (host, app).
    fn names(&self, i: usize) -> Vec<entrance::Name> {
        let id = self.doors.get(i).map(|d| d.id()).unwrap_or("");
        entrance::wants(&self.now.apps).0.get(id).map(|w| w.names.clone()).unwrap_or_default()
    }

    /// The sheet's title: the entrance and its details, each whole.
    fn details(&self, i: usize) -> String {
        let Some(d) = self.doors.get(i) else { return String::new() };
        let state = self.states.get(i);
        let names = self.names(i);
        let names = if names.is_empty() {
            "none".to_string()
        } else {
            names.iter().map(|n| format!("{} ({})", n.host, n.app)).collect::<Vec<_>>().join(", ")
        };
        let mut details = vec![
            ("State", state.map(|s| s.summary.clone()).unwrap_or_else(|| "not known yet".into())),
            ("Carries", entrance::carries(d.as_ref())),
            ("Names", names),
        ];
        for n in state.map(|s| s.notes.clone()).unwrap_or_default() {
            details.push(("Note", n));
        }
        if let Some((door, _, r)) = &self.report
            && *door == i
        {
            for c in &r.conflicts {
                details.push(("Held", format!("{} ({}) by the {}", c.host, c.app, c.holder)));
            }
        }
        frame::sheet_title(d.title(), &details)
    }

    fn plan_page(&self, page: &mut Page, plan: &Plan, size: Size) {
        let p = theme::palette();
        let w = size.width;
        let b = &mut page.body;
        b.add(Seg(plan.question.clone(), p.title())).nl();
        b.add(Seg("y makes exactly these changes, in this order. Any other key changes nothing.".into(), p.hint())).nl();
        let mut lines: Vec<Vec<Seg>> = Vec::new();
        for (i, s) in plan.steps.iter().enumerate() {
            let parts = frame::wrap_line(&[Seg(s.clone(), p.text())], w.saturating_sub(5).max(10));
            for (j, part) in parts.into_iter().enumerate() {
                let mut l = vec![if j == 0 { Seg(format!("{:>3}. ", i + 1), p.hint()) } else { Seg("     ".into(), p.text()) }];
                l.extend(part);
                lines.push(l);
            }
        }
        let long = lines.len() + 3 > size.rows;
        if long {
            b.add(Seg(format!("{} changes: pgdn shows the rest.", plan.steps.len()), p.hint())).nl();
        }
        b.nl();
        for l in lines {
            for s in l {
                b.add(s);
            }
            b.nl();
        }
        if !plan.held.is_empty() {
            b.nl().add(Seg("Left as it is, held by something else:".into(), p.hint())).nl();
            for c in &plan.held {
                hang(
                    b,
                    3,
                    Mark::Bad,
                    &[Seg(format!("{} ({}) is held by the {}: it stays until you take it over (t)", c.host, c.app, c.holder), p.text())],
                    w,
                );
            }
        }
        // The plan starts at its top.
        page.focus = Some(Focus::keep(0..1));
        page.key("y", "make these changes");
        if long {
            page.key("pgup pgdn", "scroll");
        }
        page.key("any other key", "change nothing");
        page.back = Back::Nothing;
        page.help = None;
    }
}

fn help() -> Help {
    Help {
        about: "Nothing on your machines listens to the internet. What comes in arrives through a way in: Cloudflare \
                Tunnel (two pods in the cluster dial out to Cloudflare), and later your own VPS. Each public host name \
                belongs to one app and comes in through one way in.\n\
                s looks at what a way in needs and shows every change before y makes them; with a Cloudflare API token \
                saved it sets up the tunnel, its routes and the DNS names. A name held by something else is left alone \
                until t takes it over."
            .into(),
        keys: vec![
            ("↑↓ j k".into(), "move".into()),
            ("enter".into(), "the way in's details, and what you can do to it".into()),
            ("o".into(), "open it with the token you saved".into()),
            ("s".into(), "sync: shows every change, then y makes them".into()),
            ("t".into(), "take over a name something else holds".into()),
            ("x".into(), "close it (asks first)".into()),
            ("a".into(), "the apps".into()),
            ("r".into(), "look again now".into()),
            ("esc".into(), "back to Home".into()),
        ],
    }
}

impl PlaceScreen for Screen {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        self.start(emit);
        self.load();
    }

    fn update(&mut self, ev: Event<Msg>, _: &Emit<Msg>) -> Flow {
        match ev {
            Event::Key(k) => self.key(k),
            Event::Msg(m) => {
                self.answer(m);
                Flow::Continue
            }
            Event::Tick => {
                if self.waiting.is_empty() && self.plan.is_none() && self.last_load.is_none_or(|t| t.elapsed() >= REFRESH) {
                    self.load();
                }
                Flow::Continue
            }
            Event::Resize(..) | Event::Back(_) => Flow::Continue,
        }
    }

    fn page(&self, size: Size) -> Page {
        let p = theme::palette();
        let mut page = Page::new("Outside");
        page.status = coordinator_status(&self.cluster.address(), self.seen.is_some(), self.err.as_ref(), &self.waiting, self.limits);
        page.notice = self.notice.clone();
        page.help = Some(help());
        // A plan to confirm takes the whole screen: every change it makes.
        if let Some(plan) = &self.plan {
            self.plan_page(&mut page, plan, size);
            return page;
        }
        let w = size.width;
        let b = &mut page.body;
        b.add(Seg("No machine listens to the internet; what comes in arrives through these.".into(), p.hint())).nl();
        cards(b, w, self.err.as_ref(), self.seen, self.failed.as_ref());
        change_progress(b, w, &self.waiting, self.step.as_ref(), self.limits);
        look_line(b, &self.waiting, self.limits);
        let (_, problems) = entrance::wants(&self.now.apps);
        frame::section(b, "Ways in", Some(self.doors.len()));
        if self.doors.is_empty() {
            b.append(frame::empty("This dryserver knows no way in from outside: the apps are reached only inside the cluster.")).nl();
        }
        let mut focus = None;
        for (i, d) in self.doors.iter().enumerate() {
            if i > 0 {
                b.nl();
            }
            if i == self.cursor {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let (m, summary) = match self.states.get(i) {
                None => (Mark::Wait, "not known yet".to_string()),
                Some(s) => (health_mark(s.health), s.summary.clone()),
            };
            b.append(frame::row(w, m, vec![col(Seg(d.title().into(), p.text()), 20), col(Seg(summary, p.hint()), 0)])).nl();
            let mut about = vec![format!("carries {}", entrance::carries(d.as_ref()))];
            about.extend(self.states.get(i).map(|s| s.notes.clone()).unwrap_or_default());
            for a in about {
                b.add(Seg(format!("   {a}"), p.hint())).nl();
            }
            let names = self.names(i);
            let held = self.conflicts(i);
            for n in &names {
                match held.iter().find(|c| c.host == n.host) {
                    Some(c) => hang(
                        b,
                        3,
                        Mark::Bad,
                        &[
                            Seg(format!("{} ({})", n.host, n.app), p.text()),
                            Seg(format!(" is held by the {}: t takes it over", c.holder), p.hint()),
                        ],
                        w,
                    ),
                    None => {
                        b.s("   ").append(frame::row(
                            w.saturating_sub(3),
                            Mark::Blank,
                            vec![col(Seg(n.host.clone(), p.text()), 34), col(Seg(n.app.clone(), p.hint()), 0)],
                        ));
                        b.nl();
                    }
                }
            }
            // Held names the apps no longer want are still named.
            for c in held.iter().filter(|c| !names.iter().any(|n| n.host == c.host)) {
                hang(b, 3, Mark::Bad, &[Seg(format!("{} ({}) is held by the {}", c.host, c.app, c.holder), p.text())], w);
            }
            if names.is_empty() && d.id() == entrance::VPS {
                b.add(Seg("   a server you rent: web and game ports over WireGuard (comes later)".into(), p.faint())).nl();
            } else if names.is_empty() {
                b.add(Seg("   no app comes in through it".into(), p.faint())).nl();
            }
            if let Some((door, _, r)) = &self.report
                && *door == i
            {
                for n in &r.notes {
                    b.add(Seg(format!("   {n}"), p.hint())).nl();
                }
            }
        }
        if !problems.is_empty() {
            frame::section(b, "Not served", Some(problems.len()));
            for pr in &problems {
                hang(b, 0, Mark::Bad, &[Seg(pr.clone(), p.text())], w);
            }
            b.add(Seg("Remove one of the apps in Apps (a), or start it again without the name.".into(), p.hint())).nl();
        }
        page.focus = focus;
        match &self.over {
            Some(Over::Sheet(c)) => {
                page.overlay = Some(Overlay::Sheet { title: self.details(self.cursor), items: self.items(self.cursor), cursor: *c })
            }
            Some(Over::Confirm { question, consequences, .. }) => {
                page.overlay = Some(Overlay::Confirm { question: question.clone(), consequences: consequences.clone() })
            }
            None => {}
        }
        if self.host_key() {
            page.key("m", "open Machines");
        }
        page.key("enter", "actions").key("s", "sync");
        if !self.conflicts(self.cursor).is_empty() {
            page.key("t", "take over");
        }
        page.key("o", "open").key("x", "close").key("a", "apps").key("r", "look again");
        page.back = Back::Esc;
        page
    }

    fn busy(&self) -> Option<String> {
        self.nouns.front().cloned()
    }

    fn next(&self) -> Option<Place> {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::tests::{Fake, LISTING};
    use crate::entrance::cfsync::tests::{FakeCf, entrance, fresh};
    use crate::tui::apps::tests::{Opened, Pending, doors};
    use crate::tui::theme::Tier;
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Duration;

    impl Pending for Screen {
        fn pending(&self) -> bool {
            !self.waiting.is_empty()
        }
    }

    const TOKEN: &str = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYiLCJzIjoiWldGemVTQjBieUJ6WldVPSJ9";

    fn open(fake: &Arc<Fake>, dir: &crate::testutil::TempDir) -> Opened<Screen> {
        let mut o = Opened::new(Screen::new(fake.clone(), doors(dir)));
        o.settle();
        o
    }

    /// Two apps on Cloudflare, one inside only, one tunnel copy of two.
    fn listing() -> String {
        LISTING.replace(
            r#"{"kind":"Pod","metadata":{"name":"blog-1""#,
            r#"{"kind":"Deployment","metadata":{"name":"shop","namespace":"apps","labels":{"app":"shop"}},"spec":{"replicas":1},"status":{"readyReplicas":1}},
      {"kind":"Ingress","metadata":{"name":"shop","namespace":"apps","labels":{"app":"shop"},"annotations":{"dryserver/entrance":"cloudflare"}},"spec":{"rules":[{"host":"shop.example.com"}]}},
      {"kind":"Pod","metadata":{"name":"blog-1""#,
        )
    }

    fn with_api(fake: &Arc<Fake>, dir: &crate::testutil::TempDir, cf: &Arc<FakeCf>) -> Opened<Screen> {
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), cf, true)), Box::new(entrance::Vps)]);
        let mut o = Opened::new(Screen::new(fake.clone(), doors));
        o.settle();
        o
    }

    #[test]
    fn each_way_in_and_its_names() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        let v = s.flat();
        assert!(v.contains("dryserver Outside") && v.contains("✓ answers") && v.contains("Ways in 2"), "{v}");
        assert!(v.contains("▌ ○ Cloudflare Tunnel connected with 1 of 2 copies"), "{v}");
        assert!(v.contains("blog.example.com blog") && v.contains("shop.example.com shop"), "{v}");
        assert!(v.contains("no API token: names are routed in the dashboard"), "{v}");
        assert!(v.contains("· Your VPS not set up") && v.contains("comes later"), "{v}");
        assert!(v.contains("enter actions") && v.contains("s sync") && v.contains("a apps"), "{v}");
        // The VPS cannot be opened, synced or closed yet.
        s.key(Key::Down);
        assert!(s.flat().contains("▌ · Your VPS"), "{}", s.view());
        s.key(Key::Char('o'));
        assert!(s.notice().contains("a VPS cannot be set up yet"), "{:?}", s.notice());
        s.key(Key::Char('x'));
        assert!(s.notice().contains("Your VPS is not set up; there is nothing to close"), "{:?}", s.notice());
        s.key(Key::Char('s'));
        assert!(s.notice().contains("Your VPS is not set up yet; there is nothing to sync") && !s.s.pending());
        // Its sheet says the same, in ash.
        s.key(Key::Enter);
        let v = s.flat();
        assert!(v.contains("Your VPS") && v.contains("State not set up") && v.contains("Carries web, TCP, UDP"), "{v}");
        assert!(v.contains("open it with the saved token: a VPS cannot be set up yet"), "{v}");
        assert!(v.contains("close it: not set up: there is nothing to close"), "{v}");
        s.key(Key::Esc);
        // a goes to the apps.
        assert_eq!(s.key(Key::Char('a')), Flow::Quit);
        assert_eq!(s.s.next(), Some(Place::Apps));
    }

    #[test]
    fn closing_a_way_in_that_apps_use() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        s.key(Key::Char('x'));
        let v = s.flat();
        assert!(v.contains("Close Cloudflare Tunnel?"), "{v}");
        assert!(v.contains("blog, shop still come in through it: nothing from outside reaches them after that."), "{v}");
        assert!(v.contains("The apps keep running inside the cluster.") && v.contains("y yes"), "{v}");
        s.key(Key::Esc);
        assert!(s.notice().contains("Nothing changed") && !fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete")));
        // Through the sheet: enter, then x.
        s.key(Key::Enter);
        s.key(Key::Char('x'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.notice().contains("Cloudflare Tunnel closed"), "{:?}", s.notice());
        assert!(
            fake.calls.lock().unwrap().iter().any(|(a, _)| a == "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found")
        );
        // No app on it: nobody to warn about.
        *fake.listing.lock().unwrap() = listing().replace("\"host\":\"blog.example.com\"", "\"host\":\"\"").replace("shop.example.com", "");
        s.key(Key::Char('r'));
        s.settle();
        s.key(Key::Char('x'));
        assert!(s.flat().contains("No app comes in through it."), "{}", s.view());
    }

    #[test]
    fn switching_screens_waits_for_a_change() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        *fake.delay.lock().unwrap() = Duration::from_millis(300);
        s.key(Key::Char('x'));
        s.key(Key::Char('y'));
        assert_eq!(s.s.busy().as_deref(), Some("the closing of Cloudflare Tunnel"));
        assert!(s.flat().contains("Closing Cloudflare Tunnel"), "the change shows: {}", s.view());
        assert_eq!(s.key(Key::Char('a')), Flow::Continue);
        assert!(s.notice().contains("Still closing Cloudflare Tunnel. a goes to Apps once that is done"), "{:?}", s.notice());
        assert_eq!(s.s.next(), None);
        assert_eq!(s.key(Key::Esc), Flow::Continue, "leaving asks once");
        assert!(s.notice().contains("esc again goes back to Home, and that stops half way"));
        s.settle();
        assert!(s.notice().contains("Cloudflare Tunnel closed"), "{:?}", s.notice());
        assert_eq!(fake.cut_off.load(SeqCst), 0, "the close ran to its end");
        assert_eq!(s.key(Key::Char('a')), Flow::Quit);
        assert_eq!(s.s.next(), Some(Place::Apps));
    }

    #[test]
    fn the_tunnel_from_the_saved_token() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let file = dir.join("cloudflare_tunnel_token");
        let mut s = open(&fake, &dir);
        let applied = |f: &Fake| f.calls.lock().unwrap().iter().filter(|(a, _)| a == "apply -f -").count();
        assert!(s.flat().contains("▌ · Cloudflare Tunnel not set up"), "{}", s.view());
        // No token saved: says where it goes, starts nothing.
        s.key(Key::Char('o'));
        assert!(s.notice().contains("No tunnel token yet") && s.notice().contains("cloudflare_tunnel_token"), "{:?}", s.notice());
        assert!(s.notice().contains("Then press o again"));
        s.key(Key::Enter);
        assert!(s.flat().contains("open it with the saved token: No tunnel token yet"), "{}", s.view());
        s.key(Key::Esc);
        s.key(Key::Char('x'));
        assert!(s.notice().contains("not set up; there is nothing to close"));
        // Something that is not a token.
        std::fs::write(&file, "my password\n").unwrap();
        s.key(Key::Char('o'));
        assert!(s.notice().contains("not a tunnel token"), "{:?}", s.notice());
        assert_eq!(applied(&fake), 0);
        // The dashboard's command line, pasted whole. Asks first.
        std::fs::write(&file, format!("cloudflared service install {TOKEN}\n")).unwrap();
        s.key(Key::Char('o'));
        let v = s.flat();
        assert!(v.contains("Open the tunnel with the token from") && v.contains("y yes"), "{v}");
        assert!(v.contains("Cloudflare then sends what arrives for your public host names to the ingress."), "{v}");
        assert!(!v.contains(TOKEN) && !v.contains("y to confirm"), "the token is never shown: {v}");
        s.key(Key::Char('n'));
        assert!(s.notice().contains("Nothing changed") && applied(&fake) == 0);
        s.key(Key::Char('o'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(
            s.notice().contains("Tunnel starting") && s.notice().contains("http://traefik.kube-system.svc.cluster.local:80"),
            "{:?}",
            s.notice()
        );
        let calls = fake.calls.lock().unwrap().clone();
        let (_, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert!(manifest.contains(&format!("token: \"{TOKEN}\"")) && manifest.contains("kind: Secret"), "{manifest}");
        assert!(calls.iter().all(|(a, _)| !a.contains(TOKEN)), "the token travels on stdin, never in a command line");
        // Running: o now gives it the token again.
        *fake.listing.lock().unwrap() = listing();
        s.key(Key::Char('r'));
        s.settle();
        s.key(Key::Char('o'));
        assert!(s.flat().contains("Give the tunnel the token from"), "{}", s.view());
    }

    #[test]
    fn sync_without_the_api_says_what_to_do() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        s.key(Key::Char('s'));
        s.settle();
        assert!(s.notice().contains("Cloudflare Tunnel: nothing to change"), "{:?}", s.notice());
        assert!(s.flat().contains("point each of blog.example.com, shop.example.com at"), "{}", s.view());
    }

    #[test]
    fn a_name_claimed_twice() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing().replace("shop.example.com", "blog.example.com");
        let dir = crate::testutil::TempDir::new();
        let s = open(&fake, &dir);
        let v = s.flat();
        assert!(v.contains("Not served 1"), "{v}");
        assert!(v.contains("! blog.example.com is the public name of blog and shop: none of them gets it from outside"), "{v}");
        assert!(v.contains("no app comes in through it"), "neither gets it: {v}");
        assert!(v.contains("Remove one of the apps in Apps (a)"), "{v}");
    }

    #[test]
    fn the_coordinator_off() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        let dir = crate::testutil::TempDir::new();
        let limits = Limits { read: Duration::from_millis(150), change: Duration::from_millis(150), slow: Duration::from_millis(10) };
        let mut s = Opened::new(Screen::new(fake.clone(), doors(&dir)).with_limits(limits));
        std::thread::sleep(Duration::from_millis(30));
        assert!(s.flat().contains("not answering (0s)"), "{}", s.view());
        assert!(s.flat().contains("Cloudflare Tunnel not known yet"), "{}", s.view());
        let start = Instant::now();
        s.key(Key::Down);
        s.key(Key::Up);
        s.key(Key::Char('x'));
        assert!(s.notice().contains("not known yet; wait for the coordinator's answer"), "{:?}", s.notice());
        assert!(start.elapsed() < Duration::from_millis(50));
        s.settle();
        assert!(s.flat().contains("! Cannot reach the cluster: the coordinator did not answer"), "{}", s.view());
        assert!(s.flat().contains("! does not answer"), "{}", s.view());
    }

    #[test]
    fn set_up_cloudflare_from_here() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let cf = Arc::new(fresh());
        let mut s = with_api(&fake, &dir, &cf);
        assert!(s.flat().contains("API token saved: s sets up the tunnel"), "{}", s.view());
        // s shows every change it would make, and asks. The cluster runs
        // another tunnel (LISTING's token mark): the switch and the token
        // it replaces are named before y.
        s.key(Key::Char('s'));
        assert!(s.flat().contains("Looking at Cloudflare Tunnel"), "{}", s.view());
        s.settle();
        s.resize(100, 40);
        let v = s.flat();
        assert!(v.contains("Cloudflare Tunnel: 6 changes to make, in order:"), "{v}");
        for step in [
            "1. create the tunnel dryserver in Cloudflare",
            "2. route blog.example.com, shop.example.com through the tunnel",
            "3. save the tunnel's token in secrets/cloudflare_tunnel_token",
            "4. switch the cluster from the tunnel it runs now (not dryserver) to dryserver: names routed to the old one in the dashboard stop working",
            "5. add blog.example.com to DNS",
            "6. add shop.example.com to DNS",
            "y make these changes",
        ] {
            assert!(v.contains(step), "{step:?} not shown:\n{}", s.view());
        }
        assert_eq!(cf.changes.load(SeqCst), 0, "a look changes nothing");
        // Moving or a paste does not answer the question.
        s.key(Key::Down);
        s.key(Key::Paste("y".into()));
        assert!(s.s.plan.is_some());
        s.key(Key::Char('y'));
        assert!(s.flat().contains("Syncing Cloudflare Tunnel"), "the ring shows the sync: {}", s.view());
        s.settle();
        assert!(s.notice().contains("Cloudflare Tunnel: 6 changes made."), "{:?}", s.notice());
        let records: Vec<String> = cf.cf.lock().unwrap().records.iter().map(|r| r.name.clone()).collect();
        assert_eq!(records, vec!["blog.example.com", "shop.example.com"]);
        // The tunnel in the cluster got the new tunnel's token.
        assert!(fake.calls.lock().unwrap().iter().any(|(a, m)| a == "apply -f -" && m.contains("name: cloudflared")));
        // The cluster now runs that token. Again: nothing to do, nothing asked.
        let mark = crate::entrance::cfsync::tests::mark_of(&fake).unwrap();
        let now = fake.listing.lock().unwrap().replace("00aa11bb22cc33dd", &mark);
        *fake.listing.lock().unwrap() = now;
        s.key(Key::Char('r'));
        s.settle();
        s.key(Key::Char('s'));
        s.settle();
        assert!(s.notice().contains("Cloudflare Tunnel: nothing to change.") && s.s.plan.is_none(), "{:?}", s.notice());
    }

    #[test]
    fn a_name_held_by_something_else() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let cf = Arc::new(fresh());
        for (kind, content) in [("A", "203.0.113.7"), ("AAAA", "2001:db8::7")] {
            cf.cf.lock().unwrap().records.push(crate::entrance::cfsync::Record {
                zone: crate::entrance::cfsync::tests::ZONE.into(),
                id: format!("{}{}", "f".repeat(31), if kind == "A" { "a" } else { "b" }),
                name: "blog.example.com".into(),
                kind: kind.into(),
                content: content.into(),
                proxied: false,
                comment: String::new(),
            });
        }
        let mut s = with_api(&fake, &dir, &cf);
        s.key(Key::Char('t'));
        assert!(s.notice().contains("No name of Cloudflare Tunnel is held by something else"), "{:?}", s.notice());
        s.key(Key::Char('s'));
        s.settle();
        // The plan names what it leaves alone too.
        let v = s.flat();
        assert!(v.contains("Left as it is, held by something else:"), "{v}");
        assert!(v.contains("blog.example.com (blog) is held by the A record 203.0.113.7 and AAAA record 2001:db8::7: it stays until you take it over (t)"), "{v}");
        s.key(Key::Char('y'));
        s.settle();
        let v = s.flat();
        // Every record that holds it is named.
        assert!(
            v.contains("! blog.example.com (blog) is held by the A record 203.0.113.7 and AAAA record 2001:db8::7: t takes it over"),
            "{v}"
        );
        assert!(v.contains("t take over"), "{v}");
        s.key(Key::Enter);
        assert!(s.flat().contains("take blog.example.com over from the A record 203.0.113.7 and AAAA record 2001:db8::7"), "{}", s.view());
        s.key(Key::Esc);
        // The records stay until the admin says so. t looks first and
        // shows every change, the records it deletes and the gap included.
        let before = cf.changes.load(SeqCst);
        s.key(Key::Char('t'));
        s.settle();
        s.resize(120, 40);
        let v = s.flat();
        assert!(v.contains("Take blog.example.com over? Cloudflare Tunnel makes these changes, in order:"), "{v}");
        assert!(v.contains("1. switch the cluster from the tunnel it runs now"), "{v}");
        assert!(v.contains("delete the DNS record of blog.example.com (A record 203.0.113.7,"), "{v}");
        assert!(v.contains("the name does not resolve until the tunnel's record is"), "{v}");
        assert!(v.contains("add blog.example.com to DNS"), "{v}");
        assert_eq!(cf.changes.load(SeqCst), before, "a look changes nothing");
        s.key(Key::Char('n'));
        assert!(s.notice().contains("Nothing changed"));
        assert!(cf.cf.lock().unwrap().records.iter().any(|r| r.kind == "A"));
        assert!(s.flat().contains("t take over"), "said no to, the name is still offered: {}", s.view());
        s.key(Key::Char('t'));
        s.settle();
        s.key(Key::Char('y'));
        s.settle();
        let recs = cf.cf.lock().unwrap().records.clone();
        assert!(
            !recs.iter().any(|r| r.kind == "A" || r.kind == "AAAA") && recs.iter().filter(|r| r.name == "blog.example.com").count() == 1,
            "{recs:?}"
        );
        assert!(!s.flat().contains("t take over"), "{}", s.view());
    }

    #[test]
    fn a_long_plan_scrolls() {
        // Twenty apps: more changes than 24 rows hold. pgdn scrolls, the
        // screen keeps to 80x24, and y still makes exactly those.
        let fake = Arc::new(Fake::default());
        let mut items = Vec::new();
        for i in 0..20 {
            items.push(format!(r#"{{"kind":"Deployment","metadata":{{"name":"app{i}","namespace":"apps","labels":{{"app":"app{i}"}}}},"spec":{{"replicas":1}},"status":{{}}}}"#));
            items.push(format!(r#"{{"kind":"Ingress","metadata":{{"name":"app{i}","namespace":"apps","labels":{{"app":"app{i}"}}}},"spec":{{"rules":[{{"host":"app{i}.example.com"}}]}}}}"#));
        }
        *fake.listing.lock().unwrap() = format!(r#"{{"items":[{}]}}"#, items.join(","));
        let dir = crate::testutil::TempDir::new();
        let cf = Arc::new(fresh());
        let mut s = with_api(&fake, &dir, &cf);
        s.key(Key::Char('s'));
        s.settle();
        let v = s.flat();
        assert!(v.contains("Cloudflare Tunnel: 24 changes to make, in order:") && v.contains("1. create the tunnel"), "{}", s.view());
        assert!(v.contains("24 changes: pgdn shows the rest.") && !v.contains("24. add app9.example.com"), "{}", s.view());
        assert!(v.contains("pgup pgdn scroll"), "{v}");
        assert!(s.rows().iter().any(|l| l.ends_with('▐')), "the thumb shows there is more");
        // The hub's pgdn scrolls the frame; here the scroll is moved the same way.
        for _ in 0..10 {
            s.scroll.key(&Key::PageDown);
        }
        let v = s.flat();
        assert!(v.contains("24. add app9.example.com to DNS") && !v.contains("1. create the tunnel"), "{}", s.view());
        s.scroll.key(&Key::Home);
        assert!(s.flat().contains("1. create the tunnel"), "{}", s.view());
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.notice().contains("Cloudflare Tunnel: 24 changes made."), "{:?}", s.notice());
        assert_eq!(cf.cf.lock().unwrap().records.len(), 20);
    }

    #[test]
    fn a_plan_that_changed_since_the_look_is_not_made() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let cf = Arc::new(fresh());
        let mut s = with_api(&fake, &dir, &cf);
        s.key(Key::Char('s'));
        s.settle();
        // Meanwhile one app goes: the plan the admin saw is not the one
        // that would run.
        *fake.listing.lock().unwrap() = listing().replace("shop.example.com", "");
        s.key(Key::Char('y'));
        s.settle();
        let v = s.flat();
        assert!(v.contains("not synced: something changed since you looked, so nothing was changed"), "{v}");
        assert!(v.contains("s look again"), "{v}");
        assert_eq!(cf.changes.load(SeqCst), 0);
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, _)| a == "apply -f -"));
    }

    #[test]
    fn when_cloudflare_says_no() {
        // Cloudflare down, a revoked token, a permission missing: a card
        // that says which, nothing changed, and the screen still works.
        type Setup = fn(&FakeCf);
        let cases: [(&str, Setup); 3] = [
            ("Cloudflare is having trouble", |cf| cf.down.store(true, SeqCst)),
            ("the API token does not work", |cf| cf.cf.lock().unwrap().verify.clear()),
            ("The API token needs the permission", |cf| cf.forbid.lock().unwrap().push("dns_records".into())),
        ];
        for (want, setup) in cases {
            let fake = Arc::new(Fake::default());
            *fake.listing.lock().unwrap() = listing();
            let dir = crate::testutil::TempDir::new();
            let cf = Arc::new(fresh());
            setup(&cf);
            let mut s = with_api(&fake, &dir, &cf);
            s.key(Key::Char('s'));
            s.settle();
            let v = s.flat();
            assert!(s.notice().contains("Cloudflare Tunnel: cannot look."), "{want}: {:?}", s.notice());
            assert!(v.contains("! Cloudflare Tunnel: cannot look:") && v.contains(want), "{want}: {v}");
            assert!(v.contains("Nothing was changed. s looks again.") && v.contains("s look again"), "{want}: {v}");
            assert!(!fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("apply") || a.contains("delete")));
            assert_eq!(cf.changes.load(SeqCst), 0);
            if want.contains("permission") {
                assert!(v.contains("Zone"), "the permission is named: {v}");
            }
            s.key(Key::Down);
            assert!(s.flat().contains("▌ · Your VPS"), "the screen still works");
        }
    }

    #[test]
    fn every_tier_and_size() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        for (tier, console) in [(Tier::True, false), (Tier::C256, false), (Tier::Console, true), (Tier::Plain, false)] {
            s.tier = (tier, console);
            for (w, h) in [(80, 24), (100, 32), (200, 60)] {
                s.resize(w, h);
                let v = s.flat();
                assert!(v.contains("Cloudflare Tunnel") && v.contains("Your VPS"), "{tier:?} {w}x{h}: {v}");
                if tier == Tier::Console {
                    assert!(v.contains("[s] sync") && !v.contains('✓'), "{v}");
                }
            }
        }
        s.resize(79, 24);
        assert!(s.flat().contains("Make this window at least"));
    }
}
