//! The admin's screen for the ways in from the internet: each entrance,
//! how it is doing, and the host names that come in through it. Opening,
//! syncing and closing an entrance happen here.
//!
//! Like the apps screen, every call runs on the screen's worker thread
//! with a time limit, so the screen never waits for the coordinator or
//! for Cloudflare.

use std::sync::Arc;
use std::time::Instant;

use super::worker::{Limits, Waiting, Worker, timed};
use super::{Doc, Emit, Event, Flow, Key, Model, Place, dim, err, ok, sel, theme, wrap};
use crate::apps::{self, Cluster, Overview};
use crate::ctx::Ctx;
use crate::entrance::{self, Entrances, Health, Report, State};
use crate::err::{Error, Result};

/// Each refresh asks the coordinator once, over the shared connection.
const REFRESH: std::time::Duration = std::time::Duration::from_secs(15);

/// The cluster and how each entrance is doing, in the order of the list.
pub type Look = (Overview, Vec<State>);

/// One question to the coordinator, then each entrance's own look at it.
pub fn look(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits) -> Result<Look> {
    let read = ctx.with_timeout(limits.read);
    let o = apps::overview(&read, c).map_err(|e| timed(e, limits.read))?;
    let states = doors.iter().map(|d| d.state(&read, &o)).collect();
    Ok((o, states))
}

pub enum Msg {
    Loaded(Result<Look>),
    /// A change ended: what to tell the admin.
    Done(String),
    /// A sync ran: for this entrance, dry or not, taking over these names.
    Synced {
        door: usize,
        dry: bool,
        takeover: Vec<String>,
        res: Result<Report>,
    },
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

const LOADING: &str = "asking the coordinator";

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
}

fn run(ctx: &Ctx, c: &dyn Cluster, doors: &Entrances, limits: Limits, job: Job) -> Msg {
    let change = ctx.with_timeout(limits.change);
    match job {
        Job::Load => Msg::Loaded(look(ctx, c, doors, limits)),
        Job::Open(i) => {
            let Some(d) = doors.get(i) else { return Msg::Done("No such entrance.".into()) };
            Msg::Done(match d.open(&change, c) {
                Ok(said) => said,
                Err(e) => format!("{} not opened: {}", d.title(), timed(e, limits.change)),
            })
        }
        Job::Close(i) => {
            let Some(d) = doors.get(i) else { return Msg::Done("No such entrance.".into()) };
            Msg::Done(match d.close(&change, c) {
                Ok(()) => format!("{} closed. Nothing from outside comes in through it.", d.title()),
                Err(e) => format!("{} not closed: {}", d.title(), timed(e, limits.change)),
            })
        }
        Job::Sync { door, dry, takeover, confirmed } => {
            let res = (|| {
                let d = doors.get(door).ok_or_else(|| Error::new("no such entrance"))?;
                // What the apps want now, not what the screen saw a while ago.
                let o = apps::overview(&ctx.with_timeout(limits.read), c).map_err(|e| timed(e, limits.read))?;
                let (wants, _) = entrance::wants(&o.apps);
                let mut want = wants.get(d.id()).cloned().unwrap_or_default();
                want.takeover = takeover.clone();
                want.confirmed = confirmed;
                // The admin asked for it: a closed entrance opens.
                want.open = true;
                d.sync(&change, c, &o, &want, dry).map_err(|e| timed(e, limits.change))
            })();
            Msg::Synced { door, dry, takeover, res }
        }
    }
}

/// A question waiting for "y", and what then happens.
struct Confirm {
    question: String,
    /// The changes y makes, in order. Shown in full before y (scrolled
    /// with the arrows when they do not fit): a sync may replace a token
    /// or switch the cluster's tunnel, and the admin must see that.
    steps: Vec<String>,
    job: Job,
    /// The first line of steps on screen.
    scroll: usize,
}

impl Confirm {
    fn new(question: String, job: Job) -> Confirm {
        Confirm { question, steps: Vec::new(), job, scroll: 0 }
    }
}

pub struct Screen {
    cluster: Arc<dyn Cluster>,
    doors: Entrances,
    limits: Limits,
    worker: Option<Worker<Job>>,
    waiting: Waiting,
    now: Overview,
    states: Vec<State>,
    seen: Option<Instant>,
    err: Option<Error>,
    cursor: usize,
    confirm: Option<Confirm>,
    pub notice: String,
    /// The last sync's report, for the entrance it belongs to.
    report: Option<(usize, bool, Report)>,
    last_load: Option<Instant>,
    quit_armed: bool,
    width: usize,
    height: usize,
    /// Where to go after this screen closes.
    pub next: Option<Place>,
}

impl Screen {
    pub fn new(cluster: Arc<dyn Cluster>, doors: Entrances) -> Screen {
        Screen {
            cluster,
            doors,
            limits: Limits::default(),
            worker: None,
            waiting: Waiting::default(),
            now: Overview::default(),
            states: Vec::new(),
            seen: None,
            err: None,
            cursor: 0,
            confirm: None,
            notice: String::new(),
            report: None,
            last_load: None,
            quit_armed: false,
            width: 80,
            height: 24,
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
        self.worker = Some(Worker::start(move |ctx, job| emit(run(ctx, c.as_ref(), &doors, limits, job))));
    }

    fn send(&mut self, job: Job) {
        let (label, change) = (job.label(&self.doors), !matches!(job, Job::Load | Job::Sync { dry: true, .. }));
        if self.worker.as_ref().is_some_and(|w| w.send(job)) {
            self.waiting.push(label, change);
        } else {
            self.notice = "The background worker stopped; quit and open the screen again.".into();
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

    fn answer(&mut self, m: Msg) {
        self.waiting.pop();
        match m {
            Msg::Loaded(Ok((o, states))) => {
                self.now = o;
                self.states = states;
                self.err = None;
                self.seen = Some(Instant::now());
            }
            Msg::Loaded(Err(e)) => self.err = Some(e),
            Msg::Done(notice) => {
                self.notice = notice;
                self.quit_armed = false;
                self.load();
            }
            Msg::Synced { door, dry, takeover, res: Ok(r) } => {
                let title = self.doors.get(door).map(|d| d.title()).unwrap_or("?");
                self.notice = format!("{title}: {}.", r.summary(dry));
                if dry && !r.changes.is_empty() {
                    // Every step is shown before y, and y makes exactly
                    // those (confirmed), or nothing.
                    let question = match takeover.as_slice() {
                        [host] => format!("Take {host} over? {title} makes these changes, in order:"),
                        _ => format!("{title}: {}, in order:", r.summary(true)),
                    };
                    let job = Job::Sync { door, dry: false, takeover: takeover.clone(), confirmed: Some(r.changes.clone()) };
                    self.confirm = Some(Confirm { steps: r.changes.clone(), ..Confirm::new(question, job) });
                }
                // A takeover's look keeps the last report: said no to, the
                // name is still held, and t still offers it.
                if !dry || takeover.is_empty() {
                    self.report = Some((door, dry, r));
                }
                if !dry {
                    self.quit_armed = false;
                    self.load();
                }
            }
            Msg::Synced { door, dry, res: Err(e), .. } => {
                let title = self.doors.get(door).map(|d| d.title()).unwrap_or("?");
                self.notice = if dry { format!("{title}: cannot look: {e}") } else { format!("{title}: not synced: {e}") };
                self.report = None;
                if !dry {
                    self.load();
                }
            }
        }
    }

    fn door_state(&self, i: usize) -> Option<&State> {
        self.states.get(i)
    }

    /// The names the selected entrance found held by something else, in
    /// its last look.
    fn conflicts(&self) -> Vec<entrance::Conflict> {
        match &self.report {
            Some((door, _, r)) if *door == self.cursor => r.conflicts.clone(),
            _ => Vec::new(),
        }
    }

    /// The plan's lines as shown, and how many fit on the screen.
    fn plan_lines(&self, c: &Confirm) -> (Vec<String>, usize) {
        let width = self.width.saturating_sub(4);
        let mut lines = Vec::new();
        for (i, s) in c.steps.iter().enumerate() {
            let text = wrap(&format!("{:>3}. {s}", i + 1), width.saturating_sub(5));
            for (j, l) in text.lines().enumerate() {
                lines.push(if j == 0 { format!("  {l}") } else { format!("       {l}") });
            }
        }
        // The header, the question, the scroll line and the keys take
        // the rest.
        let room = self.height.saturating_sub(4 + wrap(&c.question, width).lines().count() + 4).max(3);
        (lines, room)
    }

    fn key(&mut self, k: Key) -> Flow {
        if let Some(mut c) = self.confirm.take() {
            let (lines, room) = self.plan_lines(&c);
            let last = lines.len().saturating_sub(room);
            let scroll = match k {
                Key::Up | Key::Char('k') => Some(c.scroll.saturating_sub(1)),
                Key::Down | Key::Char('j') => Some((c.scroll + 1).min(last)),
                Key::PageUp => Some(c.scroll.saturating_sub(room)),
                Key::PageDown | Key::Char(' ') => Some((c.scroll + room).min(last)),
                _ => None,
            };
            match scroll {
                Some(s) if !c.steps.is_empty() => {
                    c.scroll = s;
                    self.confirm = Some(c);
                }
                _ if k == Key::Char('y') => {
                    self.notice.clear();
                    self.send(c.job);
                }
                _ => self.notice = "Nothing changed.".into(),
            }
            return Flow::Continue;
        }
        let armed = std::mem::take(&mut self.quit_armed);
        let id = self.doors.get(self.cursor).map(|d| d.id()).unwrap_or("");
        let title = self.doors.get(self.cursor).map(|d| d.title()).unwrap_or("?");
        match k {
            Key::Ctrl('c') => return Flow::Quit,
            Key::Char('q') | Key::Esc => match self.waiting.change() {
                Some(what) if !armed => {
                    self.notice = format!("Still {what}. Press q again to quit anyway; it may stop half way.");
                    self.quit_armed = true;
                }
                _ => return Flow::Quit,
            },
            Key::Char('a') => {
                // Switching closes this screen and its worker: a sync
                // would stop half way.
                if let Some(what) = self.waiting.change() {
                    self.notice = format!("Still {what}. a goes to the apps once that is done.");
                    return Flow::Continue;
                }
                self.next = Some(Place::Apps);
                return Flow::Quit;
            }
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.doors.len().saturating_sub(1)),
            Key::Char('o') => {
                self.notice.clear();
                match self.doors.get(self.cursor).map(|d| d.open_question(&self.now)) {
                    Some(Ok(q)) => self.confirm = Some(Confirm::new(q, Job::Open(self.cursor))),
                    Some(Err(e)) => self.notice = e.to_string(),
                    None => {}
                }
            }
            Key::Char('x') => {
                self.notice.clear();
                match self.door_state(self.cursor) {
                    None => {
                        self.notice = format!("How {title} is doing is not known yet; wait for the coordinator's answer.");
                        return Flow::Continue;
                    }
                    Some(s) if s.health == Health::NotSetUp => {
                        self.notice = format!("{title} is not set up; there is nothing to close.");
                        return Flow::Continue;
                    }
                    Some(_) => {}
                }
                // Removing a way in that apps still use leaves them
                // unreachable from outside: say which.
                let users = entrance::users(id, &self.now.apps);
                let q = if users.is_empty() {
                    format!("Close {title}? No app comes in through it. y to confirm")
                } else {
                    format!(
                        "Close {title}? {} still come{} in through it: nothing from outside reaches {} after that. y to confirm",
                        users.join(", "),
                        if users.len() == 1 { "s" } else { "" },
                        if users.len() == 1 { "it" } else { "them" }
                    )
                };
                self.confirm = Some(Confirm::new(q, Job::Close(self.cursor)));
            }
            Key::Char('s') => {
                self.notice.clear();
                self.send(Job::Sync { door: self.cursor, dry: true, takeover: Vec::new(), confirmed: None });
            }
            Key::Char('t') => {
                // A name something else holds: taken over only on the
                // admin's word, one name at a time. A takeover is a whole
                // sync (the name needs the tunnel to serve it), so it
                // looks first and shows every change before y, as s does.
                self.notice.clear();
                match self.conflicts().first() {
                    Some(c) => {
                        let takeover = vec![c.host.clone()];
                        self.send(Job::Sync { door: self.cursor, dry: true, takeover, confirmed: None });
                    }
                    None => self.notice = format!("No name of {title} is held by something else (s looks again)."),
                }
            }
            Key::Char('r') => {
                self.notice = if self.load() { String::new() } else { "Already asking the coordinator.".into() };
            }
            _ => {}
        }
        Flow::Continue
    }
}

impl Model for Screen {
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
                if self.waiting.is_empty() && self.confirm.is_none() && self.last_load.is_none_or(|t| t.elapsed() >= REFRESH) {
                    self.load();
                }
                Flow::Continue
            }
            Event::Resize(w, h) => {
                self.width = (w as usize).max(40);
                self.height = (h as usize).max(12);
                Flow::Continue
            }
            Event::Back(_) => Flow::Continue,
        }
    }

    fn view(&self) -> Doc {
        let mut b = Doc::new();
        let width = self.width.saturating_sub(4);
        b.append(theme::header("outside")).s("   ").add(dim("the ways in from the internet to your apps")).s("\n\n");
        // A plan to confirm takes the whole screen: every change it makes.
        if let Some(c) = self.confirm.as_ref().filter(|c| !c.steps.is_empty()) {
            let (lines, room) = self.plan_lines(c);
            b.add(err(wrap(&c.question, width))).nl();
            for l in lines.iter().skip(c.scroll).take(room) {
                b.s(l).nl();
            }
            if lines.len() > room {
                let shown =
                    format!("  lines {}-{} of {}; ↑↓ to see the rest", c.scroll + 1, (c.scroll + room).min(lines.len()), lines.len());
                b.add(dim(shown)).nl();
            }
            b.nl().append(theme::keys(&[("y", "make these changes"), ("↑↓", "scroll"), ("other keys", "change nothing")])).nl();
            return b;
        }
        if let Some(e) = &self.err {
            b.add(err(wrap(&format!("Cannot reach the cluster: {e}"), width))).nl();
            if let Some(t) = self.seen {
                b.add(dim(format!("  What you see is from {} ago. r asks again.", super::since(t)))).nl();
            }
            b.nl();
        }
        let (wants, problems) = entrance::wants(&self.now.apps);
        for (i, d) in self.doors.iter().enumerate() {
            let head = format!("{:<20}", d.title());
            if i == self.cursor {
                b.add(sel(format!("> {head}")));
            } else {
                b.s(format!("  {head}"));
            }
            match self.states.get(i) {
                None => b.add(dim("not known yet")),
                Some(s) => match s.health {
                    Health::Up => b.add(ok(&s.summary)),
                    Health::NotSetUp => b.add(dim(&s.summary)),
                    Health::Down | Health::Partly => b.add(err(&s.summary)),
                },
            };
            b.s("  ").add(dim(entrance::carries(d.as_ref()))).nl();
            for n in &self.states.get(i).map(|s| s.notes.clone()).unwrap_or_default() {
                b.add(dim(wrap(&format!("    {n}"), width))).nl();
            }
            let names = wants.get(d.id()).map(|w| w.names.clone()).unwrap_or_default();
            for n in &names {
                b.s(format!("    {:<34} ", n.host)).add(dim(&n.app)).nl();
            }
            if names.is_empty() && d.id() == entrance::VPS {
                b.add(dim("    a server you rent: web and game ports over WireGuard (comes later)")).nl();
            } else if names.is_empty() {
                b.add(dim("    no app comes in through it")).nl();
            }
            if let Some((door, _, r)) = &self.report
                && *door == i
            {
                for c in &r.conflicts {
                    b.add(err(wrap(&format!("    {} ({}) is held by {}", c.host, c.app, c.holder), width))).nl();
                }
                for n in &r.notes {
                    b.add(dim(wrap(&format!("    {n}"), width))).nl();
                }
            }
        }
        for p in &problems {
            b.nl().add(err(wrap(&format!("! {p}"), width))).nl();
        }
        if let Some(w) = self.waiting.view(self.limits.slow, "not answering") {
            b.nl().append(w).nl();
        }
        if let Some(c) = &self.confirm {
            b.nl().add(err(wrap(&c.question, width))).nl();
        } else if !self.notice.is_empty() {
            b.nl().s(wrap(&self.notice, width)).nl();
        }
        let mut keys = vec![("↑↓", "move"), ("o", "open"), ("s", "sync")];
        if !self.conflicts().is_empty() {
            keys.push(("t", "take over"));
        }
        keys.extend([("x", "close"), ("a", "apps"), ("r", "refresh"), ("q", "quit")]);
        b.nl().append(theme::keys(&keys)).nl();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::tests::{Fake, LISTING};
    use crate::tui::apps::tests::{Busy, Open, doors};
    use std::time::Duration;

    impl Busy for Screen {
        fn busy(&self) -> bool {
            !self.waiting.is_empty()
        }
    }

    const TOKEN: &str = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYiLCJzIjoiWldGemVTQjBieUJ6WldVPSJ9";

    fn open(fake: &Arc<Fake>, dir: &crate::testutil::TempDir) -> Open<Screen> {
        let mut o = Open::new(Screen::new(fake.clone(), doors(dir)));
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

    #[test]
    fn each_way_in_and_its_names() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        let v = s.flat();
        assert!(v.contains("> Cloudflare Tunnel") && v.contains("connected with 1 of 2 copies"), "{v}");
        assert!(v.contains("blog.example.com") && v.contains("shop.example.com"), "{v}");
        assert!(v.contains("Your VPS") && v.contains("not set up") && v.contains("comes later"), "{v}");
        s.fits(24);
        // The VPS cannot be opened or closed yet.
        s.key(Key::Down);
        s.key(Key::Char('o'));
        assert!(s.s.notice.contains("a VPS cannot be set up yet"), "{:?}", s.s.notice);
        s.key(Key::Char('x'));
        assert!(s.s.notice.contains("Your VPS is not set up; there is nothing to close"), "{:?}", s.s.notice);
        // a goes to the apps.
        assert_eq!(s.key(Key::Char('a')), Flow::Quit);
        assert_eq!(s.s.next, Some(Place::Apps));
    }

    #[test]
    fn closing_a_way_in_that_apps_use() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let mut s = open(&fake, &dir);
        s.key(Key::Char('x'));
        let v = s.flat();
        assert!(v.contains("Close Cloudflare Tunnel? blog, shop still come in through it: nothing from outside reaches them"), "{v}");
        s.fits(24);
        s.key(Key::Esc);
        assert!(s.s.notice.contains("Nothing changed") && !fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete")));
        s.key(Key::Char('x'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.contains("Cloudflare Tunnel closed"), "{:?}", s.s.notice);
        assert!(
            fake.calls.lock().unwrap().iter().any(|(a, _)| a == "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found")
        );
        // No app on it: nobody to warn about.
        *fake.listing.lock().unwrap() = listing().replace("\"host\":\"blog.example.com\"", "\"host\":\"\"").replace("shop.example.com", "");
        s.key(Key::Char('r'));
        s.settle();
        s.key(Key::Char('x'));
        assert!(s.flat().contains("Close Cloudflare Tunnel? No app comes in through it"), "{}", s.view());
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
        assert_eq!(s.key(Key::Char('a')), Flow::Continue);
        assert!(s.s.notice.contains("Still closing Cloudflare Tunnel. a goes to the apps once that is done"), "{:?}", s.s.notice);
        assert_eq!(s.s.next, None);
        s.settle();
        assert!(s.s.notice.contains("Cloudflare Tunnel closed"), "{:?}", s.s.notice);
        assert_eq!(fake.cut_off.load(std::sync::atomic::Ordering::SeqCst), 0, "the close ran to its end");
        assert_eq!(s.key(Key::Char('a')), Flow::Quit);
        assert_eq!(s.s.next, Some(Place::Apps));
    }

    #[test]
    fn the_tunnel_from_the_saved_token() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let file = dir.join("cloudflare_tunnel_token");
        let mut s = open(&fake, &dir);
        let applied = |f: &Fake| f.calls.lock().unwrap().iter().filter(|(a, _)| a == "apply -f -").count();
        assert!(s.view().contains("> Cloudflare Tunnel   not set up"), "{}", s.view());
        // No token saved: says where it goes, starts nothing.
        s.key(Key::Char('o'));
        assert!(s.s.notice.contains("No tunnel token yet") && s.s.notice.contains("cloudflare_tunnel_token"), "{:?}", s.s.notice);
        s.key(Key::Char('x'));
        assert!(s.s.notice.contains("not set up; there is nothing to close"));
        // Something that is not a token.
        std::fs::write(&file, "my password\n").unwrap();
        s.key(Key::Char('o'));
        assert!(s.s.notice.contains("not a tunnel token"), "{:?}", s.s.notice);
        assert_eq!(applied(&fake), 0);
        // The dashboard's command line, pasted whole. Asks first.
        std::fs::write(&file, format!("cloudflared service install {TOKEN}\n")).unwrap();
        s.key(Key::Char('o'));
        let v = s.flat();
        assert!(v.contains("Open the tunnel with the token from") && v.contains("y to confirm"), "{v}");
        assert!(!v.contains(TOKEN), "the token is never shown");
        s.fits(24);
        s.key(Key::Char('n'));
        assert!(s.s.notice.contains("Nothing changed") && applied(&fake) == 0);
        s.key(Key::Char('o'));
        s.key(Key::Char('y'));
        s.settle();
        assert!(
            s.s.notice.contains("Tunnel starting") && s.s.notice.contains("http://traefik.kube-system.svc.cluster.local:80"),
            "{:?}",
            s.s.notice
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
        let v = s.flat();
        assert!(s.s.notice.contains("Cloudflare Tunnel: nothing to change"), "{:?}", s.s.notice);
        assert!(v.contains("point each of blog.example.com, shop.example.com at"), "{v}");
        s.fits(24);
    }

    #[test]
    fn a_name_claimed_twice() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing().replace("shop.example.com", "blog.example.com");
        let dir = crate::testutil::TempDir::new();
        let s = open(&fake, &dir);
        let v = s.flat();
        assert!(v.contains("! blog.example.com is the public name of blog and shop"), "{v}");
        assert!(v.contains("no app comes in through it"), "neither gets it: {v}");
        s.fits(24);
    }

    #[test]
    fn the_coordinator_off() {
        let fake = Arc::new(Fake::default());
        *fake.delay.lock().unwrap() = Duration::from_secs(30);
        let dir = crate::testutil::TempDir::new();
        let limits = Limits { read: Duration::from_millis(150), change: Duration::from_millis(150), slow: Duration::from_millis(10) };
        let mut s = Open::new(Screen::new(fake.clone(), doors(&dir)).with_limits(limits));
        std::thread::sleep(Duration::from_millis(30));
        assert!(s.view().contains("not answering ("), "{}", s.view());
        let start = Instant::now();
        s.key(Key::Down);
        s.key(Key::Up);
        assert!(start.elapsed() < Duration::from_millis(50));
        s.settle();
        assert!(s.view().contains("Cannot reach the cluster: the coordinator did not answer"), "{}", s.view());
        s.fits(24);
    }

    fn with_api(fake: &Arc<Fake>, dir: &crate::testutil::TempDir, cf: &Arc<FakeCf>) -> Open<Screen> {
        let doors: Entrances = Arc::new(vec![Box::new(entrance(dir.path(), cf, true)), Box::new(entrance::Vps)]);
        let mut o = Open::new(Screen::new(fake.clone(), doors));
        o.settle();
        o
    }

    use crate::entrance::cfsync::tests::{FakeCf, entrance, fresh};
    use std::sync::atomic::Ordering::SeqCst;

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
        s.settle();
        let v = s.flat();
        assert!(v.contains("Cloudflare Tunnel: 6 changes to make, in order:"), "{v}");
        for step in [
            "1. create the tunnel dryserver in Cloudflare",
            "2. route blog.example.com, shop.example.com through the tunnel",
            "3. save the tunnel's token in secrets/cloudflare_tunnel_token",
            "4. switch the cluster from the tunnel it runs now (not dryserver) to",
            "dryserver: names routed to the old one in the dashboard stop working",
            "5. add blog.example.com to DNS",
            "6. add shop.example.com to DNS",
            "y make these changes",
        ] {
            assert!(v.contains(step), "{step:?} not shown:\n{}", s.view());
        }
        assert_eq!(cf.changes.load(SeqCst), 0, "a look changes nothing");
        s.fits(24);
        // Scrolling the list does not answer the question.
        s.key(Key::Down);
        assert!(s.s.confirm.is_some());
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.contains("Cloudflare Tunnel: 6 changes made."), "{:?}", s.s.notice);
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
        assert!(s.s.notice.contains("Cloudflare Tunnel: nothing to change.") && s.s.confirm.is_none(), "{:?}", s.s.notice);
    }

    #[test]
    fn a_name_held_by_something_else() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let cf = Arc::new(fresh());
        {
            let mut c = cf.cf.lock().unwrap();
            c.records.push(crate::entrance::cfsync::Record {
                zone: crate::entrance::cfsync::tests::ZONE.into(),
                id: "f".repeat(32),
                name: "blog.example.com".into(),
                kind: "A".into(),
                content: "203.0.113.7".into(),
                proxied: false,
                comment: String::new(),
            });
        }
        let mut s = with_api(&fake, &dir, &cf);
        s.key(Key::Char('t'));
        assert!(s.s.notice.contains("No name of Cloudflare Tunnel is held by something else"), "{:?}", s.s.notice);
        s.key(Key::Char('s'));
        s.settle();
        s.key(Key::Char('y'));
        s.settle();
        let v = s.flat();
        assert!(v.contains("blog.example.com (blog) is held by A record 203.0.113.7"), "{v}");
        assert!(v.contains("t take over"), "{v}");
        s.fits(24);
        // The A record stays until the admin says so. t looks first and
        // shows every change, the record it deletes and the gap included.
        assert!(cf.cf.lock().unwrap().records.iter().any(|r| r.kind == "A"));
        let before = cf.changes.load(SeqCst);
        s.key(Key::Char('t'));
        s.settle();
        let v = s.flat();
        // The fake cluster still says it runs the other tunnel: the
        // takeover needs the switch too, and says so.
        assert!(v.contains("Take blog.example.com over? Cloudflare Tunnel makes these changes, in order:"), "{}", s.view());
        assert!(v.contains("1. switch the cluster from the tunnel it runs now"), "{}", s.view());
        assert!(v.contains("2. delete the DNS record of blog.example.com (A record 203.0.113.7,"), "{}", s.view());
        assert!(v.contains("taken over; the name does not resolve until the tunnel's record is"), "{}", s.view());
        assert!(v.contains("3. add blog.example.com to DNS"), "{}", s.view());
        assert_eq!(cf.changes.load(SeqCst), before, "a look changes nothing");
        s.fits(24);
        s.key(Key::Char('n'));
        assert!(s.s.notice.contains("Nothing changed"));
        assert!(cf.cf.lock().unwrap().records.iter().any(|r| r.kind == "A"));
        assert!(s.flat().contains("t take over"), "said no to, the name is still offered: {}", s.view());
        s.key(Key::Char('t'));
        s.settle();
        s.key(Key::Char('y'));
        s.settle();
        let recs = cf.cf.lock().unwrap().records.clone();
        assert!(!recs.iter().any(|r| r.kind == "A") && recs.iter().filter(|r| r.name == "blog.example.com").count() == 1, "{recs:?}");
        assert!(!s.flat().contains("t take over"), "{}", s.view());
    }

    #[test]
    fn a_long_plan_scrolls() {
        // Twenty apps: more changes than 24 rows hold. The list scrolls,
        // the screen keeps to 80x24, and y still makes exactly those.
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
        assert!(v.contains("↑↓ to see the rest") && !v.contains("24. add app9.example.com"), "{}", s.view());
        s.fits(24);
        for _ in 0..40 {
            s.key(Key::Down);
        }
        let v = s.flat();
        assert!(v.contains("24. add app9.example.com to DNS") && !v.contains("1. create the tunnel"), "{}", s.view());
        s.fits(24);
        s.key(Key::PageUp);
        s.key(Key::PageUp);
        s.key(Key::PageUp);
        assert!(s.flat().contains("1. create the tunnel"), "{}", s.view());
        s.key(Key::Char('y'));
        s.settle();
        assert!(s.s.notice.contains("Cloudflare Tunnel: 24 changes made."), "{:?}", s.s.notice);
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
        assert!(s.s.notice.contains("not synced: something changed since you looked, so nothing was changed"), "{:?}", s.s.notice);
        assert_eq!(cf.changes.load(SeqCst), 0);
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, _)| a == "apply -f -"));
    }

    #[test]
    fn cloudflare_down() {
        let fake = Arc::new(Fake::default());
        *fake.listing.lock().unwrap() = listing();
        let dir = crate::testutil::TempDir::new();
        let cf = Arc::new(fresh());
        cf.down.store(true, SeqCst);
        let mut s = with_api(&fake, &dir, &cf);
        s.key(Key::Char('s'));
        s.settle();
        assert!(s.s.notice.contains("Cloudflare Tunnel: cannot look: Cloudflare is having trouble"), "{:?}", s.s.notice);
        assert!(s.flat().contains("tunnel keeps running"), "{}", s.view());
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("apply") || a.contains("delete")));
        s.fits(24);
    }
}
