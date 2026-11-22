//! The admin's screen for join requests and members, on the desktop.
//! Every decision made here is signed before it reaches the coordinator.
//!
//! Updates are published here too (u): the admin picks notes, urgent and
//! rollback, the release is checked and shown with what it changes, and y
//! signs and sends it. Checking and sending run on the screen's worker
//! thread, so the screen keeps drawing while a binary of tens of MiB goes
//! to the coordinator. R resumes a stopped rollout, after asking.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::NaiveDate;

use super::worker::{Waiting, Worker};
use super::{Doc, Emit, Event, Flow, Key, Model, TextInput, dim, err, ok, sel, theme};
use crate::admin::{Admin, NewCoordinator, View};
use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::gotime::{Time, duration_string, round_ms};
use crate::mesh;
use crate::publish::{self, Choice, Days, Parts, Plan};
use crate::registry::{Member, Request};
use crate::release::{self, Release};
use crate::report::{self, Concern, percent, short_age};
use crate::rollout;

const REFRESH: Duration = Duration::from_secs(5);
/// After a failed load: do not freeze the screen on every tick.
const RETRY: Duration = Duration::from_secs(15);
/// A member syncs every minute: three without a word and its report is
/// old news.
const STALE: i64 = 180;
/// The most WireGuard peers named in the details; the rest are counted.
const SHOWN_PEERS: usize = 24;

/// Text cut into lines of at most width columns, each starting with
/// indent.
fn wrap(text: &str, width: usize, indent: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::from(indent);
    for word in text.split(' ') {
        let fits = line.chars().count() + 1 + word.chars().count() <= width;
        if line.len() > indent.len() && !fits {
            out.push(std::mem::replace(&mut line, format!("{indent}  ")));
        }
        if line.len() > indent.len() && !line.ends_with(' ') {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.trim().is_empty() {
        out.push(line);
    }
    out
}

/// The second line under a member: what it says about itself. Values that
/// need a look are in the alarm colour; the rest of what needs a look
/// follows them. target is the release the swarm moves to.
fn health(m: &Member, now: Time, target: u64) -> Doc {
    let mut d = Doc::new();
    let Some(r) = &m.report else {
        d.s("    ").add(dim("no report: its dryserver, or the coordinator's, is older than this one"));
        return d;
    };
    let problems = r.problems(m.last_seen);
    let bad = |c: Concern| problems.iter().any(|(k, _)| *k == c);
    let mut items: Vec<(String, bool)> = Vec::new();
    let quiet = now.since(m.last_seen).num_seconds();
    if !m.last_seen.is_zero() && quiet > STALE {
        items.push((format!("silent for {}:", short_age(quiet as u64)), true));
    }
    items.push((if r.dryserver.is_empty() { "?".into() } else { r.dryserver.clone() }, false));
    if let Some(item) = rollout::member_release(r, target) {
        items.push(item);
    }
    if let Some(p) = percent(r.disk_used, r.disk_total) {
        items.push((format!("disk {p}%"), bad(Concern::Disk)));
    }
    if let Some(p) = percent(r.mem_used, r.mem_total) {
        items.push((format!("mem {p}%"), bad(Concern::Memory)));
    }
    if let Some(t) = r.temp {
        items.push((format!("{t}°C"), bad(Concern::Heat)));
    }
    items.push(match r.k3s_active {
        Some(true) => ("k3s on".into(), false),
        Some(false) => ("k3s off".into(), true),
        None => ("no k3s".into(), false),
    });
    items.push(match r.firewall {
        Some(true) => ("firewall on".into(), false),
        Some(false) => ("firewall OFF".into(), true),
        None => ("firewall ?".into(), false),
    });
    for (c, text) in &problems {
        if matches!(c, Concern::Reboot | Concern::Clock | Concern::Upgrade | Concern::Peers | Concern::Boot) {
            items.push((text.clone(), true));
        }
    }
    // As many to a line as fit 80 columns.
    let mut width = 0;
    for (text, alarm) in items {
        let w = text.chars().count();
        if width > 4 && width + 2 + w > 80 {
            d.nl();
            width = 0;
        }
        d.s(if width == 0 { "    " } else { "  " });
        width += if width == 0 { 4 } else { 2 } + w;
        if alarm {
            d.add(err(text));
        } else {
            d.s(text);
        }
    }
    d
}

/// Everything a member says about itself, for the details under the list.
/// names gives the member names by host number, for its WireGuard peers.
fn details(m: &Member, names: &dyn Fn(u32) -> String, now: Time) -> Doc {
    let mut d = Doc::new();
    let Some(r) = &m.report else {
        d.s(format!("{} sends no report: its dryserver, or the coordinator's, is older than this one.", m.name)).nl();
        return d;
    };
    d.s(format!("{}, as it reports itself", m.name)).add(dim(format!(" (relayed by the coordinator, {}):", ago(m.last_seen, now)))).nl();
    let or = |s: &str| if s.is_empty() { "?".to_string() } else { s.to_string() };
    let k3s = match (r.k3s.as_str(), r.k3s_active) {
        ("", _) => "no k3s".to_string(),
        (v, Some(true)) => format!("k3s {v}, running"),
        (v, _) => format!("k3s {v}, STOPPED"),
    };
    let fw = match r.firewall {
        Some(true) => "firewall loaded",
        Some(false) => "FIREWALL NOT LOADED",
        None => "firewall unknown",
    };
    d.s(format!("  dryserver {}   {k3s}   {fw}", or(&r.dryserver))).nl();
    if r.release != 0 || !r.update.is_empty() {
        let mut line = if r.release == 0 { "  no release installed yet".to_string() } else { format!("  release {}", r.release) };
        if !r.update.is_empty() {
            line += &format!("; update {}", r.update);
            if r.update_serial != 0 {
                line += &format!(" (release {})", r.update_serial);
            }
            if !r.update_note.is_empty() {
                line += &format!(": {}", r.update_note);
            }
        }
        for l in wrap(&line, 80, "") {
            if r.update_failed() || r.update == "held" {
                d.add(err(l));
            } else {
                d.s(l);
            }
            d.nl();
        }
    }
    if r.reboot {
        d.s(format!("  kernel {} running, {} installed: ", or(&r.kernel), or(&r.kernel_installed))).add(err("reboot needed")).nl();
    } else {
        d.s(format!("  kernel {}", or(&r.kernel))).nl();
    }
    let upgraded = if r.upgraded > 0 && r.time >= r.upgraded {
        format!("upgraded {} ago", short_age((r.time - r.upgraded) as u64))
    } else {
        "last upgrade unknown".into()
    };
    let [l1, l5, l15] = r.load;
    d.s(format!("  up {}   {upgraded}   load {l1:.2} {l5:.2} {l15:.2} on {} CPUs", short_age(r.uptime), r.cpus)).nl();
    let share = |used: u64, total: u64| match percent(used, total) {
        Some(p) => format!("{} of {} ({p}%)", report::size(used), report::size(total)),
        None => "?".into(),
    };
    let temp = r.temp.map(|t| format!("   {t}°C")).unwrap_or_default();
    d.s(format!("  memory {}   disk {}{temp}", share(r.mem_used, r.mem_total), share(r.disk_used, r.disk_total))).nl();
    match r.clock_offset(m.last_seen) {
        Some(0) => {
            d.s("  clock in step with the coordinator's").nl();
        }
        Some(off) => {
            d.s(format!("  clock {} {} the coordinator's", short_age(off.unsigned_abs()), if off > 0 { "ahead of" } else { "behind" }))
                .nl();
        }
        None => {}
    }
    if r.peers.is_empty() {
        d.s("  WireGuard: nothing reported").nl();
        return d;
    }
    // The silent ones first: they are what to look at.
    let silent = r.silent_peers();
    let mut peers: Vec<&report::Peer> = r.peers.iter().collect();
    peers.sort_by_key(|p| !silent.contains(&p.host));
    d.s("  WireGuard, last handshake:");
    let mut width = 30;
    for p in peers.iter().take(SHOWN_PEERS) {
        let text = format!(" {} {}", names(p.host), p.age.map(short_age).unwrap_or_else(|| "never".into()));
        if width + text.len() > 78 {
            d.nl().s("   ");
            width = 3;
        }
        width += text.len();
        if silent.contains(&p.host) {
            d.add(err(text));
        } else {
            d.s(text);
        }
    }
    if peers.len() > SHOWN_PEERS {
        d.add(dim(format!(" and {} more", peers.len() - SHOWN_PEERS)));
    }
    d.nl();
    d
}

pub enum Msg {
    /// The release to publish, checked, or why not.
    Planned(Result<Box<Plan>>),
    Published(Result<Release>),
}

/// What the screen needs to publish releases. Each job makes its own
/// link to the coordinator on the worker's thread.
pub struct Publisher {
    /// A new Admin with this desktop's keys.
    pub admin: Arc<dyn Fn() -> Result<Admin> + Send + Sync>,
    pub days: Arc<dyn Days>,
    /// This program and the k3s it pins.
    pub parts: Parts,
    /// The date in UTC.
    pub today: fn() -> NaiveDate,
}

enum Job {
    Plan(Choice),
    Publish(Box<Plan>),
}

const CHECKING: &str = "checking the release: binary, k3s file, Arch archive, coordinator";

impl Job {
    fn label(&self) -> String {
        match self {
            Job::Plan(_) => CHECKING.into(),
            Job::Publish(p) => format!("publishing release {}", p.release.serial),
        }
    }
}

fn work(ctx: &Ctx, p: &Publisher, job: Job) -> Msg {
    match job {
        Job::Plan(c) => Msg::Planned((|| {
            let mut a = (p.admin)()?;
            let v = a.load()?;
            publish::plan(ctx, &a, &v, p.days.as_ref(), &p.parts, &c, (p.today)()).map(Box::new)
        })()),
        Job::Publish(plan) => Msg::Published((|| {
            let mut a = (p.admin)()?;
            publish::publish(&mut a, &plan)
        })()),
    }
}

/// The admin's choices for a new release, before anything is checked.
struct Form {
    notes: TextInput,
    urgent: bool,
    rollback: bool,
    /// 0 the notes, 1 urgent, 2 rollback.
    focus: usize,
}

impl Form {
    fn new(c: &Choice) -> Form {
        let mut notes = TextInput::new(release::MAX_NOTES);
        notes.set_value(&c.notes);
        notes.placeholder = "what it is for, like: fixes the join timeout".into();
        notes.focus();
        Form { notes, urgent: c.urgent, rollback: c.rollback, focus: 0 }
    }

    fn choice(&self) -> Choice {
        Choice { notes: self.notes.value.trim().to_string(), urgent: self.urgent, rollback: self.rollback, ..Choice::default() }
    }

    fn move_focus(&mut self, by: usize) {
        self.focus = (self.focus + by) % 3;
        if self.focus == 0 {
            self.notes.focus();
        } else {
            self.notes.blur();
        }
    }
}

/// "42s ago", "3m0s ago", "never".
fn ago(t: Time, now: Time) -> String {
    if t.is_zero() {
        return "never".into();
    }
    let ms = now.since(t).num_milliseconds();
    let secs = round_ms(ms, 1000) / 1000;
    if secs < 60 {
        return format!("{} ago", duration_string(secs));
    }
    format!("{} ago", duration_string(round_ms(secs * 1000, 60_000) / 1000))
}

#[derive(Debug, Clone, PartialEq)]
enum Action {
    /// The waiting request as the admin saw it: its id, name and keys,
    /// which its code covers. The desktop signs exactly those.
    Approve(Request),
    Reject(Request),
    Remove(String),
    /// The first signature: the coordinator's own entry.
    SignCoordinator,
    /// A reinstalled coordinator takes the old one's place.
    NewCoordinator(NewCoordinator),
    Resend,
    /// Let a stopped rollout go on.
    Resume,
}

pub struct Screen {
    admin: Admin,
    subnet: String,
    now: fn() -> Time,
    view: View,
    err: Option<Error>,
    cursor: usize,
    /// A decision waiting for "y", with the question shown.
    confirm: Option<(String, Action)>,
    pub notice: String,
    last_load: Option<Instant>,
    /// Everything the selected member reports, under the list.
    details: bool,
    /// Publishing; None: this screen cannot (u says so).
    publisher: Option<Arc<Publisher>>,
    worker: Option<Worker<Job>>,
    waiting: Waiting,
    /// The choices for a new release, while the admin makes them; the
    /// last ones are kept for the next try.
    form: Option<Form>,
    choice: Choice,
    /// A checked release waiting for "y".
    plan: Option<Box<Plan>>,
    /// q was pressed once while a publish ran.
    quit_armed: bool,
    /// What to tell the admin after the screen closed.
    after: Option<String>,
}

impl Screen {
    pub fn new(admin: Admin) -> Screen {
        let subnet = admin.subnet.clone();
        Screen {
            admin,
            subnet,
            now: Time::now,
            view: View::default(),
            err: None,
            cursor: 0,
            confirm: None,
            notice: String::new(),
            last_load: None,
            details: false,
            publisher: None,
            worker: None,
            waiting: Waiting::default(),
            form: None,
            choice: Choice::default(),
            plan: None,
            quit_armed: false,
            after: None,
        }
    }

    pub fn with_publisher(mut self, p: Publisher) -> Screen {
        self.publisher = Some(Arc::new(p));
        self
    }

    /// What the admin should know once the screen is closed: a publish
    /// it cut off.
    pub fn after(&self) -> Option<&str> {
        self.after.as_deref()
    }

    fn start(&mut self, emit: &Emit<Msg>) {
        let Some(p) = self.publisher.clone() else { return };
        let emit = emit.clone();
        self.worker = Some(Worker::start(move |ctx, job| emit(work(ctx, &p, job))));
    }

    fn send(&mut self, job: Job) {
        let (label, change) = (job.label(), matches!(job, Job::Publish(_)));
        if self.worker.as_ref().is_some_and(|w| w.send(job)) {
            self.waiting.push(label, change);
        } else {
            self.notice = "The background worker stopped; quit and open the screen again.".into();
        }
    }

    fn answer(&mut self, m: Msg) {
        self.waiting.pop();
        match m {
            Msg::Planned(Ok(p)) => {
                self.notice.clear();
                self.plan = Some(p);
            }
            Msg::Planned(Err(e)) => self.notice = format!("Not published, nothing was signed: {e}"),
            Msg::Published(res) => {
                self.quit_armed = false;
                self.notice = match res {
                    Ok(r) => {
                        // The next release starts from fresh choices.
                        self.choice = Choice::default();
                        format!(
                            "Release {} is on the coordinator. It updates itself first, then one server at a time; \
                             Updates below shows how it goes.",
                            r.serial
                        )
                    }
                    Err(e) => format!("Not published: {e}"),
                };
                self.load();
            }
        }
    }

    /// u: the form for a new release, unless one is on its way.
    fn open_form(&mut self) {
        if self.publisher.is_none() {
            self.notice = "This screen cannot publish; use ./dryserver release publish".into();
        } else if let Some(what) = self.waiting.change() {
            self.notice = format!("Still {what}: one release at a time.");
        } else if self.waiting.has(CHECKING) {
            self.notice = "Already checking a release: wait for it.".into();
        } else {
            self.notice.clear();
            self.form = Some(Form::new(&self.choice));
        }
    }

    fn form_key(&mut self, mut f: Form, k: Key) {
        match k {
            Key::Esc => {
                self.choice = f.choice();
                self.notice = "Nothing signed.".into();
                return;
            }
            Key::Enter => {
                self.choice = f.choice();
                self.send(Job::Plan(self.choice.clone()));
                return;
            }
            Key::Tab | Key::Down => f.move_focus(1),
            Key::BackTab | Key::Up => f.move_focus(2),
            Key::Char(' ') if f.focus == 1 => f.urgent = !f.urgent,
            Key::Char(' ') if f.focus == 2 => f.rollback = !f.rollback,
            k if f.focus == 0 => {
                f.notes.handle(&k);
            }
            _ => {}
        }
        self.form = Some(f);
    }

    /// The form, in place of the screen.
    fn form_view(&self, f: &Form) -> Doc {
        let mut b = Doc::new();
        let version = self.publisher.as_ref().map(|p| p.parts.version.clone()).unwrap_or_default();
        b.s("Publish an update\n");
        let intro = format!(
            "A release of this dryserver ({version}) for every machine, with the k3s it pins and the newest Arch \
             snapshot day. Nothing is signed before you have seen what changes."
        );
        b.add(dim(super::wrap(&format!("  {intro}"), 78))).nl().nl();
        let label = |b: &mut Doc, i: usize, name: &str| {
            if f.focus == i {
                b.add(sel(format!("> {name:<9} ")));
            } else {
                b.s(format!("  {name:<9} "));
            }
        };
        label(&mut b, 0, "notes");
        b.append(f.notes.view()).nl();
        let check = |on: bool| if on { "[x]" } else { "[ ]" };
        label(&mut b, 1, "urgent");
        b.s(format!("{} ", check(f.urgent)))
            .add(dim(format!("roll out at once, not only in the window {}", rollout::window_text(rollout::WINDOW))))
            .nl();
        label(&mut b, 2, "rollback");
        b.s(format!("{} ", check(f.rollback))).add(dim("allow older versions than the swarm runs (the way back)")).nl();
        b.nl().append(theme::keys(&[("tab", "next"), ("space", "switch"), ("enter", "see what changes"), ("esc", "cancel")])).nl();
        b
    }

    /// The checked release, in place of the screen, waiting for y.
    fn plan_view(&self, p: &Plan) -> Doc {
        let mut b = Doc::new();
        b.add(err("Sign and send this release to the coordinator?")).nl();
        for line in p.lines() {
            b.s(super::wrap(&format!("  {line}"), 78)).nl();
        }
        b.nl().append(theme::keys(&[("y", "sign and send it"), ("other keys", "nothing is signed")])).nl();
        b
    }

    pub fn load(&mut self) {
        self.last_load = Some(Instant::now());
        match self.admin.load() {
            Ok(v) => {
                self.view = v;
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
        let n = self.view.pending.len() + self.view.members.len();
        self.cursor = self.cursor.min(n.saturating_sub(1));
    }

    fn run(&mut self, a: Action) {
        let res: Result<String> = match &a {
            Action::Approve(r) => {
                self.admin.approve(r).map(|host| format!("{} approved and signed as {}.", r.name, mesh::ip(&self.subnet, host)))
            }
            Action::Reject(r) => self.admin.reject(r).map(|_| format!("{} rejected.", r.name)),
            Action::Remove(name) => self.admin.remove(name).map(|_| format!("{name} removed; servers drop it within a minute.")),
            Action::SignCoordinator => self.admin.sign_coordinator().map(|_| "Coordinator signed. New machines can join now.".to_string()),
            Action::NewCoordinator(c) => self.admin.accept_new_coordinator(c).map(|_| {
                format!("{} is your coordinator now, with every machine you signed before. Let the servers follow it: ./dryserver quarantine-all -lift", c.name)
            }),
            Action::Resend => self.admin.resend().map(|v| format!("Signed list sent again as version {v}.")),
            Action::Resume => publish::resume(&mut self.admin)
                .map(|what| format!("Resumed: the coordinator {what}, at its next sync (within a minute)."))
                .map_err(|e| e.wrap("not resumed")),
        };
        self.notice = res.unwrap_or_else(|e| format!("Failed: {e}"));
        self.load();
    }

    /// R: asks first, saying what resuming does, or why there is nothing
    /// to resume.
    fn ask_resume(&mut self) {
        match publish::resume_does(&self.view.rollout) {
            Ok(what) => {
                let q = format!("Resume the rollout of release {}? The coordinator then {what}.", self.view.rollout.serial);
                self.confirm = Some((format!("{q} y to confirm"), Action::Resume));
            }
            Err(e) => self.notice = format!("Nothing to resume: {e}."),
        }
    }

    /// Runs a right away, or asks first when it would also drop members
    /// that are on the coordinator but not signed.
    fn decide(&mut self, a: Action, question: Option<String>, keep: &[String]) {
        let dropped = self.admin.would_drop(keep);
        let mut q = question.unwrap_or_default();
        if !dropped.is_empty() {
            if !q.is_empty() {
                q.push(' ');
            }
            q += &format!("This also drops {} from the swarm (on the coordinator, not signed by you).", dropped.join(", "));
        }
        if q.is_empty() {
            self.run(a);
        } else {
            self.confirm = Some((format!("{q} y to confirm"), a));
        }
    }

    pub fn key(&mut self, k: Key) -> Flow {
        let flow = self.key_inner(k);
        if flow == Flow::Quit
            && let Some(what) = self.waiting.change()
        {
            self.after = Some(format!(
                "The screen closed while {what}. The upload stopped half way, and a cut-off upload is not taken: \
                 ./dryserver release status shows whether it arrived. Publish again if not (it gets a new serial)."
            ));
        }
        flow
    }

    fn key_inner(&mut self, k: Key) -> Flow {
        if k == Key::Ctrl('c') {
            return Flow::Quit;
        }
        if let Some(p) = self.plan.take() {
            if k == Key::Char('y') {
                self.notice.clear();
                self.send(Job::Publish(p));
            } else {
                self.notice = "Nothing signed.".into();
            }
            return Flow::Continue;
        }
        if let Some(f) = self.form.take() {
            self.form_key(f, k);
            return Flow::Continue;
        }
        if let Some((_, a)) = self.confirm.take() {
            if k == Key::Char('y') {
                self.run(a);
            } else {
                self.notice = "Nothing changed.".into();
            }
            return Flow::Continue;
        }
        let pending = self.view.pending.clone();
        let members = self.view.members.clone();
        let n = pending.len() + members.len();
        let member = self.cursor.checked_sub(pending.len()).and_then(|i| members.get(i)).cloned();
        let armed = std::mem::take(&mut self.quit_armed);
        match k {
            Key::Esc if self.details => self.details = false,
            Key::Char('q') | Key::Esc => match self.waiting.change() {
                Some(what) if !armed => {
                    self.notice = format!("Still {what}. Press q again to quit anyway: the upload stops half way.");
                    self.quit_armed = true;
                }
                _ => return Flow::Quit,
            },
            Key::Char('u') => self.open_form(),
            Key::Char('R') => self.ask_resume(),
            Key::Char('i') => self.details = !self.details,
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(n.saturating_sub(1)),
            Key::Char(c @ ('a' | 'r')) => {
                let Some(r) = pending.get(self.cursor).cloned() else {
                    self.notice = "Select a waiting request first.".into();
                    return Flow::Continue;
                };
                let a = if c == 'a' { Action::Approve(r) } else { Action::Reject(r) };
                self.decide(a, None, &[]);
            }
            Key::Char('d') => {
                let Some((m, _)) = member else { return Flow::Continue };
                if m.host == 1 {
                    self.notice = "The coordinator cannot be removed.".into();
                    return Flow::Continue;
                }
                let q = format!("Remove {} from the swarm?", m.name);
                self.decide(Action::Remove(m.name.clone()), Some(q), std::slice::from_ref(&m.name));
            }
            Key::Char('S') => {
                if self.view.version != 0 {
                    self.notice = if self.view.unsigned().is_empty() {
                        "The coordinator is signed.".into()
                    } else {
                        "Only the coordinator is signed without a request. Machines marked NOT SIGNED were put on the coordinator \
                         without you: press p to drop them."
                            .into()
                    };
                } else if self.view.coordinator_code.is_empty() {
                    self.notice = "The coordinator sent no entry for itself.".into();
                } else {
                    let q = format!(
                        "Sign the coordinator? Its screen must show the code {} (shown after its install).",
                        self.view.coordinator_code
                    );
                    self.decide(Action::SignCoordinator, Some(q), &[]);
                }
            }
            Key::Char('N') => {
                if !self.err.as_ref().is_some_and(|e| e.is(Kind::HostKey)) {
                    self.notice = "N is for a reinstalled coordinator. The one this computer knows answers fine.".into();
                    return Flow::Continue;
                }
                match self.admin.probe_new_coordinator() {
                    Ok(c) => {
                        let q = format!(
                            "The machine at the coordinator's address was installed from your USB stick as coordinator {}. \
                             Its screen must show the code {}. Make it your coordinator?",
                            c.name, c.code
                        );
                        self.confirm = Some((format!("{q} y to confirm"), Action::NewCoordinator(c)));
                    }
                    Err(e) => self.notice = format!("Not a coordinator of yours: {e}"),
                }
            }
            Key::Char('p') => self.run(Action::Resend),
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
                let wait = if self.err.is_some() { RETRY } else { REFRESH };
                // Not while the admin types or reads: a load holds the
                // screen for a moment.
                let busy = self.confirm.is_some() || self.form.is_some() || self.plan.is_some();
                if !busy && self.last_load.is_none_or(|t| t.elapsed() >= wait) {
                    self.load();
                }
                Flow::Continue
            }
            _ => Flow::Continue,
        }
    }

    fn view(&self) -> Doc {
        let mut b = Doc::new();
        let now = (self.now)();
        b.append(theme::header("machines")).s("   ").add(dim("what you decide here is signed with this computer's key")).s("\n\n");
        // Choosing and confirming a release take the whole screen.
        if let Some(f) = &self.form {
            b.append(self.form_view(f));
            return b;
        }
        if let Some(p) = &self.plan {
            b.append(self.plan_view(p));
            return b;
        }
        if let Some(e) = &self.err {
            b.add(err(format!("Cannot talk to the coordinator: {e}"))).s("\n\n");
            if e.is(Kind::HostKey) {
                b.s("If you reinstalled the coordinator from your USB stick, press N to look at the new one.\n");
                b.add(dim("If you did not, something else answers at its address: change nothing.")).s("\n\n");
            }
        }
        let line = |b: &mut Doc, i: usize, text: String| {
            if i == self.cursor {
                b.add(sel(format!("> {text}"))).nl();
            } else {
                b.s(format!("  {text}")).nl();
            }
        };
        let pending = &self.view.pending;
        b.s("Waiting to join:\n");
        if pending.is_empty() {
            b.add(dim("  none. New machines show up here after their setup finishes.")).nl();
        }
        for (i, r) in pending.iter().enumerate() {
            let text = format!("{:<14} {:<15} code {}   {}", r.name, r.lan_ip, r.code, ago(r.created, now));
            if !self.view.unproved.contains(&r.id) {
                line(&mut b, i, text);
                continue;
            }
            if i == self.cursor {
                b.add(sel(format!("> {text}")));
            } else {
                b.s(format!("  {text}"));
            }
            b.s("  ").add(err("NO PROOF")).nl();
        }
        if !self.view.unproved.is_empty() {
            b.add(err("  NO PROOF: not installed from your USB stick, or changed by the coordinator. Cannot be approved; reject it (r)."))
                .nl();
        }
        if !pending.is_empty() {
            b.add(dim("  Approve only if the code matches the one on the new machine's screen.")).nl();
        }

        b.s("\nMembers, each with what it reports about itself:\n");
        if !self.view.members.is_empty() {
            b.add(dim(format!("  {:<14} {:<11} {:<15} {:<6} seen", "name", "mesh", "LAN", "link"))).nl();
        }
        for (i, (m, signed)) in self.view.members.iter().enumerate() {
            let link = if m.switch { "switch" } else { "router" };
            let text =
                format!("{:<14} {:<11} {:<15} {:<6} {:<10}", m.name, mesh::ip(&self.subnet, m.host), m.lan_ip, link, ago(m.last_seen, now));
            if i + pending.len() == self.cursor {
                b.add(sel(format!("> {text}")));
            } else {
                b.s(format!("  {text}"));
            }
            if *signed {
                b.s(" ").add(ok("signed")).nl();
            } else {
                b.s(" ").add(err("NOT SIGNED")).nl();
            }
            b.append(health(m, now, self.view.rollout.serial)).nl();
        }
        if self.view.version == 0 && !self.view.members.is_empty() {
            b.add(dim("  Nothing signed yet. Press S to sign the coordinator; then machines can join.")).nl();
        } else if !self.view.unsigned().is_empty() {
            b.add(err("  NOT SIGNED: put on the coordinator without you. Servers ignore it. Press p to drop it.")).nl();
        }
        if self.details {
            let selected = self.cursor.checked_sub(pending.len()).and_then(|i| self.view.members.get(i));
            b.nl();
            match selected {
                Some((m, _)) => {
                    let names = |host: u32| {
                        self.view
                            .members
                            .iter()
                            .find(|(o, _)| o.host == host)
                            .map(|(o, _)| o.name.clone())
                            .unwrap_or_else(|| host.to_string())
                    };
                    b.append(details(m, &names, now));
                }
                None => {
                    b.add(dim("Select a member to see what it reports.")).nl();
                }
            }
        }

        // The newest release and its rollout, on the coordinator's clock.
        b.s("\nUpdates:\n");
        if let Some(r) = &self.view.release {
            for l in wrap(&rollout::release_line(r), 80, "  ") {
                b.s(l).nl();
            }
        }
        let at = if self.view.coordinator_now > 0 { self.view.coordinator_now } else { now.0.timestamp() };
        for (text, alarm) in publish::rollout_lines(&self.view, at) {
            for l in wrap(&text, 80, "  ") {
                if alarm {
                    b.add(err(l));
                } else {
                    b.add(dim(l));
                }
                b.nl();
            }
        }
        if let Some(hint) = publish::stopped_keys(&self.view.rollout) {
            for l in wrap(&hint, 80, "  ") {
                b.add(err(l)).nl();
            }
        }

        if !self.view.unknown.is_empty() {
            b.s(format!("\nUnknown devices on the network (scan {}):\n", ago(self.view.scanned, now)));
            for d in &self.view.unknown {
                let ssh = if d.ssh { "  SSH open" } else { "" };
                b.add(dim(format!("  {:<15} {}  {}{ssh}", d.ip, d.mac, d.vendor))).nl();
            }
        }

        if !self.view.reports.is_empty() {
            b.s("\nCut off:\n");
            for r in &self.view.reports {
                b.add(err(format!("  {r}"))).nl();
            }
        }
        if !self.view.warnings.is_empty() {
            b.nl();
            for w in &self.view.warnings {
                b.add(err(format!("! {w}"))).nl();
            }
        }
        b.nl();
        if self.view.version == 0 {
            b.add(dim("Nothing is signed yet.")).nl();
        } else {
            b.add(dim(format!("Signed list version {}.", self.view.version))).nl();
        }
        if let Some(w) = self.waiting.view(Duration::from_secs(30), "still going") {
            b.nl().append(w).nl();
        }
        if let Some((q, _)) = &self.confirm {
            b.nl().add(err(super::wrap(q, 78))).nl();
        } else if !self.notice.is_empty() {
            b.nl().s(super::wrap(&self.notice, 78)).nl();
        }
        // Three lines, so each fits 80 columns.
        let mut keys = vec![("↑↓", "select"), ("a", "approve"), ("r", "reject"), ("d", "remove")];
        if self.view.version == 0 {
            keys.push(("S", "sign coordinator"));
        }
        let more = [("i", if self.details { "hide details" } else { "details" }), ("p", "send list again"), ("q", "quit")];
        let updates = [("u", "publish an update"), ("R", "resume a stopped rollout")];
        b.nl().append(theme::keys(&keys)).nl().append(theme::keys(&more)).nl().append(theme::keys(&updates)).nl();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::tests::{COORD_KEY, SECRET, key32, move_to, reinstalled, request, setup};
    use crate::registry::{Heartbeat, Member};
    use crate::report::Report;
    use crate::testutil::TempDir;

    #[test]
    fn ago_like_go() {
        let t = Time::ymd_hms(2026, 1, 1, 12, 0, 0);
        assert_eq!(ago(Time::zero(), t), "never");
        assert_eq!(ago(t, t.add(chrono::TimeDelta::seconds(42))), "42s ago");
        assert_eq!(ago(t, t.add(chrono::TimeDelta::seconds(150))), "3m0s ago");
    }

    #[test]
    fn approve_reject_remove() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store
            .update(|s| {
                for (name, seed) in [("node-a", 2), ("node-b", 3)] {
                    s.add_request(request(name, seed), COORD_KEY, Time::now())?;
                }
                Ok(())
            })
            .unwrap();
        let mut s = Screen::new(admin);
        s.load();
        let v = s.view().plain();
        assert!(v.contains("node-a") && v.contains("code ") && v.contains("NOT SIGNED") && v.contains("Nothing is signed yet"), "{v}");

        s.key(Key::Char('a'));
        assert!(s.notice.contains("node-a approved and signed as 10.66.0.2"), "{:?}", s.notice);
        s.key(Key::Char('r'));
        assert!(s.notice.contains("node-b rejected"), "{:?}", s.notice);
        let st = store.read().unwrap();
        assert_eq!(st.members.len(), 2);
        assert!(st.pending().is_empty() && st.signed_version > 0);
        let v = s.view().plain();
        assert!(!v.contains("NOT SIGNED") && v.contains("Signed list version"), "{v}");

        // The coordinator stays; removing a member asks first.
        s.key(Key::Char('d'));
        assert!(s.notice.contains("cannot be removed"), "{:?}", s.notice);
        s.key(Key::Down);
        s.key(Key::Char('d'));
        assert!(s.view().plain().contains("Remove node-a from the swarm? y to confirm"));
        s.key(Key::Char('n'));
        assert_eq!(store.read().unwrap().members.len(), 2, "anything but y must change nothing");
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        assert_eq!(store.read().unwrap().members.len(), 1);
        s.key(Key::Char('a'));
        assert!(s.notice.contains("Select a waiting request"));
    }

    #[test]
    fn unsigned_members_are_never_signed_here() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store
            .update(|s| {
                s.members.push(Member { host: 3, name: "rogue".into(), wg_key: key32(3), ..Member::default() });
                s.add_request(request("node-n", 9), COORD_KEY, Time::now())?;
                Ok(())
            })
            .unwrap();
        let mut s = Screen::new(admin);
        s.load();
        assert!(s.view().plain().contains("Press S to sign the coordinator"), "{}", s.view().plain());

        // The first signature asks for the coordinator's code and says
        // that the machine nobody approved is dropped.
        s.key(Key::Char('S'));
        let v = s.view().plain();
        let code = crate::registry::coordinator_code(&key32(1), COORD_KEY);
        assert!(v.contains(&format!("Its screen must show the code {code}")) && v.contains("This also drops rogue from the swarm"), "{v}");
        s.key(Key::Esc);
        assert_eq!(store.read().unwrap().signed_version, 0, "anything but y must sign nothing");
        s.key(Key::Char('S'));
        s.key(Key::Char('y'));
        assert!(s.notice.contains("Coordinator signed"), "{:?}", s.notice);
        let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["coord"]);

        // Later a machine appears on the coordinator without a request:
        // there is no key that signs it.
        store
            .update(|st| {
                st.members.push(Member { host: 7, name: "late".into(), wg_key: key32(7), ..Member::default() });
                Ok(())
            })
            .unwrap();
        s.load();
        let v = s.view().plain();
        assert!(v.contains("NOT SIGNED: put on the coordinator without you"), "{v}");
        s.key(Key::Down);
        s.key(Key::Down);
        s.key(Key::Char('s'));
        s.key(Key::Char('y'));
        assert_eq!(store.read().unwrap().members.len(), 2, "s must do nothing");
        s.key(Key::Char('S'));
        assert!(s.notice.contains("press p to drop them"), "{:?}", s.notice);
        assert!(!s.view().plain().contains("y to confirm"));
        // Approving the real request drops it, after asking.
        s.key(Key::Home);
        s.key(Key::Char('k'));
        s.key(Key::Char('k'));
        s.key(Key::Char('a'));
        assert!(s.view().plain().contains("This also drops late from the swarm"), "{}", s.view().plain());
        s.key(Key::Char('y'));
        let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["coord", "node-n"]);
    }

    #[test]
    fn unproved_requests_are_marked_and_refused() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store
            .update(|s| {
                let mut r = request("node-x", 5);
                r.wg_key = key32(55);
                s.add_request(r, COORD_KEY, Time::now())?;
                Ok(())
            })
            .unwrap();
        let mut s = Screen::new(admin);
        s.load();
        let v = s.view().plain();
        assert!(v.contains("node-x") && v.contains("NO PROOF: not installed from your USB stick"), "{v}");
        s.key(Key::Char('a'));
        assert!(s.notice.contains("Failed") && s.notice.contains("no valid proof"), "{:?}", s.notice);
        assert_eq!(store.read().unwrap().members.len(), 1);
        s.key(Key::Char('r'));
        assert!(s.notice.contains("node-x rejected"), "{:?}", s.notice);
    }

    #[test]
    fn a_reinstalled_coordinator_is_offered_and_taken() {
        let dir = TempDir::new();
        let (mut admin, store) = setup(&dir);
        store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
        admin.load().unwrap();
        admin.approve(&store.read().unwrap().requests[0]).unwrap();

        // Something without the stick's proof answers at the address.
        let (fake, key) = reinstalled(&dir, "coord", "another-secret-another-secret-another-secret");
        move_to(&mut admin, &fake, &key);
        let mut s = Screen::new(admin);
        s.load();
        let v = s.view().plain();
        assert!(v.contains("does not have the SSH key this computer saw before") && v.contains("press N to look at the new one"), "{v}");
        s.key(Key::Char('N'));
        assert!(s.notice.contains("Not a coordinator of yours") && s.notice.contains("no valid proof"), "{:?}", s.notice);
        assert!(!s.view().plain().contains("y to confirm"));

        // The real reinstall.
        let dir2 = TempDir::new();
        let (mut admin, store) = setup(&dir2);
        store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
        admin.load().unwrap();
        admin.approve(&store.read().unwrap().requests[0]).unwrap();
        let (new_store, key) = reinstalled(&dir2, "coord", SECRET);
        let pinned = move_to(&mut admin, &new_store, &key);
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('N'));
        let v = s.view().plain();
        let code = crate::registry::coordinator_code(&key32(41), &key);
        assert!(v.contains(&format!("Its screen must show the code {code}")) && v.contains("y to confirm"), "{v}");
        s.key(Key::Char('n'));
        assert_eq!(*pinned.lock().unwrap(), COORD_KEY, "saying no must change nothing");
        s.key(Key::Char('N'));
        s.key(Key::Char('y'));
        assert!(s.notice.contains("coord is your coordinator now") && s.notice.contains("quarantine-all -lift"), "{:?}", s.notice);
        assert_eq!(new_store.read().unwrap().members.len(), 2);
        let v = s.view().plain();
        assert!(!v.contains("Cannot talk") && v.contains("node-a") && !v.contains("NOT SIGNED"), "{v}");
        // With a coordinator that answers, N does nothing.
        s.key(Key::Char('N'));
        assert!(s.notice.contains("answers fine"), "{:?}", s.notice);
    }

    /// A healthy machine's report, as gather makes it.
    fn healthy(now: i64) -> Report {
        Report {
            format: report::FORMAT,
            time: now,
            dryserver: "0.1.0".into(),
            k3s: "v1.31.4+k3s1".into(),
            kernel: "6.12.1-arch1-1".into(),
            kernel_installed: "6.12.1-arch1-1".into(),
            upgraded: now - 2 * 86_400,
            uptime: 3 * 86_400,
            load: [0.5, 0.4, 0.3],
            cpus: 4,
            mem_used: 1 << 30,
            mem_total: 4 << 30,
            disk_used: 20 << 30,
            disk_total: 50 << 30,
            temp: Some(48),
            k3s_active: Some(true),
            firewall: Some(true),
            peers: vec![report::Peer { host: 2, age: Some(12) }],
            ..Report::default()
        }
    }

    /// The styled pieces of a doc whose text is exactly text.
    fn styled(d: &Doc, text: &str) -> Vec<ratatui::style::Style> {
        d.lines.iter().flatten().filter(|s| s.0 == text).map(|s| s.1).collect()
    }

    #[test]
    fn members_show_what_they_report() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('a'));
        // Nobody has sent a report yet (an older dryserver sends none).
        assert!(s.view().plain().contains("no report: its dryserver"), "{}", s.view().plain());

        let now = Time::now().0.timestamp();
        let sick = Report {
            time: now - 600,
            reboot: true,
            kernel_installed: "6.12.4-arch1-1".into(),
            disk_used: 95,
            disk_total: 100,
            k3s_active: Some(false),
            firewall: Some(false),
            peers: vec![report::Peer { host: 1, age: None }],
            boot: "fallback".into(),
            ..healthy(now)
        };
        store
            .update(|st| {
                let hb = |lan: &str, r: Report| Heartbeat { lan_ip: lan.into(), report: Some(r), ..Heartbeat::default() };
                st.heartbeat(1, hb("192.168.1.50", healthy(now)), Time::now())?;
                st.heartbeat(2, hb("192.168.1.23", sick), Time::now())
            })
            .unwrap();
        s.load();
        let doc = s.view();
        let v = doc.plain();
        assert!(v.contains("Members, each with what it reports about itself"), "{v}");
        assert!(v.contains("    0.1.0  disk 40%  mem 25%  48°C  k3s on  firewall on\n"), "{v}");
        for want in ["disk 95%", "k3s off", "firewall OFF", "reboot needed", "clock 10m behind", "1 silent peer", "running fallback kernel"]
        {
            assert!(v.contains(want), "{want}: {v}");
            assert_eq!(styled(&doc, want), vec![crate::tui::err_style()], "{want} must be an alarm");
        }
        assert_eq!(styled(&doc, "k3s on"), vec![ratatui::style::Style::new()], "a healthy value is plain");
        for line in v.lines() {
            assert!(line.chars().count() <= 80, "wider than 80 columns: {line:?}");
        }

        // The details of the coordinator, then of node-a.
        s.key(Key::Char('i'));
        let v = s.view().plain();
        for want in [
            "coord, as it reports itself (relayed by the coordinator",
            "dryserver 0.1.0   k3s v1.31.4+k3s1, running   firewall loaded",
            "kernel 6.12.1-arch1-1\n",
            "up 3d   upgraded 2d ago   load 0.50 0.40 0.30 on 4 CPUs",
            "memory 1.0 GiB of 4.0 GiB (25%)   disk 20.0 GiB of 50.0 GiB (40%)   48°C",
            "WireGuard, last handshake: node-a 12s",
            "i hide details",
        ] {
            assert!(v.contains(want), "{want}: {v}");
        }
        s.key(Key::Down);
        let v = s.view().plain();
        for want in [
            "node-a, as it reports itself",
            "k3s v1.31.4+k3s1, STOPPED   FIREWALL NOT LOADED",
            "kernel 6.12.1-arch1-1 running, 6.12.4-arch1-1 installed: reboot needed",
            "clock 10m behind the coordinator's",
            "WireGuard, last handshake: coord never",
        ] {
            assert!(v.contains(want), "{want}: {v}");
        }
        for line in v.lines() {
            assert!(line.chars().count() <= 80, "wider than 80 columns: {line:?}");
        }
        // Esc closes the details first; it quits only after that.
        assert_eq!(s.key(Key::Esc), Flow::Continue);
        assert!(!s.view().plain().contains("as it reports itself"));
        assert_eq!(s.key(Key::Esc), Flow::Quit);
    }

    #[test]
    fn a_report_is_the_machines_word_and_only_about_itself() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('a'));
        // A hacked coordinator writes what it likes into a report, past
        // the checks on its own heartbeat path.
        let now = Time::now().0.timestamp();
        store
            .update(|st| {
                let m = st.members.iter_mut().find(|m| m.host == 2).unwrap();
                m.last_seen = Time::now();
                m.report = Some(Report {
                    dryserver: "0.1.0\u{1b}]52;c;ZXZpbA==\u{7}".into(),
                    kernel: "x".repeat(300),
                    temp: Some(9999),
                    peers: (0..2000).map(|h| report::Peer { host: h, age: Some(5) }).collect(),
                    ..healthy(now)
                });
                Ok(())
            })
            .unwrap();
        s.load();
        s.key(Key::Down);
        s.key(Key::Char('i'));
        let v = s.view().plain();
        assert!(!v.contains('\u{1b}') && !v.contains("xxxx") && !v.contains("9999"), "{v}");
        assert!(v.contains("WireGuard, last handshake: coord 5s\n"), "only members are peers, never itself: {v}");
        // The coordinator's own row is untouched by it.
        s.key(Key::Up);
        assert!(s.view().plain().contains("coord sends no report"), "{}", s.view().plain());
        // A machine that went quiet: its report is old news.
        store
            .update(|st| {
                st.members.iter_mut().find(|m| m.host == 2).unwrap().last_seen = Time::now().add(chrono::TimeDelta::minutes(-10));
                Ok(())
            })
            .unwrap();
        s.load();
        let doc = s.view();
        assert_eq!(styled(&doc, "silent for 10m:"), vec![crate::tui::err_style()], "{}", doc.plain());
    }

    #[test]
    fn the_release_and_its_rollout_are_shown() {
        use crate::rollout::{Pause, Phase, Rollout};
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('a'));
        assert!(s.view().plain().contains("No release published yet: ./dryserver release publish"), "{}", s.view().plain());

        // A release on the coordinator, its rollout stopped at node-a.
        let now = Time::now().0.timestamp();
        let r = crate::release::Release {
            serial: 1_795_000_000,
            created: now - 3600,
            expires: now + crate::release::LIFETIME,
            dryserver: crate::release::Binary { version: "0.2.0".into(), sha256: "a".repeat(64), size: 10 },
            k3s: crate::release::K3s { version: crate::iso::K3S_VERSION.into(), sha256: crate::iso::K3S_SHA256.into() },
            arch_date: "2026/11/19".into(),
            rollback: false,
            urgent: true,
            notes: "fixes the relay timeout that drops long uploads on slow links".into(),
        };
        let served = crate::fsx::dir(&store.path).join(crate::rollout::SERVED_DIR);
        let at = served.join(r.serial.to_string());
        std::fs::create_dir_all(&at).unwrap();
        let env = crate::release::seal(&crate::signed::fake::Key("admin"), &r).unwrap();
        std::fs::write(at.join(crate::rollout::RELEASE_FILE), serde_json::to_string(&env).unwrap()).unwrap();
        std::fs::write(served.join("current"), format!("{}\n", r.serial)).unwrap();
        let failed = Report {
            update: "failed".into(),
            update_serial: r.serial,
            update_note: "dryserver failed: exit status 1: no space left on device".into(),
            ..healthy(now)
        };
        store
            .update(|st| {
                st.heartbeat(2, Heartbeat { lan_ip: "192.168.1.23".into(), report: Some(failed), ..Heartbeat::default() }, Time::now())?;
                st.rollout = Rollout {
                    serial: r.serial,
                    urgent: true,
                    phase: Phase::Servers,
                    paused: "node-a (the canary): update failed: dryserver failed: exit status 1: no space left on device".into(),
                    pause: Pause::Failed,
                    pause_host: 2,
                    pause_name: "node-a".into(),
                    cordoned: vec!["node-a".into()],
                    ..Rollout::default()
                };
                Ok(())
            })
            .unwrap();
        s.load();
        let doc = s.view();
        let v = doc.plain();
        for want in [
            "Updates:",
            "Release 1795000000 (urgent), made",
            ": fixes the relay\n    timeout that drops",
            "PAUSED: node-a (the canary): update failed",
            "./dryserver release resume (node-a tries again)",
            "0 of 1 servers on this release.",
        ] {
            assert!(v.contains(want), "{want}: {v}");
        }
        assert_eq!(styled(&doc, "update failed"), vec![crate::tui::err_style()], "{v}");
        for line in v.lines() {
            assert!(line.chars().count() <= 80, "wider than 80 columns: {line:?}");
        }
        // The details of node-a say why.
        s.key(Key::Down);
        s.key(Key::Char('i'));
        let v = s.view().plain();
        assert!(v.contains("no release installed yet; update failed (release 1795000000): dryserver failed"), "{v}");
        for line in v.lines() {
            assert!(line.chars().count() <= 80, "wider than 80 columns: {line:?}");
        }
    }

    #[test]
    fn wrap_keeps_lines_short() {
        assert_eq!(wrap("a b c", 80, "  "), vec!["  a b c"]);
        let long = "word ".repeat(40);
        let lines = wrap(long.trim(), 30, "  ");
        assert!(lines.len() > 1 && lines.iter().all(|l| l.chars().count() <= 30), "{lines:?}");
        assert!(lines[1].starts_with("    word"), "{lines:?}");
        assert!(wrap("", 80, "  ").is_empty());
    }

    #[test]
    fn resend_drops_what_nobody_signed() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('S'));
        s.key(Key::Char('y'));
        assert!(!s.view().plain().contains("NOT SIGNED"));

        // The coordinator's list was tampered with: shown in red.
        store
            .update(|st| {
                st.members.push(Member { host: 7, name: "late".into(), wg_key: key32(7), ..Member::default() });
                st.signed_version = 0;
                st.signed = Default::default();
                Ok(())
            })
            .unwrap();
        s.load();
        let v = s.view().plain();
        assert!(v.contains("! The coordinator has no valid signed list") && v.contains("NOT SIGNED"), "{v}");
        // "p" sends the signed list again; the machine nobody signed goes.
        s.key(Key::Char('p'));
        assert!(s.notice.contains("sent again"), "{:?}", s.notice);
        assert_eq!(store.read().unwrap().members.len(), 1);
    }

    // ---- updates ----

    use crate::publish::tests::{FakeDays, Sent, days_ago, desk, today, twin};
    use crate::tui::apps::tests::{Busy, Open};
    use std::sync::atomic::{AtomicBool, Ordering};

    impl Busy for Screen {
        fn busy(&self) -> bool {
            !self.waiting.is_empty()
        }
    }

    /// The screen of a desktop made by desk, with a publisher whose jobs
    /// wait while hold is set.
    fn publishing(dir: &TempDir, days: &Arc<FakeDays>) -> (Open<Screen>, crate::registry::Store, Sent, Arc<AtomicBool>) {
        let (admin, store, sent, fail, parts) = desk(dir);
        let hold = Arc::new(AtomicBool::new(false));
        let (path, s, f, h) = (dir.path().to_path_buf(), sent.clone(), fail.clone(), hold.clone());
        let p = Publisher {
            admin: Arc::new(move || {
                while h.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(twin(&path, &s, &f))
            }),
            days: days.clone(),
            parts,
            today,
        };
        (Open::new(Screen::new(admin).with_publisher(p)), store, sent, hold)
    }

    #[test]
    fn an_update_is_checked_shown_and_published() {
        let dir = TempDir::new();
        let days = Arc::new(FakeDays::with(&[days_ago(1)]));
        let (mut o, _store, sent, hold) = publishing(&dir, &days);
        let v = o.view();
        assert!(v.contains("u publish an update   R resume a stopped rollout"), "{v}");
        o.fits(60);

        // The choices: notes, then urgent.
        o.key(Key::Char('u'));
        for want in ["Publish an update", "A release of this dryserver (0.2.0)", "> notes", "[ ] roll out at once", "esc cancel"] {
            assert!(o.view().contains(want), "{want}: {}", o.view());
        }
        o.fits(24);
        for k in crate::tui::type_text("fixes the join timeout") {
            o.key(k);
        }
        o.key(Key::Tab);
        o.key(Key::Char(' '));
        assert!(o.view().contains("> urgent    [x]"), "{}", o.view());
        o.key(Key::Enter);
        assert!(o.view().contains("checking the release"), "the screen says what runs: {}", o.view());
        o.settle();

        // What changes, before anything is signed.
        let v = o.view();
        for want in [
            "Sign and send this release to the coordinator?",
            "for 3 machines, urgent:",
            "dryserver  0.1.0 -> 0.2.0",
            "urgent     yes: the rollout starts at once",
            "notes      fixes the join timeout",
            "y sign and send it",
        ] {
            assert!(v.contains(want), "{want}: {v}");
        }
        o.fits(24);
        assert!(sent.lock().unwrap().is_empty());
        o.key(Key::Char('n'));
        assert!(o.s.notice.contains("Nothing signed") && sent.lock().unwrap().is_empty(), "{}", o.s.notice);

        // Again: the choices are kept. y sends it on the worker.
        o.key(Key::Char('u'));
        assert!(o.view().contains("fixes the join timeout") && o.view().contains("[x]"), "{}", o.view());
        o.key(Key::Enter);
        o.settle();
        hold.store(true, Ordering::SeqCst);
        o.key(Key::Char('y'));
        let v = o.view();
        assert!(v.contains("publishing release") && v.contains("Members"), "the screen goes on while it sends: {v}");
        // One release at a time.
        o.key(Key::Char('u'));
        assert!(o.s.notice.contains("Still publishing release") && o.s.form.is_none(), "{}", o.s.notice);
        hold.store(false, Ordering::SeqCst);
        o.settle();
        assert!(o.s.notice.contains("is on the coordinator. It updates itself first"), "{}", o.s.notice);
        assert_eq!(sent.lock().unwrap().len(), 1);
        let v = o.flat();
        assert!(v.contains("(urgent), made") && v.contains("fixes the join timeout"), "the release shows under Updates: {v}");
        assert!(v.contains("Not started yet: the coordinator takes the release up") && !v.contains("No release published yet"), "{v}");
        // The next release starts from fresh choices.
        o.key(Key::Char('u'));
        let f = o.s.form.as_ref().unwrap();
        assert!(f.notes.value.is_empty() && !f.urgent, "{}", o.view());
        o.key(Key::Esc);
        assert!(o.s.form.is_none() && o.s.notice.contains("Nothing signed"));
    }

    #[test]
    fn a_refused_update_says_why_and_what_to_do() {
        let dir = TempDir::new();
        let days = Arc::new(FakeDays::with(&[]));
        *days.fail.lock().unwrap() = Some("cannot find archive.archlinux.org (is this computer online?)".into());
        let (mut o, _, sent, _) = publishing(&dir, &days);
        o.key(Key::Char('u'));
        o.key(Key::Enter);
        o.settle();
        let n = &o.s.notice;
        assert!(n.starts_with("Not published, nothing was signed: cannot find the newest Arch snapshot"), "{n}");
        assert!(n.contains("is this computer online?"), "{n}");
        assert!(o.s.plan.is_none() && sent.lock().unwrap().is_empty());
        o.fits(80);
        // Notes that are not plain text.
        o.key(Key::Char('u'));
        o.key(Key::Paste("caf\u{e9}".into()));
        o.key(Key::Enter);
        o.settle();
        assert!(o.s.notice.contains("not printable ASCII"), "{}", o.s.notice);
    }

    #[test]
    fn closing_the_screen_while_it_publishes_asks_first_and_says_what_happened() {
        let dir = TempDir::new();
        let days = Arc::new(FakeDays::with(&[days_ago(0)]));
        let (mut o, _, _, hold) = publishing(&dir, &days);
        o.key(Key::Char('u'));
        o.key(Key::Enter);
        o.settle();
        hold.store(true, Ordering::SeqCst);
        o.key(Key::Char('y'));
        assert_eq!(o.key(Key::Char('q')), Flow::Continue);
        assert!(o.s.notice.contains("Press q again to quit anyway: the upload stops half way"), "{}", o.s.notice);
        assert!(o.s.after().is_none());
        assert_eq!(o.key(Key::Char('q')), Flow::Quit);
        let after = o.s.after().unwrap().to_string();
        assert!(after.contains("The screen closed while publishing release") && after.contains("./dryserver release status"), "{after}");
        hold.store(false, Ordering::SeqCst);
        // Ctrl+C quits at once, and says the same.
        let dir = TempDir::new();
        let (mut o, _, _, hold) = publishing(&dir, &days);
        o.key(Key::Char('u'));
        o.key(Key::Enter);
        o.settle();
        hold.store(true, Ordering::SeqCst);
        o.key(Key::Char('y'));
        assert_eq!(o.key(Key::Ctrl('c')), Flow::Quit);
        assert!(o.s.after().is_some());
        hold.store(false, Ordering::SeqCst);
        // Nothing running: q quits at once, with nothing to say.
        let dir = TempDir::new();
        let (mut o, _, _, _) = publishing(&dir, &days);
        assert_eq!(o.key(Key::Char('q')), Flow::Quit);
        assert!(o.s.after().is_none());
    }

    #[test]
    fn resume_asks_first_and_only_when_stopped() {
        use crate::rollout::{Pause, Phase, Rollout};
        let dir = TempDir::new();
        let days = Arc::new(FakeDays::with(&[days_ago(0)]));
        let (mut o, store, _, _) = publishing(&dir, &days);
        o.key(Key::Char('R'));
        assert!(o.s.notice.contains("Nothing to resume: there is no rollout to resume"), "{}", o.s.notice);
        store
            .update(|s| {
                s.rollout = Rollout { serial: 5, phase: Phase::Servers, ..Rollout::default() };
                Ok(())
            })
            .unwrap();
        o.s.load();
        o.key(Key::Char('R'));
        assert!(o.s.notice.contains("is not stopped") && o.s.confirm.is_none(), "{}", o.s.notice);
        store
            .update(|s| {
                s.rollout.paused = "node-a: update failed: no space left on device".into();
                s.rollout.pause = Pause::Failed;
                s.rollout.pause_host = 2;
                s.rollout.pause_name = "node-a".into();
                Ok(())
            })
            .unwrap();
        o.s.load();
        let v = o.flat();
        assert!(v.contains("Press R to resume (the coordinator gives node-a its turn again"), "{v}");
        o.fits(60);
        o.key(Key::Char('R'));
        let v = o.flat();
        assert!(v.contains("Resume the rollout of release 5? The coordinator then gives node-a its turn again"), "{v}");
        o.key(Key::Char('n'));
        assert_eq!(store.read().unwrap().rollout.resume_asked, 0, "anything but y asks nothing");
        o.key(Key::Char('R'));
        o.key(Key::Char('y'));
        assert!(o.s.notice.contains("Resumed: the coordinator gives node-a its turn again"), "{}", o.s.notice);
        assert_eq!(store.read().unwrap().rollout.resume_asked, 1);
    }

    #[test]
    fn a_screen_without_a_publisher_says_where_to_publish() {
        let dir = TempDir::new();
        let (admin, _) = setup(&dir);
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('u'));
        assert!(s.notice.contains("./dryserver release publish") && s.form.is_none(), "{}", s.notice);
    }
}
