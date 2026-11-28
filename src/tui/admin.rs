//! Machines: who asks to join, the members and how each one is, who else
//! may log in (People), the VPN for your own devices (VPN), the release
//! they run, and what else is on the network, in five tabs.
//! Every decision made here is signed with this computer's key before it
//! reaches the coordinator, and each one asks for y first.
//!
//! The coordinator is asked on a thread of the screen's own, which owns
//! the link to it: the screen keeps drawing and taking keys while the
//! coordinator is slow or does not answer, and says how long it waits.
//! Jobs run one at a time, in the order sent, and every change is followed
//! by a fresh look. Closing the screen does not wait for the job that
//! runs (only a look at a new coordinator, which moves the pinned key for
//! a moment, is waited for): it ends by itself and its answer goes nowhere.
//!
//! Releases are published here too (p): the choices in a form, then what
//! the release changes, then y. Checking and sending run on the same
//! thread, so the screen keeps drawing while tens of MiB go to the
//! coordinator. A stopped rollout is a card: try again (t) or skip the
//! machine it stopped at (o).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use chrono::NaiveDate;
use ratatui::style::Modifier;

use super::app::{PlaceScreen, Size};
use super::form::{Field, Form, Group, Status};
use super::frame::{self, Back, Focus, Help, Notice, Overlay, Page, col};
use super::kill::WriteList;
use super::theme::{self, Mark};
use super::{Doc, Emit, Event, Flow, Key, Seg, dim, err, plain, spinner};
use crate::admin::{Admin, NewCoordinator, View};
use crate::ctx::Ctx;
use crate::err::{Error, Kind, Result};
use crate::gotime::{Time, duration_string, round_ms};
use crate::mesh;
use crate::publish::{self, Choice, Days, Parts, Plan};
use crate::registry::{Member, Request};
use crate::release;
use crate::report::{self, Concern, percent, short_age};
use crate::rollout::{self, Pause, Phase};
use crate::{bail, signed, vpn};

mod people_tab;
mod vpn_tab;
use people_tab::PersonDraft;
use vpn_tab::{DeviceDraft, PlanDraft, ShownView};

/// How often the screen looks again while the coordinator answers.
const REFRESH: Duration = Duration::from_secs(5);
/// After a look that failed: not on every tick.
const RETRY: Duration = Duration::from_secs(15);
/// After this long without an answer the screen says it waits.
const SLOW: Duration = Duration::from_secs(4);
/// A member syncs every minute: three without a word and its report is
/// old news.
const STALE: i64 = 180;
/// The most WireGuard peers named in the details; the rest are counted.
const SHOWN_PEERS: usize = 24;
/// Closing the screen while it looks at a new coordinator waits this long
/// for the old pin to be put back.
const PROBE_WAIT: Duration = Duration::from_secs(10);
/// The snake shows progress in bodies this tall; smaller ones get a bar.
const RING_ROWS: usize = 26;
/// The widest a sheet gets.
const SHEET: usize = 84;

const LOADING: &str = "asking the coordinator";
const CHECKING: &str = "checking the release: binary, k3s file, Arch archive, coordinator";

// ---- what members say about themselves ----

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

/// What a member says about itself, as short items; true marks what needs
/// a look. target is the release the swarm moves to.
fn health(m: &Member, now: Time, target: u64) -> Vec<(String, bool)> {
    let Some(r) = &m.report else {
        return vec![("no report: its dryserver is older".into(), false)];
    };
    let problems = r.problems(m.last_seen);
    let bad = |c: Concern| problems.iter().any(|(k, _)| *k == c);
    let mut items: Vec<(String, bool)> = Vec::new();
    let quiet = now.since(m.last_seen).num_seconds();
    if !m.last_seen.is_zero() && quiet > STALE {
        items.push((format!("silent for {}", short_age(quiet as u64)), true));
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
        Some(false) => ("firewall off".into(), true),
        None => ("firewall ?".into(), false),
    });
    for (c, text) in &problems {
        if matches!(c, Concern::Reboot | Concern::Clock | Concern::Upgrade | Concern::Peers | Concern::Boot) {
            items.push((text.clone(), true));
        }
    }
    items
}

/// A member's row: its mark and one line on how it is, alarm first.
fn health_line(m: &Member, signed: bool, first: bool, now: Time, target: u64) -> (Mark, String, bool) {
    if !signed && first && m.host == 1 {
        return (Mark::Act, "not signed yet: s signs it".into(), false);
    }
    if !signed {
        return (Mark::Bad, "not signed: put on the coordinator without you, servers ignore it".into(), true);
    }
    if m.report.is_none() {
        return (Mark::Wait, "no report: its dryserver is older".into(), false);
    }
    let items = health(m, now, target);
    let bad: Vec<&str> = items.iter().filter(|(_, a)| *a).map(|(t, _)| t.as_str()).collect();
    if !bad.is_empty() {
        return (Mark::Bad, bad.join(" · "), true);
    }
    let good: Vec<&str> = items.iter().map(|(t, _)| t.as_str()).filter(|t| !matches!(*t, "k3s on" | "firewall on")).collect();
    (Mark::Done, format!("healthy · {}", good.join(" · ")), false)
}

/// Everything a member says about itself, for its sheet. names gives the
/// member names by host number, for its WireGuard peers.
fn report_lines(m: &Member, names: &dyn Fn(u32) -> String, now: Time) -> Vec<Vec<Seg>> {
    let mut out: Vec<Vec<Seg>> = Vec::new();
    let Some(r) = &m.report else {
        out.push(vec![dim(format!("{} sends no report: its dryserver, or the coordinator's, is older than this one.", m.name))]);
        return out;
    };
    out.push(vec![dim(format!("As it reports itself, relayed by the coordinator {}:", ago(m.last_seen, now)))]);
    let or = |s: &str| if s.is_empty() { "?".to_string() } else { s.to_string() };
    let mut l = vec![txt(format!("dryserver {}   ", or(&r.dryserver)))];
    l.push(match (r.k3s.as_str(), r.k3s_active) {
        ("", _) => txt("no k3s"),
        (v, Some(true)) => txt(format!("k3s {v}, running")),
        (v, _) => err(format!("k3s {v}, stopped")),
    });
    l.push(txt("   "));
    l.push(match r.firewall {
        Some(true) => txt("firewall loaded"),
        Some(false) => err("firewall not loaded"),
        None => dim("firewall unknown"),
    });
    out.push(l);
    if r.release != 0 || !r.update.is_empty() {
        let mut line = if r.release == 0 { "no release installed yet".to_string() } else { format!("release {}", r.release) };
        if !r.update.is_empty() {
            line += &format!("; update {}", r.update);
            if r.update_serial != 0 {
                line += &format!(" (release {})", r.update_serial);
            }
            if !r.update_note.is_empty() {
                line += &format!(": {}", r.update_note);
            }
        }
        out.push(vec![if r.update_failed() || r.update == "held" { err(line) } else { txt(line) }]);
    }
    if r.reboot {
        out.push(vec![txt(format!("kernel {} running, {} installed: ", or(&r.kernel), or(&r.kernel_installed))), err("reboot needed")]);
    } else {
        out.push(vec![txt(format!("kernel {}", or(&r.kernel)))]);
    }
    let upgraded = if r.upgraded > 0 && r.time >= r.upgraded {
        format!("upgraded {} ago", short_age((r.time - r.upgraded) as u64))
    } else {
        "last upgrade unknown".into()
    };
    let [l1, l5, l15] = r.load;
    out.push(vec![txt(format!("up {}   {upgraded}   load {l1:.2} {l5:.2} {l15:.2} on {} CPUs", short_age(r.uptime), r.cpus))]);
    let share = |used: u64, total: u64| match percent(used, total) {
        Some(p) => format!("{} of {} ({p}%)", report::size(used), report::size(total)),
        None => "?".into(),
    };
    let temp = r.temp.map(|t| format!("   {t}°C")).unwrap_or_default();
    out.push(vec![txt(format!("memory {}   disk {}{temp}", share(r.mem_used, r.mem_total), share(r.disk_used, r.disk_total)))]);
    match r.clock_offset(m.last_seen) {
        Some(0) => out.push(vec![txt("clock in step with the coordinator's")]),
        Some(off) => out.push(vec![txt(format!(
            "clock {} {} the coordinator's",
            short_age(off.unsigned_abs()),
            if off > 0 { "ahead of" } else { "behind" }
        ))]),
        None => {}
    }
    if r.peers.is_empty() {
        out.push(vec![txt("WireGuard: nothing reported")]);
        return out;
    }
    // The silent ones first: they are what to look at.
    let silent = r.silent_peers();
    let mut peers: Vec<&report::Peer> = r.peers.iter().collect();
    peers.sort_by_key(|p| !silent.contains(&p.host));
    let mut l = vec![txt("WireGuard, last handshake:")];
    for p in peers.iter().take(SHOWN_PEERS) {
        let text = format!(" {} {}", names(p.host), p.age.map(short_age).unwrap_or_else(|| "never".into()));
        l.push(if silent.contains(&p.host) { err(text) } else { txt(text) });
    }
    if peers.len() > SHOWN_PEERS {
        l.push(dim(format!(" and {} more", peers.len() - SHOWN_PEERS)));
    }
    out.push(l);
    out
}

/// Error words for this screen: where the core says which command to run,
/// the screen names its own key or place.
fn words(s: &str) -> String {
    let s = s
        .replace("dryserver release status shows what the coordinator has", "the Updates tab shows what the coordinator has")
        .replace("dryserver release resume tries it again", "try again (t) does that");
    report::printable(&s)
}

/// s with its first letter in capitals, for an error that starts a sentence.
fn sentence(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Body text, in bone where the tier has it.
fn txt(s: impl Into<String>) -> Seg {
    Seg(s.into(), theme::palette().text())
}

/// A mark, then text that wraps under itself, width cells wide.
fn hang(width: usize, m: Mark, text: Vec<Seg>) -> Vec<Vec<Seg>> {
    let parts = frame::wrap_line(&text, width.saturating_sub(3).max(10));
    parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let mut l = vec![if i == 0 { theme::mark(m) } else { plain(" ") }, plain("  ")];
            l.extend(part);
            l
        })
        .collect()
}

/// One blank line before what comes next, unless at the top or after one.
fn space(d: &mut Doc) {
    let n = d.lines.len();
    match (n >= 2 && d.lines[n - 2].is_empty(), d.lines[n - 1].is_empty()) {
        // At the top, or a blank line is there.
        _ if n == 1 && d.lines[0].is_empty() => {}
        (true, true) => {}
        (false, true) => {
            d.nl();
        }
        (_, false) => {
            d.nl().nl();
        }
    }
}

/// Appends whole lines to d, and returns the range they took.
fn put(d: &mut Doc, lines: Vec<Vec<Seg>>) -> std::ops::Range<usize> {
    let start = d.lines.len() - 1;
    for l in lines {
        d.lines.last_mut().expect("a doc has a line").extend(l);
        d.nl();
    }
    start..d.lines.len() - 1
}

// ---- the work on the screen's own thread ----

/// What the screen needs to publish releases. Each job makes its own
/// link to the coordinator on the screen's thread.
pub struct Publisher {
    /// A new Admin with this desktop's keys.
    pub admin: Arc<dyn Fn() -> Result<Admin> + Send + Sync>,
    pub days: Arc<dyn Days>,
    /// This program and the k3s it pins.
    pub parts: Parts,
    /// The date in UTC.
    pub today: fn() -> NaiveDate,
    /// The swarm's settings from this computer's config, carried by the
    /// release.
    pub settings: Option<crate::release::Settings>,
}

/// What a change shows whole after it.
pub enum Shown {
    /// A device's config: with its private key when it was made here,
    /// shown this once and never kept.
    Device { name: String, conf: String, private: bool },
    /// The sheet of this row (its row_key), on its tab.
    Sheet(String),
}

/// What the People and VPN tabs need from this computer.
pub struct Desk {
    /// The mesh's UDP port and the home network (like 192.168.1.0/24):
    /// the VPN keeps clear of both.
    pub mesh_port: String,
    pub home: String,
    /// The admin's own account on the machines: never a person's.
    pub admin_user: String,
    /// Where files for others go (a device's config, a person's
    /// known_hosts lines): the home folder. None: nowhere.
    pub files: Option<PathBuf>,
    /// Makes a device's key pair here: (private, public).
    pub make_key: MakeKey,
    /// Puts the certificates' token on the gateway, on the terminal (ssh,
    /// then sudo and dryserver ask there).
    pub token: Token,
}

pub type MakeKey = Arc<dyn Fn() -> Result<(String, String)> + Send + Sync>;
pub type Token = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// A decision, as the admin confirmed it.
#[derive(Debug, Clone)]
enum Act {
    /// The waiting request as the admin saw it: its id, name and keys,
    /// which its code covers. The desktop signs exactly those.
    Approve(Request),
    Reject(Request),
    Remove(String),
    /// The first signature: the coordinator's own entry.
    SignCoordinator,
    /// The list signed again under a new version.
    Resend,
    /// A reinstalled coordinator takes the old one's place.
    NewCoordinator(NewCoordinator),
    /// A stopped rollout goes on: the machine it stopped at tries again.
    Resume,
    /// A rollout stopped at a server goes on without it.
    Skip,
    Publish(Box<Plan>),
    /// Someone new let in.
    LetIn(signed::Person),
    /// More keys for someone let in, merged with their keys as the newest
    /// list has them.
    AddKeys {
        name: String,
        keys: Vec<String>,
    },
    /// Where someone let in may log in (none: every server).
    PersonOn {
        name: String,
        on: Vec<String>,
    },
    TakeOut(String),
    VpnOn(vpn::Plan),
    VpnOff,
    /// A device; key: its own public key, None: made here.
    AddDevice {
        name: String,
        key: Option<String>,
    },
    RemoveDevice(String),
}

impl Act {
    fn label(&self) -> String {
        match self {
            Act::Approve(r) => format!("approving {}", r.name),
            Act::Reject(r) => format!("rejecting {}", r.name),
            Act::Remove(n) => format!("removing {n}"),
            Act::SignCoordinator => "signing the coordinator".into(),
            Act::Resend => "sending your signed list again".into(),
            Act::NewCoordinator(c) => format!("making {} your coordinator", c.name),
            Act::Resume => "asking the coordinator to try again".into(),
            Act::Skip => "asking the coordinator to skip the machine".into(),
            Act::Publish(p) => format!("publishing release {}", p.release.serial),
            Act::LetIn(p) => format!("letting {} in", p.name),
            Act::AddKeys { name, .. } => format!("adding a key for {name}"),
            Act::PersonOn { name, .. } => format!("changing where {name} may log in"),
            Act::TakeOut(n) => format!("taking {n} out"),
            Act::VpnOn(p) => format!("making {} the VPN's gateway", p.gateway),
            Act::VpnOff => "turning the VPN off".into(),
            Act::AddDevice { name, .. } => format!("adding {name} to the VPN"),
            Act::RemoveDevice(n) => format!("taking {n} off the VPN"),
        }
    }

    /// The start of what a failure says.
    fn failed(&self) -> &'static str {
        match self {
            Act::Approve(_) => "Not approved",
            Act::Reject(_) => "Not rejected",
            Act::Remove(_) => "Not removed",
            Act::SignCoordinator => "Not signed",
            Act::Resend => "Not sent",
            Act::NewCoordinator(_) => "Nothing changed",
            Act::Resume => "Not resumed",
            Act::Skip => "Not skipped",
            Act::Publish(_) => "Not published",
            Act::LetIn(_) => "Not let in",
            Act::AddKeys { .. } | Act::PersonOn { .. } => "Not changed",
            Act::TakeOut(_) => "Not taken out",
            Act::VpnOn(_) | Act::VpnOff => "The VPN was not changed",
            Act::AddDevice { .. } => "Not added",
            Act::RemoveDevice(_) => "Not taken off",
        }
    }
}

enum Job {
    Load,
    /// Looks at the machine that answers at the coordinator's address.
    Probe,
    /// Writes the server list for ssh and the kill switch.
    Write,
    Check(Choice),
    Act(Act),
}

impl Job {
    fn label(&self) -> String {
        match self {
            Job::Load => LOADING.into(),
            Job::Probe => "looking at the machine at the coordinator's address".into(),
            Job::Write => "writing the server list".into(),
            Job::Check(_) => CHECKING.into(),
            Job::Act(a) => a.label(),
        }
    }

    fn change(&self) -> bool {
        matches!(self, Job::Probe | Job::Write | Job::Act(_))
    }
}

pub enum Msg {
    Loaded(Result<View>),
    Probed(Result<NewCoordinator>),
    Wrote(Result<String>),
    Checked(Result<Box<Plan>>),
    /// A decision ran, then the screen looked again.
    Did {
        failed: &'static str,
        /// The serial, when it was a publish.
        publish: Option<u64>,
        said: Result<String>,
        /// What to show whole after it (a new device's config).
        shown: Option<Shown>,
        view: Result<View>,
    },
    /// The thread stopped on a bug: what it said.
    Lost(String),
}

struct Tools {
    publisher: Option<Arc<Publisher>>,
    write_list: Option<WriteList>,
    desk: Option<Arc<Desk>>,
}

fn run(admin: &mut Admin, tools: &Tools, act: Act, shown: &mut Option<Shown>) -> Result<String> {
    let subnet = admin.subnet.clone();
    match act {
        Act::Approve(r) => admin
            .approve(&r)
            .map(|host| format!("{} approved and signed as {}. It joins within a minute.", r.name, mesh::ip(&subnet, host))),
        Act::Reject(r) => admin.reject(&r).map(|_| format!("{} rejected: it does not join.", r.name)),
        Act::Remove(name) => admin.remove(&name).map(|notes| {
            let mut said = format!("{name} removed; servers drop it within a minute.");
            for n in notes {
                said = format!("{said} {n}");
            }
            said
        }),
        Act::SignCoordinator => admin.sign_coordinator().map(|_| "Coordinator signed. New machines can join now.".to_string()),
        Act::Resend => admin.resend().map(|v| format!("Signed list sent again as version {v}.")),
        Act::NewCoordinator(c) => admin.accept_new_coordinator(&c).map(|_| {
            format!(
                "{} is your coordinator now, with every machine you signed before. Lift the cut in Kill switch (9) so the \
                 servers follow it.",
                c.name
            )
        }),
        Act::Resume => publish::resume(admin).map(|what| format!("Resumed: the coordinator {what}, at its next sync (within a minute).")),
        Act::Skip => publish::skip(admin).map(|what| format!("Skipped: the coordinator {what}, at its next sync (within a minute).")),
        Act::Publish(plan) => {
            let p = tools.publisher.as_ref().ok_or_else(|| Error::new("this screen cannot publish"))?;
            let mut a = (p.admin)()?;
            publish::publish(&mut a, &plan).map(|r| {
                format!(
                    "Release {} is on the coordinator. It updates itself first, then one server at a time: this tab shows how it goes.",
                    r.serial
                )
            })
        }
        Act::LetIn(p) => {
            let user = tools.desk.as_ref().map(|d| d.admin_user.clone()).unwrap_or_default();
            // Someone let in meanwhile (on another computer) is not replaced.
            if admin.people().iter().any(|q| q.name == p.name) {
                bail!("{} is let in already (changed meanwhile?): look again, then change them in their sheet", p.name);
            }
            let key = format!("p:{}", p.name);
            admin.let_in(&p, &user).map(|_| {
                // Their sheet has the lines their ssh needs.
                *shown = Some(Shown::Sheet(key));
                format!(
                    "{} is let in; the machines follow within a minute. Give them the lines below for their known_hosts (f writes \
                     them to a file).",
                    p.name
                )
            })
        }
        Act::AddKeys { name, keys } => {
            let user = tools.desk.as_ref().map(|d| d.admin_user.clone()).unwrap_or_default();
            let Some(mut p) = admin.people().iter().find(|q| q.name == name).cloned() else {
                bail!("{name} is not let in any more");
            };
            // Machines removed since: never an empty list, which is every server.
            let servers = admin.servers();
            let was = p.on.len();
            p.on.retain(|n| servers.iter().any(|s| s.name == *n));
            if was > 0 && p.on.is_empty() {
                bail!("{name} may log in only on machines that are gone: choose machines first (m), or take them out (d)");
            }
            let before = p.keys.len();
            for k in keys {
                if !p.keys.iter().any(|o| signed::key_body(o) == signed::key_body(&k)) {
                    p.keys.push(k);
                }
            }
            if p.keys.len() == before {
                bail!("{name} has that key already");
            }
            admin.let_in(&p, &user).map(|_| format!("{name} may log in with the new key too, within a minute."))
        }
        Act::PersonOn { name, on } => {
            let user = tools.desk.as_ref().map(|d| d.admin_user.clone()).unwrap_or_default();
            let Some(mut p) = admin.people().iter().find(|q| q.name == name).cloned() else {
                bail!("{name} is not let in any more");
            };
            p.on = on;
            admin.let_in(&p, &user).map(|_| format!("{name} is changed; the machines follow within a minute."))
        }
        Act::TakeOut(n) => {
            admin.take_out(&n).map(|_| format!("{n} is taken out: within a minute every machine locks the account and ends its sessions."))
        }
        Act::VpnOn(plan) => admin.vpn_on(&plan).map(|_| {
            format!("{} is the VPN's gateway; it follows within a minute. Forward the port on your router (enter on the VPN).", plan.gateway)
        }),
        Act::VpnOff => admin
            .vpn_off()
            .map(|_| "The VPN is off: the gateway closes it within a minute. The devices stay listed.".to_string()),
        Act::AddDevice { name, key } => vpn_tab::add_device(admin, tools.desk.as_deref(), &name, key, shown),
        Act::RemoveDevice(n) => admin.vpn_remove(&n).map(|_| format!("{n} is off the VPN: the gateway forgets its key within a minute.")),
    }
}

fn work(ctx: &Ctx, admin: &mut Admin, tools: &Tools, job: Job) -> Msg {
    match job {
        Job::Load => Msg::Loaded(admin.load()),
        Job::Probe => Msg::Probed(admin.probe_new_coordinator()),
        Job::Write => Msg::Wrote(match &tools.write_list {
            Some(w) => w(),
            None => Err(Error::new("this screen cannot write the server list")),
        }),
        Job::Check(c) => Msg::Checked((|| {
            let p = tools.publisher.as_ref().ok_or_else(|| Error::new("this screen cannot publish"))?;
            let mut a = (p.admin)()?;
            let v = a.load()?;
            let c = Choice { settings: p.settings.clone(), ..c };
            publish::plan(ctx, &a, &v, p.days.as_ref(), &p.parts, &c, (p.today)()).map(Box::new)
        })()),
        Job::Act(act) => {
            let (failed, publish) = (act.failed(), if let Act::Publish(p) = &act { Some(p.release.serial) } else { None });
            let mut shown = None;
            let said = run(admin, tools, act, &mut shown);
            Msg::Did { failed, publish, said, shown, view: admin.load() }
        }
    }
}

/// A change that adds a device to the VPN: its config shows only after it.
fn adding(what: &str) -> bool {
    what.starts_with("adding ") && what.ends_with(" to the VPN")
}

/// The screen's thread. Dropping it lets the job that runs end by itself,
/// except a look at a new coordinator, which is waited for.
struct Line {
    jobs: mpsc::Sender<Job>,
    ctx: Ctx,
    probing: Arc<AtomicBool>,
}

impl Line {
    fn start(admin: Admin, tools: Tools, emit: Emit<Msg>) -> Line {
        let (tx, rx) = mpsc::channel::<Job>();
        let ctx = Ctx::new();
        let (c, probing) = (ctx.clone(), Arc::new(AtomicBool::new(false)));
        let p = probing.clone();
        std::thread::spawn(move || {
            let mut admin = admin;
            while let Ok(job) = rx.recv() {
                if c.done() {
                    break;
                }
                p.store(matches!(job, Job::Probe), Ordering::SeqCst);
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&c, &mut admin, &tools, job)));
                p.store(false, Ordering::SeqCst);
                match res {
                    Ok(m) => emit(m),
                    Err(e) => {
                        let what = e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned());
                        emit(Msg::Lost(what.unwrap_or_else(|| "no word why".into())));
                        break;
                    }
                }
            }
        });
        Line { jobs: tx, ctx, probing }
    }

    fn send(&self, job: Job) -> bool {
        self.jobs.send(job).is_ok()
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        self.ctx.cancel();
        let t = Instant::now();
        while self.probing.load(Ordering::SeqCst) && t.elapsed() < PROBE_WAIT {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// What the screen sent its thread and has not heard back about, in the
/// order sent: each job answers with exactly one message.
#[derive(Default)]
struct Queue {
    jobs: VecDeque<(String, bool)>,
    /// When the oldest job started.
    since: Option<Instant>,
}

impl Queue {
    fn push(&mut self, label: String, change: bool) {
        if self.jobs.is_empty() {
            self.since = Some(Instant::now());
        }
        self.jobs.push_back((label, change));
    }

    fn pop(&mut self) {
        self.jobs.pop_front();
        self.since = if self.jobs.is_empty() { None } else { Some(Instant::now()) };
    }

    fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    fn has(&self, label: &str) -> bool {
        self.jobs.iter().any(|(l, _)| l == label)
    }

    /// The first change that has not answered yet.
    fn change(&self) -> Option<&str> {
        self.jobs.iter().find(|(_, c)| *c).map(|(l, _)| l.as_str())
    }

    /// The job that runs, and for how long.
    fn running(&self) -> Option<(&str, Duration)> {
        self.jobs.front().map(|(l, _)| (l.as_str(), self.since.map(|t| t.elapsed()).unwrap_or_default()))
    }
}

// ---- the screen ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Machines,
    People,
    Vpn,
    Updates,
    Network,
}

const TABS: [Tab; 5] = [Tab::Machines, Tab::People, Tab::Vpn, Tab::Updates, Tab::Network];

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Machines => "Machines",
            Tab::People => "People",
            Tab::Vpn => "VPN",
            Tab::Updates => "Updates",
            Tab::Network => "Network",
        }
    }

    fn at(self) -> usize {
        self as usize
    }
}

/// Something on a tab that can be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    Request(usize),
    Member(usize),
    /// The stopped rollout's card.
    Stopped,
    Device(usize),
    Cut(usize),
    Warning(usize),
    /// Someone else let in (People tab).
    Person(usize),
    /// The VPN itself: its gateway, or that there is none.
    Gateway,
    /// A device on the VPN.
    VpnDevice(usize),
}

/// What a key or a line of a sheet does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Do {
    Approve,
    Reject,
    Remove,
    Sign,
    NewCoordinator,
    WriteList,
    TryAgain,
    Skip,
    Publish,
    // People
    LetIn,
    AddKey,
    OnMachines,
    HostsFile,
    TakeOut,
    // VPN
    Gateway,
    Token,
    VpnOff,
    AddDevice,
    DeviceConfig,
    RemoveDevice,
}

const DOS: [Do; 9] =
    [Do::Approve, Do::Reject, Do::Remove, Do::Sign, Do::NewCoordinator, Do::WriteList, Do::TryAgain, Do::Skip, Do::Publish];
/// The keys of the People and VPN tabs, before the ones of every tab.
const PEOPLE_DOS: [Do; 5] = [Do::LetIn, Do::AddKey, Do::OnMachines, Do::HostsFile, Do::TakeOut];
const VPN_DOS: [Do; 6] = [Do::Gateway, Do::Token, Do::VpnOff, Do::AddDevice, Do::DeviceConfig, Do::RemoveDevice];

impl Do {
    fn key(self) -> char {
        match self {
            Do::Approve => 'a',
            Do::Reject => 'x',
            Do::Remove => 'd',
            Do::Sign => 's',
            Do::NewCoordinator => 'n',
            Do::WriteList => 'w',
            Do::TryAgain => 't',
            Do::Skip => 'o',
            Do::Publish => 'p',
            Do::LetIn => 'a',
            // Not k: that moves up.
            Do::AddKey => 'e',
            Do::OnMachines => 'm',
            Do::HostsFile => 'f',
            Do::TakeOut => 'd',
            Do::Gateway => 'g',
            Do::Token => 't',
            Do::VpnOff => 'x',
            Do::AddDevice => 'a',
            Do::DeviceConfig => 'c',
            Do::RemoveDevice => 'd',
        }
    }

    /// The action of key c on tab: the tab's own first.
    fn of(c: char, tab: Tab) -> Option<Do> {
        let own: &[Do] = match tab {
            Tab::People => &PEOPLE_DOS,
            Tab::Vpn => &VPN_DOS,
            _ => &[],
        };
        own.iter().copied().chain(DOS).find(|d| d.key() == c)
    }

}

/// A question before a change: y does it.
struct Ask {
    question: String,
    consequences: Vec<String>,
    act: Act,
}

/// A form of the People or VPN tab, open in the body.
enum Entry {
    Person(Form<PersonDraft>),
    Plan(Form<PlanDraft>),
    Device(Form<DeviceDraft>),
}

/// A row's sheet, open in the body.
struct Opened {
    /// The row it is about (row_key), found again after each look.
    key: String,
    cursor: usize,
}

pub struct Screen {
    /// Moved onto the screen's thread when it starts.
    admin: Option<Admin>,
    subnet: String,
    secrets: PathBuf,
    /// The coordinator's address, for the header.
    addr: String,
    now: fn() -> Time,
    view: View,
    /// When the coordinator last answered.
    answered: Option<Instant>,
    /// When the last look ended, answered or not.
    looked: Option<Instant>,
    err: Option<Error>,
    /// Since when it has not answered.
    down_since: Option<Instant>,
    /// A key file of secrets/ that is not there.
    missing: Option<PathBuf>,
    /// The stopped rollout last seen (its release, machine and words):
    /// a new one is selected.
    stop: Option<String>,
    tab: Tab,
    sel: [usize; 5],
    /// The selected row of each tab, by row_key: kept across looks.
    pick: [Option<String>; 5],
    opened: Option<Opened>,
    ask: Option<Ask>,
    notice: Option<Notice>,
    /// A check or publish that failed: what happened, what to do.
    failed: Option<(String, String)>,
    publisher: Option<Arc<Publisher>>,
    write_list: Option<WriteList>,
    line: Option<Line>,
    queue: Queue,
    /// The choices for a new release, while the admin makes them; the
    /// last ones are kept for the next try.
    form: Option<Form<Choice>>,
    choice: Choice,
    /// A checked release: what it changes, before the confirm.
    plan: Option<Box<Plan>>,
    /// esc was pressed once while a change runs.
    leave_armed: bool,
    /// A card has just appeared at the top: it is kept in view until the
    /// next key, before the selected row.
    fresh_card: bool,
    /// What to tell the admin after the screen closed.
    after: Option<Notice>,
    desk: Option<Arc<Desk>>,
    /// A form of the People or VPN tab.
    entry: Option<Entry>,
    /// A device's config, whole, after it was added (or asked for).
    shown: Option<ShownView>,
    /// Work for the terminal (the token, over ssh).
    job: Option<super::Job>,
}

impl Screen {
    pub fn new(admin: Admin) -> Screen {
        let (subnet, secrets) = (admin.subnet.clone(), admin.secrets.clone());
        Screen {
            admin: Some(admin),
            subnet,
            secrets,
            addr: String::new(),
            now: Time::now,
            view: View::default(),
            answered: None,
            looked: None,
            err: None,
            down_since: None,
            missing: None,
            stop: None,
            tab: Tab::Machines,
            sel: [0; 5],
            pick: Default::default(),
            opened: None,
            ask: None,
            notice: None,
            failed: None,
            publisher: None,
            write_list: None,
            line: None,
            queue: Queue::default(),
            form: None,
            choice: Choice::default(),
            plan: None,
            leave_armed: false,
            fresh_card: false,
            after: None,
            desk: None,
            entry: None,
            shown: None,
            job: None,
        }
    }

    /// What the People and VPN tabs need from this computer.
    pub fn with_desk(mut self, d: Desk) -> Screen {
        self.desk = Some(Arc::new(d));
        self
    }

    pub fn with_publisher(mut self, p: Publisher) -> Screen {
        self.publisher = Some(Arc::new(p));
        self
    }

    /// Writes the server list (ssh-config), from the actions.
    pub fn with_write_list(mut self, w: WriteList) -> Screen {
        self.write_list = Some(w);
        self
    }

    /// The coordinator's address, for the header.
    pub fn at(mut self, addr: &str) -> Screen {
        self.addr = addr.into();
        self
    }

    /// Opens on another tab (Updates opens Machines on its Updates tab).
    pub fn on_tab(mut self, t: Tab) -> Screen {
        self.tab = t;
        self
    }

    // ---- the thread ----

    fn send(&mut self, job: Job) {
        let (label, change) = (job.label(), job.change());
        if self.line.as_ref().is_some_and(|l| l.send(job)) {
            self.queue.push(label, change);
        } else {
            self.notice = Some(Notice::bad("The screen's link to the coordinator stopped: esc, then open Machines (4) again."));
        }
    }

    fn look(&mut self) {
        if !self.queue.has(LOADING) {
            self.send(Job::Load);
        }
    }

    fn loaded(&mut self, res: Result<View>) {
        self.looked = Some(Instant::now());
        let (was_err, was_missing) = (self.err.is_some(), self.missing.is_some());
        match res {
            Ok(v) => {
                self.view = v;
                self.err = None;
                self.answered = Some(Instant::now());
                self.down_since = None;
            }
            Err(e) => {
                if self.down_since.is_none() {
                    self.down_since = Some(Instant::now());
                }
                self.err = Some(e);
            }
        }
        self.missing = super::home::ADMIN_KEYS.iter().map(|k| self.secrets.join(k)).find(|p| !p.exists());
        if (self.err.is_some() && !was_err) || (self.missing.is_some() && !was_missing) {
            self.fresh_card = true;
        }
        let r = &self.view.rollout;
        let stop = publish::stopped(r).then(|| format!("{} {} {}", r.serial, r.pause_host, r.paused));
        if stop.is_some() && stop != self.stop {
            self.pick[Tab::Updates.at()] = Some("stopped".into());
        }
        self.stop = stop;
        self.reselect();
    }

    fn answer(&mut self, m: Msg) {
        self.queue.pop();
        match m {
            Msg::Loaded(res) => self.loaded(res),
            Msg::Probed(Ok(c)) => {
                self.ask = Some(Ask {
                    question: format!("Make {} your coordinator?", c.name),
                    consequences: vec![
                        format!(
                            "The machine at {} was installed from your USB stick as coordinator {}.",
                            self.addr_or("the coordinator's address"),
                            c.name
                        ),
                        format!("Its screen must show the code {}.", c.code),
                        "Every machine you signed before stays; lift the cut in Kill switch (9) after, so the servers follow it.".into(),
                    ],
                    act: Act::NewCoordinator(c),
                });
            }
            Msg::Probed(Err(e)) => self.notice = Some(Notice::bad(format!("Not a coordinator of yours: {}", words(&e.to_string())))),
            Msg::Wrote(Ok(said)) => self.notice = Some(Notice::ok(words(&said))),
            Msg::Wrote(Err(e)) => self.notice = Some(Notice::bad(format!("The server list was not written: {}", words(&e.to_string())))),
            Msg::Checked(Ok(p)) => {
                self.failed = None;
                self.tab = Tab::Updates;
                self.plan = Some(p);
            }
            Msg::Checked(Err(e)) => {
                self.tab = Tab::Updates;
                self.fresh_card = true;
                self.failed = Some((
                    format!("Not published, nothing was signed. {}", sentence(&words(&e.to_string()))),
                    "Fix that, then p tries again with the same choices.".into(),
                ));
            }
            Msg::Did { failed, publish, said, shown, view } => {
                let worked = said.is_ok();
                match (said, publish) {
                    (Ok(s), Some(_)) => {
                        // The next release starts from fresh choices.
                        self.choice = Choice::default();
                        self.failed = None;
                        self.notice = Some(Notice::ok(s));
                    }
                    (Ok(s), None) => self.notice = Some(Notice::ok(s)),
                    (Err(e), Some(serial)) => {
                        self.fresh_card = true;
                        self.failed = Some((
                            format!("Release {serial} was not published. {}", sentence(&words(&e.to_string()))),
                            "p publishes again: a new release gets a higher serial.".into(),
                        ));
                    }
                    (Err(e), None) => self.notice = Some(Notice::bad(format!("{failed}: {}", words(&e.to_string())))),
                }
                self.loaded(view);
                match shown {
                    Some(Shown::Device { name, conf, private }) if worked => self.shown = Some(ShownView::new(name, conf, private)),
                    Some(Shown::Sheet(key)) if worked && self.find(&key).is_some() => {
                        // Its keys go by its tab.
                        self.tab = Tab::People;
                        self.pick[Tab::People.at()] = Some(key.clone());
                        self.reselect();
                        self.opened = Some(Opened { key, cursor: 0 });
                    }
                    _ => {}
                }
            }
            Msg::Lost(why) => {
                self.line = None;
                self.queue = Queue::default();
                self.notice = Some(Notice::bad(format!(
                    "The screen's link to the coordinator stopped ({}): esc, then open Machines (4) again.",
                    report::printable(&why)
                )));
            }
        }
    }

    fn addr_or<'a>(&'a self, or: &'a str) -> &'a str {
        if self.addr.is_empty() { or } else { &self.addr }
    }

    // ---- rows and the selection ----

    fn rows(&self, tab: Tab) -> Vec<Row> {
        let v = &self.view;
        match tab {
            Tab::Machines => (0..v.pending.len()).map(Row::Request).chain((0..v.members.len()).map(Row::Member)).collect(),
            Tab::Updates => {
                let stopped = self.answered.is_some() && publish::stopped(&v.rollout);
                stopped.then_some(Row::Stopped).into_iter().chain((0..v.members.len()).map(Row::Member)).collect()
            }
            Tab::Network => (0..v.unknown.len())
                .map(Row::Device)
                .chain((0..v.reports.len()).map(Row::Cut))
                .chain((0..v.warnings.len()).map(Row::Warning))
                .collect(),
            Tab::People => (0..v.people.len()).map(Row::Person).collect(),
            Tab::Vpn => {
                // Nothing is known before the first answer: no row says otherwise.
                let known = self.answered.is_some();
                known.then_some(Row::Gateway).into_iter().chain((0..v.devices.len()).map(Row::VpnDevice)).collect()
            }
        }
    }

    fn row_key(&self, r: Row) -> String {
        let v = &self.view;
        match r {
            Row::Request(i) => format!("r:{}", v.pending.get(i).map(|r| r.id.as_str()).unwrap_or("")),
            Row::Member(i) => format!("m:{}", v.members.get(i).map(|(m, _)| m.name.as_str()).unwrap_or("")),
            Row::Stopped => "stopped".into(),
            Row::Device(i) => format!("d:{}", v.unknown.get(i).map(|d| d.ip.as_str()).unwrap_or("")),
            Row::Cut(i) => format!("c:{}", v.reports.get(i).map(String::as_str).unwrap_or("")),
            Row::Warning(i) => format!("w:{i}"),
            Row::Person(i) => format!("p:{}", v.people.get(i).map(|p| p.name.as_str()).unwrap_or("")),
            Row::Gateway => "gateway".into(),
            Row::VpnDevice(i) => format!("v:{}", v.devices.get(i).map(|d| d.name.as_str()).unwrap_or("")),
        }
    }

    fn find(&self, key: &str) -> Option<Row> {
        TABS.iter().flat_map(|t| self.rows(*t)).find(|r| self.row_key(*r) == key)
    }

    fn selected(&self) -> Option<Row> {
        self.rows(self.tab).get(self.sel[self.tab.at()]).copied()
    }

    /// The selection of every tab found again after a look: the same row
    /// where it is still there, else the one now at its place.
    fn reselect(&mut self) {
        for t in TABS {
            let rows = self.rows(t);
            let i = t.at();
            let found = self.pick[i].as_ref().and_then(|k| rows.iter().position(|r| self.row_key(*r) == *k));
            self.sel[i] = found.unwrap_or(self.sel[i]).min(rows.len().saturating_sub(1));
            self.pick[i] = rows.get(self.sel[i]).map(|r| self.row_key(*r));
        }
        if let Some(o) = &self.opened
            && self.find(&o.key).is_none()
        {
            self.opened = None;
        }
    }

    fn move_by(&mut self, up: bool) {
        if let Some(key) = self.opened.as_ref().map(|o| o.key.clone()) {
            let n = self.find(&key).map(|r| self.items(r).len()).unwrap_or(0);
            let o = self.opened.as_mut().expect("opened");
            o.cursor = if up { o.cursor.saturating_sub(1) } else { (o.cursor + 1).min(n.saturating_sub(1)) };
            return;
        }
        let rows = self.rows(self.tab);
        let i = self.tab.at();
        self.sel[i] = if up { self.sel[i].saturating_sub(1) } else { (self.sel[i] + 1).min(rows.len().saturating_sub(1)) };
        self.pick[i] = rows.get(self.sel[i]).map(|r| self.row_key(*r));
    }

    fn switch(&mut self, by: usize) {
        self.opened = None;
        self.tab = TABS[(self.tab.at() + by) % TABS.len()];
    }

    fn request(&self, r: Option<Row>) -> Option<&Request> {
        match r {
            Some(Row::Request(i)) => self.view.pending.get(i),
            _ => None,
        }
    }

    fn member(&self, r: Option<Row>) -> Option<&(Member, bool)> {
        match r {
            Some(Row::Member(i)) => self.view.members.get(i),
            _ => None,
        }
    }

    fn coordinator(&self) -> Option<&Member> {
        self.view.members.iter().map(|(m, _)| m).find(|m| m.host == 1)
    }

    /// The member the rollout stopped at (the coordinator for its own update).
    fn stopped_at(&self) -> Option<u32> {
        let r = &self.view.rollout;
        if !publish::stopped(r) {
            return None;
        }
        Some(if r.phase == Phase::Failed { 1 } else { r.pause_host })
    }

    /// Members on the coordinator that the next signature drops because
    /// nobody signed them, except keep.
    fn drops(&self, keep: &str) -> Vec<String> {
        self.view.would_drop(&[keep])
    }

    fn host_key_changed(&self) -> bool {
        self.err.as_ref().is_some_and(|e| e.is(Kind::HostKey))
    }

    /// The signed list needs sending again: the coordinator lost it,
    /// serves another, or has members nobody signed.
    fn list_problem(&self) -> Option<String> {
        if self.answered.is_none() || self.err.is_some() || self.view.version == 0 {
            return None;
        }
        let unsigned = self.view.unsigned();
        if !unsigned.is_empty() {
            return Some(format!(
                "Not signed by you: {}. The coordinator lists {} without your signature; servers ignore {}.",
                unsigned.join(", "),
                if unsigned.len() == 1 { "it" } else { "them" },
                if unsigned.len() == 1 { "it" } else { "them" }
            ));
        }
        self.view
            .warnings
            .iter()
            .find(|w| w.starts_with("The coordinator has no valid signed list") || w.starts_with("The coordinator serves"))
            .cloned()
    }

    // ---- the actions ----

    fn items(&self, r: Row) -> Vec<Do> {
        match r {
            Row::Request(_) => vec![Do::Approve, Do::Reject],
            Row::Member(i) => {
                let host = self.view.members.get(i).map(|(m, _)| m.host).unwrap_or(0);
                let mut v = Vec::new();
                if self.stopped_at() == Some(host) {
                    v.extend([Do::TryAgain, Do::Skip]);
                }
                v.extend([Do::Remove, Do::Sign]);
                if host == 1 {
                    v.push(Do::NewCoordinator);
                }
                v.push(Do::WriteList);
                v
            }
            Row::Stopped => vec![Do::TryAgain, Do::Skip, Do::Publish],
            Row::Device(_) | Row::Cut(_) | Row::Warning(_) => Vec::new(),
            Row::Person(_) => vec![Do::AddKey, Do::OnMachines, Do::HostsFile, Do::TakeOut],
            Row::Gateway if self.view.vpn.is_none() => vec![Do::Gateway],
            Row::Gateway => vec![Do::Gateway, Do::Token, Do::AddDevice, Do::VpnOff],
            Row::VpnDevice(_) => vec![Do::DeviceConfig, Do::RemoveDevice],
        }
    }

    fn label(&self, d: Do, r: Option<Row>) -> String {
        let name = |r: Option<Row>| {
            self.request(r).map(|q| q.name.clone()).or_else(|| self.member(r).map(|(m, _)| m.name.clone())).unwrap_or_default()
        };
        let rollout = &self.view.rollout;
        match d {
            Do::Approve => format!("approve {}", name(r)),
            Do::Reject => format!("reject {}", name(r)),
            Do::Remove => format!("remove {} from the swarm", name(r)),
            Do::Sign if self.view.version == 0 => "sign the coordinator".into(),
            Do::Sign => "sign your list again and send it".into(),
            Do::NewCoordinator => "look at a new coordinator, after a reinstall".into(),
            Do::WriteList => "write the server list, for ssh and the kill switch".into(),
            Do::TryAgain => match publish::resume_does(rollout) {
                Ok(what) => format!("try again: the coordinator {what}"),
                Err(_) => "try again".into(),
            },
            Do::Skip => match publish::skip_does(rollout) {
                Ok(what) if rollout.pause != Pause::Canary => format!("skip this machine: the coordinator {what}"),
                _ => "skip this machine".into(),
            },
            Do::Publish => "publish a fixed release: it replaces this rollout".into(),
            d => self.own_label(d, r),
        }
    }

    /// Why d cannot be done now, with r selected; None: it can.
    fn why_not(&self, d: Do, r: Option<Row>) -> Option<String> {
        if d == Do::Publish {
            return if self.publisher.is_none() {
                Some("This screen cannot publish: dryserver release publish in a terminal does.".into())
            } else if let Some(what) = self.queue.change().filter(|w| w.starts_with("publishing")) {
                Some(format!("Still {what}: one release at a time."))
            } else if self.queue.has(CHECKING) {
                Some("Already checking a release: wait for it.".into())
            } else {
                None
            };
        }
        if let Some(why) = self.own_why_not(d, r) {
            return why;
        }
        if let Some(what) = self.queue.change() {
            return Some(format!("Still {what}: one change at a time."));
        }
        if d == Do::NewCoordinator {
            return (!self.host_key_changed())
                .then(|| "The coordinator answers with the SSH key this computer knows: n is for after a reinstall.".to_string());
        }
        if self.host_key_changed() {
            return Some("The coordinator's address answers with another SSH key: nothing is signed for it. n looks at it.".into());
        }
        if self.err.is_some() {
            return Some("The coordinator does not answer, so nothing can be signed now: r looks again.".into());
        }
        if self.answered.is_none() {
            return Some("The coordinator has not answered yet: wait for it, the header says how long.".into());
        }
        let v = &self.view;
        match d {
            Do::Approve => match self.request(r) {
                None => Some("Select a machine that waits to join first (Machines tab).".into()),
                Some(q) if v.unproved.contains(&q.id) => Some(format!(
                    "{} has no valid proof from your USB stick: it was not installed from it, or the coordinator changed the \
                     request. It can only be rejected (x).",
                    q.name
                )),
                Some(_) => None,
            },
            Do::Reject => self.request(r).is_none().then(|| "Select a machine that waits to join first (Machines tab).".into()),
            Do::Remove => match self.member(r) {
                None => Some("Select a member first (Machines tab).".into()),
                Some((m, _)) if m.host == 1 => Some("The coordinator cannot be removed.".into()),
                Some(_) => None,
            },
            Do::Sign if v.version == 0 && v.coordinator_code.is_empty() => {
                Some("The coordinator sent no entry for itself: there is nothing to sign.".into())
            }
            Do::Sign => None,
            Do::WriteList if self.write_list.is_none() => Some("This screen cannot write the server list.".into()),
            Do::WriteList if v.version == 0 => Some("Nothing is signed yet: sign the coordinator first (s).".into()),
            Do::WriteList => None,
            Do::TryAgain => publish::resume_does(&v.rollout).err().map(|e| format!("Nothing to try again: {}.", words(&e.to_string()))),
            Do::Skip if publish::stopped(&v.rollout) && v.rollout.pause == Pause::Canary => {
                Some("The canary stopped the rollout, not a failure: try again (t) goes on after it.".into())
            }
            Do::Skip => publish::skip_does(&v.rollout).err().map(|e| format!("Nothing to skip: {}.", words(&e.to_string()))),
            Do::NewCoordinator | Do::Publish => None,
            d => self.own_why_not_signed(d, r),
        }
    }

    /// d, for row r: asks first, or says why not.
    fn act(&mut self, d: Do, r: Option<Row>) {
        if let Some(why) = self.why_not(d, r) {
            self.notice = Some(Notice::bad(why));
            return;
        }
        let v = &self.view;
        let also = |drops: Vec<String>| -> Vec<String> {
            if drops.is_empty() {
                Vec::new()
            } else {
                vec![format!("It also drops {} from the swarm: on the coordinator, not signed by you.", drops.join(", "))]
            }
        };
        // While nothing is signed, any change signs the coordinator too.
        let first = (v.version == 0 && !matches!(d, Do::Sign | Do::TryAgain | Do::Skip)).then(|| {
            let name = self.coordinator().map(|c| c.name.clone()).unwrap_or_else(|| "the coordinator".into());
            format!("It also signs the coordinator {name}: its screen must show the code {}.", v.coordinator_code)
        });
        let ask = |question: String, mut consequences: Vec<String>, drops: Vec<String>, act: Act| {
            consequences.extend(first.clone());
            consequences.extend(also(drops));
            Some(Ask { question, consequences, act })
        };
        self.ask = match d {
            Do::Approve => {
                let q = self.request(r).cloned().expect("why_not checked it");
                ask(
                    format!("Approve {}?", q.name),
                    vec![
                        format!("Its screen must show the code {}.", q.code),
                        "It gets the next free mesh address and joins within a minute.".into(),
                    ],
                    self.drops(""),
                    Act::Approve(q),
                )
            }
            Do::Reject => {
                let q = self.request(r).cloned().expect("why_not checked it");
                ask(
                    format!("Reject {}?", q.name),
                    vec!["It does not join, and its request is closed.".into()],
                    self.drops(""),
                    Act::Reject(q),
                )
            }
            Do::Remove => {
                let (m, _) = self.member(r).cloned().expect("why_not checked it");
                ask(
                    format!("Remove {} from the swarm?", m.name),
                    {
                        let mut c = vec![
                            "Servers drop it within a minute: it leaves the mesh and the cluster.".into(),
                            format!("Its mesh address {} is kept back from the next machines.", mesh::ip(&self.subnet, m.host)),
                        ];
                        if v.vpn.as_ref().is_some_and(|p| p.gateway == m.name) {
                            c.push(
                                "It is the VPN's gateway: the VPN is off until another server is made the gateway (VPN tab).".into(),
                            );
                        }
                        let only: Vec<&str> =
                            v.people.iter().filter(|p| p.on.len() == 1 && p.on[0] == m.name).map(|p| p.name.as_str()).collect();
                        if !only.is_empty() {
                            c.push(format!("{} may log in only on it: taken out too.", only.join(", ")));
                        }
                        c
                    },
                    self.drops(&m.name),
                    Act::Remove(m.name),
                )
            }
            Do::Sign if v.version == 0 => {
                let name = self.coordinator().map(|c| c.name.clone()).unwrap_or_else(|| "the coordinator".into());
                ask(
                    format!("Sign the coordinator {name}?"),
                    vec![
                        format!("Its screen must show the code {} (shown after its install).", v.coordinator_code),
                        "It becomes the first entry of your signed list; then machines can join.".into(),
                    ],
                    self.drops(""),
                    Act::SignCoordinator,
                )
            }
            Do::Sign => ask(
                "Sign your list again and send it?".into(),
                vec!["The same members, under a new version: the coordinator hands it to every server.".into()],
                self.drops(""),
                Act::Resend,
            ),
            Do::TryAgain => ask(
                format!("Try release {} again?", v.rollout.serial),
                vec![
                    format!("The coordinator {}.", publish::resume_does(&v.rollout).unwrap_or_default()),
                    "It does so at its next sync, within a minute.".into(),
                ],
                Vec::new(),
                Act::Resume,
            ),
            Do::Skip => {
                let who = v.rollout.pause_name.clone();
                ask(
                    format!("Skip {} for release {}?", if who.is_empty() { "the server" } else { &who }, v.rollout.serial),
                    vec![
                        format!("The coordinator {}.", publish::skip_does(&v.rollout).unwrap_or_default()),
                        "The machine keeps the release it runs until the next one.".into(),
                    ],
                    Vec::new(),
                    Act::Skip,
                )
            }
            Do::NewCoordinator => {
                self.send(Job::Probe);
                None
            }
            Do::WriteList => {
                self.send(Job::Write);
                None
            }
            Do::Publish => {
                self.open_form();
                None
            }
            d => {
                let mut asked = self.own_act(d, r);
                if let Some(a) = &mut asked {
                    a.consequences.extend(first.clone());
                    a.consequences.extend(also(self.drops("")));
                }
                asked
            }
        };
    }

    // ---- the People and VPN tabs' actions (people_tab, vpn_tab) ----

    fn own_label(&self, d: Do, r: Option<Row>) -> String {
        if PEOPLE_DOS.contains(&d) { self.people_label(d, r) } else { self.vpn_label(d, r) }
    }

    /// Some: decided without the coordinator; None: the usual checks.
    fn own_why_not(&self, d: Do, r: Option<Row>) -> Option<Option<String>> {
        if PEOPLE_DOS.contains(&d) {
            self.people_why_not(d, r)
        } else if VPN_DOS.contains(&d) {
            self.vpn_why_not(d, r)
        } else {
            None
        }
    }

    fn own_why_not_signed(&self, d: Do, r: Option<Row>) -> Option<String> {
        if PEOPLE_DOS.contains(&d) { self.people_why_not_signed(d, r) } else { self.vpn_why_not_signed(d, r) }
    }

    fn own_act(&mut self, d: Do, r: Option<Row>) -> Option<Ask> {
        if PEOPLE_DOS.contains(&d) { self.people_act(d, r) } else { self.vpn_act(d, r) }
    }

    fn entry_key(&mut self, e: Entry, k: &Key) {
        match e {
            Entry::Person(f) => self.person_form_key(f, k),
            Entry::Plan(f) => self.plan_form_key(f, k),
            Entry::Device(f) => self.device_form_key(f, k),
        }
    }

    /// The question with what else the signature does: drop the members
    /// nobody signed.
    fn with_drops(&self, mut a: Ask) -> Ask {
        let drops = self.drops("");
        if !drops.is_empty() {
            a.consequences.push(format!("It also drops {} from the swarm: on the coordinator, not signed by you.", drops.join(", ")));
        }
        a
    }

    fn open_form(&mut self) {
        let version = self.publisher.as_ref().map(|p| p.parts.version.clone()).unwrap_or_default();
        self.opened = None;
        self.tab = Tab::Updates;
        self.failed = None;
        self.form = Some(publish_form(&self.choice, &version));
    }

    // ---- keys ----

    fn key(&mut self, k: Key) -> Flow {
        // A paste where a key is expected does nothing.
        if matches!(k, Key::Paste(_)) && !self.typing() {
            return Flow::Continue;
        }
        if k == Key::Ctrl('c') {
            // The hub quits right after this: say what it cut off.
            if let Some(what) = self.queue.change() {
                self.after = Some(Notice::bad(if what.starts_with("publishing") {
                    format!(
                        "dryserver closed while {what}. The upload stopped half way, and a cut-off upload is not taken: \
                         Updates (7) shows whether it arrived. Publish again if not (it gets a new serial)."
                    )
                } else {
                    format!("dryserver closed while {what}: it may not have reached the coordinator. Machines (4) shows how it stands.")
                }));
            }
            return Flow::Quit;
        }
        if self.shown.is_some() {
            return self.shown_key(k);
        }
        if let Some(a) = self.ask.take() {
            if k == Key::Char('y') {
                if let Act::Publish(_) = &a.act {
                    self.tab = Tab::Updates;
                }
                self.send(Job::Act(a.act));
            } else {
                if let Act::Publish(p) = a.act {
                    self.plan = Some(p);
                }
                self.notice = Some(Notice::info("Nothing was signed."));
            }
            return Flow::Continue;
        }
        self.notice = None;
        self.fresh_card = false;
        if let Some(mut f) = self.form.take() {
            f.update(&k);
            match f.status {
                Status::Completed => {
                    let mut c = f.state.clone();
                    c.notes = c.notes.trim().to_string();
                    self.choice = c.clone();
                    self.send(Job::Check(c));
                }
                Status::Aborted => {
                    self.choice = f.state.clone();
                    self.notice = Some(Notice::info("Nothing was signed."));
                }
                Status::Active => self.form = Some(f),
            }
            return Flow::Continue;
        }
        if let Some(e) = self.entry.take() {
            self.entry_key(e, &k);
            return Flow::Continue;
        }
        if let Some(p) = self.plan.take() {
            match k {
                Key::Enter => {
                    let n = p.machines();
                    let window = rollout::window_text(rollout::WINDOW);
                    self.ask = Some(Ask {
                        question: format!("Sign and send release {} to the coordinator?", p.release.serial),
                        consequences: vec![
                            format!(
                                "It goes to {n} machine{}: the coordinator first, then the servers one at a time.",
                                if n == 1 { "" } else { "s" }
                            ),
                            if p.release.urgent {
                                "Urgent: the rollout starts at once.".into()
                            } else {
                                format!("Machines update {window} on the coordinator's clock.")
                            },
                            "It is signed with this computer's key; a fixed release later replaces it.".into(),
                        ],
                        act: Act::Publish(p),
                    });
                }
                Key::Esc => {
                    self.notice = Some(Notice::info("Nothing was signed: change the choices and enter checks them again."));
                    self.open_form();
                }
                _ => self.plan = Some(p),
            }
            return Flow::Continue;
        }
        let armed = std::mem::take(&mut self.leave_armed);
        match k {
            Key::Esc if self.opened.is_some() => self.opened = None,
            Key::Esc => match self.queue.change().map(str::to_string) {
                Some(what) if !armed && adding(&what) => {
                    self.leave_armed = true;
                    self.notice = Some(Notice::bad(format!(
                        "Still {what}. esc again leaves, and its config is never shown: with a key made here, nobody has its \
                         private key, and the device must be taken off and added again."
                    )));
                }
                Some(what) if !armed => {
                    self.leave_armed = true;
                    self.notice = Some(Notice::bad(format!(
                        "Still {what}. esc again leaves: it goes on while dryserver runs, and Machines (4) shows how it ended."
                    )));
                }
                Some(what) => {
                    self.after = Some(Notice::info(if what.starts_with("publishing") {
                        format!(
                            "Machines closed while {what}: it goes on while dryserver runs. Updates (7) shows whether it \
                             arrived; publish again if not (it gets a new serial)."
                        )
                    } else if adding(&what) {
                        format!(
                            "Machines closed while {what}: its config was not shown. Take it off in Machines (4), VPN tab, and add \
                             it again."
                        )
                    } else {
                        format!("Machines closed while {what}: it goes on while dryserver runs. Machines (4) shows how it ended.")
                    }));
                    return Flow::Quit;
                }
                None => return Flow::Quit,
            },
            Key::Tab | Key::Right => self.switch(1),
            Key::BackTab | Key::Left => self.switch(TABS.len() - 1),
            Key::Up | Key::Char('k') => self.move_by(true),
            Key::Down | Key::Char('j') => self.move_by(false),
            Key::Enter => match &self.opened {
                Some(o) => {
                    if let Some(r) = self.find(&o.key)
                        && let Some(d) = self.items(r).get(o.cursor).copied()
                    {
                        self.act(d, Some(r));
                    }
                }
                None => {
                    // A cut and a warning are whole in the list already.
                    if let Some(
                        r @ (Row::Request(_)
                        | Row::Member(_)
                        | Row::Stopped
                        | Row::Device(_)
                        | Row::Person(_)
                        | Row::Gateway
                        | Row::VpnDevice(_)),
                    ) = self.selected()
                    {
                        self.opened = Some(Opened { key: self.row_key(r), cursor: 0 });
                    }
                }
            },
            Key::Char('r') => {
                if self.queue.has(LOADING) {
                    self.notice = Some(Notice::info("Already asking the coordinator: the header says how long it waits."));
                } else {
                    self.failed = None;
                    self.look();
                }
            }
            Key::Char(c) => {
                if let Some(d) = Do::of(c, self.tab) {
                    let r = self.opened.as_ref().and_then(|o| self.find(&o.key)).or_else(|| self.selected());
                    self.act(d, r);
                }
            }
            _ => {}
        }
        Flow::Continue
    }

    // ---- the page ----

    /// Right of the header: the coordinator and whether it answers.
    fn status(&self) -> Doc {
        let p = theme::palette();
        let mut d = Doc::new();
        d.add(Seg("coordinator ".into(), p.hint()));
        d.add(Seg(self.addr_or("?").to_string(), p.text()));
        d.s("  ");
        let loading = self.queue.running().filter(|(l, _)| *l == LOADING).map(|(_, t)| t);
        if self.host_key_changed() {
            d.add(theme::mark(Mark::Bad)).add(err(" another SSH key"));
        } else if self.err.is_some() {
            let down = self.down_since.map(|t| super::dur(t.elapsed())).unwrap_or_default();
            d.add(theme::mark(Mark::Bad)).add(err(format!(" no answer for {down}")));
            if let Some(t) = loading {
                d.add(Seg(format!(" · asking again {}", super::dur(t)), p.hint()));
            }
        } else if self.answered.is_none() {
            let t = loading.map(super::dur).unwrap_or_default();
            d.add(theme::mark(Mark::Wait)).add(Seg(format!(" asking {t}"), p.hint()));
        } else if let Some(t) = loading.filter(|t| *t >= SLOW) {
            d.add(theme::mark(Mark::Wait)).add(Seg(format!(" slow: waiting {}", super::dur(t)), p.hint()));
        } else {
            d.add(theme::mark(Mark::Done)).add(Seg(" answers".into(), p.fg(p.gold)));
        }
        d
    }

    /// The cards every tab shows first: the coordinator does not answer,
    /// or answers with another key, or a key file is missing.
    fn top_cards(&self, b: &mut Doc, w: usize) {
        if let Some(path) = &self.missing {
            space(b);
            b.append(frame::card(
                w,
                &format!("A key is missing: {} is not there. Nothing here can be signed or checked without it.", path.display()),
                "Put your copy of secrets/ back where it was. Home (esc) shows what else is missing.",
                None,
            ));
            b.nl();
        }
        let Some(e) = &self.err else {
            if self.answered.is_none() {
                let t = self.queue.running().filter(|(l, _)| *l == LOADING).map(|(_, t)| t).unwrap_or_default();
                b.add(Seg(spinner().into(), theme::palette().selected()))
                    .s(format!(" Asking the coordinator at {}{} {}", self.addr_or("its address"), theme::ellipsis(), super::dur(t)))
                    .nl();
                if t >= SLOW {
                    b.add(dim("It takes longer than usual: the coordinator may be busy, or off. The screen keeps working; esc goes back."))
                        .nl();
                }
            }
            return;
        };
        let text = words(&e.to_string());
        let stale = self.answered.map(|t| format!(" What shows below is from {} ago.", super::dur(t.elapsed()))).unwrap_or_default();
        if e.is(Kind::HostKey) {
            space(b);
            b.append(frame::card(
                w,
                &sentence(&text),
                &format!(
                    "If you reinstalled the coordinator from your USB stick, look at the new one: it must show the code on its own \
                     screen. If you did not, something else answers at its address: change nothing.{stale}"
                ),
                Some(("n", "look at the new coordinator")),
            ));
        } else {
            let todo = format!("Is it on, and on your network? The screen asks again every {}s.{stale}", RETRY.as_secs());
            space(b);
            b.append(frame::card(w, &format!("Cannot talk to the coordinator. {}", sentence(&text)), &todo, Some(("r", "look again now"))));
        }
        b.nl();
    }

    fn machines_body(&self, w: usize) -> (Doc, Option<Focus>) {
        let p = theme::palette();
        let mut b = Doc::new();
        let now = (self.now)();
        self.top_cards(&mut b, w);
        if self.answered.is_none() {
            // Nothing is known yet: no empty lists that say otherwise.
            return (b, None);
        }
        let v = &self.view;
        if self.answered.is_some() && self.err.is_none() {
            if v.version == 0 {
                if v.coordinator_code.is_empty() {
                    space(&mut b);
                    b.append(frame::card(
                        w,
                        "The coordinator sent no entry for itself. There is nothing to sign.",
                        "It was not installed as a coordinator from your USB stick, or its registry is damaged: install it again \
                         from the stick.",
                        None,
                    ));
                } else {
                    space(&mut b);
                    b.append(frame::card(
                        w,
                        &format!("Sign your coordinator: its screen shows the code {}.", v.coordinator_code),
                        "Compare it with the code on the coordinator's own screen, shown after its install. Signing makes it the \
                         first entry of your signed list; then other machines can join.",
                        Some(("s", "sign the coordinator")),
                    ));
                }
                b.nl();
            } else if let Some(problem) = self.list_problem() {
                space(&mut b);
                b.append(frame::card(
                    w,
                    &problem,
                    "Sign your list again and send it: the coordinator then serves it, and what nobody signed drops out.",
                    Some(("s", "sign your list again")),
                ));
                b.nl();
            }
            let others = v.warnings.len();
            if others > 0 {
                space(&mut b);
                put(
                    &mut b,
                    hang(
                        w,
                        Mark::Bad,
                        vec![Seg(format!("{others} warning{} on the Network tab (→).", if others == 1 { "" } else { "s" }), p.text())],
                    ),
                );
            }
        }
        let cards = b.lines.len() - 1;
        let sel = self.selected();
        let mut focus = None;
        frame::section(&mut b, "Waiting to join", Some(v.pending.len()));
        if v.pending.is_empty() {
            b.append(frame::empty("No machine waits to join. Boot the USB stick on another laptop and choose server.")).nl();
        }
        for (i, r) in v.pending.iter().enumerate() {
            if sel == Some(Row::Request(i)) {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let unproved = v.unproved.contains(&r.id);
            let (m, code) = if unproved {
                (Mark::Bad, Seg("no proof: reject only".into(), p.alarm()))
            } else {
                (Mark::Act, Seg(format!("code {}", r.code), p.text().add_modifier(Modifier::BOLD)))
            };
            b.append(frame::row(
                w,
                m,
                vec![
                    col(Seg(r.name.clone(), p.text()), 16),
                    col(Seg(r.lan_ip.clone(), p.hint()), 15),
                    col(code, 21),
                    col(Seg(ago(r.created, now), p.hint()), 0),
                ],
            ))
            .nl();
        }
        if !v.unproved.is_empty() {
            b.add(dim("No proof: not installed from your USB stick, or changed by the coordinator. It can only be rejected (x).")).nl();
        } else if !v.pending.is_empty() {
            b.add(dim("Approve only when the code is the one on the new machine's own screen.")).nl();
        }
        frame::section(&mut b, "Members", Some(v.members.len()));
        if v.members.is_empty() {
            b.append(frame::empty(
                "The coordinator lists no machine, not even itself: it was not installed as a coordinator from your stick.",
            ))
            .nl();
        }
        let target = v.rollout.serial;
        let seen_w = 14;
        let health_w = w.saturating_sub(3 + 18 + 13 + seen_w + 2).max(12);
        for (i, (m, signed)) in v.members.iter().enumerate() {
            if sel == Some(Row::Member(i)) {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let (mark, text, alarm) = health_line(m, *signed, v.version == 0, now, target);
            let style = if alarm { p.alarm() } else { p.hint() };
            let seen = if m.last_seen.is_zero() { "never seen".to_string() } else { format!("seen {}", ago(m.last_seen, now)) };
            b.append(frame::row(
                w,
                mark,
                vec![
                    col(Seg(m.name.clone(), p.text()), 16),
                    col(Seg(mesh::ip(&self.subnet, m.host), p.hint()), 11),
                    col(Seg(text, style), health_w),
                    col(Seg(seen, p.hint()), 0),
                ],
            ))
            .nl();
        }
        b.nl();
        b.add(dim(if v.version == 0 { "Nothing is signed yet.".to_string() } else { format!("Signed list version {}.", v.version) }));
        if self.fresh_card && cards > 0 {
            focus = Some(Focus::keep(0..cards));
        }
        (b, focus)
    }

    /// Progress of a job or the rollout: the snake where there is room, a
    /// line with a bar where there is not.
    fn progress(&self, b: &mut Doc, w: usize, rows: usize, pct: Option<f64>, step: &str, took: Duration) {
        let p = theme::palette();
        if rows >= RING_ROWS {
            b.append(frame::progress(w, pct, step, took)).nl();
            return;
        }
        match pct {
            Some(x) => {
                b.append(theme::bar(x, 24)).add(Seg(format!(" {:>3.0}%  ", x * 100.0), p.hint()));
            }
            None => {
                b.add(Seg(spinner().into(), p.selected())).s(" ");
            }
        }
        if !step.is_empty() {
            b.add(Seg(super::fit(step, w.saturating_sub(40).max(10)), p.text())).s("  ");
        }
        b.add(Seg(super::dur(took), p.hint())).nl();
    }

    fn updates_body(&self, w: usize, rows: usize) -> (Doc, Option<Focus>) {
        let p = theme::palette();
        let mut b = Doc::new();
        let now = (self.now)();
        self.top_cards(&mut b, w);
        if self.answered.is_none() {
            return (b, None);
        }
        if let Some((problem, todo)) = &self.failed {
            space(&mut b);
            b.append(frame::card(w, problem, todo, Some(("p", "publish again"))));
            b.nl();
        }
        if let Some((label, took)) = self.queue.running().filter(|(l, _)| *l == CHECKING || l.starts_with("publishing")) {
            let step = if label == CHECKING { "Checking the release" } else { label };
            space(&mut b);
            self.progress(&mut b, w, rows, None, &sentence(step), took);
            b.nl();
        }
        let cards = b.lines.len() - 1;
        let v = &self.view;
        frame::section(&mut b, "Release", None);
        match &v.release {
            Some(r) => {
                b.add(Seg(rollout::release_line(r), p.text())).nl();
                b.add(dim(format!("dryserver {} · k3s {} · Arch {}", r.dryserver.version, r.k3s.version, r.arch_date))).nl();
            }
            None => {
                let text = match &self.publisher {
                    Some(p) => format!(
                        "No release published yet. p publishes this dryserver ({}) to every machine: the coordinator first, then \
                         the servers one at a time.",
                        p.parts.version
                    ),
                    None => "No release published yet.".into(),
                };
                b.append(frame::empty(&text)).nl();
            }
        }
        let sel = self.selected();
        let mut focus = None;
        let r = &v.rollout;
        let stopped = self.rows(Tab::Updates).contains(&Row::Stopped);
        if stopped {
            space(&mut b);
            let start = b.lines.len() - 1;
            let name = if r.pause_name.is_empty() { "the server".to_string() } else { r.pause_name.clone() };
            let (problem, todo) = if r.phase == Phase::Failed {
                (
                    format!("The coordinator's own update of release {} failed. The coordinator says: {}", r.serial, r.paused),
                    "No server was touched. Look at the coordinator, then try again; or publish a fixed release (p): it gets a \
                     higher serial and replaces this rollout."
                        .to_string(),
                )
            } else {
                (
                    format!("The rollout of release {} stopped at {name}. The coordinator says: {}", r.serial, r.paused),
                    format!(
                        "Look at {name} first: enter on it below shows what it reports. Then try again, or skip this machine; or \
                         publish a fixed release (p): it gets a higher serial and replaces this rollout."
                    ),
                )
            };
            let key = if r.phase == Phase::Failed || r.pause == Pause::Canary { "try again" } else { "try again or skip this machine" };
            b.append(frame::card(w, &problem, &todo, Some(("enter", key))));
            b.nl();
            if sel == Some(Row::Stopped) {
                focus = Some(Focus { lines: start..b.lines.len() - 1, paint: true });
            }
        }
        let at = if v.coordinator_now > 0 { v.coordinator_now } else { now.0.timestamp() };
        let mut lines: Vec<(String, bool)> = publish::rollout_lines(v, at)
            .into_iter()
            // The card and the keys say what the commands would.
            .filter(|(l, _)| !l.contains("dryserver release"))
            .filter(|(l, _)| !(stopped && (l.starts_with("PAUSED: ") || l.starts_with("FAILED: "))))
            .collect();
        if r.serial != 0 || !lines.is_empty() {
            frame::section(&mut b, "Rollout", None);
            let members = v.members.len().max(1);
            if r.serial != 0 && !stopped && r.phase != Phase::None {
                let brain_done = r.phase == Phase::Servers
                    || self.coordinator().and_then(|c| c.report.as_ref()).is_some_and(|rep| rep.release >= r.serial);
                let servers = v.members.iter().filter(|(m, _)| m.host != 1 && r.done.contains(&m.host)).count();
                let pct = (usize::from(brain_done) + servers) as f64 / members as f64;
                let took = if r.started > 0 && at > r.started { Duration::from_secs((at - r.started) as u64) } else { Duration::ZERO };
                // Beside the snake, the first line is the step, and not said
                // twice; beside a bar the lines follow whole.
                let first = lines.iter().position(|(_, a)| !a);
                let step = first.map(|i| lines[i].0.clone()).unwrap_or_else(|| format!("Release {}", r.serial));
                if rows >= RING_ROWS {
                    self.progress(&mut b, w, rows, Some(pct), &step, took);
                    if let Some(i) = first {
                        lines.remove(i);
                    }
                } else {
                    self.progress(&mut b, w, rows, Some(pct), "", took);
                }
            }
            for (l, alarm) in &lines {
                let l = l.strip_prefix("! ").unwrap_or(l);
                let (m, style) = if *alarm { (Mark::Bad, p.text()) } else { (Mark::Blank, p.hint()) };
                put(&mut b, hang(w, m, vec![Seg(l.to_string(), style)]));
            }
        }
        frame::section(&mut b, "Machines", Some(v.members.len()));
        if v.members.is_empty() {
            b.append(frame::empty("The coordinator lists no machine.")).nl();
        }
        for (i, (m, _)) in v.members.iter().enumerate() {
            if sel == Some(Row::Member(i)) {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let (state, alarm) = publish::machine_state(m, r, at);
            let release = m.report.as_ref().map_or(0, |rep| rep.release);
            let mark = match (alarm, r.serial) {
                (true, _) => Mark::Bad,
                (false, 0) if release == 0 => Mark::Off,
                (false, 0) => Mark::Done,
                (false, t) if release >= t => Mark::Done,
                _ => Mark::Wait,
            };
            b.append(frame::row(
                w,
                mark,
                vec![
                    col(Seg(m.name.clone(), p.text()), 16),
                    col(Seg((if m.host == 1 { "coordinator" } else { "server" }).into(), p.hint()), 11),
                    col(Seg(state, if alarm { p.alarm() } else { p.hint() }), 0),
                ],
            ))
            .nl();
        }
        if self.fresh_card && cards > 0 {
            focus = Some(Focus::keep(0..cards));
        }
        (b, focus)
    }

    fn network_body(&self, w: usize) -> (Doc, Option<Focus>) {
        let p = theme::palette();
        let mut b = Doc::new();
        let now = (self.now)();
        self.top_cards(&mut b, w);
        if self.answered.is_none() {
            // Nothing is known yet: no empty lists that say otherwise.
            return (b, None);
        }
        let cards = b.lines.len() - 1;
        let v = &self.view;
        let sel = self.selected();
        let mut focus = None;
        frame::section(&mut b, "Unknown devices", Some(v.unknown.len()));
        if v.scanned.is_zero() {
            b.append(frame::empty("No scan yet: the coordinator looks at your WiFi/router network every few minutes.")).nl();
        } else if v.unknown.is_empty() {
            b.append(frame::empty(&format!("Nothing unknown on your WiFi/router network at the last scan, {}.", ago(v.scanned, now)))).nl();
        } else {
            b.add(dim(format!(
                "On your WiFi/router network at the coordinator's scan {}, and not a member. Nothing here gets into the mesh; look \
                 up one you do not know in your router.",
                ago(v.scanned, now)
            )))
            .nl();
        }
        for (i, d) in v.unknown.iter().enumerate() {
            if sel == Some(Row::Device(i)) {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let what = if d.vendor.is_empty() { "vendor unknown".to_string() } else { d.vendor.clone() };
            b.append(frame::row(
                w,
                if d.ssh { Mark::Bad } else { Mark::Wait },
                vec![
                    col(Seg(d.ip.clone(), p.text()), 15),
                    col(Seg(d.mac.clone(), p.hint()), 17),
                    col(Seg(if d.ssh { "ssh open".into() } else { String::new() }, p.alarm()), 8),
                    col(Seg(what, p.hint()), 0),
                ],
            ))
            .nl();
        }
        frame::section(&mut b, "Cut off", Some(v.reports.len()));
        if v.reports.is_empty() {
            b.append(frame::empty("No machine has cut another off.")).nl();
        }
        for (i, r) in v.reports.iter().enumerate() {
            let lines = put(&mut b, hang(w, Mark::Bad, vec![Seg(r.clone(), p.text())]));
            if sel == Some(Row::Cut(i)) {
                focus = Some(Focus { lines, paint: true });
            }
        }
        if !v.reports.is_empty() {
            b.add(dim("A member's word, relayed by the coordinator: look into it. The Kill switch (9) shows and lifts cuts.")).nl();
        }
        frame::section(&mut b, "Warnings", Some(v.warnings.len()));
        if v.warnings.is_empty() {
            b.append(frame::empty("Nothing needs a look.")).nl();
        }
        for (i, wtext) in v.warnings.iter().enumerate() {
            let lines = put(&mut b, hang(w, Mark::Bad, vec![Seg(words(wtext), p.text())]));
            if sel == Some(Row::Warning(i)) {
                focus = Some(Focus { lines, paint: true });
            }
        }
        if self.fresh_card && cards > 0 {
            focus = Some(Focus::keep(0..cards));
        }
        (b, focus)
    }

    /// A row's sheet: what is known about it, whole, then what can be done
    /// to it, as a raised panel in the body. Returns it with the line of
    /// the chosen action.
    fn sheet(&self, w: usize, r: Row, cursor: usize) -> (Doc, Option<usize>) {
        let p = theme::palette();
        let now = (self.now)();
        let v = &self.view;
        let pw = w.min(SHEET);
        let inner = pw.saturating_sub(4).max(10);
        let mut lines: Vec<Vec<Seg>> = Vec::new();
        let mut about: Vec<Vec<Seg>> = Vec::new();
        let title = match r {
            Row::Request(i) => {
                let q = &v.pending[i];
                about.push(vec![txt(format!(
                    "Asks to join from {}{}, {}.",
                    q.lan_ip,
                    if q.switch { ", with a cable to the switch" } else { "" },
                    ago(q.created, now)
                ))]);
                if v.unproved.contains(&q.id) {
                    about.push(vec![err(
                        "No proof from your USB stick: it was not installed from it, or the coordinator changed the request. It \
                         can only be rejected.",
                    )]);
                } else {
                    about.push(vec![
                        txt("Code "),
                        Seg(q.code.clone(), p.text().add_modifier(Modifier::BOLD)),
                        txt(format!(": approve only when {}'s own screen shows this code.", q.name)),
                    ]);
                }
                about.push(vec![dim(format!("WireGuard key {}", q.wg_key))]);
                about.push(vec![dim(format!("SSH key {}", q.ssh_host_key))]);
                q.name.clone()
            }
            Row::Member(i) => {
                let (m, signed) = &v.members[i];
                let link = if m.switch { "a cable to the switch" } else { "WiFi/router" };
                let seen = if m.last_seen.is_zero() { "never seen".to_string() } else { format!("seen {}", ago(m.last_seen, now)) };
                about.push(vec![txt(format!(
                    "{} · mesh {} · LAN {} · over {link} · {seen}",
                    if m.host == 1 { "coordinator" } else { "server" },
                    mesh::ip(&self.subnet, m.host),
                    if m.lan_ip.is_empty() { "?" } else { &m.lan_ip }
                ))]);
                about.push(if *signed {
                    vec![theme::mark(Mark::Done), Seg(" in the list you signed".into(), p.hint())]
                } else {
                    vec![theme::mark(Mark::Bad), err(" not signed by you: put on the coordinator without you; servers ignore it")]
                });
                if self.stopped_at() == Some(m.host) {
                    about.push(vec![theme::mark(Mark::Bad), err(format!(" the rollout stopped here: {}", v.rollout.paused))]);
                }
                about.push(Vec::new());
                let names = |host: u32| {
                    v.members.iter().find(|(o, _)| o.host == host).map(|(o, _)| o.name.clone()).unwrap_or_else(|| host.to_string())
                };
                about.extend(report_lines(m, &names, now));
                m.name.clone()
            }
            Row::Stopped => {
                let r = &v.rollout;
                about.push(vec![txt("The coordinator says: "), err(r.paused.clone())]);
                let who = if r.phase == Phase::Failed { "the coordinator".to_string() } else { r.pause_name.clone() };
                if !who.is_empty() {
                    about.push(vec![dim(format!("Look at {who} first: its own sheet shows what it reports."))]);
                }
                format!("Release {} stopped", r.serial)
            }
            Row::Device(i) => {
                let d = &v.unknown[i];
                about.push(vec![txt(format!("MAC {}", d.mac))]);
                about.push(vec![txt(format!("Vendor {}", if d.vendor.is_empty() { "unknown" } else { &d.vendor }))]);
                if d.ssh {
                    about.push(vec![err("It answers on the SSH port.")]);
                }
                about.push(vec![dim(format!(
                    "Seen by the coordinator's scan {}. dryserver never lets it into the mesh. If you do not know it, look it up in \
                     your router's list of devices.",
                    ago(if d.seen.is_zero() { v.scanned } else { d.seen }, now)
                ))]);
                d.ip.clone()
            }
            Row::Cut(_) | Row::Warning(_) => String::new(),
            Row::Person(i) => self.person_about(i, &mut about),
            Row::Gateway => self.gateway_about(&mut about),
            Row::VpnDevice(i) => self.device_about(i, &mut about),
        };
        lines.extend(frame::wrap_line(&[Seg(title, p.title())], inner));
        lines.push(Vec::new());
        for l in about {
            lines.extend(frame::wrap_line(&l, inner));
        }
        lines.push(Vec::new());
        let items = self.items(r);
        let mut at = None;
        if items.is_empty() {
            lines.push(vec![dim("Nothing to do here; esc goes back.")]);
        } else {
            lines.push(vec![Seg("What you can do".into(), p.title())]);
        }
        for (i, d) in items.iter().enumerate() {
            let pointer = if i == cursor { Seg(format!("{} ", theme::BAR), p.selected()) } else { plain("  ") };
            let k = d.key().to_string();
            let (head, body) = match self.why_not(*d, Some(r)) {
                None => (vec![pointer, theme::cap(&k)], vec![Seg(format!(" {}", self.label(*d, Some(r))), p.text())]),
                Some(why) => (
                    vec![pointer, Seg(format!(" {k} "), p.faint())],
                    vec![Seg(format!(" {}: {}", self.label(*d, Some(r)), why.trim_end_matches('.')), p.faint())],
                ),
            };
            let hw: usize = head.iter().map(|s| unicode_width::UnicodeWidthStr::width(s.0.as_str())).sum();
            if i == cursor {
                at = Some(lines.len());
            }
            for (j, part) in frame::wrap_line(&body, inner.saturating_sub(hw).max(10)).into_iter().enumerate() {
                let mut l = if j == 0 { head.clone() } else { vec![plain(" ".repeat(hw))] };
                l.extend(part);
                lines.push(l);
            }
        }
        let panel = frame::raised(pw, &lines);
        // Centred in the body, like a panel over it.
        let pad = (w.saturating_sub(pw)) / 2;
        let mut d = Doc::new();
        for (i, l) in panel.lines.into_iter().enumerate() {
            if i > 0 {
                d.nl();
            }
            if pad > 0 {
                d.s(" ".repeat(pad));
            }
            d.lines.last_mut().expect("a line").extend(l);
        }
        // The panel's first content line is its second.
        (d, at.map(|a| a + 1))
    }

    fn summary_body(&self, plan: &Plan) -> Doc {
        let p = theme::palette();
        let mut b = Doc::new();
        frame::section(&mut b, &format!("Release {}, checked and ready to sign", plan.release.serial), None);
        for line in plan.lines() {
            b.add(Seg(line, p.text())).nl();
        }
        b.nl();
        b.add(dim(
            "Nothing is signed yet. enter signs it and sends it to the coordinator, after one more question; esc goes back to the choices.",
        ))
        .nl();
        b
    }

    fn help(&self) -> Help {
        let k = |a: &str, b: &str| (a.to_string(), b.to_string());
        let mut keys = vec![k("tab ←→", "the other tabs"), k("↑↓ enter", "move; enter shows the row whole, with what can be done")];
        let about = match self.tab {
            Tab::Machines => {
                keys.extend([
                    k("a x", "approve or reject the machine that waits to join"),
                    k("d", "remove the selected member"),
                    k("s", "sign: the coordinator first, later your list again"),
                    k("n", "look at a new coordinator, after a reinstall"),
                ]);
                "Every decision here is signed with this computer's key, and asks first. Approve a machine only when its own \
                 screen shows the same code."
            }
            Tab::People => {
                keys.extend([
                    k("a", "let someone in: their own account, their SSH key only"),
                    k("e m", "add a key; change where they may log in"),
                    k("f", "write the lines their ssh needs (known_hosts) to a file"),
                    k("d", "take them out: their account is locked everywhere"),
                ]);
                "Others who may log in to your servers: an account of their own, their keys only; no sudo, no docker, no \
                 cluster. Every change is in the list you sign."
            }
            Tab::Vpn => {
                keys.extend([
                    k("g", "set the VPN up, or change its gateway, address or ports"),
                    k("t", "the certificates' token, on the gateway (over ssh)"),
                    k("a c d", "add a device; show its config; take it off"),
                    k("x", "turn the VPN off (the devices stay listed)"),
                ]);
                "Your own devices reach the apps with ENTRANCE=vpn over a WireGuard VPN of their own, through one server, \
                 the gateway. The gateway and every device are in the list you sign."
            }
            Tab::Updates => {
                keys.extend([k("p", "publish a release of this dryserver"), k("t o", "a stopped rollout: try again, or skip its machine")]);
                "A release is signed here and goes to the coordinator first, then to one server at a time."
            }
            Tab::Network => "What the coordinator sees on your WiFi/router network, the cuts members report, and the warnings.",
        };
        keys.extend([k("r", "look again"), k("esc", "back; from the list, to Home")]);
        Help { about: about.into(), keys }
    }

    fn page_keys(&self, page: &mut Page) {
        if let Some(o) = &self.opened {
            if self.find(&o.key).is_some_and(|r| !self.items(r).is_empty()) {
                page.key("↑↓", "move").key("enter", "choose");
            }
            return;
        }
        let sel = self.selected();
        if self.host_key_changed() {
            page.key("n", "look at the new coordinator");
        }
        match self.tab {
            Tab::Machines => {
                if self.answered.is_some() && self.err.is_none() && (self.view.version == 0 || self.list_problem().is_some()) {
                    page.key("s", if self.view.version == 0 { "sign the coordinator" } else { "sign your list again" });
                }
                match sel {
                    Some(Row::Request(_)) => {
                        if self.why_not(Do::Approve, sel).is_none() {
                            page.key("a", "approve");
                        }
                        if self.why_not(Do::Reject, sel).is_none() {
                            page.key("x", "reject");
                        }
                        page.key("enter", "more");
                    }
                    Some(Row::Member(_)) => {
                        if self.why_not(Do::Remove, sel).is_none() {
                            page.key("d", "remove");
                        }
                        page.key("enter", "more");
                    }
                    _ => {}
                }
            }
            Tab::Updates => {
                match sel {
                    Some(Row::Stopped) => {
                        page.key("enter", "try again or skip");
                    }
                    Some(Row::Member(_)) => {
                        page.key("enter", "more");
                    }
                    _ => {}
                }
                if self.publisher.is_some() {
                    page.key("p", "publish");
                }
            }
            Tab::Network => {
                if let Some(Row::Device(_)) = sel {
                    page.key("enter", "more");
                }
            }
            Tab::People => {
                if self.why_not(Do::LetIn, sel).is_none() {
                    page.key("a", "let someone in");
                }
                if let Some(Row::Person(_)) = sel {
                    page.key("enter", "more");
                    if self.why_not(Do::TakeOut, sel).is_none() {
                        page.key("d", "take out");
                    }
                }
            }
            Tab::Vpn => {
                match sel {
                    Some(Row::Gateway) => {
                        if self.why_not(Do::Gateway, sel).is_none() {
                            page.key("g", if self.view.vpn.is_none() { "set it up" } else { "change" });
                        }
                        if self.view.vpn.is_some() && self.why_not(Do::Token, sel).is_none() {
                            page.key("t", "token");
                        }
                    }
                    Some(Row::VpnDevice(_)) => {
                        page.key("c", "its config");
                        if self.why_not(Do::RemoveDevice, sel).is_none() {
                            page.key("d", "take off");
                        }
                    }
                    _ => {}
                }
                if self.why_not(Do::AddDevice, sel).is_none() {
                    page.key("a", "add a device");
                }
                if sel.is_some() {
                    page.key("enter", "more");
                }
            }
        }
        page.key("r", "look again").key("tab", "next tab");
    }
}

/// The choices for a new release, one step at a time, then a review.
fn publish_form(c: &Choice, version: &str) -> Form<Choice> {
    let window = rollout::window_text(rollout::WINDOW);
    let yes = |b: bool| if b { "yes".to_string() } else { "no".to_string() };
    Form::new(
        c.clone(),
        vec![
            Group::new(vec![
                Field::note(
                    "What it is for",
                    &format!(
                        "A release of this dryserver ({version}) for every machine, with the k3s it pins and the newest Arch \
                         snapshot day. Nothing is signed before you have seen what it changes."
                    ),
                ),
                Field::input("Notes", |c: &Choice| c.notes.clone(), |c, v| c.notes = v)
                    .placeholder("what it is for, like: fixes the join timeout")
                    .desc("Shown with the release on every machine. Plain text; may be left empty.")
                    .validate(|v, _| release::check_notes(v.trim())),
            ])
            .title("What it is for"),
            Group::new(vec![
                Field::select(
                    "Urgent",
                    move |_| {
                        vec![
                            (format!("No: machines update {window} on the coordinator's clock"), "no".to_string()),
                            ("Yes: the rollout starts at once (a security fix)".to_string(), "yes".to_string()),
                        ]
                    },
                    move |c: &Choice| yes(c.urgent),
                    |c, v| c.urgent = v == "yes",
                ),
                Field::select(
                    "Rollback",
                    |_| {
                        vec![
                            ("No".to_string(), "no".to_string()),
                            ("Yes: allow older versions than the swarm runs (the way back)".to_string(), "yes".to_string()),
                        ]
                    },
                    move |c: &Choice| yes(c.rollback),
                    |c, v| c.rollback = v == "yes",
                ),
            ])
            .title("How it rolls out"),
        ],
        "cancel",
    )
    .keeps_answers()
    .done_label("check the release")
}

impl PlaceScreen for Screen {
    type Msg = Msg;

    fn init(&mut self, emit: &Emit<Msg>) {
        let Some(admin) = self.admin.take() else { return };
        let tools = Tools { publisher: self.publisher.clone(), write_list: self.write_list.clone(), desk: self.desk.clone() };
        self.line = Some(Line::start(admin, tools, emit.clone()));
        self.look();
    }

    fn update(&mut self, ev: Event<Msg>, _: &Emit<Msg>) -> Flow {
        match ev {
            Event::Key(k) => return self.key(k),
            Event::Msg(m) => self.answer(m),
            Event::Tick => {
                let wait = if self.err.is_some() { RETRY } else { REFRESH };
                if self.line.is_some() && self.queue.is_empty() && self.looked.is_none_or(|t| t.elapsed() >= wait) {
                    self.look();
                }
            }
            Event::Back(res) => self.token_back(res),
            Event::Resize(..) => {}
        }
        Flow::Continue
    }

    fn job(&mut self) -> Option<super::Job> {
        self.job.take()
    }

    fn page(&self, size: Size) -> Page {
        let w = size.width;
        let mut page = Page::new("Machines");
        page.status = self.status();
        page.tabs = TABS.iter().map(|t| t.title().to_string()).collect();
        page.tab = self.tab.at();
        page.back = Back::Esc;
        page.help = Some(self.help());
        page.notice = self.notice.clone().or_else(|| {
            let (what, t) = self.queue.running().filter(|(l, _)| *l != LOADING)?;
            Some(Notice::info(format!("{} {what}{} {}", spinner(), theme::ellipsis(), super::dur(t))))
        });
        // What takes the keys first is drawn first (key()).
        if let Some(sv) = &self.shown {
            self.shown_page(sv, &mut page, size);
            return page;
        }
        if let Some(f) = &self.form {
            let (body, focus) = f.body(w);
            page.body = body;
            page.focus = focus.map(Focus::keep);
            page.keys = f.keys();
            page.key("esc", &f.esc_label());
            page.back = Back::Nothing;
            return page;
        }
        if let Some(p) = &self.plan {
            page.body = self.summary_body(p);
            page.focus = Some(Focus::keep(0..1));
            page.key("enter", "sign and send it").key("esc", "change the choices");
            page.back = Back::Nothing;
            return page;
        }
        if let Some(e) = &self.entry {
            let ((body, focus), keys, esc) = match e {
                Entry::Person(f) => (f.body(w), f.keys(), f.esc_label()),
                Entry::Plan(f) => (f.body(w), f.keys(), f.esc_label()),
                Entry::Device(f) => (f.body(w), f.keys(), f.esc_label()),
            };
            page.body = body;
            page.focus = focus.map(Focus::keep);
            page.keys = keys;
            page.key("esc", &esc);
            page.back = Back::Nothing;
            return page;
        }
        let opened = self.opened.as_ref().and_then(|o| self.find(&o.key).map(|r| (r, o.cursor)));
        if let Some(Act::Publish(p)) = self.ask.as_ref().map(|a| &a.act) {
            page.body = self.summary_body(p);
        } else if let Some((r, cursor)) = opened {
            let (body, at) = self.sheet(w, r, cursor);
            page.body = body;
            page.focus = Some(Focus::keep(at.map(|a| a..a + 1).unwrap_or(0..1)));
        } else {
            let (body, focus) = match self.tab {
                Tab::Machines => self.machines_body(w),
                Tab::People => self.people_body(w),
                Tab::Vpn => self.vpn_body(w),
                Tab::Updates => self.updates_body(w, size.rows),
                Tab::Network => self.network_body(w),
            };
            page.body = body;
            // Nothing to select: the top, so a new tab starts there.
            page.focus = Some(focus.unwrap_or(Focus::keep(0..1)));
        }
        self.page_keys(&mut page);
        if let Some(a) = &self.ask {
            page.overlay = Some(Overlay::Confirm { question: a.question.clone(), consequences: a.consequences.clone() });
            // Any key answers the question, ? too.
            page.help = None;
        }
        page
    }

    fn busy(&self) -> Option<String> {
        self.queue.change().map(str::to_string)
    }

    fn after(&self) -> Option<Notice> {
        self.after.clone()
    }

    fn typing(&self) -> bool {
        let entry = match &self.entry {
            Some(Entry::Person(f)) => f.typing(),
            Some(Entry::Plan(f)) => f.typing(),
            Some(Entry::Device(f)) => f.typing(),
            None => false,
        };
        self.ask.is_none() && (self.form.as_ref().is_some_and(|f| f.typing()) || entry)
    }
}

#[cfg(test)]
mod tests;
