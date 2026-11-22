//! Publishing a release from the desktop, made hard to get wrong. The same
//! steps run for `./dryserver release publish` and for the approve
//! screen's publish key:
//!
//! 1. `plan` checks everything that goes into the release before anything
//!    is signed: the binary is the static one, the notes are plain text,
//!    nothing is older than what the swarm runs (unless rollback), the k3s
//!    binary is the one this dryserver pins, and the Arch snapshot day is
//!    on archive.archlinux.org. A release naming a day the archive does not
//!    have would fail on every machine.
//! 2. `Plan::lines` says what changes, against the newest release on the
//!    coordinator: the admin confirms only after reading it.
//! 3. `publish` signs and sends exactly that release, or nothing: it
//!    refuses when the coordinator's newest release changed since the plan
//!    was made (another publish), or when another publish runs on this
//!    computer.
//!
//! The Arch archive is asked with curl, like the Cloudflare API: `-q` so
//! no ~/.curlrc has a say, everything else on stdin, HTTPS only (redirects
//! too), a time limit. Only the day is in the request, nothing about the
//! admin or the swarm. The Days trait is the seam: tests never reach the
//! internet.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use chrono::NaiveDate;

use crate::admin::{self, Admin, View};
use crate::ctx::Ctx;
use crate::err::Result;
use crate::registry::{self, Member};
use crate::release::{self, K3sVersion, Release, Version};
use crate::rollout::{self, Pause, Phase, Rollout, Skip, Turn};
use crate::runner::{Cmd, ExecRunner, Runner};
use crate::signed::Envelope;
use crate::{bail, errf, fsx, iso, report};

// ---- the Arch snapshot day ----

/// How many days before today the default looks for a snapshot. The
/// archive makes each day's snapshot shortly after midnight UTC, so
/// yesterday's is there when today's is not yet.
pub const DAYS_BACK: i64 = 3;
/// What pacman reads of a snapshot day: each repository's database.
const REPOS: [&str; 2] = ["core", "extra"];
/// Seconds one request to the archive may take, connecting included.
const REQUEST_SECONDS: u32 = 20;
const ARCHIVE: &str = "archive.archlinux.org";

/// Whether a snapshot day is on the Arch archive.
pub trait Days: Send + Sync {
    /// Ok(true) when the archive has every repository of day (YYYY/MM/DD),
    /// Ok(false) when it says it has not, Err when it cannot tell.
    fn exists(&self, ctx: &Ctx, day: &str) -> Result<bool>;
}

/// The database of a repository on a snapshot day, where pacman reads it:
/// the mirrorlist's Server line with $repo and $arch filled in.
pub fn db_url(day: &str, repo: &str) -> String {
    format!("{}{repo}/os/x86_64/{repo}.db", release::arch_url(day))
}

/// archive.archlinux.org, asked with curl on the desktop.
pub struct Archive {
    pub run: Arc<dyn Runner>,
}

impl Archive {
    pub fn new() -> Archive {
        Archive { run: Arc::new(ExecRunner::silent()) }
    }

    /// What curl reads from stdin: a HEAD request for url and nothing else
    /// (no cookies, no referer, no credentials), its status code as the
    /// only output.
    fn config(url: &str) -> String {
        let mut c = String::new();
        let mut line = |k: &str, v: &str| c.push_str(&format!("{k} = \"{v}\"\n"));
        // url comes from db_url: a checked date and fixed words, nothing
        // that needs quoting.
        line("url", url);
        line("proto", "=https");
        line("proto-redir", "=https");
        line("max-redirs", "3");
        line("max-time", &REQUEST_SECONDS.to_string());
        line("connect-timeout", "10");
        line("output", "/dev/null");
        line("write-out", "%{http_code}");
        c.push_str("head\nlocation\ntlsv1.2\nsilent\nshow-error\n");
        c
    }

    /// The HTTP status of a HEAD request for url, after redirects.
    fn status(&self, ctx: &Ctx, url: &str) -> Result<u16> {
        // -q first: the user's ~/.curlrc has no say.
        let cmd = Cmd::new("curl", &["-q", "--config", "-"]).stdin(Archive::config(url)).quiet().stdout_only();
        let (out, res) = self.run.run(ctx, &cmd);
        if let Err(e) = res {
            if let Some(why) = ctx.err() {
                return Err(why);
            }
            let msg = e.to_string();
            if msg.contains("executable file not found") {
                bail!("curl is not installed on this computer");
            }
            let code = msg
                .split_once("exit status ")
                .map(|(_, rest)| rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
                .and_then(|d| d.parse().ok());
            bail!("{}", curl_failure(code));
        }
        let status: u16 = out.trim().parse().map_err(|_| errf!("curl gave no HTTP status for {url}"))?;
        if status == 0 {
            bail!("no answer from {ARCHIVE}");
        }
        Ok(status)
    }
}

impl Days for Archive {
    fn exists(&self, ctx: &Ctx, day: &str) -> Result<bool> {
        for repo in REPOS {
            match self.status(ctx, &db_url(day, repo))? {
                200 => {}
                404 | 410 => return Ok(false),
                s @ 500..=599 => bail!("{ARCHIVE} has a problem (HTTP {s} for {repo}.db); try again later"),
                s => bail!("{ARCHIVE} answered HTTP {s} for the {repo}.db of {day}, not the file"),
            }
        }
        Ok(true)
    }
}

/// What curl's exit code means for the admin.
fn curl_failure(code: Option<u32>) -> String {
    match code {
        Some(6) => format!("cannot find {ARCHIVE} (is this computer online?)"),
        Some(7) => format!("cannot connect to {ARCHIVE} (is this computer online?)"),
        Some(28) => format!("{ARCHIVE} did not answer within {REQUEST_SECONDS}s"),
        Some(1) => format!("{ARCHIVE} sent this computer to an address that is not HTTPS; refused"),
        Some(47) => format!("{ARCHIVE} redirected more than 3 times; refused"),
        Some(35 | 51 | 53 | 54 | 58 | 59 | 60 | 66 | 77 | 80 | 83 | 90 | 91) => {
            format!("the secure connection to {ARCHIVE} failed (its certificate, or something in between)")
        }
        Some(c) => format!("curl failed with exit status {c}"),
        None => "curl failed".into(),
    }
}

/// A day as the admin may type it: YYYY/MM/DD, or YYYY-MM-DD.
pub fn normalize_day(s: &str) -> String {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() == 10 && b[4] == b'-' && b[7] == b'-' { s.replace('-', "/") } else { s.to_string() }
}

fn day_text(d: NaiveDate) -> String {
    d.format("%Y/%m/%d").to_string()
}

/// The Arch snapshot day of a new release, and how it was found.
#[derive(Debug, Clone, PartialEq)]
pub struct Day {
    pub day: String,
    pub how: String,
}

/// What can be said about a day without asking anyone: it is a date, it
/// is not in the future, and it is not older than the swarm's (current)
/// unless the admin set rollback.
fn day_rules(given: &str, current: Option<&str>, rollback: bool, today: NaiveDate) -> Result<()> {
    if given.is_empty() {
        if let Some(c) = current.and_then(|c| release::arch_day(c).ok())
            && c > today
        {
            bail!(
                "the swarm runs Arch snapshot {}, after today ({} UTC) by this computer's clock: check this computer's clock",
                day_text(c),
                day_text(today)
            );
        }
        return Ok(());
    }
    let d = release::arch_day(given)?;
    if d > today {
        bail!("Arch snapshot {given} is in the future: today is {} (UTC) on this computer. Name a day that has passed", day_text(today));
    }
    if let Some(c) = current.and_then(|c| release::arch_day(c).ok())
        && d < c
        && !rollback
    {
        bail!("Arch snapshot {given} is older than the swarm's ({}). To go back to it, publish with rollback on (-rollback)", day_text(c));
    }
    Ok(())
}

/// Picks the Arch snapshot day of a new release. given is what the admin
/// named ("" for the default), current the day of the swarm's newest
/// release, today the date in UTC.
///
/// A named day must be on the archive. The default is the newest day
/// there, from today back DAYS_BACK days, never older than the swarm's
/// day unless rollback is set. Only the swarm's own day is taken when the
/// archive cannot be asked: the machines run it already.
pub fn pick_day(ctx: &Ctx, days: &dyn Days, given: &str, current: Option<&str>, rollback: bool, today: NaiveDate) -> Result<Day> {
    let given = normalize_day(given);
    day_rules(&given, current, rollback, today)?;
    if !given.is_empty() {
        return match days.exists(ctx, &given) {
            Ok(true) => Ok(Day { day: given, how: format!("checked: it is on {ARCHIVE}") }),
            Ok(false) => {
                let recent = release::arch_day(&given).is_ok_and(|d| (today - d).num_days() <= 1);
                Err(errf!(
                    "Arch snapshot {given} is not on {ARCHIVE}{}: every machine would fail to update to it. \
                     Name another day, or leave the day out for the newest one",
                    if recent { " (yet)" } else { "" }
                ))
            }
            Err(e) if ctx.done() => Err(e),
            Err(e) if current == Some(given.as_str()) => {
                Ok(Day { day: given, how: format!("not checked ({e}); the swarm runs this day already") })
            }
            Err(e) => Err(e.wrap(format!("cannot check Arch snapshot {given}"))),
        };
    }
    let mut floor = today - chrono::TimeDelta::days(DAYS_BACK);
    if !rollback && let Some(c) = current.and_then(|c| release::arch_day(c).ok()) {
        floor = floor.max(c);
    }
    let mut d = today;
    while d >= floor {
        let name = day_text(d);
        match days.exists(ctx, &name) {
            Ok(true) => {
                let how = if d == today {
                    format!("today's, the newest on {ARCHIVE}")
                } else {
                    format!("the newest on {ARCHIVE}; today's is not there yet")
                };
                return Ok(Day { day: name, how });
            }
            Ok(false) => {}
            Err(e) => {
                let keep = match current {
                    Some(c) if !ctx.done() => format!(". To keep the swarm's day without asking, name it: -arch-date {c}"),
                    _ => String::new(),
                };
                return Err(errf!("cannot find the newest Arch snapshot: {e}{keep}"));
            }
        }
        d -= chrono::TimeDelta::days(1);
    }
    bail!(
        "no Arch snapshot from {} to {} is on {ARCHIVE}. Try again later, or name a day with -arch-date YYYY/MM/DD",
        day_text(floor),
        day_text(today)
    )
}

// ---- the k3s binary ----

/// Where `./dryserver build` keeps the k3s binary it downloads for the USB
/// stick.
pub fn default_k3s(out_dir: &Path) -> PathBuf {
    out_dir.join("pkgcache").join(format!("k3s-{}", iso::K3S_VERSION))
}

/// Where the official k3s release of version is.
pub fn k3s_url(version: &str) -> String {
    format!("https://github.com/k3s-io/k3s/releases/download/{}/k3s", version.replace('+', "%2B"))
}

/// Exactly how to get k3s version to path.
pub fn get_k3s(path: &Path, version: &str) -> String {
    let p = path.display().to_string();
    let dir = fsx::dir(path).display().to_string();
    format!(
        "Get it one of two ways, then publish again:\n  \
         ./dryserver build    (downloads it while it builds the USB stick image, about 6 minutes)\n  \
         mkdir -p '{dir}' && curl -fL -o '{p}' '{}'\n\
         Its sha256 is checked here before anything is signed.",
        k3s_url(version)
    )
}

/// The k3s binary as a release needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K3sFile {
    /// On this computer, with the pinned sha256: it goes along when the
    /// coordinator asks for it.
    Checked,
    /// Not on this computer, and the coordinator runs this k3s already.
    NotNeeded,
}

/// Checks the k3s binary at path before anything is signed: when it is
/// there it must have the pinned sha256; when it is not, the coordinator
/// must run that k3s already (brain_k3s is what it reports), or the
/// release could not reach the servers.
pub fn check_k3s(path: &Path, version: &str, sha256: &str, brain_k3s: Option<&str>) -> Result<K3sFile> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if brain_k3s == Some(version) {
                return Ok(K3sFile::NotNeeded);
            }
            let runs = match brain_k3s {
                Some(v) if !v.is_empty() => format!("runs k3s {v}"),
                _ => "does not say which k3s it runs".into(),
            };
            bail!(
                "k3s {version} is not on this computer ({} is missing), and the coordinator {runs}, so it needs this one.\n{}",
                path.display(),
                get_k3s(path, version)
            );
        }
        Err(e) => return Err(crate::err::Error::from(e).wrap(format!("look at {}", path.display()))),
        Ok(_) => {}
    }
    let (got, _) = release::hash_file(path, rollout::MAX_K3S)?;
    if got != sha256 {
        bail!(
            "{} is not k3s {version}: its sha256 is {got}, this dryserver pins {sha256}. Remove it and get it again.\n{}",
            path.display(),
            get_k3s(path, version)
        );
    }
    Ok(K3sFile::Checked)
}

// ---- the signing key ----

/// Whether the private key at path has a passphrase: ssh-keygen then asks
/// for it at every signature, which only a terminal can answer.
pub fn has_passphrase(key: &Path) -> bool {
    if !key.exists() {
        return false;
    }
    let out = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-P")
        .arg("")
        .arg("-f")
        .arg(key)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) => !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("passphrase"),
        Err(_) => false,
    }
}

// ---- the plan ----

/// What a release is made of on this desktop, apart from the admin's
/// choices: this program and the k3s it pins.
#[derive(Debug, Clone)]
pub struct Parts {
    pub binary: PathBuf,
    pub version: String,
    pub k3s: PathBuf,
    pub k3s_version: String,
    pub k3s_sha256: String,
}

impl Parts {
    /// The program that runs, and the k3s at k3s (None: the USB stick
    /// build's copy in out_dir).
    pub fn this_program(out_dir: &Path, k3s: Option<PathBuf>) -> Result<Parts> {
        let binary = std::env::current_exe().map_err(|e| crate::err::Error::from(e).wrap("find this program"))?;
        Ok(Parts {
            binary,
            version: env!("CARGO_PKG_VERSION").into(),
            k3s: k3s.unwrap_or_else(|| default_k3s(out_dir)),
            k3s_version: iso::K3S_VERSION.into(),
            k3s_sha256: iso::K3S_SHA256.into(),
        })
    }
}

/// What the admin chooses for a release.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Choice {
    /// YYYY/MM/DD; "" for the newest day on the archive.
    pub arch_date: String,
    pub notes: String,
    pub urgent: bool,
    pub rollback: bool,
}

/// A release checked and ready to sign, and what it changes.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Exactly what `publish` signs.
    pub release: Release,
    pub parts: Parts,
    /// The coordinator's newest release when the plan was made: what the
    /// swarm runs, or moves to.
    pub current: Option<Release>,
    /// When the newest failed on the coordinator and went back: the
    /// release the machines run (0: what they ran before it).
    pub went_back: Option<u64>,
    /// What the release is compared with: the newest, or the release the
    /// machines run when the newest went back (None: what they report).
    pub runs: Option<Release>,
    /// A release signed on this computer after the coordinator's newest,
    /// that never reached it.
    pub unsent: Option<u64>,
    /// How the Arch day was found.
    pub arch_how: String,
    pub k3s: K3sFile,
    /// The coordinator's name, and the servers in the order of the list.
    pub brain: Option<String>,
    pub servers: Vec<String>,
    /// What the machines report running, for a swarm without a release
    /// (or without a copy here of the one it runs).
    pub reported_dryserver: Vec<String>,
    pub reported_k3s: Vec<String>,
}

/// The distinct non-empty values, sorted.
fn distinct(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = values.filter(|s| !s.is_empty()).collect();
    v.sort();
    v.dedup();
    v
}

/// Checks everything a release of parts with the admin's choice needs,
/// before anything is signed, and drafts it. a and v are the admin and
/// the view of a load just made. The checks that need nobody come first:
/// a refused binary, notes or version is said before the archive is
/// asked.
pub fn plan(ctx: &Ctx, a: &Admin, v: &View, days: &dyn Days, parts: &Parts, c: &Choice, today: NaiveDate) -> Result<Plan> {
    let current = v.release.clone();
    rollout::check_static(&parts.binary)?;
    release::check_notes(&c.notes)?;
    let given = normalize_day(&c.arch_date);
    let went_back = went_back(v);
    let runs = match went_back {
        Some(m) => signed_copy(a, m),
        None => current.clone(),
    };
    // The newest day the swarm took: the newest release's, or the one the
    // machines run when that is later. Below either the release would be
    // refused, here (against the newest) or on the machines.
    let swarm_day =
        [current.as_ref(), runs.as_ref()].into_iter().flatten().map(|r| r.arch_date.clone()).max_by_key(|d| release::arch_day(d).ok());
    let current_day = swarm_day.as_deref();
    day_rules(&given, current_day, c.rollback, today)?;
    // The versions go by what the machines run: after a newest that went
    // back, a release between it and that one needs no rollback.
    if let Some(cur) = &runs
        && !c.rollback
    {
        if let (Ok(new), Ok(old)) = (Version::parse(&parts.version), Version::parse(&cur.dryserver.version))
            && new < old
        {
            bail!(
                "this dryserver ({}) is older than the swarm's ({}). To go back to it, publish with rollback on (-rollback)",
                parts.version,
                cur.dryserver.version
            );
        }
        if let (Ok(new), Ok(old)) = (K3sVersion::parse(&parts.k3s_version), K3sVersion::parse(&cur.k3s.version))
            && new < old
        {
            bail!(
                "this dryserver pins k3s {}, older than the swarm's ({}). To go back to it, publish with rollback on (-rollback)",
                parts.k3s_version,
                cur.k3s.version
            );
        }
    }
    // Everything else the machines would refuse, with a stand-in day: the
    // one named, or today.
    let probe = if given.is_empty() { day_text(today) } else { given.clone() };
    let draft = |day: &str| {
        a.draft_release(&release::Draft {
            binary: &parts.binary,
            version: &parts.version,
            arch_date: day,
            rollback: c.rollback,
            urgent: c.urgent,
            notes: &c.notes,
        })
    };
    draft(&probe)?;
    let brain = v.members.iter().find(|(m, _)| m.host == 1).map(|(m, _)| m);
    let brain_k3s = brain.and_then(|m| m.report.as_ref()).map(|r| r.k3s.as_str());
    let k3s = check_k3s(&parts.k3s, &parts.k3s_version, &parts.k3s_sha256, brain_k3s)?;
    let day = match current_day {
        // An urgent fix is not held up by a package update on every
        // machine: it keeps the swarm's day, already on every machine.
        Some(d) if c.urgent && given.is_empty() => Day { day: d.to_string(), how: URGENT_DAY.into() },
        _ => pick_day(ctx, days, &given, current_day, c.rollback, today)?,
    };
    let r = draft(&day.day)?;
    let last = a.last_release().map(|l| l.serial);
    let members: Vec<&Member> = v.members.iter().map(|(m, _)| m).collect();
    Ok(Plan {
        release: r,
        parts: parts.clone(),
        unsent: last.filter(|l| current.as_ref().is_none_or(|cur| *l > cur.serial)),
        current,
        went_back,
        runs,
        arch_how: day.how,
        k3s,
        brain: brain.map(|m| m.name.clone()),
        servers: members.iter().filter(|m| m.host != 1).map(|m| m.name.clone()).collect(),
        reported_dryserver: distinct(members.iter().filter_map(|m| m.report.as_ref()).map(|r| r.dryserver.clone())),
        reported_k3s: distinct(members.iter().filter_map(|m| m.report.as_ref()).map(|r| r.k3s.clone())),
    })
}

/// How the preview says an urgent release keeps the Arch day.
pub const URGENT_DAY: &str = "urgent releases keep the day; give -arch-date to move it";

/// When the coordinator's newest release failed on the coordinator and
/// went back (its own update failed, so no server took it): the release
/// the machines run, by the coordinator's report (0: not known, or none).
/// The rollout and the report are the coordinator's word; they only
/// choose what the preview compares with, never what is allowed.
fn went_back(v: &View) -> Option<u64> {
    let newest = v.release.as_ref()?;
    let rep = v.members.iter().find(|(m, _)| m.host == 1).and_then(|(m, _)| m.report.as_ref());
    if rep.is_some_and(|r| r.release >= newest.serial) {
        return None;
    }
    let failed = v.rollout.serial == newest.serial && v.rollout.phase == Phase::Failed;
    let reverted = rep.is_some_and(|r| r.update_failed() && r.update_serial == newest.serial);
    (failed || reverted).then(|| rep.map(|r| r.release).unwrap_or(0))
}

/// "old -> new", or "same (new)".
fn change(old: &str, new: &str) -> String {
    if old == new { format!("same ({new})") } else { format!("{old} -> {new}") }
}

/// Names for a sentence: "a", "a and b", "a, b and c", the rest counted.
fn names(list: &[String]) -> String {
    const SHOWN: usize = 6;
    let mut shown: Vec<String> = list.iter().take(SHOWN).cloned().collect();
    if list.len() > SHOWN {
        shown.push(format!("{} more", list.len() - SHOWN));
    }
    match shown.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

impl Plan {
    /// How many machines the release goes to.
    pub fn machines(&self) -> usize {
        self.servers.len() + usize::from(self.brain.is_some())
    }

    /// What the release changes, for the admin to read before saying yes.
    /// The CLI prints these lines and the approve screen shows them.
    pub fn lines(&self) -> Vec<String> {
        let r = &self.release;
        let n = self.machines();
        let mut out = vec![format!(
            "Release {} for {n} machine{}{}{}:",
            r.serial,
            if n == 1 { "" } else { "s" },
            if r.urgent { ", urgent" } else { "" },
            if r.rollback { ", rollback" } else { "" }
        )];
        let row = |k: &str, v: String| format!("  {k:<10} {v}");
        let joined = |l: &[String]| if l.is_empty() { "?".to_string() } else { l.join(", ") };
        let (ds, k3s, arch) = match &self.runs {
            Some(cur) => {
                let ds = if cur.dryserver.version == r.dryserver.version && cur.dryserver.sha256 != r.dryserver.sha256 {
                    format!(
                        "{}, another build (sha256 {}... -> {}...)",
                        r.dryserver.version,
                        &cur.dryserver.sha256[..12],
                        &r.dryserver.sha256[..12]
                    )
                } else {
                    change(&cur.dryserver.version, &r.dryserver.version)
                };
                (ds, change(&cur.k3s.version, &r.k3s.version), change(&cur.arch_date, &r.arch_date))
            }
            None => {
                let ds = match self.reported_dryserver.as_slice() {
                    // A report says the version, not the build: this one
                    // may well be another, and it goes to every machine.
                    [one] if *one == r.dryserver.version => {
                        format!("{one} (the machines report {one}, not which build: they all get this one)")
                    }
                    [one] => change(one, &r.dryserver.version),
                    l => format!("{} -> {}", joined(l), r.dryserver.version),
                };
                // A k3s version is one binary: this dryserver pins its sha256.
                let k3s = match self.reported_k3s.as_slice() {
                    [one] => change(one, &r.k3s.version),
                    l => format!("{} -> {}", joined(l), r.k3s.version),
                };
                let was = match self.went_back {
                    Some(m) if m > 0 => format!("as in release {m}"),
                    _ => "as installed".into(),
                };
                (ds, k3s, format!("{was} -> {}", r.arch_date))
            }
        };
        out.push(row("dryserver", ds));
        out.push(row("k3s", k3s));
        out.push(row("Arch", format!("{arch} ({})", self.arch_how)));
        let window = rollout::window_text(rollout::WINDOW);
        out.push(row(
            "urgent",
            if r.urgent {
                "yes: the rollout starts at once".into()
            } else {
                format!("no: machines update only {window} on the coordinator's clock")
            },
        ));
        out.push(row("rollback", if r.rollback { "yes: older versions than the swarm runs are allowed".into() } else { "no".into() }));
        out.push(row("notes", if r.notes.is_empty() { "none".into() } else { r.notes.clone() }));
        match (&self.current, self.went_back) {
            (Some(cur), Some(m)) => {
                let what = if m > 0 { format!("release {m}") } else { "what they ran before it".into() };
                out.push(format!("Release {} failed on the coordinator and went back; the machines run {what}.", cur.serial));
                out.push(match &self.runs {
                    Some(base) => format!("Compared with release {}, which the machines run.", base.serial),
                    None if m > 0 => format!("Compared with what the machines report: this computer has no copy of release {m}."),
                    None => "Compared with what the machines report.".into(),
                });
            }
            (Some(cur), None) => out.push(format!("Compared with release {}, the newest on the coordinator.", cur.serial)),
            (None, _) => out.push("No release yet: compared with what the machines report.".into()),
        }
        if let Some(u) = self.unsent {
            out.push(format!("Release {u} was signed here but never reached the coordinator; this one replaces it."));
        }
        if let Some(cur) = &self.runs
            && cur.dryserver.sha256 == r.dryserver.sha256
            && cur.k3s == r.k3s
            && cur.arch_date == r.arch_date
        {
            out.push(format!(
                "Nothing changes on the machines: the same dryserver build, k3s and Arch day as release {}. \
                 It only renews the release, which machines warn about once it expires.",
                cur.serial
            ));
        }
        let soak = report::short_age((if r.urgent { rollout::SOAK_URGENT } else { rollout::SOAK }) as u64);
        let brain = self.brain.clone().unwrap_or_else(|| "the coordinator".into());
        out.push(match self.servers.as_slice() {
            [] => format!("Only {brain} gets it: there are no servers yet."),
            [one] => format!("{brain} updates itself first, then {one} (the canary, watched for {soak})."),
            [first, ..] => format!(
                "{brain} updates itself first, then the servers one at a time: {} ({first} is the canary, watched for {soak}).",
                names(&self.servers)
            ),
        });
        if self.k3s == K3sFile::NotNeeded {
            out.push(format!(
                "The k3s binary is not on this computer ({}); the coordinator runs k3s {} already.",
                self.parts.k3s.display(),
                r.k3s.version
            ));
        }
        // Names and versions come from the coordinator (checked at the
        // load): still, no line reaches the terminal with a control
        // character.
        out.into_iter().map(|l| l.replace(|c: char| c.is_control(), "?")).collect()
    }
}

/// The desktop's lock around signing and sending a release: two
/// publishes at once (two terminals, the screen and a terminal) never
/// both sign.
pub const LOCK: &str = "release.lock";
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Signs and sends what p shows, or nothing. Refused before anything is
/// signed when another publish runs on this computer, when the
/// coordinator cannot be reached, or when its newest release is no longer
/// the one p was made against.
pub fn publish(a: &mut Admin, p: &Plan) -> Result<Release> {
    let lock = a.secrets.join(LOCK);
    // A short wait: a program another thread forks holds a copy of the
    // lock until it starts, and a publish that really runs takes minutes.
    let Some(_held) = fsx::try_lock_for(&lock, LOCK_WAIT)? else {
        bail!("another publish runs on this computer ({} is taken). Nothing was signed; wait for it, then look again", lock.display());
    };
    let v = a.load().map_err(|e| e.wrap("nothing was signed"))?;
    let now = v.release.as_ref().map(|r| r.serial);
    if now != p.current.as_ref().map(|r| r.serial) {
        bail!(
            "the coordinator's newest release changed since you looked ({} now): another publish? Nothing was signed; look again",
            now.map(|s| format!("release {s}")).unwrap_or_else(|| "none".into())
        );
    }
    let sent = a.send_release(&p.release, &p.parts.binary, &p.parts.k3s);
    // Signed, whether or not it arrived: a copy for later previews. Only
    // a preview needs it, so a copy that cannot be made fails nothing.
    let _ = keep_copy(a, p.release.serial);
    sent?;
    Ok(p.release.clone())
}

/// Where this computer keeps a copy of each release it signed, by serial
/// (the newest KEPT_COPIES of them): when the newest fails and goes back,
/// the preview compares with the one the machines still run.
pub const COPIES: &str = "releases";
const KEPT_COPIES: usize = 16;

fn copy_path(a: &Admin, serial: u64) -> PathBuf {
    a.secrets.join(COPIES).join(format!("{serial}.json"))
}

/// Release serial as this computer signed it, its signature checked.
pub fn signed_copy(a: &Admin, serial: u64) -> Option<Release> {
    if serial == 0 {
        return None;
    }
    let b = std::fs::read(copy_path(a, serial)).ok()?;
    let env: Envelope = serde_json::from_slice(&b).ok()?;
    let r = release::open(a.verifier.as_ref(), &env, (a.now)().0.timestamp()).ok()?;
    (r.serial == serial).then_some(r)
}

/// Keeps a copy of release serial, when it is the one this computer
/// signed last (admin::RELEASE_COPY), and only the newest KEPT_COPIES.
fn keep_copy(a: &Admin, serial: u64) -> Result<()> {
    let b = std::fs::read(a.secrets.join(admin::RELEASE_COPY))?;
    let env: Envelope = serde_json::from_slice(&b)?;
    if release::open(a.verifier.as_ref(), &env, (a.now)().0.timestamp())?.serial != serial {
        return Ok(());
    }
    let dir = a.secrets.join(COPIES);
    fsx::mkdir_all(&dir, 0o700)?;
    let tmp = dir.join(format!(".{serial}.json.tmp"));
    let _ = std::fs::remove_file(&tmp);
    fsx::write_new(&tmp, &b, 0o600)?;
    fsx::rename(&tmp, copy_path(a, serial))?;
    let mut kept: Vec<u64> =
        std::fs::read_dir(&dir)?.flatten().filter_map(|e| e.file_name().to_str()?.strip_suffix(".json")?.parse().ok()).collect();
    kept.sort_unstable_by(|x, y| y.cmp(x));
    for old in kept.into_iter().skip(KEPT_COPIES) {
        let _ = std::fs::remove_file(copy_path(a, old));
    }
    Ok(())
}

// ---- the coordinator's rollout, as the desktop takes it ----

/// The most warnings and passed-over servers taken: far more than a
/// rollout makes.
const MAX_SHOWN: usize = 64;

impl Rollout {
    /// The rollout as the desktop may show it, taken right after a load
    /// (like report::Report::sanitized). The registry account writes the
    /// copy the desktop reads, and may be hacked: every text in it is cut
    /// to printable ASCII, so no escape sequence reaches the admin's
    /// terminal (OSC 52 sets the clipboard, ESC [2J clears the screen and
    /// the warnings on it); a name that is not a hostname is dropped (the
    /// text then says "the server" or the host number); the lists are
    /// capped.
    pub fn sanitized(self) -> Rollout {
        let name = |s: String| if registry::valid_name(&s) { s } else { String::new() };
        let newest = self.warnings.len().saturating_sub(MAX_SHOWN);
        Rollout {
            turn: self.turn.map(|t| Turn { name: name(t.name), ..t }),
            skipped: self
                .skipped
                .into_iter()
                .take(MAX_SHOWN)
                .map(|s| Skip { name: name(s.name), why: report::shown(&s.why, 200), ..s })
                .collect(),
            cordoned: self.cordoned.into_iter().filter(|n| registry::valid_name(n)).take(MAX_SHOWN).collect(),
            paused: report::shown(&self.paused, 300),
            pause_name: name(self.pause_name),
            warnings: self.warnings.iter().skip(newest).map(|w| report::shown(w, 300)).collect(),
            refused: report::shown(&self.refused, 300),
            ..self
        }
    }
}

// ---- resuming ----

/// Whether the rollout stopped and waits for the admin.
pub fn stopped(r: &Rollout) -> bool {
    r.serial != 0 && (r.phase == Phase::Failed || !r.paused.is_empty())
}

fn paused_name(r: &Rollout) -> String {
    if registry::valid_name(&r.pause_name) { r.pause_name.clone() } else { "the server".to_string() }
}

/// What a resume does now ("gives node-a its turn again..."), or why
/// there is nothing to resume.
pub fn resume_does(r: &Rollout) -> Result<String> {
    if r.serial == 0 {
        bail!("there is no rollout to resume (a new release starts its rollout within a minute of its publish)");
    }
    if r.phase == Phase::Failed {
        return Ok("tries its own update again".into());
    }
    if r.paused.is_empty() {
        bail!("the rollout of release {} is not stopped: there is nothing to resume", r.serial);
    }
    let name = paused_name(r);
    Ok(match r.pause {
        Pause::Drain => format!("updates {name} without draining it"),
        Pause::Canary => format!("goes on after the canary {name}"),
        _ => format!("gives {name} its turn again, to try release {} once more", r.serial),
    })
}

/// What `release resume -skip` does now ("passes node-a over..."), or why
/// it does nothing: the rollout is not stopped at a server, or it stopped
/// at the coordinator's own update, which is never passed over.
pub fn skip_does(r: &Rollout) -> Result<String> {
    if r.serial == 0 {
        bail!("there is no rollout to resume (a new release starts its rollout within a minute of its publish)");
    }
    if r.phase == Phase::Failed {
        bail!("the coordinator's own update is never passed over: ./dryserver release resume tries it again");
    }
    if r.paused.is_empty() || r.pause_host == 0 {
        bail!("the rollout of release {} is not stopped at a server: there is nothing to pass over", r.serial);
    }
    let name = paused_name(r);
    Ok(match r.pause {
        Pause::Canary => format!("goes on after the canary {name}"),
        _ => format!("passes {name} over for release {} and goes on with the next server", r.serial),
    })
}

/// Lets a stopped rollout go on, after a fresh look that it is stopped.
/// Returns what the coordinator then does.
pub fn resume(a: &mut Admin) -> Result<String> {
    let v = a.load()?;
    let what = resume_does(&v.rollout)?;
    a.resume_release()?;
    Ok(what)
}

/// Lets a rollout stopped at a server go on without it, after a fresh
/// look. Returns what the coordinator then does.
pub fn skip(a: &mut Admin) -> Result<String> {
    let v = a.load()?;
    let what = skip_does(&v.rollout)?;
    a.skip_release()?;
    Ok(what)
}

// ---- where the rollout stands ----

/// One machine's line in `release status`: its name, its part and where
/// its update stands; true marks what needs the admin.
fn machine_line(m: &Member, r: &Rollout, now: i64) -> (String, bool) {
    let role = if m.host == 1 { "coordinator" } else { "server" };
    let (state, alarm) = machine_state(m, r, now);
    let version = m.report.as_ref().filter(|rep| !rep.dryserver.is_empty()).map(|rep| format!("  dryserver {}", rep.dryserver));
    (format!("{:<14} {role:<11}  {state}{}", m.name, version.unwrap_or_default()), alarm)
}

fn machine_state(m: &Member, r: &Rollout, now: i64) -> (String, bool) {
    let Some(rep) = &m.report else {
        return ("no report: its dryserver is too old to update itself".into(), true);
    };
    let target = r.serial;
    let quiet = if m.last_seen.is_zero() { i64::MAX } else { now - m.last_seen.0.timestamp() };
    if quiet > rollout::OFFLINE {
        let age = if quiet == i64::MAX { "a long time".to_string() } else { report::short_age(quiet as u64) };
        return (format!("silent for {age}: updates when it is back"), false);
    }
    let about = if rep.update_serial != 0 { format!(" (release {})", rep.update_serial) } else { String::new() };
    let note = if rep.update_note.is_empty() { String::new() } else { format!(": {}", rep.update_note) };
    match rep.update.as_str() {
        "" => {}
        "fetching" => return (format!("loading the update{about}"), false),
        // The note says what it does: loading or installing the packages,
        // k3s, a reboot, or the check before it is kept.
        "pending" => return (format!("updating{about}{}", if note.is_empty() { ", checking it before keeping it" } else { &note }), false),
        "held" => return ("held: its kill switch is on, it updates nothing until it is lifted".into(), true),
        s if rep.update_failed() && (target == 0 || rep.update_serial >= target) => {
            return (format!("update {s}{about}{note}"), true);
        }
        s if !rep.update_failed() => return (format!("{s}{about}{note}"), false),
        _ => {}
    }
    if let Some(s) = r.skipped.iter().find(|s| s.host == m.host) {
        return (format!("passed over: {}", report::shown(&s.why, 200)), true);
    }
    if r.turn.as_ref().is_some_and(|t| t.host == m.host) {
        let ready = r.turn.as_ref().is_some_and(|t| t.ready);
        // Done before the coordinator read the report that says so.
        if ready && target != 0 && rep.release >= target {
            return (format!("confirmed release {}, the coordinator takes note at its next sync", rep.release), false);
        }
        return ((if ready { "its turn: updating" } else { "its turn: draining" }).into(), false);
    }
    if r.pause_host == m.host && !r.paused.is_empty() {
        return ("the rollout stopped here".into(), true);
    }
    match (target, rep.release) {
        (0, 0) => ("no release installed".into(), false),
        (0, n) => (format!("on release {n}"), false),
        (t, n) if n >= t => (format!("on release {n}"), false),
        (_, 0) => ("no release yet, waits its turn".into(), false),
        (_, n) => (format!("on release {n} (old), waits its turn"), false),
    }
}

/// Where the rollout stands, one sentence per item, true for what needs
/// the admin: rollout::lines, and a release the coordinator has but did
/// not take up yet (it does at its next sync).
pub fn rollout_lines(v: &View, now: i64) -> Vec<(String, bool)> {
    let members: Vec<Member> = v.members.iter().map(|(m, _)| m.clone()).collect();
    let mut lines = rollout::lines(&v.rollout, &members, now);
    if v.rollout.serial == 0 && v.release.is_some() {
        // Not "no release published yet": one was, a moment ago.
        lines.retain(|(_, alarm)| *alarm);
        lines.push(("Not started yet: the coordinator takes the release up at its next sync, within a minute.".into(), false));
    }
    lines
}

/// `release status`: the newest release first, then where its rollout
/// stands, one line per machine, and what to do when it stopped.
pub fn status_lines(v: &View, now: i64) -> Vec<String> {
    let now = if v.coordinator_now > 0 { v.coordinator_now } else { now };
    let mut out = Vec::new();
    if let Some(r) = &v.release {
        out.push(rollout::release_line(r));
        out.push(format!("  dryserver {}, k3s {}, Arch snapshot {}", r.dryserver.version, r.k3s.version, r.arch_date));
        out.push(String::new());
    }
    let members: Vec<Member> = v.members.iter().map(|(m, _)| m.clone()).collect();
    out.push("Rollout:".into());
    for (line, _) in rollout_lines(v, now) {
        out.push(format!("  {line}"));
    }
    if !members.is_empty() {
        out.push(String::new());
        out.push("Machines:".into());
        for m in &members {
            let (line, alarm) = machine_line(m, &v.rollout, now);
            out.push(format!("{} {line}", if alarm { "!" } else { " " }));
        }
    }
    if let Ok(what) = resume_does(&v.rollout)
        && stopped(&v.rollout)
    {
        out.push(String::new());
        out.push("The rollout is stopped. Look at the machine first, then either".into());
        out.push(format!("  ./dryserver release resume                       the coordinator {what}, or"));
        if let Ok(skip) = skip_does(&v.rollout)
            && v.rollout.pause != Pause::Canary
        {
            out.push(format!("  ./dryserver release resume -skip                 the coordinator {skip}, or"));
        }
        out.push("  ./dryserver release publish -notes \"the fix\"    a fixed release: it gets a higher serial".into());
        out.push("                                                   and replaces this rollout".into());
    }
    // Every line carries the coordinator's words: none reaches the
    // terminal with a character it would obey.
    out.into_iter().map(|l| l.replace(|c: char| c.is_control(), "?")).collect()
}

/// The same advice for the approve screen, with its keys.
pub fn stopped_keys(r: &Rollout) -> Option<String> {
    if !stopped(r) {
        return None;
    }
    let what = resume_does(r).ok()?;
    let mut s = format!(
        "Press R to resume (the coordinator {what}), or u to publish a fixed release: it gets a higher serial and replaces this rollout."
    );
    if skip_does(r).is_ok() && r.pause != Pause::Canary {
        s += &format!(" To pass {} over instead: ./dryserver release resume -skip", paused_name(r));
    }
    Some(s)
}

#[cfg(test)]
pub mod tests;
