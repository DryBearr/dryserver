use super::*;
use crate::admin::Link;
use crate::admin::tests::{Direct, setup, static_binary};
use crate::err::Error;
use crate::gotime::Time;
use crate::registry::{Heartbeat, Store};
use crate::report::Report;
use crate::rollout::{Skip, Turn};
use crate::signed::fake::Key;
use crate::testutil::TempDir;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

// ---- fakes ----

/// What curl prints for a URL, and how it ends.
type Answer = Box<dyn Fn(&str) -> (String, Result<()>) + Send + Sync>;

/// A runner that plays curl: records what it was given and answers by the
/// URL in its config.
struct FakeCurl {
    got: Mutex<Vec<Cmd>>,
    answer: Answer,
}

impl Runner for FakeCurl {
    fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
        self.got.lock().unwrap().push(c.clone());
        let url = c.stdin.lines().find_map(|l| l.strip_prefix("url = \"")).and_then(|l| l.strip_suffix('"')).unwrap_or("").to_string();
        (self.answer)(&url)
    }
}

fn curl(answer: impl Fn(&str) -> (String, Result<()>) + Send + Sync + 'static) -> (Archive, Arc<FakeCurl>) {
    let fake = Arc::new(FakeCurl { got: Mutex::default(), answer: Box::new(answer) });
    (Archive { run: fake.clone() }, fake)
}

/// The archive as tests see it: these days are there.
pub struct FakeDays {
    pub have: Mutex<Vec<String>>,
    pub asked: Mutex<Vec<String>>,
    /// Every question fails with this.
    pub fail: Mutex<Option<String>>,
}

impl FakeDays {
    pub fn with(days: &[String]) -> FakeDays {
        FakeDays { have: Mutex::new(days.to_vec()), asked: Mutex::default(), fail: Mutex::default() }
    }

    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl Days for FakeDays {
    fn exists(&self, _: &Ctx, day: &str) -> Result<bool> {
        self.asked.lock().unwrap().push(day.into());
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e.into());
        }
        Ok(self.have.lock().unwrap().iter().any(|d| d == day))
    }
}

pub fn today() -> NaiveDate {
    chrono::Utc::now().date_naive()
}

/// The day n days before today, as a release names it.
pub fn days_ago(n: i64) -> String {
    day_text(today() - chrono::TimeDelta::days(n))
}

/// What the desktop sent: the header of each upload.
pub type Sent = Arc<Mutex<Vec<String>>>;

/// The coordinator's registry for everything but uploads, which it keeps
/// the way the registry account does (the release file, "current"), so
/// the next load shows the release. With fail set, every upload fails
/// like a coordinator that went away in the middle.
pub struct Keeper {
    pub inner: Direct,
    pub sent: Sent,
    pub fail: Arc<AtomicBool>,
}

impl Link for Keeper {
    fn call(&self, command: &str, stdin: &str) -> Result<String> {
        self.inner.call(command, stdin)
    }
    fn upload(&self, command: &str, header: &str, files: &[&Path]) -> Result<String> {
        assert_eq!(command, "release-put");
        self.sent.lock().unwrap().push(header.into());
        if self.fail.load(Ordering::SeqCst) {
            return Err("cannot reach the coordinator at 192.168.1.50: Connection timed out".into());
        }
        let head: rollout::PutHeader = serde_json::from_str(header.trim_end())?;
        let r: Release = serde_json::from_str(&head.release.doc)?;
        assert_eq!(files.len(), 1, "no k3s unless the coordinator asks");
        let served = fsx::dir(&self.inner.store.path).join(rollout::SERVED_DIR);
        std::fs::create_dir_all(served.join(r.serial.to_string()))?;
        std::fs::write(served.join(r.serial.to_string()).join(rollout::RELEASE_FILE), serde_json::to_string(&head.release)?)?;
        std::fs::write(served.join("current"), format!("{}\n", r.serial))?;
        Ok(format!("{{\"serial\":{}}}", r.serial))
    }
    fn host_key(&self) -> Result<String> {
        self.inner.host_key()
    }
    fn scan_host_key(&self) -> Result<String> {
        self.inner.scan_host_key()
    }
    fn repin(&self, key: &str) -> Result<()> {
        self.inner.repin(key)
    }
}

/// An Admin of the desktop in dir, talking to the coordinator setup made
/// there; uploads are kept by a Keeper.
pub fn twin(dir: &Path, sent: &Sent, fail: &Arc<AtomicBool>) -> Admin {
    let link = Keeper {
        inner: Direct {
            store: Store::new(dir.join("registry.json")),
            host_key: crate::admin::tests::COORD_KEY.into(),
            publish_fails: Arc::default(),
            verifier: None,
            pinned: Arc::new(Mutex::new(crate::admin::tests::COORD_KEY.into())),
        },
        sent: sent.clone(),
        fail: fail.clone(),
    };
    Admin::new(Box::new(link), Box::new(Key("admin")), Box::new(Key("admin")), &dir.join("secrets"), "10.66.0.0/24")
}

/// A desktop and its coordinator: coord, and node-a and node-b as servers,
/// each reporting dryserver 0.1.0 and the pinned k3s. Returns the admin,
/// the coordinator's store, what was sent, the switch that cuts the
/// uploads off, and the parts of a release (a static binary of version
/// 0.2.0, a k3s file with the sha256 they pin).
pub fn desk(dir: &TempDir) -> (Admin, Store, Sent, Arc<AtomicBool>, Parts) {
    let (_, store) = setup(dir);
    let now = Time::now().0.timestamp();
    store
        .update(|s| {
            for (host, name) in [(2, "node-a"), (3, "node-b")] {
                s.members.push(Member { host, name: name.into(), wg_key: crate::admin::tests::key32(host as u8), ..Member::default() });
            }
            for host in 1..=3 {
                let rep = Report {
                    format: report::FORMAT,
                    time: now,
                    dryserver: "0.1.0".into(),
                    k3s: iso::K3S_VERSION.into(),
                    ..Report::default()
                };
                s.heartbeat(host, Heartbeat { lan_ip: "192.168.1.50".into(), report: Some(rep), ..Heartbeat::default() }, Time::now())?;
            }
            Ok(())
        })
        .unwrap();
    let sent: Sent = Arc::default();
    let fail = Arc::new(AtomicBool::new(false));
    let a = twin(dir.path(), &sent, &fail);
    (a, store, sent, fail, parts(dir, "0.2.0"))
}

pub fn parts(dir: &TempDir, version: &str) -> Parts {
    let binary = static_binary(dir, &format!("dryserver-{version}"), version);
    let k3s = dir.join("k3s-pinned");
    std::fs::write(&k3s, "the pinned k3s").unwrap();
    Parts {
        binary,
        version: version.into(),
        k3s,
        k3s_version: iso::K3S_VERSION.into(),
        k3s_sha256: fsx::hex(&Sha256::digest(b"the pinned k3s")),
    }
}

// ---- the archive ----

#[test]
fn the_archive_is_asked_for_the_day_and_nothing_else() {
    let (archive, fake) = curl(|_| ("200".into(), Ok(())));
    assert!(archive.exists(&Ctx::new(), "2026/11/20").unwrap());
    let got = fake.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2, "core and extra");
    for (c, repo) in got.iter().zip(REPOS) {
        assert_eq!((c.name.as_str(), c.args.clone()), ("curl", vec!["-q".to_string(), "--config".into(), "-".into()]));
        assert!(c.quiet && c.stdout_only);
        for want in [
            format!("url = \"https://archive.archlinux.org/repos/2026/11/20/{repo}/os/x86_64/{repo}.db\"\n"),
            "proto = \"=https\"\n".into(),
            "proto-redir = \"=https\"\n".into(),
            "max-redirs = \"3\"\n".into(),
            "max-time = \"20\"\n".into(),
            "output = \"/dev/null\"\n".into(),
            "write-out = \"%{http_code}\"\n".into(),
            "head\n".into(),
            "location\n".into(),
            "tlsv1.2\n".into(),
        ] {
            assert!(c.stdin.contains(&want), "config missing {want:?}:\n{}", c.stdin);
        }
        // Nothing about the admin goes with it.
        for never in ["header", "cookie", "user", "referer", "data"] {
            assert!(!c.stdin.contains(never), "{never} in the request:\n{}", c.stdin);
        }
    }
}

#[test]
fn what_the_archive_answers() {
    let ctx = Ctx::new();
    let answer = |status: &'static str| curl(move |_| (status.into(), Ok(())));
    // Missing: the first repository says so, the second is not asked.
    let (a, fake) = answer("404");
    assert!(!a.exists(&ctx, "2026/11/22").unwrap());
    assert_eq!(fake.got.lock().unwrap().len(), 1);
    assert!(!answer("410").0.exists(&ctx, "2026/11/22").unwrap());
    // Only extra is missing: the day is not there.
    let (a, _) = curl(|url| ((if url.contains("extra") { "404" } else { "200" }).into(), Ok(())));
    assert!(!a.exists(&ctx, "2026/11/22").unwrap());
    // It cannot tell: never taken as there, nor as missing.
    let e = answer("503").0.exists(&ctx, "2026/11/22").unwrap_err().to_string();
    assert!(e.contains("archive.archlinux.org has a problem (HTTP 503") && e.contains("try again later"), "{e}");
    let e = answer("403").0.exists(&ctx, "2026/11/22").unwrap_err().to_string();
    assert!(e.contains("answered HTTP 403"), "{e}");
    let e = answer("").0.exists(&ctx, "2026/11/22").unwrap_err().to_string();
    assert!(e.contains("no HTTP status"), "{e}");
    let e = answer("000").0.exists(&ctx, "2026/11/22").unwrap_err().to_string();
    assert!(e.contains("no answer from archive.archlinux.org"), "{e}");
    // curl's own failures, as the admin reads them.
    for (code, want) in [
        (6, "cannot find archive.archlinux.org (is this computer online?)"),
        (7, "cannot connect to archive.archlinux.org"),
        (28, "did not answer within 20s"),
        (47, "redirected more than 3 times"),
        (1, "not HTTPS; refused"),
        (60, "the secure connection to archive.archlinux.org failed"),
        (99, "curl failed with exit status 99"),
    ] {
        let (a, _) = curl(move |_| (String::new(), Err(Error::new(format!("curl failed: exit status {code}")))));
        let e = a.exists(&ctx, "2026/11/22").unwrap_err().to_string();
        assert!(e.contains(want), "{code}: {e}");
    }
    let (a, _) = curl(|_| (String::new(), Err("curl failed: exec: \"curl\": executable file not found in $PATH".into())));
    assert!(a.exists(&ctx, "2026/11/22").unwrap_err().to_string().contains("curl is not installed"));
    // A cancelled check says so, not "curl failed".
    let c = Ctx::new();
    c.cancel();
    let (a, _) = curl(|_| (String::new(), Err("curl failed: signal: killed".into())));
    assert!(a.exists(&c, "2026/11/22").unwrap_err().is_canceled());
}

#[test]
fn real_curl_reads_the_config() {
    // Every option name as curl itself reads them, against a port where
    // nothing listens on this computer (never the archive).
    if std::process::Command::new("curl").arg("--version").output().is_err() {
        return;
    }
    let a = Archive::new();
    let e = a.status(&Ctx::new(), "https://127.0.0.1:9/repos/2026/11/20/core/os/x86_64/core.db").unwrap_err().to_string();
    assert!(e.contains("cannot connect to archive.archlinux.org"), "a config curl did not take: {e}");
    // Plain HTTP is refused before anything is sent.
    let e = a.status(&Ctx::new(), "http://127.0.0.1:9/x").unwrap_err().to_string();
    assert!(e.contains("not HTTPS"), "{e}");
}

// ---- the day ----

#[test]
fn the_default_is_the_newest_day_on_the_archive() {
    let ctx = Ctx::new();
    let t = today();
    let days = FakeDays::with(&[days_ago(0), days_ago(1)]);
    let d = pick_day(&ctx, &days, "", None, false, t).unwrap();
    assert_eq!(d.day, days_ago(0));
    assert!(d.how.contains("today's, the newest on archive.archlinux.org"), "{}", d.how);

    // Today's is not there yet: the day before.
    let days = FakeDays::with(&[days_ago(1), days_ago(2)]);
    let d = pick_day(&ctx, &days, "", Some(&days_ago(5)), false, t).unwrap();
    assert_eq!(d.day, days_ago(1));
    assert!(d.how.contains("today's is not there yet"), "{}", d.how);
    assert_eq!(days.asked(), vec![days_ago(0), days_ago(1)]);

    // Never older than the swarm's day: from today down to it, no further.
    let days = FakeDays::with(&[days_ago(2), days_ago(3)]);
    let e = pick_day(&ctx, &days, "", Some(&days_ago(1)), false, t).unwrap_err().to_string();
    assert!(e.contains(&format!("no Arch snapshot from {} to {}", days_ago(1), days_ago(0))) && e.contains("-arch-date"), "{e}");
    assert_eq!(days.asked(), vec![days_ago(0), days_ago(1)]);
    // The swarm's own day, when it is the newest there.
    let days = FakeDays::with(&[days_ago(1)]);
    assert_eq!(pick_day(&ctx, &days, "", Some(&days_ago(1)), false, t).unwrap().day, days_ago(1));
    // With rollback the default may be older than the swarm's day.
    let days = FakeDays::with(&[days_ago(3)]);
    assert_eq!(pick_day(&ctx, &days, "", Some(&days_ago(1)), true, t).unwrap().day, days_ago(3));
    // At most DAYS_BACK days back.
    let days = FakeDays::with(&[days_ago(DAYS_BACK + 1)]);
    assert!(pick_day(&ctx, &days, "", None, false, t).is_err());
    assert_eq!(days.asked().len() as i64, DAYS_BACK + 1);
}

#[test]
fn a_named_day_must_be_on_the_archive() {
    let ctx = Ctx::new();
    let t = today();
    let days = FakeDays::with(&[days_ago(10)]);
    let d = pick_day(&ctx, &days, &days_ago(10), None, false, t).unwrap();
    assert_eq!((d.day.as_str(), d.how.as_str()), (days_ago(10).as_str(), "checked: it is on archive.archlinux.org"));
    // Typed with dashes.
    assert_eq!(pick_day(&ctx, &days, &days_ago(10).replace('/', "-"), None, false, t).unwrap().day, days_ago(10));
    // Not there: every machine would fail, so it is refused here.
    let e = pick_day(&ctx, &days, &days_ago(9), None, false, t).unwrap_err().to_string();
    assert!(e.contains(&format!("Arch snapshot {} is not on archive.archlinux.org:", days_ago(9))), "{e}");
    assert!(e.contains("every machine would fail"), "{e}");
    let e = pick_day(&ctx, &days, &days_ago(0), None, false, t).unwrap_err().to_string();
    assert!(e.contains("not on archive.archlinux.org (yet)"), "{e}");
    // Not a date at all.
    assert!(pick_day(&ctx, &days, "2026/13/01", None, false, t).unwrap_err().to_string().contains("not a date like"));
    assert!(pick_day(&ctx, &days, "yesterday", None, false, t).is_err());
}

#[test]
fn what_is_refused_without_asking_the_archive() {
    let ctx = Ctx::new();
    let t = today();
    let days = FakeDays::with(&[days_ago(0), days_ago(1), days_ago(5), days_ago(-1)]);
    // A day in the future.
    let e = pick_day(&ctx, &days, &days_ago(-1), None, false, t).unwrap_err().to_string();
    assert!(e.contains(&format!("Arch snapshot {} is in the future: today is {}", days_ago(-1), days_ago(0))), "{e}");
    // An older day than the swarm's needs rollback.
    let e = pick_day(&ctx, &days, &days_ago(5), Some(&days_ago(1)), false, t).unwrap_err().to_string();
    assert!(e.contains(&format!("older than the swarm's ({})", days_ago(1))) && e.contains("-rollback"), "{e}");
    // The swarm runs a day after today: this computer's clock is behind.
    let e = pick_day(&ctx, &days, "", Some(&days_ago(-2)), false, t).unwrap_err().to_string();
    assert!(e.contains("after today") && e.contains("check this computer's clock"), "{e}");
    assert!(days.asked().is_empty(), "asked {:?}", days.asked());
    // With rollback, the older day is asked for and taken.
    assert_eq!(pick_day(&ctx, &days, &days_ago(5), Some(&days_ago(1)), true, t).unwrap().day, days_ago(5));
}

#[test]
fn without_the_archive_only_the_swarms_own_day_goes() {
    let ctx = Ctx::new();
    let t = today();
    let days = FakeDays::with(&[]);
    *days.fail.lock().unwrap() = Some("cannot find archive.archlinux.org (is this computer online?)".into());
    // The default cannot be found; the message says how to keep the day.
    let e = pick_day(&ctx, &days, "", Some(&days_ago(4)), false, t).unwrap_err().to_string();
    assert!(e.contains("is this computer online?") && e.contains(&format!("-arch-date {}", days_ago(4))), "{e}");
    let e = pick_day(&ctx, &days, "", None, false, t).unwrap_err().to_string();
    assert!(e.contains("is this computer online?") && !e.contains("-arch-date"), "{e}");
    // The swarm's own day: the machines run it already.
    let d = pick_day(&ctx, &days, &days_ago(4), Some(&days_ago(4)), false, t).unwrap();
    assert!(d.day == days_ago(4) && d.how.contains("not checked") && d.how.contains("the swarm runs this day already"), "{d:?}");
    // Any other day is refused.
    let e = pick_day(&ctx, &days, &days_ago(2), Some(&days_ago(4)), false, t).unwrap_err().to_string();
    assert!(e.contains(&format!("cannot check Arch snapshot {}", days_ago(2))), "{e}");
}

// ---- k3s and the signing key ----

#[test]
fn the_k3s_file_is_checked_before_signing() {
    let dir = TempDir::new();
    let p = dir.join("k3s-v1.37.2+k3s1");
    let v = iso::K3S_VERSION;
    // Missing: fine when the coordinator runs it already.
    assert_eq!(check_k3s(&p, v, &"a".repeat(64), Some(v)).unwrap(), K3sFile::NotNeeded);
    // Otherwise the message says exactly how to get it.
    let e = check_k3s(&p, v, &"a".repeat(64), Some("v1.36.1+k3s1")).unwrap_err().to_string();
    for want in [
        &format!("k3s {v} is not on this computer ({} is missing)", p.display()),
        "the coordinator runs k3s v1.36.1+k3s1, so it needs this one",
        "dryserver build",
        &format!("mkdir -p '{}' && curl -fL -o '{}'", dir.path().display(), p.display()),
        &format!("https://github.com/k3s-io/k3s/releases/download/{}/k3s", v.replace('+', "%2B")),
        "checked here before anything is signed",
    ] {
        assert!(e.contains(want), "{want}: {e}");
    }
    let e = check_k3s(&p, v, &"a".repeat(64), None).unwrap_err().to_string();
    assert!(e.contains("does not say which k3s it runs"), "{e}");
    // There, but not the pinned binary.
    std::fs::write(&p, "half a download").unwrap();
    let e = check_k3s(&p, v, &"a".repeat(64), Some(v)).unwrap_err().to_string();
    assert!(e.contains("is not k3s") && e.contains(&"a".repeat(64)) && e.contains("Remove it and get it again"), "{e}");
    // The pinned one.
    let sha = fsx::hex(&Sha256::digest(b"half a download"));
    assert_eq!(check_k3s(&p, v, &sha, None).unwrap(), K3sFile::Checked);
    // A link in its place is not followed.
    let link = dir.join("k3s-link");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    assert!(check_k3s(&link, v, &sha, None).unwrap_err().to_string().contains("symbolic link"));
}

#[test]
fn a_signing_key_with_a_passphrase_is_found() {
    if std::process::Command::new("ssh-keygen").arg("-?").output().is_err() {
        return;
    }
    let dir = TempDir::new();
    let keygen = |name: &str, pass: &str| {
        let out = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-C", "test", "-N", pass, "-f"])
            .arg(dir.join(name))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    };
    keygen("plain", "");
    keygen("locked", "a passphrase");
    assert!(!has_passphrase(&dir.join("plain")));
    assert!(has_passphrase(&dir.join("locked")));
    assert!(!has_passphrase(&dir.join("missing")));
}

// ---- plan and publish ----

#[test]
fn a_release_is_planned_shown_and_published() {
    let dir = TempDir::new();
    let (mut a, store, sent, _, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(1), days_ago(2)]);
    let ctx = Ctx::new();
    let v = a.load().unwrap();
    let choice = Choice { notes: "fixes the join timeout".into(), ..Choice::default() };
    let p = plan(&ctx, &a, &v, &days, &parts, &choice, today()).unwrap();
    assert_eq!(p.release.arch_date, days_ago(1));
    assert_eq!((p.machines(), p.k3s), (3, K3sFile::Checked));
    let text = p.lines().join("\n");
    for want in [
        &format!("Release {} for 3 machines:", p.release.serial),
        "  dryserver  0.1.0 -> 0.2.0",
        &format!("  k3s        same ({})", iso::K3S_VERSION),
        &format!("  Arch       as installed -> {} (the newest on archive.archlinux.org; today's is not there yet)", days_ago(1)),
        "  urgent     no: machines update only 03:00-05:00 on the coordinator's clock",
        "  rollback   no",
        "  notes      fixes the join timeout",
        "No release yet: compared with what the machines report.",
        "coord updates itself first, then the servers one at a time: node-a and node-b (node-a is the canary, watched for 5m).",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    assert!(sent.lock().unwrap().is_empty(), "nothing is sent before the admin says yes");
    assert!(!dir.join("secrets").join(crate::admin::RELEASE_COPY).exists(), "nothing is signed either");

    // Exactly the release shown is signed and sent.
    let r = publish(&mut a, &p).unwrap();
    assert_eq!(r, p.release);
    let head: rollout::PutHeader = serde_json::from_str(sent.lock().unwrap()[0].trim_end()).unwrap();
    assert_eq!(release::open(&Key("admin"), &head.release, Time::now().0.timestamp()).unwrap(), p.release);
    let v = a.load().unwrap();
    assert_eq!(v.release.as_ref(), Some(&p.release));
    // The same plan again is refused: the coordinator moved on since.
    let e = publish(&mut a, &p).unwrap_err().to_string();
    assert!(e.contains("changed since you looked") && e.contains("Nothing was signed"), "{e}");
    assert_eq!(sent.lock().unwrap().len(), 1);

    // Before the machines took it, the next one says they did not.
    let urgent = Choice { urgent: true, ..Choice::default() };
    let text = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap().lines().join("\n");
    let want = format!(
        "Not on release {} yet: coord (its Arch day not known here), node-a (its Arch day not known here) and node-b (its Arch day not known here).",
        p.release.serial
    );
    assert!(text.contains(&want) && !text.contains("Nothing changes"), "{text}");
    for host in 1..=3 {
        on_release(&store, host, p.release.serial);
    }
    let v = a.load().unwrap();

    // The next one compares with it. Nothing changes but the urgency.
    let p2 = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap();
    assert!(p2.release.serial > p.release.serial);
    let text = p2.lines().join("\n");
    for want in [
        ", urgent:",
        "  dryserver  same (0.2.0)",
        &format!("  Arch       same ({})", days_ago(1)),
        "  urgent     yes: the rollout starts at once",
        "  notes      none",
        &format!("Compared with release {}, the newest on the coordinator.", p.release.serial),
        &format!("Nothing changes on the machines: the same dryserver build, k3s and Arch day as release {}", p.release.serial),
        "(node-a is the canary, watched for 1m)",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    // Another build of the same version is told apart.
    let rebuilt = static_binary(&dir, "dryserver-0.2.0", "0.2.0 rebuilt");
    let p3 = plan(&ctx, &a, &v, &days, &Parts { binary: rebuilt, ..parts.clone() }, &Choice::default(), today()).unwrap();
    assert!(p3.lines()[1].contains("0.2.0, another build (sha256"), "{:?}", p3.lines());
    drop(store);
}

#[test]
fn a_plan_says_why_not_before_the_archive_is_asked() {
    let dir = TempDir::new();
    let (mut a, _, _, _, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let ctx = Ctx::new();
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    publish(&mut a, &p).unwrap();
    let v = a.load().unwrap();
    let asked = days.asked().len();

    // An older dryserver, a build for this desktop, bad notes, an older
    // day: each is refused without a question to the archive.
    let old = super::tests::parts(&dir, "0.1.9");
    let e = plan(&ctx, &a, &v, &days, &old, &Choice::default(), today()).unwrap_err().to_string();
    assert!(e.contains("this dryserver (0.1.9) is older than the swarm's (0.2.0)") && e.contains("-rollback"), "{e}");
    let mut dynamic = std::fs::read(&parts.binary).unwrap();
    dynamic[64..68].copy_from_slice(&3u32.to_le_bytes());
    let linked = dir.join("dryserver-linked");
    std::fs::write(&linked, dynamic).unwrap();
    let e = plan(&ctx, &a, &v, &days, &Parts { binary: linked, ..parts.clone() }, &Choice::default(), today()).unwrap_err().to_string();
    assert!(e.contains("linked against this computer's libraries"), "{e}");
    let bad = Choice { notes: "two\nlines".into(), ..Choice::default() };
    assert!(plan(&ctx, &a, &v, &days, &parts, &bad, today()).unwrap_err().to_string().contains("notes"));
    let older = Choice { arch_date: days_ago(3), ..Choice::default() };
    let e = plan(&ctx, &a, &v, &days, &parts, &older, today()).unwrap_err().to_string();
    assert!(e.contains("older than the swarm's") && e.contains("-rollback"), "{e}");
    let wrong_k3s = Parts { k3s_sha256: "b".repeat(64), ..parts.clone() };
    assert!(plan(&ctx, &a, &v, &days, &wrong_k3s, &Choice::default(), today()).unwrap_err().to_string().contains("is not k3s"));
    assert_eq!(days.asked().len(), asked);
    // With rollback the older dryserver goes.
    let back = Choice { rollback: true, ..Choice::default() };
    let p = plan(&ctx, &a, &v, &days, &old, &back, today()).unwrap();
    assert!(p.release.rollback && p.lines()[0].ends_with(", rollback:") && p.lines()[1].contains("0.2.0 -> 0.1.9"), "{:?}", p.lines());
}

#[test]
fn a_cut_off_upload_is_said_and_the_next_one_goes_up() {
    let dir = TempDir::new();
    let (mut a, _, sent, fail, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let ctx = Ctx::new();
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    fail.store(true, Ordering::SeqCst);
    let e = publish(&mut a, &p).unwrap_err().to_string();
    assert!(
        e.contains(&format!("release {} is signed and kept on this computer, but the coordinator did not take it", p.release.serial)),
        "{e}"
    );
    assert!(e.contains("Connection timed out") && e.contains("dryserver release status shows what the coordinator has"), "{e}");
    assert!(e.contains("Publishing again is safe"), "{e}");
    assert_eq!(sent.lock().unwrap().len(), 1);
    // The next plan says so and goes up from it.
    fail.store(false, Ordering::SeqCst);
    let v = a.load().unwrap();
    assert!(v.release.is_none());
    let p2 = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    assert!(p2.release.serial > p.release.serial);
    let text = p2.lines().join("\n");
    assert!(text.contains(&format!("Release {} was signed here but never reached the coordinator", p.release.serial)), "{text}");
    publish(&mut a, &p2).unwrap();
    // The first plan can never be signed after it: its serial is used.
    let e = publish(&mut a, &p).unwrap_err().to_string();
    assert!(e.contains("Nothing was signed"), "{e}");
}

#[test]
fn two_publishes_never_both_sign() {
    let dir = TempDir::new();
    let (mut a, _, sent, fail, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let ctx = Ctx::new();
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    // Another terminal (another Admin on the same desktop) publishes in
    // between: this plan no longer fits.
    let mut other = twin(dir.path(), &sent, &fail);
    let v2 = other.load().unwrap();
    let q = plan(&ctx, &other, &v2, &days, &parts, &Choice { notes: "other".into(), ..Choice::default() }, today()).unwrap();
    publish(&mut other, &q).unwrap();
    let e = publish(&mut a, &p).unwrap_err().to_string();
    assert!(e.contains(&format!("changed since you looked (release {} now)", q.release.serial)), "{e}");
    // One that runs holds the lock: the other one waits for nothing and
    // signs nothing.
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    let held = fsx::try_lock(dir.join("secrets").join(LOCK)).unwrap().unwrap();
    let e = publish(&mut a, &p).unwrap_err().to_string();
    assert!(e.contains("another publish runs on this computer") && e.contains("Nothing was signed"), "{e}");
    drop(held);
    publish(&mut a, &p).unwrap();
    assert_eq!(sent.lock().unwrap().len(), 2);
}

#[test]
fn a_binary_changed_after_the_plan_is_not_signed() {
    let dir = TempDir::new();
    let (mut a, _, sent, _, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let v = a.load().unwrap();
    let p = plan(&Ctx::new(), &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    static_binary(&dir, "dryserver-0.2.0", "0.2.0 and a fix made after the plan");
    let e = publish(&mut a, &p).unwrap_err().to_string();
    assert!(e.contains("changed since the release was drafted") && e.contains("Nothing was signed"), "{e}");
    assert!(sent.lock().unwrap().is_empty() && !dir.join("secrets").join(crate::admin::RELEASE_COPY).exists());
}

#[test]
fn a_missing_k3s_is_fine_when_the_coordinator_runs_it() {
    let dir = TempDir::new();
    let (mut a, _, _, _, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let v = a.load().unwrap();
    let gone = Parts { k3s: dir.join("not-here"), ..parts };
    let p = plan(&Ctx::new(), &a, &v, &days, &gone, &Choice::default(), today()).unwrap();
    assert_eq!(p.k3s, K3sFile::NotNeeded);
    assert!(
        p.lines().last().unwrap().contains("not on this computer") && p.lines().last().unwrap().contains("runs k3s"),
        "{:?}",
        p.lines()
    );
}

// ---- resume ----

#[test]
fn resume_says_what_it_does_or_why_not() {
    let base = Rollout { serial: 9, phase: Phase::Servers, pause_name: "node-a".into(), pause_host: 2, ..Rollout::default() };
    assert!(resume_does(&Rollout::default()).unwrap_err().to_string().contains("there is no rollout to resume"));
    let e = resume_does(&base).unwrap_err().to_string();
    assert!(e.contains("release 9 is not stopped: there is nothing to resume"), "{e}");
    assert!(!stopped(&base) && !stopped(&Rollout::default()));
    let paused = |pause: Pause| Rollout { paused: "why".into(), pause, ..base.clone() };
    // A resume tries the server again; -skip passes it over.
    for (pause, want, skip) in [
        (Pause::Failed, "gives node-a its turn again, to try release 9 once more", "passes node-a over for release 9"),
        (Pause::Timeout, "gives node-a its turn again", "passes node-a over for release 9"),
        (Pause::Drain, "updates node-a without draining it", "passes node-a over for release 9"),
        (Pause::Canary, "goes on after the canary node-a", "goes on after the canary node-a"),
    ] {
        assert!(stopped(&paused(pause)));
        let does = resume_does(&paused(pause)).unwrap();
        assert!(does.starts_with(want), "{pause:?}: {does}");
        let does = skip_does(&paused(pause)).unwrap();
        assert!(does.starts_with(skip), "{pause:?}: {does}");
    }
    let failed = Rollout { phase: Phase::Failed, paused: "its update failed".into(), ..base.clone() };
    assert_eq!(resume_does(&failed).unwrap(), "tries its own update again");
    // The coordinator is never passed over, and nothing is when nothing stopped.
    assert!(skip_does(&failed).unwrap_err().to_string().contains("never passed over"));
    assert!(skip_does(&base).unwrap_err().to_string().contains("nothing to pass over"));
    assert!(skip_does(&Rollout::default()).unwrap_err().to_string().contains("no rollout to resume"));
}

#[test]
fn resume_asks_the_coordinator_only_when_it_stopped() {
    let dir = TempDir::new();
    let (mut a, store, _, _, _) = desk(&dir);
    let e = resume(&mut a).unwrap_err().to_string();
    assert!(e.contains("no rollout to resume"), "{e}");
    store
        .update(|s| {
            s.rollout = Rollout { serial: 5, phase: Phase::Servers, ..Rollout::default() };
            Ok(())
        })
        .unwrap();
    assert!(resume(&mut a).unwrap_err().to_string().contains("not stopped"));
    assert_eq!(store.read().unwrap().rollout.resume_asked, 0, "nothing was asked");
    assert!(skip(&mut a).unwrap_err().to_string().contains("nothing to pass over"));
    assert_eq!(store.read().unwrap().rollout.skip_asked, 0, "nothing was asked");
    store
        .update(|s| {
            s.rollout.paused = "node-a: update failed".into();
            s.rollout.pause = Pause::Failed;
            s.rollout.pause_host = 2;
            s.rollout.pause_name = "node-a".into();
            Ok(())
        })
        .unwrap();
    assert_eq!(resume(&mut a).unwrap(), "gives node-a its turn again, to try release 5 once more");
    assert_eq!(store.read().unwrap().rollout.resume_asked, 1);
    assert_eq!(skip(&mut a).unwrap(), "passes node-a over for release 5 and goes on with the next server");
    let r = store.read().unwrap().rollout;
    assert_eq!((r.resume_asked, r.skip_asked), (1, 1));
}

// ---- status ----

fn member(host: u32, name: &str, rep: Option<Report>, seen: i64) -> (Member, bool) {
    let last_seen = Time(chrono::DateTime::from_timestamp(seen, 0).unwrap());
    (Member { host, name: name.into(), last_seen, report: rep, ..Member::default() }, true)
}

fn rep(release: u64, update: &str, serial: u64, note: &str) -> Report {
    Report {
        dryserver: "0.2.0".into(),
        release,
        update: update.into(),
        update_serial: serial,
        update_note: note.into(),
        ..Report::default()
    }
}

#[test]
fn status_is_one_line_per_machine_and_says_what_to_do() {
    let now = 1_800_000_000;
    let r = Release {
        serial: 1_795_000_000,
        created: now - 3600,
        expires: now + release::LIFETIME,
        dryserver: release::Binary { version: "0.2.0".into(), sha256: "a".repeat(64), size: 10 },
        k3s: release::K3s { version: iso::K3S_VERSION.into(), sha256: iso::K3S_SHA256.into() },
        arch_date: "2026/11/19".into(),
        rollback: false,
        urgent: true,
        notes: "fixes X".into(),
    };
    let s = r.serial;
    let v = View {
        release: Some(r),
        rollout: Rollout {
            serial: s,
            urgent: true,
            phase: Phase::Servers,
            done: vec![2],
            paused: "node-b: update failed: no space left on device".into(),
            pause: Pause::Failed,
            pause_host: 3,
            pause_name: "node-b".into(),
            skipped: vec![Skip { host: 6, name: "node-e".into(), why: "it refused the release".into() }],
            turn: None,
            ..Rollout::default()
        },
        members: vec![
            member(1, "coord", Some(rep(s, "", 0, "")), now - 20),
            member(2, "node-a", Some(rep(s, "", 0, "")), now - 20),
            member(3, "node-b", Some(rep(1, "failed", s, "no space left on device")), now - 20),
            member(4, "node-c", Some(rep(1, "", 0, "")), now - 7200),
            member(5, "node-d", None, now - 20),
            member(6, "node-e", Some(rep(1, "", 0, "")), now - 20),
            member(7, "node-f", Some(rep(1, "rebooting", s, "")), now - 20),
            member(8, "node-g", Some(rep(1, "held", 0, "")), now - 20),
            member(9, "node-h", Some(rep(1, "pending", s, "installing the packages of Arch 2026/11/20")), now - 20),
        ],
        coordinator_now: now,
        ..View::default()
    };
    let text = status_lines(&v, 0).join("\n");
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with(&format!("Release {s} (urgent), made")) && lines[0].ends_with(": fixes X"), "{text}");
    assert_eq!(lines[1], format!("  dryserver 0.2.0, k3s {}, Arch snapshot 2026/11/19", iso::K3S_VERSION));
    for want in [
        "Rollout:\n  PAUSED: node-b: update failed",
        "Machines:\n",
        &format!("  coord          coordinator  on release {s}  dryserver 0.2.0"),
        &format!("  node-a         server       on release {s}  dryserver 0.2.0"),
        &format!("! node-b         server       update failed (release {s}): no space left on device  dryserver 0.2.0"),
        "  node-c         server       silent for 2h: updates when it is back",
        "! node-d         server       no report: its dryserver is too old to update itself",
        "! node-e         server       passed over: it refused the release",
        // A state this version does not know is shown as the machine says it.
        &format!("  node-f         server       rebooting (release {s})"),
        "! node-g         server       held: its kill switch is on",
        // What its update does now, from the note.
        &format!("  node-h         server       updating (release {s}): installing the packages of Arch 2026/11/20"),
        "The rollout is stopped. Look at the machine first, then either",
        "dryserver release resume                       the coordinator gives node-b its turn again",
        "dryserver release resume -skip                 the coordinator passes node-b over for release",
        "dryserver release publish -notes \"the fix\"    a fixed release: it gets a higher serial",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }

    // Running: no advice. A server whose turn it is says so.
    let mut running = v.clone();
    running.rollout.paused.clear();
    running.rollout.pause = Pause::None;
    running.rollout.turn = Some(Turn { host: 4, name: "node-c".into(), since: now - 60, ready: true, ..Turn::default() });
    running.members[3].0.last_seen = Time(chrono::DateTime::from_timestamp(now - 10, 0).unwrap());
    let text = status_lines(&running, 0).join("\n");
    assert!(!text.contains("The rollout is stopped"), "{text}");
    assert!(text.contains("  node-c         server       its turn: updating"), "{text}");

    // Nothing published yet.
    let none = View { members: vec![member(1, "coord", Some(rep(0, "", 0, "")), now - 5)], coordinator_now: now, ..View::default() };
    let text = status_lines(&none, 0).join("\n");
    assert!(text.starts_with("Rollout:\n  No release published yet: dryserver release publish"), "{text}");
    assert!(text.contains("  coord          coordinator  no release installed  dryserver 0.2.0"), "{text}");

    // Published a moment ago: the coordinator did not take it up yet.
    let fresh = View { release: v.release.clone(), rollout: Rollout::default(), ..none.clone() };
    let text = status_lines(&fresh, 0).join("\n");
    assert!(text.contains("Rollout:\n  Not started yet: the coordinator takes the release up at its next sync"), "{text}");
    assert!(!text.contains("No release published yet"), "{text}");
    // A refused upload still shows.
    let refused = View { rollout: Rollout { refused: "release 7 was refused: bad signature".into(), ..Rollout::default() }, ..fresh };
    let lines = rollout_lines(&refused, now);
    assert!(lines[0] == ("release 7 was refused: bad signature".to_string(), true) && lines.len() == 2, "{lines:?}");
}

// ---- the coordinator's words on the admin's terminal ----

/// What a hacked registry account can put in the rollout copy the desktop
/// reads: an OSC 52 that writes the admin's clipboard, a screen clear and
/// a window title. `release status` prints none of it.
#[test]
fn review_release_status_prints_no_control_characters() {
    let now = 1_795_400_000;
    let seen = Time(chrono::DateTime::from_timestamp(now, 0).unwrap());
    let m = Member { host: 2, name: "node-a".into(), report: Some(Report::default()), last_seen: seen, ..Member::default() };
    let rollout = Rollout {
        serial: 10,
        phase: Phase::Servers,
        skipped: vec![Skip { host: 2, name: "node-a".into(), why: "\x1b]52;c;Y3VybCBldmlsLmV4YW1wbGUgfCBzaA==\x07".into() }],
        paused: "stopped".into(),
        pause: Pause::Failed,
        pause_host: 3,
        pause_name: "\x1b[2J\x1b]0;pwned\x07".into(),
        ..Rollout::default()
    };
    let v = View { members: vec![(m, true)], rollout, coordinator_now: now, ..View::default() };
    let bad: Vec<String> = status_lines(&v, now).into_iter().filter(|l| l.chars().any(|c| c.is_control())).collect();
    assert!(bad.is_empty(), "{bad:?}");
    // The name that is not a hostname is not shown at all.
    let text = status_lines(&v, now).join("\n");
    assert!(text.contains("the coordinator gives the server its turn again") && !text.contains("pwned"), "{text}");
    assert!(!resume_does(&v.rollout).unwrap().contains('\x1b') && !skip_does(&v.rollout).unwrap().contains('\x1b'));
}

/// Every text of the rollout as the desktop takes it is printable ASCII
/// and cut short, names that are not hostnames are gone, the lists are
/// capped (the newest warnings kept); numbers and plain words stay.
#[test]
fn a_rollout_from_the_coordinator_is_made_plain() {
    let evil = "a\x1b]52;c;eA==\x07\u{9b}2J\u{202e}\r\n";
    let r = Rollout {
        serial: 7,
        phase: Phase::Servers,
        turn: Some(Turn { host: 4, name: "node-c\x1b[2J".into(), since: 5, ready: true, ..Turn::default() }),
        skipped: (0..100)
            .map(|h| Skip { host: h, name: if h == 0 { "node-a".into() } else { evil.into() }, why: evil.repeat(100) })
            .collect(),
        cordoned: vec!["node-b".into(), evil.into(), "-bad".into()],
        paused: evil.into(),
        pause: Pause::Drain,
        pause_host: 3,
        pause_name: "Node-B".into(),
        warnings: (0..100).map(|i| format!("w{i} {evil}")).collect(),
        refused: evil.repeat(100),
        done: vec![2, 3],
        resume_asked: 4,
        ..Rollout::default()
    };
    let s = r.clone().sanitized();
    let plain = |t: &str| t.chars().all(|c| (' '..='~').contains(&c));
    assert_eq!(s.turn.as_ref().map(|t| (t.host, t.name.as_str(), t.ready)), Some((4, "", true)));
    assert_eq!(s.skipped.len(), MAX_SHOWN);
    assert_eq!((s.skipped[0].host, s.skipped[0].name.as_str(), s.skipped[1].name.as_str()), (0, "node-a", ""));
    assert!(s.skipped.iter().all(|k| plain(&k.why) && k.why.len() == 200));
    assert_eq!(s.cordoned, vec!["node-b".to_string()]);
    assert_eq!(s.paused, "a?]52;c;eA==??2J???");
    assert_eq!(s.pause_name, "", "not a hostname");
    assert_eq!(s.warnings.len(), MAX_SHOWN);
    assert!(s.warnings[0].starts_with("w36 ") && s.warnings.iter().all(|w| plain(w)), "the newest are kept");
    assert!(plain(&s.refused) && s.refused.len() == 300);
    assert_eq!(
        (s.serial, s.phase, s.pause, s.pause_host, s.done.clone(), s.resume_asked),
        (7, Phase::Servers, Pause::Drain, 3, vec![2, 3], 4)
    );
    assert_eq!(s.clone().sanitized(), s, "once is enough");
    // What a sane coordinator sends goes through as it is.
    let fine = Rollout {
        serial: 7,
        skipped: vec![Skip { host: 2, name: "node-a".into(), why: "it refused the release".into() }],
        paused: "node-b: update failed: no space left on device".into(),
        pause_name: "node-b".into(),
        warnings: vec!["draining node-c timed out".into()],
        ..Rollout::default()
    };
    assert_eq!(fine.clone().sanitized(), fine);
}

/// The desktop's load cuts the rollout down before anything shows it, and
/// the cuts a member reports show only hostnames.
#[test]
fn a_load_takes_the_rollout_and_the_cuts_as_plain_text() {
    let dir = TempDir::new();
    let (mut a, store, _, _, _) = desk(&dir);
    store
        .update(|s| {
            s.rollout = Rollout {
                serial: 5,
                phase: Phase::Servers,
                paused: "\x1b]52;c;Y3VybA==\x07stopped".into(),
                pause: Pause::Failed,
                pause_host: 2,
                pause_name: "\x1b[2J".into(),
                warnings: vec!["\x1b]0;pwned\x07".into()],
                ..Rollout::default()
            };
            let m = s.members.iter_mut().find(|m| m.host == 2).unwrap();
            m.cuts = vec![
                crate::registry::CutReport { name: "node-b".into(), auto: true },
                crate::registry::CutReport { name: "x\x1b[2J".into(), auto: false },
            ];
            Ok(())
        })
        .unwrap();
    let v = a.load().unwrap();
    assert_eq!((v.rollout.paused.as_str(), v.rollout.pause_name.as_str()), ("?]52;c;Y3VybA==?stopped", ""));
    assert_eq!(v.rollout.warnings, vec!["?]0;pwned?".to_string()]);
    assert_eq!(v.reports.len(), 1, "{:?}", v.reports);
    assert!(v.reports[0].starts_with("node-a cut off node-b by itself"), "{:?}", v.reports);
    assert_eq!(resume(&mut a).unwrap(), "gives the server its turn again, to try release 5 once more");
}

// ---- what the preview compares with ----

/// With no release yet the machines' reports say the version and not the
/// build: the same version is not "same", it may be another build.
#[test]
fn no_release_yet_the_same_version_is_not_called_the_same() {
    let dir = TempDir::new();
    let (mut a, _, _, _, _) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let v = a.load().unwrap();
    let rebuilt = super::tests::parts(&dir, "0.1.0");
    let p = plan(&Ctx::new(), &a, &v, &days, &rebuilt, &Choice::default(), today()).unwrap();
    let lines = p.lines();
    assert_eq!(lines[1], "  dryserver  0.1.0 (the machines report 0.1.0, not which build: they all get this one)");
    assert_eq!(lines[2], format!("  k3s        same ({})", iso::K3S_VERSION), "a k3s version is one pinned binary");
    assert!(!lines.join("\n").contains("same (0.1.0)"), "{lines:?}");
}

/// An urgent release keeps the swarm's Arch day unless one is named: no
/// machine runs pacman for it, and the archive is not even asked.
#[test]
fn an_urgent_release_keeps_the_arch_day() {
    let dir = TempDir::new();
    let (mut a, _, _, _, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(2)]);
    let ctx = Ctx::new();
    let urgent = Choice { urgent: true, ..Choice::default() };
    // No release yet: the swarm's day is not known here; the newest.
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap();
    assert_eq!(p.release.arch_date, days_ago(2));
    assert!(!days.asked().is_empty());
    publish(&mut a, &p).unwrap();

    days.have.lock().unwrap().push(days_ago(0));
    let v = a.load().unwrap();
    let asked = days.asked().len();
    let p = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap();
    assert_eq!(p.release.arch_date, days_ago(2));
    assert_eq!(days.asked().len(), asked, "the archive is not asked");
    let text = p.lines().join("\n");
    assert!(
        text.contains(&format!("  Arch       same ({}) (urgent releases keep the day; give -arch-date to move it)", days_ago(2))),
        "{text}"
    );
    // Urgent and rollback: the day stays too.
    let back = Choice { rollback: true, ..urgent.clone() };
    assert_eq!(plan(&ctx, &a, &v, &days, &parts, &back, today()).unwrap().release.arch_date, days_ago(2));
    assert_eq!(days.asked().len(), asked);
    // Not urgent: the newest day, as before.
    assert_eq!(plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap().release.arch_date, days_ago(0));
    // Urgent with a day named: that day, checked on the archive.
    let named = Choice { arch_date: days_ago(0), ..urgent.clone() };
    let asked = days.asked().len();
    let p = plan(&ctx, &a, &v, &days, &parts, &named, today()).unwrap();
    assert_eq!(p.release.arch_date, days_ago(0));
    assert_eq!(days.asked(), [days.asked()[..asked].to_vec(), vec![days_ago(0)]].concat());
    assert!(p.lines().join("\n").contains(&format!("  Arch       {} -> {} (checked", days_ago(2), days_ago(0))));
}

/// An urgent release keeps the newest release's day, but a server its
/// rollout did not reach runs an older day: the preview said "same", and
/// that server got a package update all the same. It says which machines
/// get packages now.
#[test]
fn review_an_urgent_release_says_which_machines_still_get_packages() {
    let dir = TempDir::new();
    let (mut a, store, _, _, parts) = desk(&dir);
    let ctx = Ctx::new();
    let days = FakeDays::with(&[days_ago(3)]);
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    let first = publish(&mut a, &p).unwrap();
    days.have.lock().unwrap().push(days_ago(2));
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    let second = publish(&mut a, &p).unwrap();
    assert_eq!((first.arch_date.as_str(), second.arch_date.as_str()), (days_ago(3).as_str(), days_ago(2).as_str()));
    // The rollout of the second stopped before node-b, which runs the first.
    let runs = |host: u32, release: u64| on_release(&store, host, release);
    runs(1, second.serial);
    runs(2, second.serial);
    runs(3, first.serial);
    let urgent = Choice { urgent: true, ..Choice::default() };
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap();
    assert_eq!(p.release.arch_date, days_ago(2));
    let text = p.lines().join("\n");
    assert!(text.contains(&format!("  Arch       same ({})", days_ago(2))), "{text}");
    let want = format!(
        "Not on release {} yet: node-b (Arch {}). Their packages go to Arch {} with this one: a package update",
        second.serial,
        days_ago(3),
        days_ago(2)
    );
    assert!(text.contains(&want), "{text}");
    // Every machine on it: nothing more to say.
    runs(3, second.serial);
    let v = a.load().unwrap();
    let text = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap().lines().join("\n");
    assert!(!text.contains("Not on release"), "{text}");
}

/// A machine's report: it runs release.
fn on_release(store: &Store, host: u32, release: u64) {
    store
        .update(|s| {
            let rep = Report {
                format: report::FORMAT,
                time: Time::now().0.timestamp(),
                dryserver: "0.2.0".into(),
                k3s: iso::K3S_VERSION.into(),
                release,
                ..Report::default()
            };
            s.heartbeat(host, Heartbeat { lan_ip: "192.168.1.50".into(), report: Some(rep), ..Heartbeat::default() }, Time::now())
        })
        .unwrap()
}

/// The coordinator's report of itself: on release, its update of serial
/// ended as update.
fn brain_says(store: &Store, release: u64, update: &str, serial: u64) {
    store
        .update(|s| {
            let rep = Report {
                format: report::FORMAT,
                time: Time::now().0.timestamp(),
                dryserver: "0.2.0".into(),
                k3s: iso::K3S_VERSION.into(),
                release,
                update: update.into(),
                update_serial: serial,
                ..Report::default()
            };
            s.heartbeat(1, Heartbeat { lan_ip: "192.168.1.50".into(), report: Some(rep), ..Heartbeat::default() }, Time::now())
        })
        .unwrap();
}

/// The VM lab's case: the newest release failed on the coordinator and
/// went back. The next preview compares with the release the machines
/// still run (this computer keeps a copy of each it signed), not with the
/// failed one, and says so.
#[test]
fn after_a_release_went_back_the_preview_compares_with_what_runs() {
    let dir = TempDir::new();
    let (mut a, store, _, _, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(1), days_ago(10)]);
    let ctx = Ctx::new();
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    let m = publish(&mut a, &p).unwrap();
    assert_eq!(signed_copy(&a, m.serial).as_ref(), Some(&m), "a copy of each release signed here");
    let v = a.load().unwrap();
    let old = super::tests::parts(&dir, "0.1.9");
    let back = Choice { rollback: true, arch_date: days_ago(10), ..Choice::default() };
    let p = plan(&ctx, &a, &v, &days, &old, &back, today()).unwrap();
    let n = publish(&mut a, &p).unwrap();
    store
        .update(|s| {
            s.rollout = Rollout { serial: n.serial, phase: Phase::Failed, paused: "its own update failed".into(), ..Rollout::default() };
            Ok(())
        })
        .unwrap();
    brain_says(&store, m.serial, "reverted", n.serial);
    for host in [2, 3] {
        on_release(&store, host, m.serial);
    }

    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    assert_eq!((p.went_back, p.runs.as_ref().map(|r| r.serial)), (Some(m.serial), Some(m.serial)));
    assert_eq!(p.release.arch_date, days_ago(1));
    let text = p.lines().join("\n");
    for want in [
        "  dryserver  same (0.2.0)".to_string(),
        format!("  Arch       same ({})", days_ago(1)),
        format!("Release {} failed on the coordinator and went back; the machines run release {}.", n.serial, m.serial),
        format!("Compared with release {}, which the machines run.", m.serial),
        format!("Nothing changes on the machines: the same dryserver build, k3s and Arch day as release {}", m.serial),
    ] {
        assert!(text.contains(&want), "{want}:\n{text}");
    }
    assert!(!text.contains(&days_ago(10)) && !text.contains("0.1.9"), "{text}");
    // The rollout alone says so as well (an older coordinator's report).
    store
        .update(|s| {
            s.members.iter_mut().find(|m| m.host == 1).unwrap().report.as_mut().unwrap().update.clear();
            Ok(())
        })
        .unwrap();
    let v = a.load().unwrap();
    assert_eq!(plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap().went_back, Some(m.serial));

    // Without a good copy of it here: compared with the reports. A copy
    // whose signature does not check out does not count.
    let copy = dir.join("secrets").join(COPIES).join(format!("{}.json", m.serial));
    let mut env: Envelope = serde_json::from_slice(&std::fs::read(&copy).unwrap()).unwrap();
    env.sig = crate::signed::Signer::sign(&Key("someone"), release::NS_RELEASE, &env.doc).unwrap();
    std::fs::write(&copy, serde_json::to_string(&env).unwrap()).unwrap();
    for _ in 0..2 {
        let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
        assert_eq!((p.went_back, p.runs.is_none()), (Some(m.serial), true));
        let text = p.lines().join("\n");
        assert!(text.contains(&format!("  Arch       as in release {} -> {}", m.serial, days_ago(1))), "{text}");
        assert!(text.contains(&format!("Compared with what the machines report: this computer has no copy of release {}.", m.serial)));
        assert!(!text.contains("Nothing changes"), "{text}");
        std::fs::remove_file(&copy).unwrap_or_default();
    }
    // An urgent release does not keep the newest's day then: the machines
    // may run a later one (seen on the VM lab: refused as a downgrade).
    let urgent = Choice { urgent: true, ..Choice::default() };
    let p = plan(&ctx, &a, &v, &days, &parts, &urgent, today()).unwrap();
    assert_ne!(p.arch_how, URGENT_DAY);
    assert_eq!(p.release.arch_date, days_ago(1));

    // Stopped at a server instead: the coordinator runs the newest, and
    // the preview compares with it.
    store
        .update(|s| {
            s.rollout = Rollout {
                serial: n.serial,
                phase: Phase::Servers,
                paused: "x".into(),
                pause: Pause::Failed,
                pause_host: 2,
                ..s.rollout.clone()
            };
            Ok(())
        })
        .unwrap();
    brain_says(&store, n.serial, "", 0);
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    assert_eq!((p.went_back, p.runs.as_ref().map(|r| r.serial)), (None, Some(n.serial)));
    let text = p.lines().join("\n");
    assert!(text.contains(&format!("Compared with release {}, the newest on the coordinator.", n.serial)), "{text}");
    // The servers it did not reach run release m still (whose copy is
    // gone here): their packages move with this one.
    let want = format!("Not on release {} yet: node-a (its Arch day not known here) and node-b (its Arch day not known here).", n.serial);
    assert!(text.contains(&want), "{text}");
}

/// The copies: kept when the upload broke off too (the release is signed
/// and may have arrived), and only the newest ones.
#[test]
fn copies_of_signed_releases_are_kept_and_few() {
    let dir = TempDir::new();
    let (mut a, _, _, fail, parts) = desk(&dir);
    let days = FakeDays::with(&[days_ago(0)]);
    let ctx = Ctx::new();
    let copies = dir.join("secrets").join(COPIES);
    fsx::mkdir_all(&copies, 0o700).unwrap();
    for s in 1..=20 {
        std::fs::write(copies.join(format!("{s}.json")), "{}").unwrap();
    }
    std::fs::write(copies.join("notes.txt"), "mine").unwrap();
    let v = a.load().unwrap();
    let p = plan(&ctx, &a, &v, &days, &parts, &Choice::default(), today()).unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(publish(&mut a, &p).is_err());
    assert_eq!(signed_copy(&a, p.release.serial).as_ref(), Some(&p.release));
    let left: Vec<String> = std::fs::read_dir(&copies).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(left.len(), KEPT_COPIES + 1, "{left:?}");
    assert!(left.contains(&"notes.txt".to_string()) && !left.contains(&"5.json".to_string()) && left.contains(&"6.json".to_string()));
    assert!(signed_copy(&a, 5).is_none() && signed_copy(&a, 0).is_none(), "not a signed release");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(copies.join(format!("{}.json", p.release.serial))).unwrap().permissions().mode() & 0o777, 0o600);
}
