use super::*;
use crate::admin::Link;
use crate::admin::tests::{Direct, setup, static_binary};
use crate::err::Error;
use crate::gotime::Time;
use crate::registry::{Heartbeat, Store};
use crate::report::Report;
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
        "./dryserver build",
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

    // The next one compares with it. Nothing changes but the urgency.
    let urgent = Choice { urgent: true, ..Choice::default() };
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
        e.contains(&format!("release {} is signed and kept on this computer, but did not reach the coordinator", p.release.serial)),
        "{e}"
    );
    assert!(e.contains("Connection timed out") && e.contains("Nothing changed on the machines"), "{e}");
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
