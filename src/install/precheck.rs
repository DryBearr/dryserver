//! Gets the live system ready to download, checks what can be checked
//! before the disk is touched, and installs packages with retries.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{Choices, Progress, Real, Step, real::tcp_dial};
use crate::config::Config;
use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::gotime::duration_string;
use crate::runner::Cmd;
use crate::sysconf::Role;
use crate::{errf, fsx};

const CLOCK_WAIT: Duration = Duration::from_secs(60);
const MIRROR_TIMEOUT: Duration = Duration::from_secs(180);
pub(super) const KEEP_MIRRORS: usize = 10;

/// One download hiccup on WiFi should not end the install. Packages already
/// downloaded stay in the target's cache, so a new attempt continues where
/// the last one stopped.
const PACSTRAP_ATTEMPTS: u32 = 3;

/// How long a retry waits for the internet to come back.
const NETWORK_WAIT: Duration = Duration::from_secs(180);

/// Preferred mirrors: geo picks a mirror near the laptop, fastly is a
/// worldwide CDN. They go first; the live system's list is only fallback.
const PREFERRED_MIRRORS: [&str; 2] =
    ["Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch", "Server = https://fastly.mirror.pkgbuild.com/$repo/os/$arch"];

/// Resets the log sink when a step sequence ends.
pub(super) struct SinkGuard<'a>(pub &'a Real);

impl Drop for SinkGuard<'_> {
    fn drop(&mut self) {
        self.0.log.set_sink(None);
    }
}

impl Real {
    /// Sends log lines to the setup screen until the guard is dropped.
    pub(super) fn stream_to(&self, progress: &Progress) -> SinkGuard<'_> {
        let p = progress.clone();
        self.log.set_sink(Some(std::sync::Arc::new(move |l: &str| p(Step::line(l)))));
        SinkGuard(self)
    }

    pub(super) fn precheck_impl(&self, ctx: &Ctx, cfg: &Config, ch: &Choices, progress: Progress) -> Result<()> {
        let _sink = self.stream_to(&progress);
        let step = |name: &str, f: &mut dyn FnMut() -> Result<()>| -> Result<()> {
            progress(Step::start(name));
            f().map_err(|e| e.wrap(name))?;
            progress(Step::finished(name));
            Ok(())
        };

        step("Check the clock", &mut || self.sync_clock(ctx))?;
        step("Prepare package signing keys", &mut || self.wait_keyring(ctx))?;
        step("Pick package mirrors", &mut || self.trim_mirrors())?;
        step("Update package lists", &mut || {
            let c = ctx.with_timeout(MIRROR_TIMEOUT);
            match self.cmd(&c, "pacman", &["-Sy", "--noconfirm"]) {
                Ok(()) => Ok(()),
                Err(_) if c.done() && !ctx.done() => Err(errf!(
                    "the package mirrors did not answer within {}; check the internet connection",
                    duration_string(MIRROR_TIMEOUT.as_secs() as i64)
                )),
                Err(e) => Err(e.wrap("cannot reach the package mirrors")),
            }
        })?;
        let extra = cfg.extra_list();
        if !extra.is_empty() {
            step("Check extra packages", &mut || {
                let mut args = vec!["-Si"];
                args.extend(extra.iter().map(String::as_str));
                let (out, res) = self.run.run(ctx, &Cmd::new("pacman", &args).quiet());
                if res.is_err() {
                    return Err(errf!(
                        "unknown extra packages: {} (fix EXTRA_PACKAGES in the desktop config)",
                        missing_packages(&out).join(" ")
                    ));
                }
                self.log(&format!("found: {}", extra.join(" ")));
                Ok(())
            })?;
        }
        if ch.role() == Role::Node {
            // Only a warning: the server keeps asking to join after it boots.
            let _ = step("Check the coordinator", &mut || {
                match tcp_dial(&cfg.coord_lan_ip, 22, Duration::from_secs(5)) {
                    Err(e) => self.log(&format!(
                        "warning: coordinator {} does not answer ({e}). Install it first, or this server asks to join after it boots.",
                        cfg.coord_lan_ip
                    )),
                    Ok(()) => self.log(&format!("coordinator {} answers", cfg.coord_lan_ip)),
                }
                Ok(())
            });
        }
        Ok(())
    }

    /// Waits for NTP. Laptops with a dead clock battery boot with a wrong
    /// date, and then every HTTPS download fails its certificate check.
    fn sync_clock(&self, ctx: &Ctx) -> Result<()> {
        let _ = self.run.run(ctx, &Cmd::new("timedatectl", &["set-ntp", "true"]).quiet());
        let deadline = Instant::now() + CLOCK_WAIT;
        let mut next = Instant::now();
        loop {
            let (out, _) = self.run.run(ctx, &Cmd::new("timedatectl", &["show", "-p", "NTPSynchronized", "--value"]).quiet().stdout_only());
            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
            if out.trim() == "yes" {
                self.log(&format!("clock synced: {now}"));
                return Ok(());
            }
            if Instant::now() > deadline {
                self.log(&format!("warning: the clock did not sync (it says {now}); if that is wrong, downloads will fail"));
                return Ok(());
            }
            if Instant::now() > next {
                self.log(&format!("waiting for the clock to sync from the internet (it says {now})"));
                next = Instant::now() + Duration::from_secs(10);
            }
            ctx.sleep(Duration::from_secs(2))?;
        }
    }

    /// Waits for the live system's pacman-init service, which sets up the
    /// keys that verify downloaded packages.
    fn wait_keyring(&self, ctx: &Ctx) -> Result<()> {
        let deadline = Instant::now() + CLOCK_WAIT;
        loop {
            if self.run.ok(ctx, &Cmd::new("systemctl", &["is-active", "--quiet", "pacman-init.service"]).quiet()).is_ok() {
                self.log("package signing keys ready");
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err("the package signing keys were not set up (pacman-init.service); reboot from the USB".into());
            }
            ctx.sleep(Duration::from_secs(2))?;
        }
    }

    /// Puts the preferred mirrors first and keeps a few fallbacks from the
    /// live system's list. That list has hundreds of entries in alphabetical
    /// country order, and pacman walks all of them when the network is bad,
    /// which looks like a hang.
    fn trim_mirrors(&self) -> Result<()> {
        let text = fsx::read_string(&self.mirror_list)?;
        let mut servers: Vec<String> = PREFERRED_MIRRORS.iter().map(|s| s.to_string()).collect();
        for l in text.split('\n') {
            let l = l.trim();
            if l.starts_with("Server") && !servers.iter().any(|s| s == l) && servers.len() < KEEP_MIRRORS {
                servers.push(l.to_string());
            }
        }
        let out = format!("# dryserver: nearby and CDN mirrors first, a few fallbacks after.\n{}\n", servers.join("\n"));
        fsx::write_file(&self.mirror_list, out, 0o644)?;
        let first = servers[0].split_once('=').map(|(_, v)| v.trim()).unwrap_or("");
        self.log(&format!("using {} mirrors, first: {first}", servers.len()));
        Ok(())
    }

    /// Logs how much pacstrap has downloaded, every few seconds, until stop
    /// is set: pacman prints nothing while downloading when it has no
    /// terminal.
    pub(super) fn report_downloads(&self, stop: &AtomicBool, every: Duration) {
        let cache = self.target("/var/cache/pacman/pkg");
        let mut last = 0u64;
        loop {
            let until = Instant::now() + every;
            while Instant::now() < until {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let size = dir_size(&cache);
            if size == last {
                continue;
            }
            last = size;
            // MiB like pacman's "Total Download Size".
            let mut msg = format!("downloaded {:.1} MiB", size as f64 / (1u64 << 20) as f64);
            let total = self.log.dl_total();
            if !total.is_empty() {
                msg += &format!(" of {total}");
            }
            self.log(&msg);
        }
    }

    /// Waits until the package mirrors can be reached, so a retry does not
    /// run (and fail) while WiFi is still down.
    fn wait_network(&self, ctx: &Ctx, limit: Duration) -> Result<()> {
        let check = |ctx: &Ctx| match &self.net_check {
            Some(f) => f(ctx),
            None => super::real::tcp_answers("geo.mirror.pkgbuild.com", 443, Duration::from_secs(4)),
        };
        let deadline = Instant::now() + limit;
        let mut logged = false;
        while !check(ctx) {
            if Instant::now() > deadline {
                return Err(errf!(
                    "the internet did not come back within {}; check WiFi, then press r to retry",
                    duration_string(limit.as_secs() as i64)
                ));
            }
            if !logged {
                self.log("waiting for the network to come back");
                logged = true;
            }
            ctx.sleep(self.net_poll)?;
        }
        Ok(())
    }

    /// Installs the packages into the target, retrying on failure. A
    /// signature problem first refreshes the live system's signing keys.
    pub(super) fn pacstrap(&self, ctx: &Ctx, pkgs: &[String]) -> Result<()> {
        let target = self.target.display().to_string();
        let mut args = vec!["-K".to_string(), target];
        args.extend(pkgs.iter().cloned());
        let mut out = String::new();
        let mut last: Option<Error> = None;
        for attempt in 1..=PACSTRAP_ATTEMPTS {
            if attempt > 1 {
                self.log(&format!(
                    "package install failed ({}); trying again, attempt {attempt} of {PACSTRAP_ATTEMPTS}",
                    pacman_problem(&out)
                ));
                self.wait_network(ctx, NETWORK_WAIT)?;
                if signature_problem(&out) {
                    self.log("updating the package signing keys first");
                    let _ = self.cmd(ctx, "pacman", &["-Sy", "--noconfirm", "archlinux-keyring"]);
                }
            }
            let (o, res) = self.run.run(ctx, &Cmd::new("pacstrap", &args));
            out = o;
            match res {
                Ok(()) => return Ok(()),
                Err(e) if ctx.done() => return Err(e),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap().wrap(format!("{} (after {PACSTRAP_ATTEMPTS} attempts)", pacman_problem(&out))))
    }
}

fn dir_size(p: &Path) -> u64 {
    let Ok(ents) = std::fs::read_dir(p) else {
        return 0;
    };
    ents.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(_) => e.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => 0,
        })
        .sum()
}

/// The names in "package 'X' was not found" lines.
fn missing_packages(out: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = out;
    while let Some(i) = rest.find("package '") {
        let after = &rest[i + "package '".len()..];
        match after.find('\'') {
            Some(j) if j > 0 && after[j..].starts_with("' was not found") => {
                found.push(after[..j].to_string());
                rest = &after[j..];
            }
            Some(j) => rest = &after[j..],
            None => break,
        }
    }
    found
}

pub(super) fn signature_problem(out: &str) -> bool {
    // Specific pacman error texts only: package names like
    // "archlinux-keyring" appear in every package list.
    ["PGP signature", "unknown trust", "invalid signature", "signature from", "keyring is not writable", "public key not found"]
        .iter()
        .any(|s| out.contains(s))
}

/// Turns pacman's output into a short explanation.
pub(super) fn pacman_problem(out: &str) -> &'static str {
    let has = |l: &[&str]| l.iter().any(|s| out.contains(s));
    if out.contains("No space left") {
        "the disk is full"
    } else if signature_problem(out) {
        "package signatures could not be checked (wrong clock or outdated signing keys)"
    } else if has(&["failed to retrieve some files", "failed retrieving file", "Operation too slow", "Could not resolve host"]) {
        "downloads failed; the network may be unstable (move closer to the router or use a cable)"
    } else if has(&["conflicting files", "could not satisfy dependencies", "are in conflict"]) {
        "packages conflict; check EXTRA_PACKAGES in the config"
    } else {
        "pacman failed; see the log"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::Backend;
    use crate::runner::Runner;
    use crate::testutil::TempDir;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CheckRunner {
        cmds: Mutex<Vec<Cmd>>,
        /// A package pacman -Si does not know.
        missing: String,
    }

    impl Runner for CheckRunner {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            self.cmds.lock().unwrap().push(c.clone());
            if c.name == "timedatectl" && c.args[0] == "show" {
                return ("yes\n".into(), Ok(()));
            }
            if c.name == "pacman" && c.args[0] == "-Si" && !self.missing.is_empty() {
                return (format!("error: package '{}' was not found\n", self.missing), Err("exit status 1".into()));
            }
            (String::new(), Ok(()))
        }
    }

    fn precheck_real(missing: &str) -> (TempDir, Real, Arc<CheckRunner>) {
        let dir = TempDir::new();
        let mut list = String::from("# mirrors\n");
        for i in 0..50u8 {
            list += &format!("Server = https://mirror{}.example/$repo/os/$arch\n", (b'a' + i % 26) as char);
        }
        let ml = dir.join("mirrorlist");
        std::fs::write(&ml, list).unwrap();
        let cr = Arc::new(CheckRunner { missing: missing.into(), ..CheckRunner::default() });
        let mut r = Real::new(Config::default(), Default::default(), "", "");
        r.run = cr.clone();
        r.mirror_list = ml;
        (dir, r, cr)
    }

    #[test]
    fn precheck_steps_and_logs() {
        let (_dir, r, cr) = precheck_real("");
        let cfg = Config { coord_lan_ip: "192.0.2.1".into(), extra_packages: "python".into(), ..Config::default() }; // TEST-NET: never answers
        let seen: Arc<Mutex<(Vec<String>, Vec<String>)>> = Arc::default();
        let s = seen.clone();
        let progress: Progress = Arc::new(move |st: Step| {
            let mut g = s.lock().unwrap();
            if !st.log.is_empty() {
                g.1.push(st.log);
            } else if st.done {
                g.0.push(st.name);
            }
        });
        r.precheck(&Ctx::new(), &cfg, &Choices { role: Some(Role::Node), ..Choices::default() }, progress).unwrap();
        let (steps, logs) = seen.lock().unwrap().clone();
        assert_eq!(
            steps.join(","),
            "Check the clock,Prepare package signing keys,Pick package mirrors,Update package lists,Check extra packages,Check the coordinator"
        );
        let all = logs.join("\n");
        for w in ["clock synced", "package signing keys ready", "using 10 mirrors", "warning: coordinator 192.0.2.1 does not answer"] {
            assert!(all.contains(w), "log missing {w:?}:\n{all}");
        }
        let b = std::fs::read_to_string(&r.mirror_list).unwrap();
        assert_eq!(b.matches("Server =").count(), KEEP_MIRRORS);
        assert!(b.split_once('\n').unwrap().1.starts_with("Server = https://geo.mirror.pkgbuild.com/"), "geo mirror must come first:\n{b}");
        let pacman: Vec<String> = cr.cmds.lock().unwrap().iter().filter(|c| c.name == "pacman").map(|c| c.to_string()).collect();
        assert_eq!(pacman.len(), 2, "{pacman:?}");
        assert_eq!(pacman[0], "pacman -Sy --noconfirm");
    }

    #[test]
    fn precheck_unknown_package() {
        let (_dir, r, _) = precheck_real("pyhton");
        let cfg = Config { extra_packages: "pyhton".into(), ..Config::default() };
        let err =
            r.precheck(&Ctx::new(), &cfg, &Choices { role: Some(Role::Coordinator), ..Choices::default() }, Arc::new(|_| {})).unwrap_err();
        assert!(err.to_string().contains("unknown extra packages: pyhton"), "{err}");
    }

    #[test]
    fn pacman_problems() {
        let list = "Packages (238) acl-2.4.0-1  archlinux-keyring-20260909-1  attr-2.6.0-1\n";
        for (out, want) in [
            (
                format!(
                    "{list}error: failed retrieving file 'x' from m : Could not resolve host: m\nerror: failed to commit transaction (failed to retrieve some files)"
                ),
                "downloads failed",
            ),
            (format!("{list}error: x: signature from \"A\" is unknown trust"), "signatures"),
            (format!("{list}error: failed to commit transaction (conflicting files)"), "packages conflict"),
        ] {
            assert!(pacman_problem(&out).contains(want), "{out}");
        }
        assert!(
            !signature_problem(&format!("{list}error: failed to retrieve some files")),
            "a package list mentioning archlinux-keyring is not a signature problem"
        );
        assert_eq!(missing_packages("error: package 'a' was not found\nerror: package 'b-c' was not found\n"), vec!["a", "b-c"]);
    }
}
