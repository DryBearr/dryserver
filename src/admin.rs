//! The admin's side of approval, on the desktop. `dryserver approve`
//! shows the machines waiting to join and the members, and every decision
//! is signed here with secrets/signing_ed25519 before it goes to the
//! coordinator. The coordinator stores and hands out the signed list; it
//! cannot change it.
//!
//! What the coordinator sends is treated as a claim: entries are checked,
//! pairing codes are computed here, and members that are on the
//! coordinator but not in the list this desktop signed are shown as such.
//!
//! Releases go the same way (`dryserver release publish`): signed here,
//! uploaded with their binaries, and rolled out by the coordinator.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::err::{Error, Result};
use crate::gotime::Time;
use crate::registry::{self, AdminState, Device, Member, Request};
use crate::release::{self, Release};
use crate::rollout::{self, Rollout};
use crate::signed::{self, Entry, Envelope, List, Signer, Verifier, key_body};
use crate::{bail, errf, fsx, sysconf};

/// This desktop's copy of the last list it signed, in secrets/. Versions
/// continue from it even if the coordinator forgets or lies, and it is the
/// backup of who is in the mesh.
pub const SIGNED_COPY: &str = "members.signed.json";
/// This desktop's copy of the last release it signed, in secrets/: serials
/// continue from it.
pub const RELEASE_COPY: &str = "release.signed.json";
/// Further apart than this, the coordinator's clock is called off.
const CLOCK_OFF: i64 = 120;
/// The coordinator's SSH host key as first seen from this desktop.
pub const KNOWN_HOSTS: &str = "coordinator_known_hosts";
/// By WireGuard key, the LAN address in the newest report each member
/// signed itself, in secrets/. A member that signed once is never taken
/// unsigned again, and its `NAME.lan` (the kill switch's way in) stays
/// where it said it is, whatever the registry account says.
pub const SIGNERS: &str = "report-signers.json";
/// After this long, a list the coordinator has not applied is called out.
pub const RECEIPT_LAG: i64 = 180;
/// A receipt older than this says the coordinator's sync does not run (it
/// makes one at least every five minutes), or the registry holds them.
pub const RECEIPT_OLD: i64 = 900;
/// Host numbers of members this desktop removed, oldest first, in
/// secrets/. A new machine gets none of them while another is free:
/// servers that cut a removed machine off (quarantine) drop its mesh
/// address, and would drop the new one's with it.
pub const RETIRED: &str = "retired-hosts.json";

/// A way to run one registry command on the coordinator.
pub trait Link: Send {
    /// Runs one registry command. Fails with Kind::HostKey when the machine
    /// at the coordinator's address has another SSH key than the pinned one.
    fn call(&self, command: &str, stdin: &str) -> Result<String>;
    /// Like call, with header and then the files, whole, as its input: a
    /// release and its binaries.
    fn upload(&self, command: &str, header: &str, files: &[&Path]) -> Result<String>;
    /// The coordinator's SSH host key ("type base64") that this desktop
    /// pinned on first contact.
    fn host_key(&self) -> Result<String>;
    /// The SSH host key of whatever answers at the coordinator's address
    /// now. Nothing vouches for it.
    fn scan_host_key(&self) -> Result<String>;
    /// Replaces the pinned host key ("" removes it).
    fn repin(&self, key: &str) -> Result<()>;
}

/// The registry over SSH, with the key from secrets/ that every machine
/// uses to ask to join. That key proves nothing; admin and publish are
/// authorized by the signature in their input.
pub struct SshLink {
    pub key: PathBuf,
    pub known_hosts: PathBuf,
    pub host: String,
    pub port: String,
}

impl SshLink {
    /// Everything about how to reach the coordinator, before the target.
    fn options(&self) -> Vec<String> {
        let port = if self.port.is_empty() { "22" } else { &self.port };
        let mut o: Vec<String> = vec!["-i".into(), self.key.display().to_string(), "-p".into(), port.into()];
        for opt in [
            "BatchMode=yes",
            "ConnectTimeout=5",
            "IdentitiesOnly=yes",
            "HostKeyAlgorithms=ssh-ed25519",
            "StrictHostKeyChecking=accept-new",
            "HashKnownHosts=no",
            "GlobalKnownHostsFile=/dev/null",
            "LogLevel=ERROR",
            "ForwardAgent=no",
            "ProxyJump=none",
        ] {
            o.extend(["-o".into(), opt.into()]);
        }
        o.extend(["-o".into(), format!("UserKnownHostsFile={}", self.known_hosts.display())]);
        o
    }

    /// Where the shared connection's socket goes: a directory of this
    /// user's alone in the user's runtime directory (fsx::socket_dir).
    /// None without one (then every call connects). Signed lists and
    /// releases go through that socket, and what answers on it speaks for
    /// the coordinator: one that someone else could put there is never
    /// used.
    fn control_path(&self, runtime_dir: Option<&std::ffi::OsStr>) -> Option<String> {
        fsx::control_path(runtime_dir, &self.socket_name())
    }

    /// The socket's name. It carries which key file and which pinned host
    /// key file the connection was made with. A connection is checked
    /// against the pinned key once, when it is made: one made from another
    /// directory (another stick's secrets) must never be reused here.
    fn socket_name(&self) -> String {
        format!("reg-%C-{:016x}", fsx::paths_id(&[&self.key, &self.known_hosts]))
    }

    /// The host as known_hosts writes it.
    fn known_name(&self) -> String {
        if self.port.is_empty() || self.port == "22" { self.host.clone() } else { format!("[{}]:{}", self.host, self.port) }
    }
}

/// At most one try to start the shared connection per half minute,
/// whatever the check says: a second guard against piling up connections.
fn master_due() -> bool {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) {
        return false;
    }
    *last = Some(Instant::now());
    true
}

impl Link for SshLink {
    fn call(&self, command: &str, stdin: &str) -> Result<String> {
        use std::io::Write;
        let text = stdin.to_string();
        self.run(command, move |pipe| {
            let _ = pipe.write_all(text.as_bytes());
        })
    }

    fn upload(&self, command: &str, header: &str, files: &[&Path]) -> Result<String> {
        use std::io::Write;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        // Opened before connecting: a file that is not there is this
        // computer's problem, said as such.
        let mut opened = Vec::new();
        let mut total = header.len() as u64;
        for p in files {
            let f = std::fs::File::open(p).map_err(|e| Error::from(e).wrap(format!("open {}", p.display())))?;
            total += f.metadata().map(|m| m.len()).unwrap_or(0);
            opened.push(f);
        }
        let head = header.to_string();
        let sent = Arc::new(AtomicU64::new(0));
        let counter = sent.clone();
        let res = self.run(command, move |pipe| {
            let mut w = Counted { inner: pipe, n: &counter };
            if w.write_all(head.as_bytes()).is_err() {
                return;
            }
            for mut f in opened {
                if std::io::copy(&mut f, &mut w).is_err() {
                    return;
                }
            }
        });
        let sent = sent.load(Ordering::SeqCst);
        match res {
            Err(e) => Err(cut_off(e, sent, total)),
            // The registry reads every byte of an upload before it answers.
            Ok(_) if sent < total => Err(cut_off(Error::new("the coordinator answered before the upload was whole"), sent, total)),
            ok => ok,
        }
    }

    fn host_key(&self) -> Result<String> {
        let text = fsx::read_string(&self.known_hosts).map_err(|e| e.wrap("the coordinator's SSH key is not recorded yet"))?;
        let name = self.known_name();
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 3 && f[1] == "ssh-ed25519" && f[0].split(',').any(|h| h == name) {
                return Ok(format!("{} {}", f[1], f[2]));
            }
        }
        bail!("the coordinator's SSH key is not recorded in {}", self.known_hosts.display())
    }

    fn scan_host_key(&self) -> Result<String> {
        let port = if self.port.is_empty() { "22" } else { &self.port };
        let out = Command::new("ssh-keyscan")
            .args(["-t", "ed25519", "-T", "5", "-p", port, &self.host])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| Error::from(e).wrap("ssh-keyscan"))?;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 3 && f[1] == "ssh-ed25519" && f[2].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')) {
                return Ok(format!("{} {}", f[1], f[2]));
            }
        }
        bail!("no SSH server answers at {}", self.host)
    }

    fn repin(&self, key: &str) -> Result<()> {
        if key.is_empty() {
            return match std::fs::remove_file(&self.known_hosts) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(Error::from(e).wrap(format!("remove {}", self.known_hosts.display())))
                }
                _ => Ok(()),
            };
        }
        let tmp = PathBuf::from(format!("{}.tmp", self.known_hosts.display()));
        fsx::write_new(&tmp, format!("{} {}\n", self.known_name(), key_body(key)), 0o600)?;
        fsx::rename(&tmp, &self.known_hosts)
    }
}

impl SshLink {
    /// Runs one registry command; feed writes its input from a thread of
    /// its own, so a large input never waits on the output.
    fn run(&self, command: &str, feed: impl FnOnce(&mut std::process::ChildStdin) + Send + 'static) -> Result<String> {
        let target = format!("{}@{}", sysconf::REGISTRY_USER, self.host);
        let mut cmd = Command::new("ssh");
        cmd.args(self.options());
        // One connection for the whole session: the approval screen asks
        // every few seconds, and the coordinator's firewall lets one
        // address open only 10 SSH connections a minute. The connection is
        // held by a master in the background, started with nothing
        // attached: one that inherits our pipes would keep every call
        // waiting until it exits. Without a master the call connects by
        // itself and reports what is wrong.
        if let Some(ctl) = self.control_path(std::env::var_os("XDG_RUNTIME_DIR").as_deref()) {
            let quiet =
                |c: &mut Command| c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
            // The check and the master get the same options. The socket's
            // name (%C) is made from host, port and user: a check that
            // looks under another name never finds the master, and every
            // call would leave one more connection that never ends.
            let mux = |extra: &[&str]| {
                let mut c = Command::new("ssh");
                c.args(self.options()).args(["-o", &ctl]).args(extra).arg(&target);
                c
            };
            if !quiet(&mut mux(&["-O", "check"])) && master_due() {
                quiet(&mut mux(&["-M", "-N", "-f", "-o", "ControlPersist=20"]));
            }
            cmd.args(["-o", "ControlMaster=no", "-o", &ctl]);
        }
        let mut child = cmd
            .arg(&target)
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::from(e).wrap("ssh"))?;
        let mut pipe = child.stdin.take().ok_or_else(|| Error::new("ssh: no stdin"))?;
        // The pipe closes when the thread ends: the coordinator sees the
        // end of the input. ssh may end first (the coordinator refused
        // early, the connection broke): the feed then fails, it does not
        // end this program.
        let writer = std::thread::spawn(move || {
            quiet_broken_pipe();
            feed(&mut pipe)
        });
        let out = bounded_output(child, MAX_ANSWER);
        let _ = writer.join();
        let out = out?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        // The coordinator's words: never raw onto the admin's terminal.
        let msg = clean(String::from_utf8_lossy(&out.stderr).trim(), 300);
        if msg.contains("Host key verification failed") || msg.contains("HOST IDENTIFICATION HAS CHANGED") {
            return Err(Error::with_kind(
                crate::err::Kind::HostKey,
                format!(
                    "the machine at {} does not have the SSH key this computer saw before. Either the coordinator was \
                     reinstalled, or something else answers at its address. Nothing was sent.",
                    self.host
                ),
            ));
        }
        if out.status.code() == Some(255) {
            bail!("cannot reach the coordinator at {}: {}", self.host, msg.lines().last().unwrap_or("no answer"));
        }
        // The registry's own error, e.g. "dryserver: this list is not newer".
        Err(errf!("the coordinator refused: {}", msg.trim_start_matches("dryserver: ")))
    }
}

/// Makes a write to a pipe whose reader is gone fail with "broken pipe"
/// in this thread, instead of ending the whole program: main lets
/// SIGPIPE end it (quietly, for `| head`), and ssh can end while a
/// release of tens of MiB is still being fed to it. A SIGPIPE blocked
/// here stays with this thread and goes when the thread ends.
fn quiet_broken_pipe() {
    // SAFETY: changes only this thread's signal mask, with a set made here.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGPIPE);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// A writer that counts what went through it.
struct Counted<'a, W: std::io::Write> {
    inner: &'a mut W,
    n: &'a std::sync::atomic::AtomicU64,
}

impl<W: std::io::Write> std::io::Write for Counted<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.n.fetch_add(k as u64, std::sync::atomic::Ordering::SeqCst);
        Ok(k)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// An upload's failure, with how far it got when it did not go out whole.
/// The coordinator keeps nothing of an upload that did not arrive whole.
fn cut_off(e: Error, sent: u64, total: u64) -> Error {
    if sent >= total || e.is(crate::err::Kind::HostKey) {
        return e;
    }
    let got = if sent == 0 {
        "nothing of the upload went out".to_string()
    } else {
        format!("the upload stopped after {} of {}", crate::report::size(sent), crate::report::size(total))
    };
    errf!("{e} ({got}; the coordinator keeps nothing of an upload that did not arrive whole)")
}

/// The most the coordinator may answer one registry command with. Its
/// largest answer, the admin's view of every member with its report, is
/// far below this.
const MAX_ANSWER: u64 = 16 << 20;

/// Waits for child, keeping at most max bytes of what it prints and 64 KiB
/// of its errors. More than max is an error, and the child is killed: what
/// the coordinator sends never fills this computer's memory.
fn bounded_output(mut child: std::process::Child, max: u64) -> Result<std::process::Output> {
    use std::io::Read;
    let mut err_pipe = child.stderr.take().ok_or_else(|| Error::new("ssh: no stderr"))?;
    let errs = std::thread::spawn(move || {
        let mut kept = Vec::new();
        let _ = (&mut err_pipe).take(64 << 10).read_to_end(&mut kept);
        let _ = std::io::copy(&mut err_pipe, &mut std::io::sink());
        kept
    });
    let mut stdout = Vec::new();
    let read = match child.stdout.take() {
        Some(mut pipe) => (&mut pipe).take(max + 1).read_to_end(&mut stdout).map(|_| ()),
        None => Ok(()),
    };
    let too_long = stdout.len() as u64 > max;
    if too_long {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|e| Error::from(e).wrap("ssh"))?;
    let stderr = errs.join().unwrap_or_default();
    if too_long {
        bail!("the coordinator's answer is longer than {} MiB; not taken", max >> 20);
    }
    read.map_err(|e| Error::from(e).wrap("read from ssh"))?;
    Ok(std::process::Output { status, stdout, stderr })
}

/// Text from the coordinator made safe to print: no control characters
/// (a terminal would obey them), and not longer than max.
fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// A scan-report entry is shown only with a real address; its other fields
/// are cut down to plain text.
fn clean_device(d: Device) -> Option<Device> {
    let ip = crate::cidr::parse_ip4(&d.ip)?.to_string();
    let mac: String = d.mac.chars().filter(|c| c.is_ascii_hexdigit() || *c == ':').take(17).collect();
    let vendor: String = d.vendor.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(40).collect();
    Some(Device { ip, mac, vendor, ..d })
}

/// What the approval screen shows.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// Waiting requests, with pairing codes computed on this desktop.
    pub pending: Vec<Request>,
    /// IDs of waiting requests without a valid proof from the USB stick's
    /// join secret. They cannot be approved.
    pub unproved: Vec<String>,
    /// Members on the coordinator, and whether this desktop signed them.
    pub members: Vec<(Member, bool)>,
    pub unknown: Vec<Device>,
    pub scanned: Time,
    /// Version of the newest valid signed list; 0 when nothing is signed.
    pub version: u64,
    /// The coordinator's own pairing code, shown on its screen after its
    /// install: compared before the first signature.
    pub coordinator_code: String,
    pub warnings: Vec<String>,
    /// Cuts the members reported: who cut whom off.
    pub reports: Vec<String>,
    /// The newest release on the coordinator, its signature checked here.
    pub release: Option<Release>,
    /// Its rollout, as the coordinator tells it.
    pub rollout: Rollout,
    /// The coordinator's clock, unix seconds (0: an older one).
    pub coordinator_now: i64,
    /// What the newest signed list says beyond its members: who else may
    /// log in, the VPN and its devices.
    pub people: Vec<signed::Person>,
    pub vpn: Option<crate::vpn::Plan>,
    pub devices: Vec<crate::vpn::Device>,
    /// The signed machines, with the LAN address each one signed itself.
    pub servers: Vec<crate::mesh::Server>,
    /// The gateway's WireGuard key as the signed list has it ("" without
    /// a VPN): the one devices check it by.
    pub gateway_key: String,
}

/// A machine at the coordinator's address with other keys than the ones
/// this desktop knew: what it says it is. Nothing has been changed yet.
#[derive(Debug, Clone, PartialEq)]
pub struct NewCoordinator {
    pub name: String,
    /// The code its screen must show.
    pub code: String,
    entry: Entry,
    /// The pin to put back when the admin says no.
    old_pin: String,
}

impl View {
    pub fn unsigned(&self) -> Vec<String> {
        self.members.iter().filter(|(_, s)| !s).map(|(m, _)| m.name.clone()).collect()
    }

    /// Members on the coordinator that the next signature would drop
    /// because they are not in the signed list, except those in keep.
    pub fn would_drop(&self, keep: &[&str]) -> Vec<String> {
        self.members.iter().filter(|(m, s)| m.host != 1 && !s && !keep.contains(&m.name.as_str())).map(|(m, _)| m.name.clone()).collect()
    }
}

pub struct Admin {
    pub link: Box<dyn Link>,
    pub signer: Box<dyn Signer>,
    pub verifier: Box<dyn Verifier>,
    /// The desktop's secrets directory.
    pub secrets: PathBuf,
    pub subnet: String,
    pub now: fn() -> Time,
    /// The newest valid signed list (version 0, empty: none yet).
    base: List,
    /// The coordinator's members and requests, as last loaded and checked.
    members: Vec<Member>,
    pending: Vec<Request>,
    unproved: Vec<String>,
    /// The coordinator showed the proof that it was installed from the
    /// admin's stick, for the keys it has now.
    coordinator_proved: bool,
    /// The newest release on the coordinator, verified, as last loaded.
    release: Option<Release>,
    /// That release as the coordinator holds it, signed: replace-key signs
    /// its text again with the new key.
    release_env: Option<Envelope>,
    /// When that one failed on the coordinator and went back, the release
    /// the machines run instead (rollout::went_back), as last loaded.
    went_back: Option<u64>,
    /// Where the rollout stopped, as last loaded: its release and the
    /// host (0: the coordinator's own update). A resume or a skip names
    /// it, and the coordinator carries out only an ask for its own stop.
    stop: Option<(u64, u32)>,
    /// Runs ssh-keygen for the checks of the machines' own signatures
    /// (reports, the coordinator's receipt).
    pub run: std::sync::Arc<dyn crate::runner::Runner>,
    /// LAN addresses from the members' signed reports (SIGNERS), as last
    /// loaded.
    lans: std::collections::BTreeMap<String, String>,
    /// Digests of the signatures that checked out (key, namespace, text,
    /// signature): the screen loads every few seconds, and the same report
    /// is checked once.
    good: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

/// What replace_key did.
#[derive(Debug, Clone, PartialEq)]
pub struct Replaced {
    /// The list that carries the change.
    pub version: u64,
    /// The release signed again with the new key.
    pub release: Option<u64>,
    /// What did not work but changes nothing about the key.
    pub warning: Option<String>,
}

/// Whether a release is still rolling out: the coordinator updates
/// itself, waits for the window, failed, or a server has it to come.
fn rollout_busy(r: &Rollout, members: &[(Member, bool)]) -> bool {
    match r.phase {
        rollout::Phase::None => false,
        rollout::Phase::Waiting | rollout::Phase::Brain | rollout::Phase::Failed => true,
        rollout::Phase::Servers => {
            members.iter().any(|(m, _)| m.host != 1 && !r.done.contains(&m.host) && !r.skipped.iter().any(|s| s.host == m.host))
        }
    }
}

impl Admin {
    pub fn new(link: Box<dyn Link>, signer: Box<dyn Signer>, verifier: Box<dyn Verifier>, secrets: &Path, subnet: &str) -> Admin {
        Admin {
            link,
            signer,
            verifier,
            secrets: secrets.to_path_buf(),
            subnet: subnet.into(),
            now: Time::now,
            base: List::default(),
            members: Vec::new(),
            pending: Vec::new(),
            unproved: Vec::new(),
            coordinator_proved: false,
            release: None,
            release_env: None,
            went_back: None,
            stop: None,
            run: std::sync::Arc::new(crate::runner::ExecRunner::silent()),
            lans: Default::default(),
            good: Default::default(),
        }
    }

    /// signed::host_verify, remembering what checked out.
    fn host_verify(&self, key: &str, namespace: &str, text: &str, sig: &str) -> Result<()> {
        let id = fsx::hex(&<sha2::Sha256 as sha2::Digest>::digest(format!("{key}\n{namespace}\n{text}\n{sig}").as_bytes()));
        if self.good.borrow().contains(&id) {
            return Ok(());
        }
        signed::host_verify(&crate::ctx::Ctx::new(), self.run.as_ref(), &std::env::temp_dir(), key, namespace, text, sig)?;
        let mut good = self.good.borrow_mut();
        if good.len() > 1024 {
            good.clear();
        }
        good.insert(id);
        Ok(())
    }

    /// The members' signed LAN addresses (SIGNERS).
    fn signers(&self) -> std::collections::BTreeMap<String, String> {
        serde_json::from_str(&fsx::read_or_empty(self.secrets.join(SIGNERS))).unwrap_or_default()
    }

    /// Checks what each member says about itself against its own host key
    /// in the list this desktop signed: the registry account relays it. A
    /// report that does not check out is dropped, with a warning; one that
    /// is not signed is kept, named, as the word of a server of an older
    /// version, unless that member has signed one before.
    fn check_reports(&mut self, members: &mut [Member], warnings: &mut Vec<String>) {
        let was = self.signers();
        let mut lans = was.clone();
        let (mut unsigned, mut forged) = (Vec::new(), Vec::new());
        for m in members.iter_mut() {
            let Some(e) = self.base.members.iter().find(|e| e.matches(m)) else { continue };
            let Some(r) = &m.report else { continue };
            if r.sig.is_empty() {
                if was.contains_key(&m.wg_key) {
                    forged.push(m.name.clone());
                    m.report = None;
                } else {
                    unsigned.push(m.name.clone());
                }
                continue;
            }
            match self.host_verify(&e.ssh_host_key, signed::NS_REPORT, &r.signed_text(e.host, &e.wg_key), &r.sig) {
                Ok(()) => {
                    lans.insert(m.wg_key.clone(), r.lan.clone());
                }
                Err(_) => {
                    forged.push(m.name.clone());
                    m.report = None;
                }
            }
        }
        lans.retain(|k, _| self.base.members.iter().any(|e| e.wg_key == *k));
        if lans != was {
            let path = self.secrets.join(SIGNERS);
            let tmp = PathBuf::from(format!("{}.tmp", path.display()));
            let _ = std::fs::remove_file(&tmp);
            let saved = serde_json::to_string(&lans)
                .map_err(Error::from)
                .and_then(|t| fsx::write_new(&tmp, t + "\n", 0o600))
                .and_then(|_| fsx::rename(&tmp, &path));
            if let Err(e) = saved {
                warnings.push(format!("Cannot keep the members' signed addresses in {}: {e}", path.display()));
            }
        }
        if !forged.is_empty() {
            warnings.push(format!(
                "Not signed by the machine it is about, so not shown: the report of {}. The coordinator's registry account may \
                 be broken into.",
                forged.join(", ")
            ));
        }
        if !unsigned.is_empty() {
            warnings.push(format!(
                "Unsigned report (a dryserver from before reports were signed): {}. What it says about itself is the \
                 coordinator's word until it updates.",
                unsigned.join(", ")
            ));
        }
        self.lans = lans;
    }

    /// Whether the coordinator applied the list this desktop signed last,
    /// by its receipt, checked against the coordinator's key in that list;
    /// a warning when it did not, RECEIPT_LAG after the signature.
    fn check_receipt(&self, r: &registry::Receipt, now: i64) -> Option<String> {
        let coord = self.base.members.iter().find(|e| e.host == 1)?;
        let signed_at = std::fs::metadata(self.copy_path())
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(now, |d| d.as_secs() as i64);
        let late = now - signed_at > RECEIPT_LAG;
        let v = self.base.version;
        let removed = "A server you removed may still be in its mesh and its cluster: cut it off with \
                       dryserver quarantine-all -name NAME.";
        if r.is_empty() {
            return late.then(|| {
                format!(
                    "The coordinator has sent no receipt for the list you signed (version {v}): it is older than this \
                     dryserver, or its registry account holds the receipt back. Nothing shows that it applied your last \
                     change. {removed}"
                )
            });
        }
        let text = registry::Receipt::text(r.version, &r.sha256, r.time);
        if self.host_verify(&coord.ssh_host_key, signed::NS_RECEIPT, &text, &r.sig).is_err() {
            return Some(format!(
                "The coordinator's receipt for the list it follows is not signed by the coordinator you signed: its \
                 registry account may be broken into. {removed}"
            ));
        }
        let sha = std::fs::read(self.copy_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<Envelope>(&b).ok())
            .map(|e| fsx::hex(&<sha2::Sha256 as sha2::Digest>::digest(e.doc.as_bytes())));
        if r.version < v && late {
            let ago = crate::report::short_age((now - signed_at).max(0) as u64);
            return Some(format!(
                "The coordinator has not applied list version {v}, which you signed {ago} ago: it follows version {}. Its \
                 registry account may be holding your list back. {removed}",
                r.version
            ));
        }
        if r.version == v && sha.is_some_and(|s| s != r.sha256) {
            return Some(format!("The coordinator follows another list under version {v} than the one you signed. {removed}"));
        }
        if now - r.time > RECEIPT_OLD && late {
            let ago = crate::report::short_age((now - r.time).max(0) as u64);
            return Some(format!(
                "The coordinator's newest receipt is {ago} old: its sync does not run, or its registry account holds its \
                 receipts back. Whether it follows your list is not known."
            ));
        }
        None
    }

    /// The join secret installers used, from secrets/.
    fn join_secret(&self) -> Result<String> {
        let path = self.secrets.join(crate::iso::JOIN_SECRET);
        let s = fsx::read_string(&path).map_err(|e| e.wrap("no join secret; it is created when you build the USB stick"))?;
        if s.trim().len() < 32 {
            bail!("{} is damaged", path.display());
        }
        Ok(s)
    }

    fn fits(&self, host: u32) -> bool {
        !crate::mesh::ip(&self.subnet, host).is_empty()
    }

    fn copy_path(&self) -> PathBuf {
        self.secrets.join(SIGNED_COPY)
    }

    fn save_copy(&self, env: &Envelope) -> Result<()> {
        let path = self.copy_path();
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        fsx::write_new(&tmp, serde_json::to_string(env)? + "\n", 0o600)?;
        fsx::rename(&tmp, &path)
    }

    /// Fetches the coordinator's state and compares it with what this
    /// desktop signed.
    pub fn load(&mut self) -> Result<View> {
        let ask = serde_json::to_string(&signed::seal_admin(self.signer.as_ref(), "state", (self.now)().0.timestamp())?)?;
        let out = match self.link.call("admin", &ask) {
            Ok(out) => out,
            Err(e) => self.after_refused_ask(e, &ask)?,
        };
        let st: AdminState = serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("the coordinator's answer"))?;
        let mut v = View { unknown: st.unknown.into_iter().filter_map(clean_device).collect(), scanned: st.scanned, ..View::default() };
        let coord_key = self.link.host_key()?;
        let now = (self.now)().0.timestamp();

        // The release: only what the admin's signature covers is shown.
        self.release = None;
        self.release_env = None;
        // A key change on another computer: taken on before anything else
        // is checked, which then goes by the new key.
        if !st.signed.is_empty()
            && let Some(w) = self.follow_key_change(&st.signed)?
        {
            v.warnings.push(w);
        }
        if !st.release.is_empty() {
            match release::open(self.verifier.as_ref(), &st.release, now) {
                Ok(r) => {
                    self.release = Some(r);
                    self.release_env = Some(st.release.clone());
                }
                Err(e) => v.warnings.push(format!("The coordinator's newest release was refused: {e}")),
            }
        }
        v.release = self.release.clone();
        // The registry account writes the rollout: its words are cut to
        // plain text before anything shows them.
        v.rollout = st.rollout.sanitized();
        v.coordinator_now = st.now;
        if st.now > 0 && (st.now - now).abs() > CLOCK_OFF {
            let off = crate::report::short_age((st.now - now).unsigned_abs());
            v.warnings.push(format!(
                "The coordinator's clock is {off} {} this computer's: the update window and the expiry of releases go by it.",
                if st.now > now { "ahead of" } else { "behind" }
            ));
        }

        let (mut members, problems) = registry::check_members(st.members, |h| self.fits(h));
        v.warnings.extend(problems.into_iter().map(|p| format!("The coordinator lists a bad entry, ignored: {p}")));
        // What each machine says about itself, as relayed by the
        // coordinator: checked again here, as either could lie. Its peers
        // can only be other members.
        let hosts: Vec<u32> = members.iter().map(|m| m.host).collect();
        for m in members.iter_mut() {
            let me = m.host;
            m.report = m.report.take().map(|r| r.sanitized(|h| h != me && hosts.contains(&h)));
        }
        self.coordinator_proved = false;
        if let Some(c) = members.iter().find(|m| m.host == 1) {
            v.coordinator_code = registry::coordinator_code(&c.wg_key, &coord_key);
            self.coordinator_proved =
                registry::proof_matches(&self.join_secret()?, &c.name, &c.wg_key, &c.ssh_host_key, &st.coordinator_proof);
        }
        match members.iter().find(|m| m.host == 1) {
            None => v.warnings.push("The coordinator sent no entry for itself.".into()),
            Some(c) if key_body(&c.ssh_host_key) != coord_key => v.warnings.push(
                "The coordinator's own entry has another SSH key than the machine this computer is connected to. Do not sign.".into(),
            ),
            _ => {}
        }

        // The newest valid signed list: this desktop's copy or the
        // coordinator's. Neither is trusted without its signature.
        let fits = |h: u32| !crate::mesh::ip(&self.subnet, h).is_empty();
        let local: Option<List> = match std::fs::read(self.copy_path()) {
            Err(_) => None,
            Ok(b) => match serde_json::from_slice::<Envelope>(&b).map_err(Error::from).and_then(|e| e.list(self.verifier.as_ref(), fits)) {
                Ok(l) => Some(l),
                Err(e) => {
                    v.warnings.push(format!("This computer's copy of the signed list ({}) was refused: {e}", self.copy_path().display()));
                    None
                }
            },
        };
        let remote: Option<List> = if st.signed.is_empty() {
            None
        } else {
            match st.signed.list(self.verifier.as_ref(), fits) {
                Ok(l) => Some(l),
                Err(e) => {
                    v.warnings.push(format!("The coordinator's signed list was refused: {e}"));
                    None
                }
            }
        };
        self.base = match (local, remote) {
            (Some(l), Some(r)) if r.version > l.version => {
                // Signed with this key on another computer: take it over.
                self.save_copy(&st.signed)?;
                r
            }
            (Some(l), Some(r)) => {
                if r.version < l.version {
                    v.warnings.push(format!(
                        "The coordinator serves signed list version {}, older than the version {} you signed last. \
                         Your next change sends the newer one.",
                        r.version, l.version
                    ));
                } else if r != l {
                    v.warnings.push(format!("The coordinator serves a different signed list under version {}.", l.version));
                }
                l
            }
            (Some(l), None) => {
                v.warnings.push(format!(
                    "The coordinator has no valid signed list; you signed version {} last. Your next change sends it again.",
                    l.version
                ));
                l
            }
            (None, Some(r)) => {
                self.save_copy(&st.signed)?;
                r
            }
            (None, None) => List::default(),
        };
        v.version = self.base.version;
        if let Some(w) = self.check_receipt(&st.receipt, now) {
            v.warnings.push(w);
        }
        self.check_reports(&mut members, &mut v.warnings);

        let missing: Vec<&str> =
            self.base.members.iter().filter(|e| !members.iter().any(|m| e.matches(m))).map(|e| e.name.as_str()).collect();
        if !missing.is_empty() {
            v.warnings.push(format!("Signed by you but not on the coordinator (or changed there): {}", missing.join(", ")));
        }
        v.members = members.iter().map(|m| (m.clone(), self.base.has(m))).collect();
        // What members say they cut off. A member's word, relayed by the
        // coordinator: something to look into, not a fact. Only hostnames
        // are shown of it.
        for m in &members {
            for c in m.cuts.iter().filter(|c| registry::valid_name(&c.name)) {
                v.reports.push(if c.auto {
                    format!("{} cut off {} by itself: {} tried closed ports on it. Check {}.", m.name, c.name, c.name, c.name)
                } else {
                    format!("{} has {} cut off (quarantine).", m.name, c.name)
                });
            }
        }

        // Requests are untrusted too; the code is computed here from the
        // keys in the request and the coordinator key this desktop pinned.
        let secret = self.join_secret()?;
        let mut requests = Vec::new();
        for mut r in st.requests {
            if let Err(e) = registry::validate_request(&r) {
                v.warnings.push(format!("The coordinator sent a bad join request, ignored: {e}"));
                continue;
            }
            r.code = registry::pairing_code(&r.wg_key, &r.ssh_host_key, &coord_key);
            requests.push(r);
        }
        // The registry lists one request per id, name and key. Two under
        // one of them come from a registry account that was broken into:
        // the admin would pick the line with the right code, and the
        // desktop would sign whichever comes first under its id.
        let twice = |r: &Request| requests.iter().filter(|q| q.id == r.id || q.name == r.name || q.wg_key == r.wg_key).count() > 1;
        let doubled: Vec<bool> = requests.iter().map(twice).collect();
        let mut dropped: Vec<String> = Vec::new();
        for (r, d) in requests.into_iter().zip(doubled) {
            if d {
                if !dropped.contains(&r.name) {
                    dropped.push(r.name.clone());
                }
                continue;
            }
            // Without the proof the request does not come from a machine
            // installed from this stick, or the coordinator changed it.
            if !registry::proof_ok(&secret, &r) {
                v.unproved.push(r.id.clone());
            }
            v.pending.push(r);
        }
        // Requests the registry turned down because the name or the key is
        // taken: a machine installed again under a member's name, or one
        // whose name another request holds, waits there unseen otherwise.
        // The registry's word: shown only with the stick's proof, and with
        // the code computed here, which the machine's screen shows.
        for f in st.refused {
            let r = f.request;
            if registry::validate_request(&r).is_err() || !registry::proof_ok(&secret, &r) || v.pending.iter().any(|p| p.wg_key == r.wg_key)
            {
                continue;
            }
            let code = registry::pairing_code(&r.wg_key, &r.ssh_host_key, &coord_key);
            let (name, lan) = (&r.name, &r.lan_ip);
            v.warnings.push(match self.base.members.iter().find(|e| e.name == r.name || e.wg_key == r.wg_key) {
                Some(e) if e.wg_key == r.wg_key => format!(
                    "{name} ({lan}) asks to join, but it is a member already: it lost its record of that \
                     (/etc/dryserver/join.json on it). Put it back, or remove {} (d) and it asks again by itself.",
                    e.name
                ),
                Some(_) => format!(
                    "{name} ({lan}) asks to join with code {code}, but a member is called {name} already. If {name} was \
                     installed again and its screen shows {code}, remove {name} (d): it then asks again by itself."
                ),
                None => format!(
                    "{name} ({lan}) asks to join with code {code}, but another request waits under that name. If {name}'s \
                     screen shows {code}, reject the other one (r): this one then asks again by itself."
                ),
            });
        }
        if !dropped.is_empty() {
            v.warnings.push(format!(
                "The coordinator lists more than one join request under the same id, name or WireGuard key ({}). None of them \
                 is shown, and none can be approved while it does: its registry account may be broken into.",
                dropped.join(", ")
            ));
        }
        let newest = self.release.as_ref().map_or(0, |r| r.serial);
        let brain = members.iter().find(|m| m.host == 1).and_then(|m| m.report.as_ref());
        self.went_back = rollout::went_back(&v.rollout, brain, newest);
        self.stop = Some((v.rollout.serial, v.rollout.pause_host));
        self.members = members;
        self.pending = v.pending.clone();
        self.unproved = v.unproved.clone();
        v.people = self.base.people.clone();
        v.vpn = self.base.vpn.clone();
        v.devices = self.base.devices.clone();
        v.servers = self.servers();
        v.gateway_key = v.vpn.as_ref().and_then(|p| self.machine_key(&p.gateway)).unwrap_or_default();
        Ok(v)
    }

    /// Builds the next list from the last signed one, signs it, keeps a
    /// copy and sends it to the coordinator.
    fn publish(&mut self, change: impl FnOnce(&mut List, &Admin) -> Result<()>) -> Result<u64> {
        self.publish_with(change, |_| Ok(()))
    }

    /// publish, with saved run once the new list is this computer's copy
    /// and before it is sent.
    fn publish_with(
        &mut self,
        change: impl FnOnce(&mut List, &Admin) -> Result<()>,
        saved: impl FnOnce(&Admin) -> Result<()>,
    ) -> Result<u64> {
        let mut list = self.base.clone();
        list.rejected.clear();
        if !list.members.iter().any(|e| e.host == 1) {
            // The first signature. The coordinator's entry is its own claim,
            // tied to the SSH key this desktop pinned when it first
            // connected.
            let Some(c) = self.members.iter().find(|m| m.host == 1) else {
                bail!("the coordinator sent no entry for itself; nothing signed");
            };
            if key_body(&c.ssh_host_key) != self.link.host_key()? {
                bail!("the coordinator's own entry has another SSH key than the machine you are connected to; nothing signed");
            }
            if !self.coordinator_proved {
                bail!(
                    "the machine at the coordinator's address has no valid proof from your USB stick: it was not installed \
                     from it, or it is not the coordinator. Nothing signed."
                );
            }
            list.members.insert(0, Entry::of(c));
        }
        change(&mut list, self)?;
        // Always higher than anything signed before, also if this
        // computer's copy was lost: the clock is the floor.
        list.version = (self.base.version + 1).max((self.now)().0.timestamp().max(0) as u64);
        list.check(|h| self.fits(h))?;
        let env = signed::seal(self.signer.as_ref(), &list)?;
        // Our own signature must pass our own check, or the two halves of
        // the key do not belong together and no server would accept it.
        env.list(self.verifier.as_ref(), |h| self.fits(h))
            .map_err(|e| e.wrap("the new signature does not verify with secrets/signing_ed25519.pub"))?;
        // Saved before sending: a version is never used for two lists.
        self.save_copy(&env)?;
        self.base = list;
        saved(self)?;
        self.link.call("publish", &serde_json::to_string(&env)?)?;
        Ok(self.base.version)
    }

    /// When the coordinator refuses this computer's ask, a key change may
    /// stand between them. This computer made one the coordinator did not
    /// take yet (its copy of the list carries it): sent again, and the ask
    /// once more. Or another computer made one: this computer follows it
    /// (from the list anyone may read) and says why it cannot sign.
    fn after_refused_ask(&mut self, e: Error, ask: &str) -> Result<String> {
        if e.is(crate::err::Kind::HostKey) {
            return Err(e);
        }
        let fits = |h: u32| !crate::mesh::ip(&self.subnet, h).is_empty();
        let copy = std::fs::read(self.copy_path()).ok().and_then(|b| serde_json::from_slice::<Envelope>(&b).ok());
        if let Some(env) = copy
            && let Ok((l, Some(_))) = env.list_signed_by(self.verifier.as_ref(), fits)
            && !l.keys.is_empty()
            && self.link.call("publish", &serde_json::to_string(&env)?).is_ok()
        {
            return self.link.call("admin", ask);
        }
        if let Ok(out) = self.link.call("signed", "")
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&out)
            && let Ok(env) = serde_json::from_value::<Envelope>(v["signed"].clone())
            && !env.is_empty()
            && let Some(w) = self.follow_key_change(&env)?
        {
            return Err(errf!("{w}"));
        }
        Err(e)
    }

    /// The coordinator's list, signed through key changes from the key
    /// this computer trusts to another one: the key was replaced on another
    /// computer. This one trusts the new key from now on (its old key is
    /// handed on, nothing it signs counts any more). Returns what to tell.
    fn follow_key_change(&mut self, env: &Envelope) -> Result<Option<String>> {
        let fits = |h: u32| !crate::mesh::ip(&self.subnet, h).is_empty();
        let Some(now) = self.verifier.key() else { return Ok(None) };
        let Ok((_, Some(signer))) = env.list_signed_by(self.verifier.as_ref(), fits) else { return Ok(None) };
        if signer == key_body(&now) {
            return Ok(None);
        }
        self.trust_key(&signer)?;
        Ok(Some(format!(
            "Your swarm's key was replaced on another computer: it is {} now, and this computer trusts it. To sign here, \
             this computer needs that key, in ssh-agent or ~/.ssh (dryserver import, or copy it).",
            signed::short_key(&signer)
        )))
    }

    /// From now on this computer trusts key, and signs with it: its public
    /// half becomes SIGNING_PUB. An older swarm's own signing key, handed
    /// on, moves to secrets/replaced/ so that nothing signs with it again.
    fn trust_key(&self, key: &str) -> Result<()> {
        let path = self.secrets.join(crate::iso::SIGNING_PUB);
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        fsx::write_new(&tmp, format!("{} dryserver-signing\n", key_body(key)), 0o644)?;
        fsx::rename(&tmp, &path)?;
        let legacy = self.secrets.join(crate::iso::SIGNING_KEY_NAME);
        if legacy.exists() {
            let dir = self.secrets.join("replaced");
            fsx::mkdir_all(&dir, 0o700)?;
            fsx::rename(&legacy, dir.join(format!("{}-{}", crate::iso::SIGNING_KEY_NAME, (self.now)().0.timestamp())))?;
        }
        Ok(())
    }

    /// Hands the swarm's trust from the key that signs now to the key to,
    /// whose private half new signs with: one key change, signed by the
    /// key it replaces, in a new list signed by to. Every machine follows
    /// it from the key it trusts at its next sync, and from then on takes
    /// nothing the old key signs. login: to also becomes the admin's login
    /// key on the machines. The newest release is signed again with to,
    /// so the coordinator's copy of it stays good.
    pub fn replace_key(&mut self, new: Box<dyn Signer>, to: &str, login: bool) -> Result<Replaced> {
        let v = self.load()?;
        if self.base.version == 0 {
            bail!("nothing is signed yet: the USB stick takes your key from the config, build it again instead");
        }
        if rollout_busy(&v.rollout, &v.members) {
            bail!("release {} is rolling out: replace the key once it is done (dryserver release status)", v.rollout.serial);
        }
        let from = self.verifier.key().ok_or_else(|| Error::new("this computer trusts no key it can name"))?;
        let to = key_body(to);
        if !to.starts_with("ssh-ed25519 ") || to.split_whitespace().count() != 2 {
            bail!("the new key must be an ed25519 public key (ssh-ed25519 ...)");
        }
        if to == key_body(&from) {
            bail!("that is the key your swarm trusts now");
        }
        let last = self.base.keys.iter().filter_map(|e| serde_json::from_str::<signed::KeyChange>(&e.doc).ok()).map(|c| c.serial).max();
        let serial = ((self.now)().0.timestamp().max(0) as u64).max(last.map_or(0, |s| s + 1));
        let change = signed::KeyChange { serial, from: key_body(&from), to: to.clone(), login };
        let change = signed::seal_key_change(self.signer.as_ref(), &change)?;
        let release = self.release_env.clone();
        let old = std::mem::replace(&mut self.signer, new);
        let version = match self.publish_with(
            |list, _| {
                list.keys.push(change);
                Ok(())
            },
            |a| a.trust_key(&to),
        ) {
            Ok(v) => v,
            Err(e) if self.verifier.key().is_some_and(|k| k == to) => {
                // Saved and trusted here, not sent: the next change sends
                // it (or resend).
                return Err(e.wrap(
                    "the key is replaced on this computer, but the coordinator did not take it yet: open Machines to send it again",
                ));
            }
            Err(e) => {
                self.signer = old;
                return Err(e.wrap("nothing changed"));
            }
        };
        let mut done = Replaced { version, release: None, warning: None };
        if let Some(env) = release {
            let resigned = (|| -> Result<u64> {
                let sig = self.signer.sign(release::NS_RELEASE, &env.doc)?;
                let env = Envelope { doc: env.doc.clone(), sig };
                let out = self.link.call("release-resign", &serde_json::to_string(&env)?)?;
                let serial = serde_json::from_str::<serde_json::Value>(&out)
                    .ok()
                    .and_then(|v| v["serial"].as_u64())
                    .ok_or_else(|| Error::new("the coordinator's answer"))?;
                // This computer's copy goes by the new key too.
                if self.last_release().is_none_or(|r| r.serial <= serial) {
                    let path = self.secrets.join(RELEASE_COPY);
                    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
                    fsx::write_new(&tmp, serde_json::to_string(&env)? + "\n", 0o600)?;
                    fsx::rename(&tmp, &path)?;
                }
                Ok(serial)
            })();
            match resigned {
                Ok(s) => done.release = Some(s),
                Err(e) => {
                    done.warning = Some(format!(
                        "release {} on the coordinator still carries the old key's signature ({e}): publish the next \
                         release with the new key",
                        self.release.as_ref().map_or(0, |r| r.serial)
                    ))
                }
            }
        }
        Ok(done)
    }

    /// The numbers of removed members (RETIRED), oldest first.
    fn retired(&self) -> Vec<u32> {
        serde_json::from_str(&fsx::read_or_empty(self.secrets.join(RETIRED))).unwrap_or_default()
    }

    fn save_retired(&self, hosts: &[u32]) -> Result<()> {
        let path = self.secrets.join(RETIRED);
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        let _ = std::fs::remove_file(&tmp);
        fsx::write_new(&tmp, serde_json::to_string(hosts)? + "\n", 0o600)?;
        fsx::rename(&tmp, &path)
    }

    /// The lowest number no member has and no removed member had; the
    /// longest retired one when the subnet has no other.
    fn free_host(&self, list: &List) -> Result<u32> {
        let retired = self.retired();
        let free = |h: &u32| !list.members.iter().any(|e| e.host == *h);
        (2u32..)
            .take_while(|h| self.fits(*h))
            .find(|h| free(h) && !retired.contains(h))
            .or_else(|| retired.iter().copied().find(|h| self.fits(*h) && free(h)))
            .ok_or_else(|| Error::new("the mesh subnet is full"))
    }

    /// The waiting request the admin chose, as it was shown: its id, name
    /// and both keys. A request that changed since is not taken for it.
    fn chosen(&self, r: &Request) -> Result<Request> {
        self.pending
            .iter()
            .find(|p| p.id == r.id && p.name == r.name && p.wg_key == r.wg_key && key_body(&p.ssh_host_key) == key_body(&r.ssh_host_key))
            .cloned()
            .ok_or_else(|| Error::new("that request is gone, or the coordinator changed it since you looked: look again"))
    }

    /// Lets the waiting machine chosen in, exactly the one the admin saw
    /// (its keys, which the code covers). Returns its mesh host number.
    pub fn approve(&mut self, chosen: &Request) -> Result<u32> {
        let r = self.chosen(chosen)?;
        if self.unproved.contains(&r.id) {
            bail!(
                "{} has no valid proof from your USB stick: it was not installed from it, or the coordinator changed the request. \
                 Not approved. Reject it (r); if the machine is yours, reinstall it from your stick.",
                r.name
            );
        }
        let mut host = 0;
        self.publish(|list, a| {
            if list.members.iter().any(|e| e.name == r.name) {
                bail!("a member named {} exists already; remove it first", r.name);
            }
            if list.members.iter().any(|e| e.wg_key == r.wg_key) {
                bail!("{} is a member already", r.name);
            }
            host = a.free_host(list)?;
            list.members.push(Entry { host, name: r.name.clone(), wg_key: r.wg_key.clone(), ssh_host_key: key_body(&r.ssh_host_key) });
            Ok(())
        })?;
        // A number given out again is no longer kept back.
        let retired = self.retired();
        if retired.contains(&host) {
            let _ = self.save_retired(&retired.into_iter().filter(|h| *h != host).collect::<Vec<_>>());
        }
        Ok(host)
    }

    pub fn reject(&mut self, chosen: &Request) -> Result<()> {
        let r = self.chosen(chosen)?;
        self.publish(|list, _| {
            list.rejected.push(r.wg_key.clone());
            Ok(())
        })
        .map(|_| ())
    }

    /// Removes a member, signed or not. The coordinator stays. Its number
    /// is kept back from the next machines (RETIRED). Returns what else
    /// the admin should know (it was the VPN's gateway), as sentences.
    pub fn remove(&mut self, name: &str) -> Result<Vec<String>> {
        let mut gone = Vec::new();
        let mut notes = Vec::new();
        self.publish(|list, a| {
            if a.members.iter().any(|m| m.name == name && m.host == 1) {
                bail!("the coordinator cannot be removed");
            }
            if list.members.iter().any(|e| e.name == name && e.host == 1) {
                bail!("the coordinator cannot be removed");
            }
            gone = list.members.iter().filter(|e| e.name == name).map(|e| e.host).collect();
            list.members.retain(|e| e.name != name);
            // The VPN's gateway goes with it: no VPN until another server is
            // made the gateway (the devices stay listed).
            if list.vpn.as_ref().is_some_and(|p| p.gateway == name) {
                list.vpn = None;
                notes.push(format!("{name} was the VPN's gateway: there is no VPN until another server is made the gateway."));
            }
            // Its name goes from where people may log in. Someone who could
            // log in there only is taken out: an empty list would be every
            // server.
            let mut out = Vec::new();
            for p in list.people.iter_mut().filter(|p| p.on.iter().any(|n| n == name)) {
                p.on.retain(|n| n != name);
                if p.on.is_empty() {
                    out.push(p.name.clone());
                }
            }
            list.people.retain(|p| !out.contains(&p.name));
            for n in out {
                notes.push(format!("{n} could log in only on {name}: taken out too (let them in again on another machine)."));
            }
            Ok(())
        })?;
        let mut retired = self.retired();
        retired.retain(|h| !gone.contains(h));
        retired.extend(gone);
        // The list is signed and sent: a lost record only means a number
        // may come back.
        if let Err(e) = self.save_retired(&retired) {
            notes.push(format!("Its number may be given out again: it could not be kept in {RETIRED} ({e})."));
        }
        Ok(notes)
    }

    /// The people the signed list lets in, as last loaded.
    pub fn people(&self) -> &[signed::Person] {
        &self.base.people
    }

    /// Lets a person in (or changes who they are let in as): their own
    /// account on the machines named in on (none: every server), their
    /// keys only. admin is the admin's own account, never a person's.
    /// Returns the version that carries it.
    pub fn let_in(&mut self, p: &signed::Person, admin: &str) -> Result<u64> {
        if !signed::valid_person_name(&p.name) || p.name == admin {
            bail!(
                "{:?} cannot be a person's account: lowercase letters, digits, _ and -, at most 32, and none of the \
                 machines' own accounts",
                p.name
            );
        }
        let mut keys = Vec::new();
        for k in &p.keys {
            let k = key_body(k);
            if !registry::valid_ssh_key(&k) {
                bail!("not an SSH public key: {k:?}");
            }
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        if keys.is_empty() {
            bail!("{} needs at least one SSH public key", p.name);
        }
        let person = signed::Person { name: p.name.clone(), keys, on: p.on.clone() };
        self.publish(|list, _| {
            if let Some(n) = person.on.iter().find(|n| !list.members.iter().any(|e| e.name == **n)) {
                bail!("there is no machine called {n} in your swarm");
            }
            list.people.retain(|q| q.name != person.name);
            list.people.push(person);
            Ok(())
        })
    }

    /// Takes a person out: within a minute their account on every machine
    /// is locked and their sessions end.
    pub fn take_out(&mut self, name: &str) -> Result<u64> {
        self.publish(|list, _| {
            if !list.people.iter().any(|p| p.name == name) {
                bail!("{name} is not let in");
            }
            list.people.retain(|p| p.name != name);
            Ok(())
        })
    }

    /// The VPN as the signed list has it, as last loaded.
    pub fn vpn(&self) -> Option<&crate::vpn::Plan> {
        self.base.vpn.as_ref()
    }

    /// The devices on the VPN, as last loaded.
    pub fn devices(&self) -> &[crate::vpn::Device] {
        &self.base.devices
    }

    /// The WireGuard key the signed list has for a machine: a gateway's is
    /// the one devices check it by.
    pub fn machine_key(&self, name: &str) -> Option<String> {
        self.base.members.iter().find(|e| e.name == name).map(|e| e.wg_key.clone())
    }

    /// Sets the VPN up (or changes it). The subnet may change only while
    /// no device is listed: their addresses are in it.
    pub fn vpn_on(&mut self, plan: &crate::vpn::Plan) -> Result<u64> {
        plan.check()?;
        plan.clashes("the mesh", &self.subnet)?;
        let plan = plan.clone();
        self.publish(|list, _| {
            if !list.devices.is_empty()
                && let Some(c) = plan.cidr()
                && list.devices.iter().any(|d| d.addr.parse().is_ok_and(|ip| !c.contains(ip)))
            {
                bail!(
                    "the devices have addresses in another subnet: keep it (leave --subnet out), or take them out first \
                     (dryserver vpn remove NAME) and add them again"
                );
            }
            list.vpn = Some(plan);
            Ok(())
        })
    }

    /// Takes the VPN away: the gateway's interface goes within a minute.
    /// The devices stay listed, for when it is set up again.
    pub fn vpn_off(&mut self) -> Result<u64> {
        self.publish(|list, _| {
            if list.vpn.is_none() {
                bail!("the VPN is not set up");
            }
            list.vpn = None;
            Ok(())
        })
    }

    /// Adds a device with its public key, at the next free address.
    /// Returns the device and the version that carries it.
    pub fn vpn_add(&mut self, name: &str, key: &str) -> Result<(crate::vpn::Device, u64)> {
        if !crate::vpn::valid_device_name(name) {
            bail!("{name:?}: a device's name is lowercase letters, digits and -, at most 32 (like phone or ana-laptop)");
        }
        if !registry::valid_wg_key(key) {
            bail!("not a WireGuard public key (44 characters of base64, ending in =)");
        }
        let mut made = None;
        let version = self.publish(|list, _| {
            let Some(plan) = &list.vpn else { bail!("set the VPN up first: dryserver vpn on SERVER --endpoint ADDRESS") };
            if list.devices.iter().any(|d| d.name == name) {
                bail!("there is a device called {name} already: dryserver vpn remove {name} first, or choose another name");
            }
            if list.devices.iter().any(|d| d.key == key) || list.members.iter().any(|e| e.wg_key == key) {
                bail!("that key is another device's or a machine's: every device needs its own");
            }
            let addr = crate::vpn::next_addr(plan, &list.devices).ok_or_else(|| errf!("the VPN's subnet has no free address left"))?;
            let d = crate::vpn::Device { name: name.into(), key: key.into(), addr: addr.to_string() };
            list.devices.push(d.clone());
            made = Some(d);
            Ok(())
        })?;
        Ok((made.expect("added"), version))
    }

    /// Takes a device out: the gateway forgets its key within a minute.
    pub fn vpn_remove(&mut self, name: &str) -> Result<u64> {
        self.publish(|list, _| {
            if !list.devices.iter().any(|d| d.name == name) {
                bail!("there is no device called {name}");
            }
            list.devices.retain(|d| d.name != name);
            Ok(())
        })
    }

    /// The first signature: signs the coordinator's own entry, which
    /// nothing vouches for but the code the admin compared. Later machines
    /// come in only through approve.
    ///
    /// There is no way to sign another machine that is on the coordinator
    /// without a request: nobody can put it there but the coordinator
    /// itself, so it is either a mistake or an attack.
    pub fn sign_coordinator(&mut self) -> Result<()> {
        if self.base.members.iter().any(|e| e.host == 1) {
            bail!("the coordinator is signed already");
        }
        if !self.coordinator_proved {
            bail!(
                "the machine at the coordinator's address has no valid proof from your USB stick: it was not installed \
                 from it, or it is not the coordinator. Not signed."
            );
        }
        self.publish(|_, _| Ok(())).map(|_| ())
    }

    /// After Kind::HostKey: looks at the machine that answers at the
    /// coordinator's address now. It must show the proof from the admin's
    /// USB stick for the keys it has; the code is for the admin to compare
    /// with its screen. Changes nothing: the old pin is back when this
    /// returns.
    pub fn probe_new_coordinator(&mut self) -> Result<NewCoordinator> {
        let old_pin = self.link.host_key().unwrap_or_default();
        let key = self.link.scan_host_key()?;
        if key == old_pin {
            bail!("the coordinator has the SSH key this computer knows; there is nothing to replace");
        }
        self.link.repin(&key)?;
        let looked = (|| -> Result<NewCoordinator> {
            let ask = signed::seal_admin(self.signer.as_ref(), "state", (self.now)().0.timestamp())?;
            let out = self.link.call("admin", &serde_json::to_string(&ask)?)?;
            let st: AdminState = serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("the new coordinator's answer"))?;
            let (members, _) = registry::check_members(st.members, |h| self.fits(h));
            let Some(c) = members.iter().find(|m| m.host == 1) else {
                bail!("the machine at the coordinator's address sent no valid entry for itself");
            };
            if key_body(&c.ssh_host_key) != key {
                bail!("the machine at the coordinator's address claims another SSH key than the one it uses");
            }
            if !registry::proof_matches(&self.join_secret()?, &c.name, &c.wg_key, &c.ssh_host_key, &st.coordinator_proof) {
                bail!(
                    "the machine at the coordinator's address has no valid proof from your USB stick: it was not installed \
                     from it as a coordinator"
                );
            }
            Ok(NewCoordinator {
                name: c.name.clone(),
                code: registry::coordinator_code(&c.wg_key, &key),
                entry: Entry::of(c),
                old_pin: old_pin.clone(),
            })
        })();
        // Back to the old pin either way: only accept changes it.
        self.link.repin(&old_pin)?;
        looked
    }

    /// Makes the probed machine the coordinator: pins its SSH key and signs
    /// a new list in which it replaces the old coordinator. Every other
    /// member stays, from this desktop's copy of the last signed list. The
    /// servers take the new keys from that list when their quarantine is
    /// lifted.
    pub fn accept_new_coordinator(&mut self, c: &NewCoordinator) -> Result<u64> {
        // The base is this desktop's copy: the old coordinator is gone and
        // the new one has no list yet.
        let fits = |h: u32| !crate::mesh::ip(&self.subnet, h).is_empty();
        self.base = match std::fs::read(self.copy_path()) {
            Err(_) => List::default(),
            Ok(b) => serde_json::from_slice::<Envelope>(&b)
                .map_err(Error::from)
                .and_then(|e| e.list(self.verifier.as_ref(), fits))
                .map_err(|e| e.wrap(format!("this computer's copy of the signed list ({}) was refused", self.copy_path().display())))?,
        };
        if self.base.members.iter().any(|e| e.host != 1 && (e.name == c.entry.name || e.wg_key == c.entry.wg_key)) {
            bail!("a signed member already has the new coordinator's name or key ({}); remove it first", c.entry.name);
        }
        self.link.repin(&c.entry.ssh_host_key)?;
        let entry = c.entry.clone();
        let res = self.publish(|list, _| {
            list.members.retain(|e| e.host != 1);
            list.members.insert(0, entry);
            Ok(())
        });
        if res.is_err() && self.base.members.first().is_some_and(|e| e.host == 1 && *e != c.entry) {
            // Nothing was signed: keep pinning the coordinator in the list.
            let _ = self.link.repin(&c.old_pin);
        }
        res
    }

    /// Signs and sends the current list again under a new version, for
    /// when the coordinator lost it or serves an older one.
    pub fn resend(&mut self) -> Result<u64> {
        if self.base.version == 0 {
            bail!("nothing is signed yet");
        }
        self.publish(|_, _| Ok(()))
    }

    /// The servers in the signed list, with the LAN addresses the
    /// coordinator reported at the last load.
    pub fn servers(&self) -> Vec<crate::mesh::Server> {
        self.base
            .members
            .iter()
            .map(|e| crate::mesh::Server {
                name: e.name.clone(),
                mesh_ip: crate::mesh::ip(&self.subnet, e.host),
                // What the member signed itself; the coordinator's word only
                // for one that never signed a report (an older version).
                lan_ip: match self.lans.get(&e.wg_key) {
                    Some(lan) => lan.clone(),
                    None => self.members.iter().find(|m| e.matches(m)).map(|m| m.lan_ip.clone()).unwrap_or_default(),
                },
                host_key: e.ssh_host_key.clone(),
            })
            .collect()
    }

    /// The newest release this desktop knows was signed: its own copy or
    /// the coordinator's (as last loaded), whichever is newer. Neither
    /// counts without its signature.
    pub fn last_release(&self) -> Option<Release> {
        let now = (self.now)().0.timestamp();
        let local = std::fs::read(self.secrets.join(RELEASE_COPY))
            .ok()
            .and_then(|b| serde_json::from_slice::<Envelope>(&b).ok())
            .and_then(|e| release::open(self.verifier.as_ref(), &e, now).ok());
        match (local, self.release.clone()) {
            (Some(a), Some(b)) => Some(if b.serial > a.serial { b } else { a }),
            (a, b) => a.or(b),
        }
    }

    /// What a new release's versions are compared with: the last one
    /// signed, or, when that is the coordinator's newest and it failed
    /// there and went back, the release the machines run instead (this
    /// computer's signed copy of it; none without one, or when they ran
    /// none before: each machine checks against what it runs). The serial
    /// always comes after the last one signed (last_release).
    pub fn release_base(&self) -> Option<Release> {
        let last = self.last_release();
        match (self.went_back, &last, &self.release) {
            (Some(m), Some(l), Some(newest)) if l.serial == newest.serial => crate::publish::signed_copy(self, m),
            _ => last,
        }
    }

    /// Builds the release that d describes, without signing or sending
    /// it: what send_release would sign, or why the coordinator would
    /// refuse it. publish::plan checks the rest (the Arch day, the k3s
    /// file) and shows the admin what changes.
    pub fn draft_release(&self, d: &release::Draft) -> Result<Release> {
        rollout::check_static(d.binary)?;
        let after = self.last_release().map(|l| l.serial);
        release::build_after(d, after, self.release_base().as_ref(), (self.now)().0.timestamp())
    }

    /// Drafts the release that d describes and sends it at once: the
    /// tests' short way. k3s is the pinned k3s binary, sent only when the
    /// coordinator does not have it.
    ///
    /// Refused here, before anything is signed, when the coordinator would
    /// refuse it (an older version without rollback, a malformed field) or
    /// when the binary would not run on the servers.
    #[cfg(test)]
    pub fn publish_release(&mut self, d: &release::Draft, k3s: &Path) -> Result<Release> {
        let r = self.draft_release(d)?;
        self.send_release(&r, d.binary, k3s)?;
        Ok(r)
    }

    /// Signs r, a release drafted a moment ago (draft_release), and
    /// uploads it with binary, its dryserver; k3s goes along when the
    /// coordinator asks for it. Refused before anything is signed when r
    /// no longer fits: binary changed since, or another release was signed
    /// in between (its serial would be used twice).
    pub fn send_release(&mut self, r: &Release, binary: &Path, k3s: &Path) -> Result<()> {
        let now = (self.now)().0.timestamp();
        let unsigned = |e: Error| e.wrap("nothing was signed");
        rollout::check_static(binary).map_err(unsigned)?;
        let (sha, size) = release::hash_file(binary, release::MAX_BINARY).map_err(unsigned)?;
        if sha != r.dryserver.sha256 || size != r.dryserver.size {
            bail!("{} changed since the release was drafted (a new build?). Nothing was signed; look again", binary.display());
        }
        r.validate(now).map_err(unsigned)?;
        // Its serial after the last one signed; its versions after what
        // the machines run (release_base).
        let last = self.last_release();
        let base = match &last {
            Some(l) if r.serial <= l.serial => last.clone(),
            _ => self.release_base(),
        };
        release::decide(r, base.as_ref(), release::Place::Brain, now).map_err(unsigned)?;
        let r = r.clone();
        let env = release::seal(self.signer.as_ref(), &r)?;
        // Our own signature must pass our own check, or no machine would
        // accept it.
        release::open(self.verifier.as_ref(), &env, now)
            .map_err(|e| e.wrap("the new signature does not verify with secrets/signing_ed25519.pub"))?;
        // Saved before sending: a serial is never used for two releases.
        let path = self.secrets.join(RELEASE_COPY);
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        fsx::write_new(&tmp, serde_json::to_string(&env)? + "\n", 0o600)?;
        fsx::rename(&tmp, &path)?;
        // From here on the release is signed and kept: a failure says so,
        // and that publishing again is safe. A cut-off upload is not kept
        // by the coordinator; one that arrived whole just before the
        // connection broke is, and status shows which.
        let kept = |e: Error| {
            errf!(
                "release {} is signed and kept on this computer, but the coordinator did not take it: {e}. \
                 dryserver release status shows what the coordinator has. Publishing again is safe: \
                 the next release gets a higher serial",
                r.serial
            )
        };
        let mut head = rollout::PutHeader { release: env, k3s_size: 0 };
        match self.link.upload("release-put", &(serde_json::to_string(&head)? + "\n"), &[binary]) {
            Ok(_) => {}
            Err(e) if e.to_string().contains(rollout::SEND_K3S) => {
                // The coordinator runs another k3s: it gets the pinned one.
                let (sha, size) = release::hash_file(k3s, rollout::MAX_K3S).map_err(|e| {
                    kept(e.wrap(format!(
                        "the coordinator needs k3s {}, and this computer has none at {} (build the USB stick once to download it). {}",
                        r.k3s.version,
                        k3s.display(),
                        crate::publish::get_k3s(k3s, &r.k3s.version)
                    )))
                })?;
                if sha != r.k3s.sha256 {
                    return Err(kept(errf!(
                        "{} is not k3s {}: its sha256 is {sha}, the release says {}",
                        k3s.display(),
                        r.k3s.version,
                        r.k3s.sha256
                    )));
                }
                head.k3s_size = size;
                self.link.upload("release-put", &(serde_json::to_string(&head)? + "\n"), &[binary, k3s]).map_err(kept)?;
            }
            Err(e) => return Err(kept(e)),
        }
        self.release = Some(r);
        Ok(())
    }

    /// Lets a stopped rollout go on (what that means depends on why it
    /// stopped; see rollout::Pause): a server whose update failed or did
    /// not finish tries again. Returns how many resumes were asked.
    pub fn resume_release(&mut self) -> Result<u64> {
        self.release_ask("release-resume", "resume")
    }

    /// Lets a rollout stopped at a server go on without it: the server is
    /// passed over for this release. Refused for the coordinator's own
    /// update. Returns how many skips were asked.
    pub fn skip_release(&mut self) -> Result<u64> {
        self.release_ask("release-skip", "skip")
    }

    /// Asks for op at the stop last loaded (one load first, when none
    /// was).
    fn release_ask(&mut self, op: &str, field: &str) -> Result<u64> {
        if self.stop.is_none() {
            self.load()?;
        }
        let (serial, host) = self.stop.unwrap_or_default();
        let ask = signed::seal_ask(self.signer.as_ref(), op, (self.now)().0.timestamp(), serial, host)?;
        let out = self.link.call(op, &serde_json::to_string(&ask)?)?;
        let v: serde_json::Value = serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("the coordinator's answer"))?;
        Ok(v[field].as_u64().unwrap_or(0))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::registry::{Mesh, Status, Store};
    use crate::report::Report;
    use crate::signed::fake::Key;
    use crate::testutil::TempDir;
    use base64::Engine;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    pub const COORD_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcoordinatorkey";
    pub const SECRET: &str = "7e577e577e577e577e577e577e577e577e577e577e577e577e577e577e577e57";

    pub fn key32(seed: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    struct Subnet;
    impl Mesh for Subnet {
        fn host_of(&self, _: Ipv4Addr) -> u32 {
            0
        }
        fn fits(&self, host: u32) -> bool {
            (1..=254).contains(&host)
        }
    }

    /// The real registry, called in process.
    pub struct Direct {
        pub store: Store,
        pub host_key: String,
        /// Fail every publish, like a coordinator that went away.
        pub publish_fails: Arc<Mutex<bool>>,
        /// The coordinator's signature checker; None: the fake admin key.
        pub verifier: Option<Box<dyn Verifier>>,
        /// What this desktop pinned; host_key is what the machine has.
        pub pinned: Arc<Mutex<String>>,
    }

    impl Direct {
        /// Where the coordinator keeps uploaded releases, beside its
        /// registry; its own k3s is the file "k3s" there.
        pub fn served(&self) -> crate::rollout::Served {
            crate::rollout::Served::beside(&self.store, fsx::dir(&self.store.path).join("k3s"))
        }

        fn serve(&self, command: &str, input: &[u8]) -> Result<String> {
            if *self.pinned.lock().unwrap() != self.host_key {
                return Err(Error::with_kind(crate::err::Kind::HostKey, "does not have the SSH key this computer saw before"));
            }
            if command == "publish" && *self.publish_fails.lock().unwrap() {
                return Err("cannot reach the coordinator".into());
            }
            let mut out = Vec::new();
            let fake = Key("admin");
            let v: &dyn Verifier = self.verifier.as_deref().unwrap_or(&fake);
            registry::serve(
                &self.store,
                &self.served(),
                &Subnet,
                v,
                COORD_KEY,
                command,
                "192.168.1.9 5000 22",
                &mut &input[..],
                &mut out,
                Time::now(),
            )?;
            Ok(String::from_utf8(out).unwrap())
        }
    }

    impl Link for Direct {
        fn call(&self, command: &str, stdin: &str) -> Result<String> {
            self.serve(command, stdin.as_bytes())
        }
        fn upload(&self, command: &str, header: &str, files: &[&Path]) -> Result<String> {
            let mut input = header.as_bytes().to_vec();
            for f in files {
                input.extend(std::fs::read(f)?);
            }
            self.serve(command, &input)
        }
        fn host_key(&self) -> Result<String> {
            let k = self.pinned.lock().unwrap().clone();
            if k.is_empty() { Err("not recorded".into()) } else { Ok(k) }
        }
        fn scan_host_key(&self) -> Result<String> {
            Ok(self.host_key.clone())
        }
        fn repin(&self, key: &str) -> Result<()> {
            *self.pinned.lock().unwrap() = key_body(key);
            Ok(())
        }
    }

    /// A join request as a machine installed from the admin's stick sends it.
    pub fn request(name: &str, seed: u8) -> Request {
        let mut r = Request {
            name: name.into(),
            wg_key: key32(seed),
            ssh_host_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{} root@{name}", name.replace('-', "")),
            lan_ip: "192.168.1.23".into(),
            ..Request::default()
        };
        r.proof = registry::join_proof(SECRET, &r.name, &r.wg_key, &r.ssh_host_key);
        r
    }

    /// A coordinator with itself as member 1, and an Admin talking to it.
    pub fn setup(dir: &TempDir) -> (Admin, Store) {
        let (a, store, _) = setup_failing(dir);
        (a, store)
    }

    /// Like setup, with the switch that makes every publish fail.
    pub fn setup_failing(dir: &TempDir) -> (Admin, Store, Arc<Mutex<bool>>) {
        let store = Store::new(dir.join("registry.json"));
        store
            .update(|s| {
                s.members = vec![Member {
                    host: 1,
                    name: "coord".into(),
                    wg_key: key32(1),
                    ssh_host_key: format!("{COORD_KEY} root@coord"),
                    lan_ip: "192.168.1.50".into(),
                    ..Member::default()
                }];
                s.coordinator_proof = registry::join_proof(SECRET, "coord", &key32(1), COORD_KEY);
                Ok(())
            })
            .unwrap();
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join(crate::iso::JOIN_SECRET), format!("{SECRET}\n")).unwrap();
        let fails: Arc<Mutex<bool>> = Arc::default();
        let link = Direct {
            store: Store::new(&store.path),
            host_key: COORD_KEY.into(),
            publish_fails: fails.clone(),
            verifier: None,
            pinned: Arc::new(Mutex::new(COORD_KEY.into())),
        };
        let a = Admin::new(Box::new(link), Box::new(Key("admin")), Box::new(Key("admin")), &secrets, "10.66.0.0/24");
        (a, store, fails)
    }

    /// Points a at another coordinator machine while it still pins the
    /// first one's SSH key.
    pub fn move_to(a: &mut Admin, store: &Store, host_key: &str) -> Arc<Mutex<String>> {
        let pinned = Arc::new(Mutex::new(COORD_KEY.to_string()));
        a.link = Box::new(Direct {
            store: Store::new(&store.path),
            host_key: host_key.into(),
            publish_fails: Arc::default(),
            verifier: None,
            pinned: pinned.clone(),
        });
        pinned
    }

    fn ask(store: &Store, name: &str, seed: u8) -> String {
        store.update(|s| s.add_request(request(name, seed), COORD_KEY, Time::now())).unwrap()
    }

    /// The waiting request with id as the desktop shows it (one made up
    /// when there is none).
    pub fn by_id(a: &Admin, id: &str) -> Request {
        a.pending.iter().find(|r| r.id == id).cloned().unwrap_or(Request { id: id.into(), ..Request::default() })
    }

    /// ssh-keygen as signed::fake::host_run answers it.
    struct HostKeys;

    impl crate::runner::Runner for HostKeys {
        fn run(&self, _: &crate::ctx::Ctx, c: &crate::runner::Cmd) -> (String, Result<()>) {
            signed::fake::host_run(c).unwrap_or_else(|| (String::new(), Err(Error::new("unknown"))))
        }
    }

    /// Puts the copy of the signed list secs into the past, as if signed
    /// then.
    fn signed_ago(a: &Admin, secs: u64) {
        let f = std::fs::File::options().write(true).open(a.copy_path()).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(secs)).unwrap();
    }

    /// A receipt by the coordinator with SSH host key key.
    fn receipt(key: &str, version: u64, doc: &str, time: i64) -> registry::Receipt {
        let sha256 = fsx::hex(&<sha2::Sha256 as sha2::Digest>::digest(doc.as_bytes()));
        let sig = signed::fake::host_sig(key, signed::NS_RECEIPT, &registry::Receipt::text(version, &sha256, time));
        registry::Receipt { version, sha256, time, sig }
    }

    /// The review's case: the registry account takes the admin's newest
    /// list, answers the desktop with it, and never keeps it for root. The
    /// coordinator's receipt, signed with its host key, says what root
    /// follows: the approval screen (and release status) say so plainly.
    #[test]
    fn review_a_list_the_registry_holds_back_is_called_out() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        a.run = Arc::new(HostKeys);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let now = Time::now().0.timestamp();
        let doc = store.read().unwrap().signed.doc;
        let v1 = a.base.version;
        let warned = |a: &mut Admin, want: &str| a.load().unwrap().warnings.iter().any(|w| w.contains(want));
        let set = |r: registry::Receipt| {
            store
                .update(|s| {
                    s.receipt = r;
                    Ok(())
                })
                .unwrap()
        };
        // Signed a moment ago: nothing to say yet, even without a receipt.
        assert!(!warned(&mut a, "receipt") && !warned(&mut a, "not applied"));
        signed_ago(&a, 600);
        assert!(warned(&mut a, "sent no receipt for the list you signed"), "an older coordinator, or one held back");
        set(receipt(COORD_KEY, v1, &doc, now));
        assert!(a.load().unwrap().warnings.iter().all(|w| !w.contains("receipt") && !w.contains("applied")));
        // The admin removes node-a; the registry account keeps the old list.
        a.remove("node-a").unwrap();
        store
            .update(|s| {
                s.signed.doc = doc.clone();
                s.signed_version = v1;
                Ok(())
            })
            .unwrap();
        assert!(!warned(&mut a, "has not applied"), "signed a moment ago");
        signed_ago(&a, 300);
        let w = a.load().unwrap().warnings.join("\n");
        assert!(
            w.contains(&format!("has not applied list version {}", a.base.version)) && w.contains(&format!("it follows version {v1}")),
            "{w}"
        );
        assert!(w.contains("quarantine-all -name NAME"), "{w}");
        // A receipt the registry account made itself, or one it put back
        // from another list under the version.
        set(receipt("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIevil", a.base.version, "{}", now));
        assert!(warned(&mut a, "not signed by the coordinator you signed"));
        set(receipt(COORD_KEY, a.base.version, "another list", now));
        assert!(warned(&mut a, "follows another list under version"));
        // Root applied it: nothing to say. Then its sync stops.
        let doc2 = std::fs::read_to_string(a.copy_path()).unwrap();
        let env: Envelope = serde_json::from_str(&doc2).unwrap();
        set(receipt(COORD_KEY, a.base.version, &env.doc, now));
        assert!(a.load().unwrap().warnings.iter().all(|w| !w.contains("receipt") && !w.contains("applied")));
        set(receipt(COORD_KEY, a.base.version, &env.doc, now - 3600));
        assert!(warned(&mut a, "newest receipt is 1h old"));
    }

    /// What a server says about itself counts only signed by it: one the
    /// registry account changed is not shown, and the kill switch's way to
    /// it stays the address it signed.
    #[test]
    fn a_report_counts_only_signed_by_its_machine() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        a.run = Arc::new(HostKeys);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let key = request("node-a", 2).ssh_host_key;
        let signed_report = |lan: &str, release: u64| {
            let r = Report { time: 1_800_000_000, release, lan: lan.into(), ..Report::default() };
            Report { sig: signed::fake::host_sig(&key, signed::NS_REPORT, &r.signed_text(2, &key32(2))), ..r }
        };
        let send = |r: Option<Report>, lan: &str| {
            store
                .update(|s| {
                    let m = s.members.iter_mut().find(|m| m.host == 2).unwrap();
                    m.report = r;
                    m.lan_ip = lan.into();
                    Ok(())
                })
                .unwrap()
        };
        let lan = |a: &Admin| a.servers().into_iter().find(|s| s.name == "node-a").unwrap().lan_ip;
        // An older server: unsigned, said so, the coordinator's address.
        send(Some(Report { release: 3, ..Report::default() }), "192.168.1.23");
        let v = a.load().unwrap();
        assert!(v.warnings.iter().any(|w| w.contains("Unsigned report") && w.contains("node-a")), "{:?}", v.warnings);
        assert_eq!(lan(&a), "192.168.1.23");
        // Updated: signed. Shown, and its own address taken.
        send(Some(signed_report("192.168.1.24", 4)), "192.168.1.24");
        let v = a.load().unwrap();
        assert!(v.warnings.iter().all(|w| !w.contains("report")), "{:?}", v.warnings);
        assert_eq!(v.members.iter().find(|(m, _)| m.host == 2).unwrap().0.report.as_ref().unwrap().release, 4);
        assert_eq!(lan(&a), "192.168.1.24");
        // The registry account changes it, points the address elsewhere,
        // or drops the signature: not shown, and the address stays.
        for (r, at, good) in [
            (Report { release: 9, ..signed_report("192.168.1.24", 4) }, "192.168.1.24", false),
            (signed_report("192.168.1.24", 4), "192.168.1.66", true),
            (Report { lan: "192.168.1.66".into(), ..signed_report("192.168.1.24", 4) }, "192.168.1.66", false),
            (Report { sig: String::new(), ..signed_report("192.168.1.24", 9) }, "192.168.1.66", false),
        ] {
            send(Some(r.clone()), at);
            let v = a.load().unwrap();
            let shown = v.members.iter().find(|(m, _)| m.host == 2).unwrap().0.report.is_some();
            let warned = v.warnings.iter().any(|w| w.contains("Not signed by the machine") && w.contains("node-a"));
            assert_eq!((shown, warned), (good, !good), "{r:?}");
            assert_eq!(lan(&a), "192.168.1.24", "{r:?}");
        }
    }

    /// A removed member's number is not given to the next machine while
    /// another is free: servers that cut it off drop its address.
    #[test]
    fn a_removed_members_number_is_kept_back() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let ida = ask(&store, "node-a", 2);
        let idb = ask(&store, "node-b", 3);
        a.load().unwrap();
        assert_eq!((a.approve(&by_id(&a, &ida)).unwrap(), a.approve(&by_id(&a, &idb)).unwrap()), (2, 3));
        a.load().unwrap();
        a.remove("node-a").unwrap();
        let idc = ask(&store, "node-c", 4);
        a.load().unwrap();
        assert_eq!(a.approve(&by_id(&a, &idc)).unwrap(), 4, "node-c got node-a's number");
        assert_eq!(std::fs::read_to_string(a.secrets.join(RETIRED)).unwrap().trim(), "[2]");
        // A subnet with no other number left gives the retired one.
        a.subnet = "10.66.0.0/29".into();
        let ide = ask(&store, "node-e", 5);
        let idf = ask(&store, "node-f", 6);
        a.load().unwrap();
        assert_eq!(a.approve(&by_id(&a, &ide)).unwrap(), 5);
        assert_eq!(a.approve(&by_id(&a, &idf)).unwrap(), 6);
        let idg = ask(&store, "node-g", 7);
        a.load().unwrap();
        assert_eq!(a.approve(&by_id(&a, &idg)).unwrap(), 2, "the last free number");
        assert_eq!(std::fs::read_to_string(a.secrets.join(RETIRED)).unwrap().trim(), "[]");
    }

    /// A machine installed again under a member's name, or one whose name
    /// another request holds, is turned down by the registry; the approval
    /// screen says so, with the code from its screen and what to do.
    #[test]
    fn requests_turned_down_are_shown_with_what_to_do() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let turned_down = |r: Request| store.update(|s| Ok(s.add_request_from(r, COORD_KEY, Time::now(), "192.168.1.24"))).unwrap();
        // node-a installed again: new keys, the same name.
        assert!(turned_down(request("node-a", 7)).is_err());
        // Waiting as node-b, and another machine asks under node-b.
        let idb = ask(&store, "node-b", 3);
        assert!(turned_down(request("node-b", 8)).is_err());
        // Without the stick's proof: the registry account's own word.
        assert!(turned_down(Request { proof: String::new(), ..request("node-a", 10) }).is_err());
        let v = a.load().unwrap();
        let code = |seed: u8, name: &str| registry::pairing_code(&key32(seed), &request(name, seed).ssh_host_key, COORD_KEY);
        let w = v.warnings.join("\n");
        assert!(
            w.contains(&format!(
                "node-a (192.168.1.23) asks to join with code {}, but a member is called node-a already",
                code(7, "node-a")
            )) && w.contains("remove node-a (d)"),
            "{w}"
        );
        assert!(
            w.contains(&format!("node-b (192.168.1.23) asks to join with code {}, but another request waits", code(8, "node-b"))),
            "{w}"
        );
        assert!(!w.contains(&code(10, "node-a")), "a refusal without proof is shown: {w}");
        // The admin rejects the other node-b: the one turned down asks
        // again and is a waiting request now, no longer a warning.
        a.reject(&by_id(&a, &idb)).unwrap();
        store.update(|s| s.add_request_from(request("node-b", 8), COORD_KEY, Time::now(), "192.168.1.25")).unwrap();
        let v = a.load().unwrap();
        assert!(
            v.pending.iter().any(|r| r.wg_key == key32(8)) && !v.warnings.join("\n").contains("another request waits"),
            "{:?}",
            v.warnings
        );
    }

    /// The review's case: the registry account lists, before the real
    /// request, one under the same id from a machine of its own (with a
    /// valid proof: a removed server keeps its join.proof). The admin
    /// picks the line whose code matches; the desktop signs exactly that
    /// machine, or nothing.
    #[test]
    fn review_two_requests_under_one_id_approve_the_wrong_machine() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        let real = store.read().unwrap().requests[0].clone();
        let evil_under = |field: &str| {
            let mut evil = request("node-x", 66);
            match field {
                "id" => evil.id = real.id.clone(),
                "name" => {
                    evil = request("node-a", 66);
                    evil.id = "00000000000000ee".into();
                }
                _ => {
                    evil.wg_key = real.wg_key.clone();
                    evil.id = "00000000000000ee".into();
                }
            }
            evil.status = registry::Status::Pending;
            evil.created = real.created;
            evil
        };
        for field in ["id", "name", "key"] {
            let evil = evil_under(field);
            store
                .update(|s| {
                    s.requests = vec![evil.clone(), real.clone()];
                    Ok(())
                })
                .unwrap();
            let v = a.load().unwrap();
            assert!(v.pending.is_empty(), "{field}: both shown: {:?}", v.pending);
            assert!(v.warnings.iter().any(|w| w.contains("more than one join request")), "{field}: {:?}", v.warnings);
            let real_code = registry::pairing_code(&key32(2), &request("node-a", 2).ssh_host_key, COORD_KEY);
            let chosen = Request { code: real_code, ..real.clone() };
            assert!(a.approve(&chosen).unwrap_err().to_string().contains("gone"), "{field}");
        }
        // One request again: the admin approves the line with the code.
        store
            .update(|s| {
                s.requests = vec![real.clone()];
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert!(v.unproved.is_empty(), "both carry a valid proof");
        let real_code = registry::pairing_code(&key32(2), &request("node-a", 2).ssh_host_key, COORD_KEY);
        let chosen = v.pending.iter().find(|r| r.code == real_code).expect("the real machine's line").clone();
        assert_eq!(chosen.id, id);
        // Between the look and the key, the registry swaps another machine
        // in under the same id: the one the admin saw is gone.
        store
            .update(|s| {
                let mut evil = request("node-a", 66);
                evil.id = real.id.clone();
                evil.status = registry::Status::Pending;
                evil.created = real.created;
                s.requests = vec![evil];
                Ok(())
            })
            .unwrap();
        a.load().unwrap();
        assert!(a.approve(&chosen).unwrap_err().to_string().contains("changed it since you looked"));
        assert!(a.reject(&chosen).is_err());
        store
            .update(|s| {
                s.requests = vec![real.clone()];
                Ok(())
            })
            .unwrap();
        a.load().unwrap();
        a.approve(&chosen).unwrap();
        let list = store.read().unwrap().signed.list(&Key("admin"), |h| h < 255).unwrap();
        let signed: Vec<String> = list.members.iter().filter(|e| e.host != 1).map(|e| e.wg_key.clone()).collect();
        assert_eq!(signed, vec![key32(2)], "the admin approved node-a with code {real_code}; the desktop signed another key");
    }

    #[test]
    fn approve_signs_and_publishes() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        let v = a.load().unwrap();
        assert_eq!(v.version, 0);
        assert_eq!(v.unsigned(), vec!["coord".to_string()], "nothing is signed before the first approval");
        assert_eq!(v.pending.len(), 1);
        assert_eq!(v.pending[0].code, registry::pairing_code(&key32(2), &request("node-a", 2).ssh_host_key, COORD_KEY));

        assert_eq!(a.approve(&by_id(&a, &id)).unwrap(), 2);
        let s = store.read().unwrap();
        assert_eq!(s.members.len(), 2);
        assert_eq!(s.requests[0].status, Status::Approved);
        assert!(s.signed_version > 1_600_000_000, "the version starts at the clock: {}", s.signed_version);
        // The coordinator now serves exactly what was signed, and this
        // desktop kept a copy.
        let list = s.signed.list(&Key("admin"), |h| h < 255).unwrap();
        assert_eq!(list.members.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["coord", "node-a"]);
        let copy: Envelope = serde_json::from_slice(&std::fs::read(dir.join("secrets").join(SIGNED_COPY)).unwrap()).unwrap();
        assert_eq!(copy, s.signed);

        let v = a.load().unwrap();
        assert!(v.unsigned().is_empty() && v.pending.is_empty() && v.warnings.is_empty(), "{v:?}");
        assert_eq!(v.version, s.signed_version);

        // Next free number; a second approval raises the version.
        let id = ask(&store, "node-b", 3);
        a.load().unwrap();
        assert_eq!(a.approve(&by_id(&a, &id)).unwrap(), 3);
        assert!(store.read().unwrap().signed_version > s.signed_version);
    }

    #[test]
    fn reject_and_remove() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let (ida, idb) = (ask(&store, "node-a", 2), ask(&store, "node-b", 3));
        a.load().unwrap();
        a.approve(&by_id(&a, &ida)).unwrap();
        a.load().unwrap();
        a.reject(&by_id(&a, &idb)).unwrap();
        let s = store.read().unwrap();
        assert!(s.pending().is_empty());
        assert_eq!(s.members.len(), 2);

        a.load().unwrap();
        assert!(a.remove("coord").unwrap_err().to_string().contains("cannot be removed"));
        a.remove("node-a").unwrap();
        assert_eq!(store.read().unwrap().members.len(), 1);
        assert!(a.approve(&by_id(&a, "nope")).unwrap_err().to_string().contains("gone"));
    }

    #[test]
    fn only_the_coordinator_is_signed_without_a_request() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        // Machines that are on the coordinator without the admin: only the
        // coordinator itself can have put them there.
        store
            .update(|s| {
                for (host, name, seed) in [(2, "node-a", 2), (3, "rogue", 3)] {
                    s.members.push(Member {
                        host,
                        name: name.into(),
                        wg_key: key32(seed),
                        ssh_host_key: "ssh-ed25519 AAAAx".into(),
                        ..Member::default()
                    });
                }
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.unsigned().len(), 3);
        assert_eq!(v.coordinator_code, registry::coordinator_code(&key32(1), COORD_KEY));
        assert_eq!(v.would_drop(&[]), vec!["node-a".to_string(), "rogue".into()]);

        a.sign_coordinator().unwrap();
        let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["coord"], "the first signature covers the coordinator and nothing else");
        let v = a.load().unwrap();
        assert!(v.unsigned().is_empty() && v.would_drop(&[]).is_empty());
        assert!(a.sign_coordinator().unwrap_err().to_string().contains("signed already"));
    }

    #[test]
    fn coordinator_needs_the_proof_from_the_stick() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        // Something answers at the coordinator's address with keys of its
        // own, tried until the 6-digit code matched: it has no proof.
        for bad in ["", "0000000000000000000000000000000000000000000000000000000000000000"] {
            store
                .update(|s| {
                    s.coordinator_proof = bad.into();
                    Ok(())
                })
                .unwrap();
            let id = ask(&store, "node-a", 2);
            a.load().unwrap();
            assert!(a.sign_coordinator().unwrap_err().to_string().contains("no valid proof from your USB stick"));
            // The first approval would sign the coordinator too: refused.
            assert!(a.approve(&by_id(&a, &id)).unwrap_err().to_string().contains("no valid proof from your USB stick"));
            assert_eq!(store.read().unwrap().signed_version, 0);
            assert!(!dir.join("secrets").join(SIGNED_COPY).exists());
        }
        // A proof for other keys (taken from another install) does not fit.
        store
            .update(|s| {
                s.coordinator_proof = registry::join_proof(SECRET, "coord", &key32(99), COORD_KEY);
                Ok(())
            })
            .unwrap();
        a.load().unwrap();
        assert!(a.sign_coordinator().is_err());
    }

    /// A reinstalled coordinator: fresh registry, new keys, new proof.
    pub fn reinstalled(dir: &TempDir, name: &str, proof_secret: &str) -> (Store, String) {
        let new_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInewcoordinator";
        let store = Store::new(dir.join("registry-new.json"));
        store
            .update(|s| {
                s.members = vec![Member {
                    host: 1,
                    name: name.into(),
                    wg_key: key32(41),
                    ssh_host_key: format!("{new_key} root@coord"),
                    lan_ip: "192.168.1.50".into(),
                    ..Member::default()
                }];
                s.coordinator_proof = registry::join_proof(proof_secret, name, &key32(41), new_key);
                Ok(())
            })
            .unwrap();
        (store, new_key.to_string())
    }

    #[test]
    fn a_reinstalled_coordinator_is_taken_over() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let v1 = store.read().unwrap().signed_version;

        // The coordinator was hacked, cut off and reinstalled.
        let (new_store, new_key) = reinstalled(&dir, "coord", SECRET);
        let pinned = Arc::new(Mutex::new(COORD_KEY.to_string()));
        a.link = Box::new(Direct {
            store: Store::new(&new_store.path),
            host_key: new_key.clone(),
            publish_fails: Arc::default(),
            verifier: None,
            pinned: pinned.clone(),
        });
        let e = a.load().unwrap_err();
        assert!(e.is(crate::err::Kind::HostKey), "{e}");

        // Looking changes nothing.
        let c = a.probe_new_coordinator().unwrap();
        assert_eq!(c.name, "coord");
        assert_eq!(c.code, registry::coordinator_code(&key32(41), &new_key));
        assert_eq!(*pinned.lock().unwrap(), COORD_KEY, "probing must leave the old pin");
        assert_eq!(new_store.read().unwrap().signed_version, 0);

        // Accepting pins it and signs a list with it in the old one's place.
        let v2 = a.accept_new_coordinator(&c).unwrap();
        assert!(v2 > v1);
        assert_eq!(*pinned.lock().unwrap(), new_key);
        let s = new_store.read().unwrap();
        let list = s.signed.list(&Key("admin"), |h| h < 255).unwrap();
        assert_eq!(list.members.len(), 2, "every other member stays");
        assert_eq!(
            (list.members[0].host, list.members[0].wg_key.clone(), list.members[0].ssh_host_key.clone()),
            (1, key32(41), new_key.clone())
        );
        assert_eq!(list.members[1].name, "node-a");
        assert_eq!(s.members.len(), 2, "the new coordinator has the members back");
        let v = a.load().unwrap();
        assert!(v.unsigned().is_empty() && v.warnings.is_empty(), "{:?}", v.warnings);
        assert!(a.probe_new_coordinator().unwrap_err().to_string().contains("nothing to replace"));
    }

    #[test]
    fn a_fake_coordinator_is_not_taken_over() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let copy = std::fs::read(dir.join("secrets").join(SIGNED_COPY)).unwrap();
        let attach = |a: &mut Admin, store: &Store, key: &str| {
            let pinned = Arc::new(Mutex::new(COORD_KEY.to_string()));
            a.link = Box::new(Direct {
                store: Store::new(&store.path),
                host_key: key.into(),
                publish_fails: Arc::default(),
                verifier: None,
                pinned: pinned.clone(),
            });
            pinned
        };

        // No proof from the stick (another secret, or none).
        let (fake, key) = reinstalled(&dir, "coord", "not-the-secret-not-the-secret-not-the-secret");
        let pinned = attach(&mut a, &fake, &key);
        assert!(a.probe_new_coordinator().unwrap_err().to_string().contains("no valid proof from your USB stick"));
        assert_eq!(*pinned.lock().unwrap(), COORD_KEY);

        // It claims another SSH key than the one it answers with.
        let (liar, _) = reinstalled(&dir, "coord", SECRET);
        let pinned = attach(&mut a, &liar, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsomethingelse");
        assert!(a.probe_new_coordinator().unwrap_err().to_string().contains("claims another SSH key"));
        assert_eq!(*pinned.lock().unwrap(), COORD_KEY);
        assert_eq!(std::fs::read(dir.join("secrets").join(SIGNED_COPY)).unwrap(), copy, "nothing may be signed");

        // A real reinstall whose name is already a member's.
        let (clash, key) = reinstalled(&dir, "node-a", SECRET);
        let pinned = attach(&mut a, &clash, &key);
        let c = a.probe_new_coordinator().unwrap();
        assert!(a.accept_new_coordinator(&c).unwrap_err().to_string().contains("already has the new coordinator's name"));
        assert_eq!(*pinned.lock().unwrap(), COORD_KEY, "a refused takeover must leave the old pin");
    }

    #[test]
    fn requests_need_the_proof_from_the_stick() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        // The real machine asks. Then a hacked coordinator swaps in its own
        // WireGuard key, and adds a request of its own, with a made-up
        // proof and with none.
        let real = ask(&store, "node-a", 2);
        store
            .update(|s| {
                let mut swapped = s.requests[0].clone();
                swapped.id = "00000000000000aa".into();
                swapped.name = "node-b".into();
                swapped.wg_key = key32(66);
                s.requests.push(swapped);
                let mut made_up = request("node-c", 4);
                made_up.id = "00000000000000bb".into();
                made_up.proof = "0".repeat(64);
                made_up.status = registry::Status::Pending;
                made_up.created = Time::now();
                s.requests.push(made_up);
                let mut none = request("node-d", 5);
                none.id = "00000000000000cc".into();
                none.proof.clear();
                none.status = registry::Status::Pending;
                none.created = Time::now();
                s.requests.push(none);
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.pending.len(), 4);
        assert_eq!(v.unproved, vec!["00000000000000aa".to_string(), "00000000000000bb".into(), "00000000000000cc".into()]);
        for id in &v.unproved {
            let e = a.approve(&by_id(&a, id)).unwrap_err().to_string();
            assert!(e.contains("no valid proof from your USB stick"), "{e}");
        }
        assert_eq!(store.read().unwrap().members.len(), 1, "an unproved request became a member");
        // The untouched request of the real machine goes through.
        a.approve(&by_id(&a, &real)).unwrap();
        // They can still be rejected.
        a.load().unwrap();
        a.reject(&by_id(&a, "00000000000000aa")).unwrap();

        // Without the secret nothing can be judged: refused outright.
        std::fs::remove_file(dir.join("secrets").join(crate::iso::JOIN_SECRET)).unwrap();
        assert!(a.load().unwrap_err().to_string().contains("no join secret"));
    }

    #[test]
    fn cuts_reported_by_members_are_shown() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        store
            .update(|s| {
                s.members.push(Member { host: 2, name: "node-a".into(), wg_key: key32(2), ..Member::default() });
                let cuts =
                    [registry::CutReport { name: "node-c".into(), auto: true }, registry::CutReport { name: "coord".into(), auto: false }];
                s.heartbeat(
                    2,
                    registry::Heartbeat { lan_ip: "192.168.1.23".into(), cuts: cuts.to_vec(), ..registry::Heartbeat::default() },
                    Time::now(),
                )
            })
            .unwrap();
        let v = a.load().unwrap();
        assert_eq!(
            v.reports,
            vec![
                "node-a cut off node-c by itself: node-c tried closed ports on it. Check node-c.".to_string(),
                "node-a has coord cut off (quarantine).".to_string()
            ]
        );
    }

    #[test]
    fn coordinator_text_is_cleaned() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        store
            .update(|s| {
                s.unknown = vec![
                    Device {
                        ip: "192.168.1.77".into(),
                        mac: "aa:bb:cc:dd:ee:ff\x1b[2J".into(),
                        vendor: "Evil\x1b]0;pwned\x07 Corp\n".into(),
                        ..Device::default()
                    },
                    Device { ip: "\x1b[31mnot-an-ip".into(), ..Device::default() },
                ];
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.unknown.len(), 1, "an entry without a real address is not shown");
        let d = &v.unknown[0];
        assert_eq!(d.mac, "aa:bb:cc:dd:ee:ff");
        assert!(!d.vendor.contains('\x1b') && !d.vendor.contains('\x07') && !d.vendor.contains('\n'), "{:?}", d.vendor);
        assert_eq!(clean("a\x1b[2Jb\r\n", 10), "a[2Jb");
        assert_eq!(clean("abcdef", 3), "abc");
    }

    #[test]
    fn coordinator_tampering_is_shown() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();

        // A hacked coordinator adds a machine, swaps a key and sends junk.
        store
            .update(|s| {
                s.members.push(Member { host: 9, name: "rogue".into(), wg_key: key32(9), ..Member::default() });
                s.members.push(Member { host: 10, name: "x archlinux.org".into(), wg_key: key32(10), ..Member::default() });
                s.members[1].wg_key = key32(77);
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.unsigned(), vec!["node-a".to_string(), "rogue".into()], "a swapped key makes the member unsigned");
        let w = v.warnings.join("\n");
        assert!(w.contains("bad entry") && w.contains("Signed by you but not on the coordinator (or changed there): node-a"), "{w}");

        // It rolls back to no signed list at all.
        store
            .update(|s| {
                s.signed = Envelope::default();
                s.signed_version = 0;
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert!(v.version > 0 && v.warnings.join("\n").contains("no valid signed list"), "{:?}", v.warnings);

        // It serves a list signed by someone else.
        let forged = signed::seal(
            &Key("thief"),
            &List {
                version: u64::MAX,
                members: vec![Entry { host: 1, name: "coord".into(), wg_key: key32(1), ssh_host_key: COORD_KEY.into() }],
                rejected: vec![],
                keys: vec![],
                people: vec![],
                vpn: None,
                devices: vec![],
            },
        )
        .unwrap();
        store
            .update(|s| {
                s.signed = forged.clone();
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert!(v.warnings.join("\n").contains("signed list was refused"), "{:?}", v.warnings);
        assert!(v.version < u64::MAX, "a forged list must not become the base");
    }

    #[test]
    fn wrong_coordinator_is_not_signed() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        // The machine we are connected to has another SSH key than the
        // entry claims.
        store
            .update(|s| {
                s.members[0].ssh_host_key = "ssh-ed25519 AAAAsomeoneelse".into();
                Ok(())
            })
            .unwrap();
        let id = ask(&store, "node-a", 2);
        let v = a.load().unwrap();
        assert!(v.warnings.join("\n").contains("Do not sign"), "{:?}", v.warnings);
        assert!(a.approve(&by_id(&a, &id)).unwrap_err().to_string().contains("nothing signed"));
        assert!(!dir.join("secrets").join(SIGNED_COPY).exists());
        assert_eq!(store.read().unwrap().signed_version, 0);
    }

    #[test]
    fn versions_never_repeat() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let v1 = store.read().unwrap().signed_version;

        // This desktop's copy is lost: the coordinator's verified list is
        // taken over and the next version is still higher.
        std::fs::remove_file(dir.join("secrets").join(SIGNED_COPY)).unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.version, v1);
        assert!(dir.join("secrets").join(SIGNED_COPY).exists());
        let id = ask(&store, "node-b", 3);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let v2 = store.read().unwrap().signed_version;
        assert!(v2 > v1);

        // A clock set far back still gives a higher version.
        a.load().unwrap();
        a.now = || Time::ymd_hms(2001, 1, 1, 0, 0, 0);
        a.remove("node-b").unwrap();
        assert_eq!(store.read().unwrap().signed_version, v2 + 1);
        // With such a clock the coordinator refuses to show its registry.
        assert!(a.load().unwrap_err().to_string().contains("check the clock"));

        // A damaged copy is reported and not used.
        std::fs::write(dir.join("secrets").join(SIGNED_COPY), "{broken").unwrap();
        a.now = Time::now;
        let v = a.load().unwrap();
        assert!(v.warnings.join("\n").contains("was refused") && v.version == v2 + 1, "{:?}", v.warnings);
    }

    /// Desktop, coordinator and node with real OpenSSH keys and signatures.
    #[test]
    fn real_keys_end_to_end() {
        use crate::signed::{SshSigner, SshVerifier};
        if !crate::iso::in_path("ssh-keygen") {
            return;
        }
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let make = |name: &str| {
            let key = dir.join(name);
            assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status().unwrap().success());
            key
        };
        let (signing, thief) = (make("signing_ed25519"), make("thief"));
        let checker = || SshVerifier { pubkey: dir.join("signing_ed25519.pub"), tmp_dir: dir.path().to_path_buf() };
        a.signer = Box::new(SshSigner { key: signing });
        a.verifier = Box::new(checker());
        a.link = Box::new(Direct {
            store: Store::new(&store.path),
            host_key: COORD_KEY.into(),
            publish_fails: Arc::default(),
            verifier: Some(Box::new(checker())),
            pinned: Arc::new(Mutex::new(COORD_KEY.into())),
        });

        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        assert_eq!(a.approve(&by_id(&a, &id)).unwrap(), 2);
        let s = store.read().unwrap();
        assert_eq!(s.members.len(), 2);

        // A node uses what the coordinator hands out only as far as it is
        // signed.
        let node = crate::node::Node {
            cfg: crate::config::Config { wg_subnet: "10.66.0.0/24".into(), ..crate::config::Config::default() },
            hostname: "node-a".into(),
            root: dir.join("node"),
            run: Arc::new(crate::runner::ExecRunner::silent()),
            tmp_dir: None,
            verifier: Arc::new(checker()),
        };
        let (members, status) = node.signed_members(2, &s.members, &s.signed).unwrap();
        assert_eq!(members.len(), 2);
        assert!(status.starts_with("ok: signed version"), "{status}");
        let mut more = s.members.clone();
        more.push(Member { host: 9, name: "rogue".into(), wg_key: key32(9), ..Member::default() });
        let (members, status) = node.signed_members(2, &more, &s.signed).unwrap();
        assert!(members.len() == 2 && status.contains("IGNORED, not signed by the admin: rogue"), "{status}");

        // Someone with the registry key but another signing key gets nothing.
        a.signer = Box::new(SshSigner { key: thief });
        assert!(a.load().unwrap_err().to_string().contains("bad signature"), "the registry opened for a wrong key");
        let forged = signed::seal(
            a.signer.as_ref(),
            &List {
                version: u64::MAX,
                members: vec![Entry::of(&s.members[0])],
                rejected: vec![],
                keys: vec![],
                people: vec![],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(a.link.call("publish", &serde_json::to_string(&forged).unwrap()).unwrap_err().to_string().contains("bad signature"));
        assert_eq!(store.read().unwrap().members.len(), 2);
        assert!(node.signed_members(2, &s.members, &forged).unwrap_err().to_string().contains("bad signature"));
    }

    /// A program as `make` builds it, as far as check_static looks: a
    /// static x86-64 ELF header.
    pub fn static_binary(dir: &TempDir, name: &str, body: &str) -> PathBuf {
        let mut b = vec![0u8; 64 + 56];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(body.as_bytes());
        let p = dir.join(name);
        std::fs::write(&p, b).unwrap();
        p
    }

    /// Uploads as sent: command, header, files.
    type Uploads = Arc<Mutex<Vec<(String, String, Vec<PathBuf>)>>>;

    /// The registry for everything but uploads, which it records and takes.
    struct Recorder {
        inner: Direct,
        uploads: Uploads,
    }

    impl Link for Recorder {
        fn call(&self, command: &str, stdin: &str) -> Result<String> {
            self.inner.call(command, stdin)
        }
        fn upload(&self, command: &str, header: &str, files: &[&Path]) -> Result<String> {
            self.uploads.lock().unwrap().push((command.into(), header.into(), files.iter().map(|p| p.to_path_buf()).collect()));
            Ok(r#"{"serial":1}"#.into())
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

    fn recording(a: &mut Admin, store: &Store) -> Uploads {
        let uploads: Uploads = Arc::default();
        a.link = Box::new(Recorder {
            inner: Direct {
                store: Store::new(&store.path),
                host_key: COORD_KEY.into(),
                publish_fails: Arc::default(),
                verifier: None,
                pinned: Arc::new(Mutex::new(COORD_KEY.into())),
            },
            uploads: uploads.clone(),
        });
        uploads
    }

    /// A desktop whose trusted key is in its file (like SshVerifier), with
    /// a coordinator that follows the key changes of its stored list (like
    /// Trust::for_registry). Uploads are recorded, not stored.
    fn chained(dir: &TempDir) -> (Admin, Store, Arc<Mutex<bool>>) {
        let (mut a, store, _) = setup_failing(dir);
        let pubf = dir.join("secrets").join(crate::iso::SIGNING_PUB);
        std::fs::write(&pubf, format!("{} dryserver-signing\n", Key("admin").public())).unwrap();
        a.verifier = Box::new(signed::fake::FileKey(pubf));
        let fails: Arc<Mutex<bool>> = Arc::default();
        a.link = Box::new(Recorder {
            inner: Direct {
                store: Store::new(&store.path),
                host_key: COORD_KEY.into(),
                publish_fails: fails.clone(),
                verifier: Some(Box::new(signed::fake::Chained { base: "admin", newest: store.path.clone() })),
                pinned: Arc::new(Mutex::new(COORD_KEY.into())),
            },
            uploads: Arc::default(),
        });
        (a, store, fails)
    }

    #[test]
    fn people_are_let_in_and_taken_out_by_signed_list() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        a.load().unwrap();
        a.sign_coordinator().unwrap();
        let alice = signed::Person { name: "alice".into(), keys: vec!["ssh-ed25519 AAAAalice alice@laptop".into()], on: vec![] };
        let v = a.let_in(&alice, "admin").unwrap();
        let s = store.read().unwrap();
        let list = s.signed.list(&Key("admin"), |h| h < 255).unwrap();
        assert_eq!(list.version, v);
        // Keys without their comments.
        assert_eq!(list.people, vec![signed::Person { keys: vec!["ssh-ed25519 AAAAalice".into()], ..alice.clone() }]);
        // Again with another key and a machine: changed, not twice.
        let on = signed::Person { keys: vec!["ssh-ed25519 AAAAnew".into()], on: vec!["coord".into()], ..alice.clone() };
        a.let_in(&on, "admin").unwrap();
        assert_eq!(a.people().len(), 1);
        assert_eq!(a.people()[0].on, vec!["coord"]);
        // Refused before anything is signed.
        let v = a.load().unwrap().version;
        for (p, why) in [
            (signed::Person { name: "admin".into(), ..alice.clone() }, "cannot be a person's account"),
            (signed::Person { name: "root".into(), ..alice.clone() }, "cannot be a person's account"),
            (signed::Person { name: "Al ice".into(), ..alice.clone() }, "cannot be a person's account"),
            (signed::Person { keys: vec![], ..alice.clone() }, "at least one"),
            (signed::Person { keys: vec!["hello".into()], ..alice.clone() }, "not an SSH public key"),
            (signed::Person { on: vec!["nowhere".into()], ..alice.clone() }, "no machine called nowhere"),
        ] {
            let e = a.let_in(&p, "admin").unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
        }
        assert_eq!(a.load().unwrap().version, v);
        a.take_out("alice").unwrap();
        assert!(a.people().is_empty());
        assert!(a.take_out("alice").unwrap_err().to_string().contains("not let in"));
    }

    #[test]
    fn a_removed_machine_goes_from_where_people_may_log_in() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let ida = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &ida)).unwrap();
        a.load().unwrap();
        let p = |name: &str, on: &[&str]| signed::Person {
            name: name.into(),
            keys: vec![format!("ssh-ed25519 AAAA{name}")],
            on: on.iter().map(|s| s.to_string()).collect(),
        };
        for q in [p("only", &["node-a"]), p("both", &["coord", "node-a"]), p("all", &[])] {
            a.let_in(&q, "admin").unwrap();
        }
        let notes = a.remove("node-a").unwrap();
        // Never widened to every server: someone let in only there is out.
        let left: Vec<(String, Vec<String>)> = a.people().iter().map(|q| (q.name.clone(), q.on.clone())).collect();
        assert_eq!(left, vec![("both".into(), vec!["coord".into()]), ("all".into(), vec![])]);
        assert!(notes.iter().any(|n| n.contains("only could log in only on node-a: taken out too")), "{notes:?}");
    }

    #[test]
    fn the_vpn_and_its_devices_are_in_the_signed_list() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        a.run = Arc::new(HostKeys);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&by_id(&a, &id)).unwrap();
        let phone = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let laptop = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
        // Not before the VPN is set up; never on the coordinator.
        assert!(a.vpn_add("phone", phone).unwrap_err().to_string().contains("set the VPN up first"));
        let on = |gw: &str| crate::vpn::Plan::new(gw, "vpn.example.com");
        assert!(a.vpn_on(&on("coord")).unwrap_err().to_string().contains("cannot be the coordinator"));
        assert!(a.vpn_on(&on("nowhere")).unwrap_err().to_string().contains("not a machine of the swarm"));
        let clash = crate::vpn::Plan { subnet: a.subnet.clone(), ..on("node-a") };
        assert!(a.vpn_on(&clash).unwrap_err().to_string().contains("overlaps the mesh"));
        a.vpn_on(&on("node-a")).unwrap();
        let (d, v) = a.vpn_add("phone", phone).unwrap();
        assert_eq!(d.addr, "10.99.0.2");
        let list = store.read().unwrap().signed.list(&Key("admin"), |h| h < 255).unwrap();
        assert_eq!((list.version, list.vpn.as_ref().map(|p| p.gateway.as_str()), list.devices.len()), (v, Some("node-a"), 1));
        let (d2, _) = a.vpn_add("laptop", laptop).unwrap();
        assert_eq!(d2.addr, "10.99.0.3");
        for (name, key, why) in [
            ("phone", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "a device called phone already"),
            ("tablet", phone, "another device's or a machine's"),
            ("tablet", &key32(1), "another device's or a machine's"),
            ("Tab let", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=", "a device's name"),
            ("tablet", "not-a-key", "not a WireGuard public key"),
        ] {
            let e = a.vpn_add(name, key).unwrap_err().to_string();
            assert!(e.contains(why), "{why}: {e}");
        }
        // The subnet stays while devices are in it.
        let moved = crate::vpn::Plan { subnet: "10.98.0.0/24".into(), ..on("node-a") };
        assert!(a.vpn_on(&moved).unwrap_err().to_string().contains("addresses in another subnet"));
        // Off: the devices stay for when it is back.
        a.vpn_off().unwrap();
        assert!(a.vpn().is_none() && a.devices().len() == 2);
        assert!(a.vpn_off().unwrap_err().to_string().contains("not set up"));
        a.vpn_on(&on("node-a")).unwrap();
        a.vpn_remove("phone").unwrap();
        assert_eq!(a.devices().iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), vec!["laptop"]);
        assert!(a.vpn_remove("phone").unwrap_err().to_string().contains("no device called phone"));
        // The freed address is the next one handed out.
        assert_eq!(a.vpn_add("tablet", phone).unwrap().0.addr, "10.99.0.2");
        assert_eq!(a.machine_key("node-a"), Some(key32(2)));
        // Removing the gateway (a hacked one, say) is never refused: the
        // VPN goes with it, the devices stay.
        a.remove("node-a").unwrap();
        assert!(a.vpn().is_none() && a.devices().len() == 2);
    }

    #[test]
    fn replace_key_hands_the_trust_to_the_new_key_everywhere() {
        let dir = TempDir::new();
        let (mut a, store, _) = chained(&dir);
        a.load().unwrap();
        a.sign_coordinator().unwrap();
        // A release on the coordinator, signed with the old key.
        let bin = static_binary(&dir, "dryserver", "0.2.0");
        let d = release::Draft { binary: &bin, version: "0.2.0", arch_date: "2026/11/19", ..release::Draft::default() };
        let r = a.publish_release(&d, &dir.join("no-k3s")).unwrap();
        let served = fsx::dir(&store.path).join(rollout::SERVED_DIR).join(r.serial.to_string());
        std::fs::create_dir_all(&served).unwrap();
        std::fs::copy(dir.join("secrets").join(RELEASE_COPY), served.join(rollout::RELEASE_FILE)).unwrap();
        std::fs::write(fsx::dir(&store.path).join(rollout::SERVED_DIR).join("current"), format!("{}\n", r.serial)).unwrap();
        a.load().unwrap();

        let (old, new) = (Key("admin"), Key("admin2"));
        // Not to the key trusted now, nor to something not ed25519.
        assert!(a.replace_key(Box::new(Key("admin")), &old.public(), true).unwrap_err().to_string().contains("trusts now"));
        assert!(a.replace_key(Box::new(Key("x")), "ssh-rsa AAAA", true).unwrap_err().to_string().contains("ed25519"));
        let done = a.replace_key(Box::new(Key("admin2")), &new.public(), true).unwrap();
        assert_eq!((done.release, done.warning.clone()), (Some(r.serial), None), "{done:?}");
        // This computer trusts the new key...
        let pubf = dir.join("secrets").join(crate::iso::SIGNING_PUB);
        assert_eq!(key_body(&std::fs::read_to_string(&pubf).unwrap()), new.public());
        // ...the coordinator's list carries the change, signed by the old
        // key, and the list by the new one: a machine on the old key
        // follows it.
        let s = store.read().unwrap();
        let (list, by) = s.signed.list_signed_by(&old, |h| h < 255).unwrap();
        assert_eq!(by, Some(new.public()));
        let change: signed::KeyChange = serde_json::from_str(&list.keys[0].doc).unwrap();
        assert_eq!((change.from, change.to, change.login), (old.public(), new.public(), true));
        assert_eq!(list.version, done.version);
        // The release on the coordinator and this computer's copy are
        // signed by the new key, the text as it was.
        let now = Time::now().0.timestamp();
        let env: Envelope = serde_json::from_str(&std::fs::read_to_string(served.join(rollout::RELEASE_FILE)).unwrap()).unwrap();
        assert_eq!(release::open(&new, &env, now).unwrap(), r);
        assert!(release::open(&old, &env, now).is_err());
        let copy: Envelope = serde_json::from_slice(&std::fs::read(dir.join("secrets").join(RELEASE_COPY)).unwrap()).unwrap();
        assert_eq!(copy, env);
        // Everything goes on with the new key: loading, signing.
        let v = a.load().unwrap();
        assert!(v.warnings.is_empty(), "{:?}", v.warnings);
        assert!(a.resend().unwrap() > done.version);
        // The old key is refused by the coordinator.
        let ask = signed::seal_admin(&old, "state", now).unwrap();
        assert!(a.link.call("admin", &serde_json::to_string(&ask).unwrap()).is_err());

        // A second computer still on the old key follows the change on its
        // next load, and says so.
        let dir2 = TempDir::new();
        let (mut b, _, _) = chained(&dir2);
        b.link = Box::new(Direct {
            store: Store::new(&store.path),
            host_key: COORD_KEY.into(),
            publish_fails: Arc::default(),
            verifier: Some(Box::new(signed::fake::Chained { base: "admin", newest: store.path.clone() })),
            pinned: Arc::new(Mutex::new(COORD_KEY.into())),
        });
        std::fs::write(dir2.join("secrets").join(crate::iso::SIGNING_KEY_NAME), "an older swarm's own key").unwrap();
        // Its asks are refused now; it reads the list anyone may, follows
        // the change and says why it cannot go on.
        let w = b.load().unwrap_err().to_string();
        assert!(w.contains("replaced on another computer") && w.contains("needs that key"), "{w}");
        assert_eq!(key_body(&std::fs::read_to_string(dir2.join("secrets").join(crate::iso::SIGNING_PUB)).unwrap()), new.public());
        assert!(!dir2.join("secrets").join(crate::iso::SIGNING_KEY_NAME).exists(), "the handed-on key no longer signs");
        assert_eq!(std::fs::read_dir(dir2.join("secrets").join("replaced")).unwrap().count(), 1);
        // With the new key there (import), it goes on.
        b.signer = Box::new(Key("admin2"));
        let w = b.load().unwrap().warnings.join("\n");
        assert!(!w.contains("replaced on another computer"), "said once: {w}");
        assert!(b.resend().is_ok());
    }

    #[test]
    fn replace_key_waits_for_a_rollout_and_says_what_a_failed_send_left() {
        let dir = TempDir::new();
        let (mut a, store, fails) = chained(&dir);
        a.load().unwrap();
        // Nothing signed yet: the stick takes the key from the config.
        assert!(
            a.replace_key(Box::new(Key("admin2")), &Key("admin2").public(), true).unwrap_err().to_string().contains("nothing is signed")
        );
        a.sign_coordinator().unwrap();
        store
            .update(|s| {
                s.rollout.serial = 7;
                s.rollout.phase = rollout::Phase::Brain;
                Ok(())
            })
            .unwrap();
        let e = a.replace_key(Box::new(Key("admin2")), &Key("admin2").public(), true).unwrap_err().to_string();
        assert!(e.contains("rolling out"), "{e}");
        store
            .update(|s| {
                s.rollout = Rollout::default();
                Ok(())
            })
            .unwrap();
        // The coordinator does not answer the publish: this computer is on
        // the new key already, and says how the coordinator gets it.
        *fails.lock().unwrap() = true;
        let e = a.replace_key(Box::new(Key("admin2")), &Key("admin2").public(), true).unwrap_err().to_string();
        assert!(e.contains("did not take it yet"), "{e}");
        assert_eq!(a.verifier.key(), Some(Key("admin2").public()));
        *fails.lock().unwrap() = false;
        a.load().unwrap();
        a.resend().unwrap();
        let (_, by) = store.read().unwrap().signed.list_signed_by(&Key("admin"), |h| h < 255).unwrap();
        assert_eq!(by, Some(Key("admin2").public()));
    }

    /// Release N failed on the coordinator and went back: the machines run
    /// M < N. A release between M and N was refused without -rollback,
    /// here and on the coordinator, as both compared with N. Now the
    /// versions go by M (this computer's signed copy of it), and the serial
    /// still comes after N.
    #[test]
    fn after_a_release_that_went_back_the_versions_go_by_what_the_machines_run() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        recording(&mut a, &store);
        a.load().unwrap();
        let k3s = dir.join("no-k3s");
        // What the coordinator took: the release this computer signed last.
        let took = |serial: u64| {
            let served = fsx::dir(&store.path).join(rollout::SERVED_DIR);
            std::fs::create_dir_all(served.join(serial.to_string())).unwrap();
            std::fs::copy(dir.join("secrets").join(RELEASE_COPY), served.join(serial.to_string()).join(rollout::RELEASE_FILE)).unwrap();
            std::fs::write(served.join("current"), format!("{serial}\n")).unwrap();
        };
        let at = |v: &str| static_binary(&dir, &format!("dryserver-{v}"), v);
        let (b1, b3, b2, b0) = (at("0.2.0"), at("0.4.0"), at("0.3.0"), at("0.1.9"));
        fn d<'a>(bin: &'a Path, version: &'a str) -> release::Draft<'a> {
            release::Draft { binary: bin, version, arch_date: "2026/11/19", ..release::Draft::default() }
        }
        let m = a.publish_release(&d(&b1, "0.2.0"), &k3s).unwrap();
        took(m.serial);
        let copies = dir.join("secrets").join(crate::publish::COPIES);
        std::fs::create_dir_all(&copies).unwrap();
        std::fs::copy(dir.join("secrets").join(RELEASE_COPY), copies.join(format!("{}.json", m.serial))).unwrap();
        let n = a.publish_release(&d(&b3, "0.4.0"), &k3s).unwrap();
        took(n.serial);
        // Before it went back: 0.3.0 is older than the swarm's.
        a.load().unwrap();
        assert!(a.draft_release(&d(&b2, "0.3.0")).unwrap_err().to_string().contains("rollback"));
        store
            .update(|s| {
                s.rollout = Rollout { serial: n.serial, phase: rollout::Phase::Failed, paused: "it reverted".into(), ..Rollout::default() };
                s.members[0].report = Some(crate::report::Report {
                    release: m.serial,
                    update: "reverted".into(),
                    update_serial: n.serial,
                    ..crate::report::Report::default()
                });
                Ok(())
            })
            .unwrap();
        a.load().unwrap();
        assert_eq!(a.release_base().map(|r| r.serial), Some(m.serial));
        assert!(a.draft_release(&d(&b0, "0.1.9")).unwrap_err().to_string().contains("rollback"), "below M");
        let r = a.publish_release(&d(&b2, "0.3.0"), &k3s).unwrap();
        assert!(r.serial > n.serial && !r.rollback, "{r:?}");
        // Without this computer's copy of M: the versions go by what this
        // dryserver is, as before any release, and by the machines
        // themselves; the serial still follows N.
        let mut a2 = setup(&dir).0;
        recording(&mut a2, &store);
        a2.secrets = dir.join("other-secrets");
        std::fs::create_dir_all(&a2.secrets).unwrap();
        std::fs::write(a2.secrets.join(crate::iso::JOIN_SECRET), format!("{SECRET}\n")).unwrap();
        a2.load().unwrap();
        assert!(a2.release_base().is_none());
        assert!(a2.draft_release(&d(&b2, "0.3.0")).unwrap().serial > n.serial);
    }

    #[test]
    fn a_release_is_signed_kept_and_sent() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let uploads = recording(&mut a, &store);
        a.load().unwrap();
        let bin = static_binary(&dir, "dryserver", "0.2.0");
        let d = release::Draft { binary: &bin, version: "0.2.0", arch_date: "2026/11/19", notes: "fixes X", ..release::Draft::default() };
        let r = a.publish_release(&d, &dir.join("no-k3s")).unwrap();
        assert!(r.serial as i64 >= Time::now().0.timestamp() - 5 && r.notes == "fixes X" && !r.urgent);
        // Sent: the signed release, then the binary; no k3s unless asked.
        let up = uploads.lock().unwrap().clone();
        assert_eq!(up.len(), 1);
        assert_eq!((up[0].0.as_str(), up[0].2.clone()), ("release-put", vec![bin.clone()]));
        let head: rollout::PutHeader = serde_json::from_str(up[0].1.trim_end()).unwrap();
        assert!(up[0].1.ends_with('\n') && head.k3s_size == 0);
        assert_eq!(release::open(&Key("admin"), &head.release, Time::now().0.timestamp()).unwrap(), r);
        // Kept here before it was sent.
        let copy: Envelope = serde_json::from_slice(&std::fs::read(dir.join("secrets").join(RELEASE_COPY)).unwrap()).unwrap();
        assert_eq!(copy, head.release);

        // The next one goes up from it, also published at once after it.
        let urgent = a.publish_release(&release::Draft { urgent: true, ..d.clone() }, &dir.join("no-k3s")).unwrap();
        assert!(urgent.serial > r.serial && urgent.urgent);
        // An older dryserver needs rollback; refused before anything is
        // signed or sent.
        let old = release::Draft { version: "0.1.9", ..d.clone() };
        let e = a.publish_release(&old, &dir.join("no-k3s")).unwrap_err().to_string();
        assert!(e.contains("rollback"), "{e}");
        assert_eq!(uploads.lock().unwrap().len(), 2);
        assert!(a.publish_release(&release::Draft { rollback: true, ..old }, &dir.join("no-k3s")).unwrap().rollback);
        // Notes that are not printable ASCII are refused here too.
        let e = a.publish_release(&release::Draft { notes: "line\nbreak", ..d.clone() }, &dir.join("no-k3s")).unwrap_err().to_string();
        assert!(e.contains("notes"), "{e}");
    }

    #[test]
    fn only_a_static_binary_is_published() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let uploads = recording(&mut a, &store);
        a.load().unwrap();
        let bin = static_binary(&dir, "dryserver", "x");
        // The same with a program header that asks for a dynamic loader.
        let mut b = std::fs::read(&bin).unwrap();
        b[64..68].copy_from_slice(&3u32.to_le_bytes());
        std::fs::write(&bin, b).unwrap();
        let d = release::Draft { binary: &bin, version: "0.2.0", arch_date: "2026/11/19", ..release::Draft::default() };
        let e = a.publish_release(&d, &dir.join("no-k3s")).unwrap_err().to_string();
        assert!(e.contains("linked against this computer's libraries") && e.contains("make"), "{e}");
        assert!(uploads.lock().unwrap().is_empty() && !dir.join("secrets").join(RELEASE_COPY).exists());
    }

    #[test]
    fn the_coordinator_asks_for_k3s_when_it_has_another() {
        let dir = TempDir::new();
        let (mut a, _) = setup(&dir);
        a.load().unwrap();
        let bin = static_binary(&dir, "dryserver", "0.2.0");
        let d = release::Draft { binary: &bin, version: "0.2.0", arch_date: "2026/11/19", ..release::Draft::default() };
        // The real registry: it has no k3s of the release's.
        let e = a.publish_release(&d, &dir.join("no-k3s")).unwrap_err().to_string();
        assert!(e.contains("the coordinator needs k3s") && e.contains("build the USB stick once"), "{e}");
        std::fs::write(dir.join("desktop-k3s"), "not the pinned k3s").unwrap();
        let e = a.publish_release(&d, &dir.join("desktop-k3s")).unwrap_err().to_string();
        assert!(e.contains("is not k3s") && e.contains(crate::iso::K3S_SHA256), "{e}");
        // Nothing reached the coordinator, and each try used a serial of its
        // own.
        let served = Direct {
            store: Store::new(dir.join("registry.json")),
            host_key: String::new(),
            publish_fails: Arc::default(),
            verifier: None,
            pinned: Arc::default(),
        }
        .served();
        assert_eq!(served.current(), None);
        assert!(a.last_release().is_some());
    }

    #[test]
    fn the_view_shows_the_release_and_the_coordinators_clock() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let now = Time::now().0.timestamp();
        let r = release::Release {
            serial: 77,
            created: now - 60,
            expires: now + release::LIFETIME,
            dryserver: release::Binary { version: "0.2.0".into(), sha256: "a".repeat(64), size: 10 },
            k3s: release::K3s { version: crate::iso::K3S_VERSION.into(), sha256: crate::iso::K3S_SHA256.into() },
            arch_date: "2026/11/19".into(),
            rollback: false,
            urgent: true,
            notes: "fixes X".into(),
            settings: None,
        };
        let served = fsx::dir(&store.path).join(rollout::SERVED_DIR);
        let put_release = |key: &Key| {
            std::fs::create_dir_all(served.join("77")).unwrap();
            std::fs::write(served.join("77").join(rollout::RELEASE_FILE), serde_json::to_string(&release::seal(key, &r).unwrap()).unwrap())
                .unwrap();
            std::fs::write(served.join("current"), "77\n").unwrap();
        };
        put_release(&Key("admin"));
        store
            .update(|s| {
                s.rollout = Rollout { serial: 77, urgent: true, phase: rollout::Phase::Brain, ..Rollout::default() };
                Ok(())
            })
            .unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.release.as_ref().map(|x| x.serial), Some(77));
        assert_eq!(v.rollout.phase, rollout::Phase::Brain);
        assert!((v.coordinator_now - now).abs() < 5 && v.warnings.is_empty(), "{:?}", v.warnings);
        assert_eq!(a.last_release().map(|x| x.serial), Some(77), "the coordinator's release counts for the next serial");
        // Signed by someone else: not shown, said so.
        put_release(&Key("thief"));
        let v = a.load().unwrap();
        assert!(v.release.is_none() && v.warnings.iter().any(|w| w.contains("newest release was refused")), "{:?}", v.warnings);
        // This computer's clock is ten minutes ahead of the coordinator's.
        a.now = || Time::now().add(chrono::TimeDelta::minutes(10));
        let v = a.load().unwrap();
        assert!(v.warnings.iter().any(|w| w.contains("The coordinator's clock is 10m behind this computer's")), "{:?}", v.warnings);
    }

    #[test]
    fn resume_needs_a_rollout() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        a.load().unwrap();
        assert!(a.resume_release().unwrap_err().to_string().contains("no rollout to resume"));
        store
            .update(|s| {
                s.rollout = Rollout { serial: 5, phase: rollout::Phase::Servers, paused: "x".into(), ..Rollout::default() };
                Ok(())
            })
            .unwrap();
        // Asked for the stop as last seen: it changed since.
        let e = a.resume_release().unwrap_err().to_string();
        assert!(e.contains("look again") && e.contains("release 5"), "{e}");
        a.load().unwrap();
        assert_eq!(a.resume_release().unwrap(), 1);
        let r = store.read().unwrap().rollout;
        assert_eq!(r.resume_asked, 1);
        // The ask itself is kept, signed, naming the release and the stop.
        let ask = signed::open_request(&Key("admin"), &r.resume_ask, "release-resume", Time::now().0.timestamp()).unwrap();
        assert_eq!((ask.serial, ask.host), (5, 0));
        // Passing over needs a stop at a server, never the coordinator.
        assert!(a.skip_release().unwrap_err().to_string().contains("not stopped at a server"));
        let at = |a: &mut Admin, phase, pause_host| {
            store
                .update(|s| {
                    s.rollout = Rollout { serial: 5, phase, paused: "x".into(), pause_host, ..s.rollout.clone() };
                    Ok(())
                })
                .unwrap();
            a.load().unwrap();
        };
        at(&mut a, rollout::Phase::Failed, 0);
        assert!(a.skip_release().unwrap_err().to_string().contains("never passed over"));
        at(&mut a, rollout::Phase::Servers, 2);
        assert_eq!(a.skip_release().unwrap(), 1);
        let r = store.read().unwrap().rollout;
        assert_eq!((r.skip_asked, r.resume_asked), (1, 1));
        let ask = signed::open_request(&Key("admin"), &r.skip_ask, "release-skip", Time::now().0.timestamp()).unwrap();
        assert_eq!((ask.serial, ask.host), (5, 2));
    }

    #[test]
    fn failed_send_is_recovered() {
        let dir = TempDir::new();
        let (mut a, store, fails) = setup_failing(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        *fails.lock().unwrap() = true;
        assert!(a.approve(&by_id(&a, &id)).unwrap_err().to_string().contains("cannot reach"));
        // Signed and kept here, not on the coordinator.
        assert_eq!(store.read().unwrap().members.len(), 1);
        assert!(dir.join("secrets").join(SIGNED_COPY).exists());

        *fails.lock().unwrap() = false;
        let v = a.load().unwrap();
        assert!(v.warnings.join("\n").contains("Your next change sends it again"), "{:?}", v.warnings);
        let first = v.version;
        // Sending again uses a new version, never the one already signed.
        assert!(a.resend().unwrap() > first);
        let s = store.read().unwrap();
        assert_eq!(s.members.len(), 2);
        assert!(a.load().unwrap().warnings.is_empty());
        // Before anything is signed there is nothing to send again.
        let other = TempDir::new();
        let (mut b, _) = setup(&other);
        b.load().unwrap();
        assert!(b.resend().unwrap_err().to_string().contains("nothing is signed yet"));
    }

    #[test]
    fn the_coordinators_answer_has_a_ceiling() {
        let sh = |script: &str| {
            Command::new("sh").args(["-c", script]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
        };
        // An answer that never ends: refused, and the child is gone.
        let start = std::time::Instant::now();
        let e = bounded_output(sh("yes"), 1 << 20).unwrap_err().to_string();
        assert!(e.contains("longer than 1 MiB") && start.elapsed() < std::time::Duration::from_secs(10), "{e}");
        // Endless errors are cut short, the answer is kept.
        let out = bounded_output(sh("head -c 50000000 /dev/zero >&2; printf ok; exit 3"), 1 << 20).unwrap();
        assert_eq!((out.stdout.as_slice(), out.stderr.len(), out.status.code()), (&b"ok"[..], 64 << 10, Some(3)));
        // Exactly the ceiling is still an answer.
        let out = bounded_output(sh("head -c 1048576 /dev/zero"), 1 << 20).unwrap();
        assert_eq!(out.stdout.len(), 1 << 20);
    }

    #[test]
    fn the_registry_connection_is_shared_only_through_a_directory_of_ours() {
        use std::os::unix::fs::PermissionsExt;
        let link =
            |key: &str, kh: &str| SshLink { key: key.into(), known_hosts: kh.into(), host: "192.168.1.50".into(), port: "22".into() };
        let a = link("s/registry_ed25519", "s/coordinator_known_hosts");
        assert_eq!(a.control_path(None), None, "without a runtime directory every call connects");
        assert_eq!(a.control_path(Some("".as_ref())), None);
        // Another stick's key or pinned host key: another connection.
        assert_ne!(a.socket_name(), link("t/registry_ed25519", "s/coordinator_known_hosts").socket_name());
        assert_ne!(a.socket_name(), link("s/registry_ed25519", "t/coordinator_known_hosts").socket_name());
        // In dryserver/ of the runtime directory, never in the runtime
        // directory itself, where another could have put a socket.
        let t = TempDir::new();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let ours = fsx::socket_dir(t.path(), fsx::geteuid()).unwrap();
        let p = a.control_path(Some(t.path().as_os_str()));
        assert_eq!(p, fsx::socket_in(&ours, &a.socket_name()));
        // (The temporary directory may be too deep for a socket.)
        if let Some(p) = p {
            assert!(p.starts_with(&format!("ControlPath={}/reg-%C-", ours.display())), "{p}");
        }
        // A directory others may enter, or a link in its place: not used.
        std::fs::set_permissions(&ours, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(a.control_path(Some(t.path().as_os_str())), None);
        std::fs::remove_dir(&ours).unwrap();
        let elsewhere = t.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &ours).unwrap();
        assert_eq!(a.control_path(Some(t.path().as_os_str())), None);
        // A runtime directory anyone may write to.
        std::fs::remove_file(&ours).unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(a.control_path(Some(t.path().as_os_str())), None);
        assert!(!ours.exists(), "nothing made there");
    }

    /// Set in the copy of the test program that a_dead_ssh_does_not_end_the_program starts.
    const SIGPIPE_CHILD: &str = "DRYSERVER_TEST_SIGPIPE_CHILD";

    #[test]
    fn a_dead_ssh_does_not_end_the_program() {
        if std::env::var_os(SIGPIPE_CHILD).is_some() {
            // As main has it: a write to a broken pipe ends the program.
            // SAFETY: a signal disposition, in a process of this one test.
            unsafe {
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            }
            // ssh that ends after a little of a large upload, like a
            // coordinator that refuses it at once.
            let mut child = Command::new("sh")
                .args(["-c", "head -c 100 >/dev/null; echo refused >&2; exit 1"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut pipe = child.stdin.take().unwrap();
            let feeder = std::thread::spawn(move || {
                use std::io::Write;
                quiet_broken_pipe();
                let chunk = vec![0u8; 1 << 20];
                (0..64).try_for_each(|_| pipe.write_all(&chunk))
            });
            let out = bounded_output(child, MAX_ANSWER).unwrap();
            let fed = feeder.join().unwrap();
            assert_eq!(out.status.code(), Some(1));
            assert_eq!(fed.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
            return;
        }
        let me = std::env::current_exe().unwrap();
        let out = Command::new(me)
            .args(["--exact", "admin::tests::a_dead_ssh_does_not_end_the_program", "--test-threads=1"])
            .env(SIGPIPE_CHILD, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("1 passed"), "the program ended: {:?}\n{text}", out.status);
    }

    #[test]
    fn an_upload_that_did_not_go_out_whole_says_how_far_it_got() {
        let e = cut_off("cannot reach the coordinator at 192.168.1.50: Broken pipe".into(), 12 << 20, 30 << 20).to_string();
        assert!(
            e.starts_with("cannot reach the coordinator at 192.168.1.50: Broken pipe (the upload stopped after 12 MiB of 30 MiB"),
            "{e}"
        );
        assert!(e.contains("the coordinator keeps nothing of an upload that did not arrive whole"), "{e}");
        let e = cut_off("the coordinator refused: bad signature".into(), 0, 30 << 20).to_string();
        assert!(e.contains("(nothing of the upload went out;"), "{e}");
        // Whole: the coordinator's own words only.
        assert_eq!(cut_off("the coordinator refused: no room".into(), 5, 5).to_string(), "the coordinator refused: no room");
        let k = cut_off(Error::with_kind(crate::err::Kind::HostKey, "another key"), 0, 5);
        assert!(k.is(crate::err::Kind::HostKey) && k.to_string() == "another key");
    }

    #[test]
    fn the_release_copy_is_never_written_through_a_link() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        recording(&mut a, &store);
        a.load().unwrap();
        // Left behind by someone else, pointing outside secrets/.
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, "untouched").unwrap();
        let tmp = dir.join("secrets").join(format!("{RELEASE_COPY}.tmp"));
        std::os::unix::fs::symlink(&elsewhere, &tmp).unwrap();
        let bin = static_binary(&dir, "dryserver", "0.2.0");
        let d = release::Draft { binary: &bin, version: "0.2.0", arch_date: "2026/11/19", ..release::Draft::default() };
        a.publish_release(&d, &dir.join("no-k3s")).unwrap();
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "untouched");
        let copy = dir.join("secrets").join(RELEASE_COPY);
        let m = std::fs::symlink_metadata(&copy).unwrap();
        assert!(m.is_file(), "a file of its own");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }
}
