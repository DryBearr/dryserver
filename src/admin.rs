//! The admin's side of approval, on the desktop. `./dryserver approve`
//! shows the machines waiting to join and the members, and every decision
//! is signed here with secrets/signing_ed25519 before it goes to the
//! coordinator. The coordinator stores and hands out the signed list; it
//! cannot change it.
//!
//! What the coordinator sends is treated as a claim: entries are checked,
//! pairing codes are computed here, and members that are on the
//! coordinator but not in the list this desktop signed are shown as such.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::err::{Error, Result};
use crate::gotime::Time;
use crate::registry::{self, AdminState, Device, Member, Request};
use crate::signed::{self, Entry, Envelope, List, Signer, Verifier, key_body};
use crate::{bail, errf, fsx, sysconf};

/// This desktop's copy of the last list it signed, in secrets/. Versions
/// continue from it even if the coordinator forgets or lies, and it is the
/// backup of who is in the mesh.
pub const SIGNED_COPY: &str = "members.signed.json";
/// The coordinator's SSH host key as first seen from this desktop.
pub const KNOWN_HOSTS: &str = "coordinator_known_hosts";

/// A way to run one registry command on the coordinator.
pub trait Link {
    /// Runs one registry command. Fails with Kind::HostKey when the machine
    /// at the coordinator's address has another SSH key than the pinned one.
    fn call(&self, command: &str, stdin: &str) -> Result<String>;
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

    /// Where the shared connection's socket goes: the user's private
    /// runtime directory. None without one (then every call connects).
    ///
    /// The name carries which key file and which pinned host key file the
    /// connection was made with. A connection is checked against the
    /// pinned key once, when it is made: one made from another directory
    /// (another stick's secrets) must never be reused here.
    fn control_path(&self) -> Option<String> {
        let dir = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty())?;
        let full = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
        let mut id: u64 = 0xcbf2_9ce4_8422_2325;
        for b in
            full(&self.key).as_os_str().as_encoded_bytes().iter().chain(&[0]).chain(full(&self.known_hosts).as_os_str().as_encoded_bytes())
        {
            id = (id ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
        Some(format!("ControlPath={}", Path::new(&dir).join(format!("dryserver-%C-{id:016x}")).display()))
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
        if let Some(ctl) = self.control_path() {
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
        let text = stdin.to_string();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(text.as_bytes());
        });
        let out = child.wait_with_output().map_err(|e| Error::from(e).wrap("ssh"))?;
        let _ = writer.join();
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
        fsx::write_file(&tmp, format!("{} {}\n", self.known_name(), key_body(key)), 0o600)?;
        fsx::rename(&tmp, &self.known_hosts)
    }
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
        }
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
        fsx::write_file(&tmp, serde_json::to_string(env)? + "\n", 0o600)?;
        fsx::rename(&tmp, &path)
    }

    /// Fetches the coordinator's state and compares it with what this
    /// desktop signed.
    pub fn load(&mut self) -> Result<View> {
        let ask = signed::seal_admin(self.signer.as_ref(), "state", (self.now)().0.timestamp())?;
        let out = self.link.call("admin", &serde_json::to_string(&ask)?)?;
        let st: AdminState = serde_json::from_str(&out).map_err(|e| Error::from(e).wrap("the coordinator's answer"))?;
        let mut v = View { unknown: st.unknown.into_iter().filter_map(clean_device).collect(), scanned: st.scanned, ..View::default() };
        let coord_key = self.link.host_key()?;

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

        let missing: Vec<&str> =
            self.base.members.iter().filter(|e| !members.iter().any(|m| e.matches(m))).map(|e| e.name.as_str()).collect();
        if !missing.is_empty() {
            v.warnings.push(format!("Signed by you but not on the coordinator (or changed there): {}", missing.join(", ")));
        }
        v.members = members.iter().map(|m| (m.clone(), self.base.has(m))).collect();
        // What members say they cut off. A member's word, relayed by the
        // coordinator: something to look into, not a fact.
        for m in &members {
            for c in &m.cuts {
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
        for mut r in st.requests {
            if let Err(e) = registry::validate_request(&r) {
                v.warnings.push(format!("The coordinator sent a bad join request, ignored: {e}"));
                continue;
            }
            r.code = registry::pairing_code(&r.wg_key, &r.ssh_host_key, &coord_key);
            // Without the proof the request does not come from a machine
            // installed from this stick, or the coordinator changed it.
            if !registry::proof_ok(&secret, &r) {
                v.unproved.push(r.id.clone());
            }
            v.pending.push(r);
        }
        self.members = members;
        self.pending = v.pending.clone();
        self.unproved = v.unproved.clone();
        Ok(v)
    }

    /// Builds the next list from the last signed one, signs it, keeps a
    /// copy and sends it to the coordinator.
    fn publish(&mut self, change: impl FnOnce(&mut List, &Admin) -> Result<()>) -> Result<u64> {
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
        self.link.call("publish", &serde_json::to_string(&env)?)?;
        Ok(self.base.version)
    }

    fn free_host(&self, list: &List) -> Result<u32> {
        (2u32..)
            .take_while(|h| self.fits(*h))
            .find(|h| !list.members.iter().any(|e| e.host == *h))
            .ok_or_else(|| Error::new("the mesh subnet is full"))
    }

    /// Lets a waiting machine in. Returns its mesh host number.
    pub fn approve(&mut self, id: &str) -> Result<u32> {
        let Some(r) = self.pending.iter().find(|r| r.id == id).cloned() else {
            bail!("that request is gone");
        };
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
        Ok(host)
    }

    pub fn reject(&mut self, id: &str) -> Result<()> {
        let Some(r) = self.pending.iter().find(|r| r.id == id).cloned() else {
            bail!("that request is gone");
        };
        self.publish(|list, _| {
            list.rejected.push(r.wg_key.clone());
            Ok(())
        })
        .map(|_| ())
    }

    /// Removes a member, signed or not. The coordinator stays.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.publish(|list, a| {
            if a.members.iter().any(|m| m.name == name && m.host == 1) {
                bail!("the coordinator cannot be removed");
            }
            if list.members.iter().any(|e| e.name == name && e.host == 1) {
                bail!("the coordinator cannot be removed");
            }
            list.members.retain(|e| e.name != name);
            Ok(())
        })
        .map(|_| ())
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
                lan_ip: self.members.iter().find(|m| e.matches(m)).map(|m| m.lan_ip.clone()).unwrap_or_default(),
                host_key: e.ssh_host_key.clone(),
            })
            .collect()
    }

    /// Members on the coordinator that the next signature would drop
    /// because they are not in the signed list, except those in keep.
    pub fn would_drop(&self, keep: &[String]) -> Vec<String> {
        self.members.iter().filter(|m| m.host != 1 && !self.base.has(m) && !keep.contains(&m.name)).map(|m| m.name.clone()).collect()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::registry::{Mesh, Status, Store};
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

    impl Link for Direct {
        fn call(&self, command: &str, stdin: &str) -> Result<String> {
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
                &Subnet,
                v,
                COORD_KEY,
                command,
                "192.168.1.9 5000 22",
                &mut stdin.as_bytes(),
                &mut out,
                Time::now(),
            )?;
            Ok(String::from_utf8(out).unwrap())
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

        assert_eq!(a.approve(&id).unwrap(), 2);
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
        assert_eq!(a.approve(&id).unwrap(), 3);
        assert!(store.read().unwrap().signed_version > s.signed_version);
    }

    #[test]
    fn reject_and_remove() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let (ida, idb) = (ask(&store, "node-a", 2), ask(&store, "node-b", 3));
        a.load().unwrap();
        a.approve(&ida).unwrap();
        a.load().unwrap();
        a.reject(&idb).unwrap();
        let s = store.read().unwrap();
        assert!(s.pending().is_empty());
        assert_eq!(s.members.len(), 2);

        a.load().unwrap();
        assert!(a.remove("coord").unwrap_err().to_string().contains("cannot be removed"));
        a.remove("node-a").unwrap();
        assert_eq!(store.read().unwrap().members.len(), 1);
        assert!(a.approve("nope").unwrap_err().to_string().contains("gone"));
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
        assert_eq!(a.would_drop(&[]), vec!["node-a".to_string(), "rogue".into()]);

        a.sign_coordinator().unwrap();
        let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["coord"], "the first signature covers the coordinator and nothing else");
        let v = a.load().unwrap();
        assert!(v.unsigned().is_empty() && a.would_drop(&[]).is_empty());
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
            assert!(a.approve(&id).unwrap_err().to_string().contains("no valid proof from your USB stick"));
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
        a.approve(&id).unwrap();
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
        a.approve(&id).unwrap();
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
            let e = a.approve(id).unwrap_err().to_string();
            assert!(e.contains("no valid proof from your USB stick"), "{e}");
        }
        assert_eq!(store.read().unwrap().members.len(), 1, "an unproved request became a member");
        // The untouched request of the real machine goes through.
        a.approve(&real).unwrap();
        // They can still be rejected.
        a.load().unwrap();
        a.reject("00000000000000aa").unwrap();

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
        a.approve(&id).unwrap();

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
        assert!(a.approve(&id).unwrap_err().to_string().contains("nothing signed"));
        assert!(!dir.join("secrets").join(SIGNED_COPY).exists());
        assert_eq!(store.read().unwrap().signed_version, 0);
    }

    #[test]
    fn versions_never_repeat() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        a.approve(&id).unwrap();
        let v1 = store.read().unwrap().signed_version;

        // This desktop's copy is lost: the coordinator's verified list is
        // taken over and the next version is still higher.
        std::fs::remove_file(dir.join("secrets").join(SIGNED_COPY)).unwrap();
        let v = a.load().unwrap();
        assert_eq!(v.version, v1);
        assert!(dir.join("secrets").join(SIGNED_COPY).exists());
        let id = ask(&store, "node-b", 3);
        a.load().unwrap();
        a.approve(&id).unwrap();
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
        assert_eq!(a.approve(&id).unwrap(), 2);
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
        let forged =
            signed::seal(a.signer.as_ref(), &List { version: u64::MAX, members: vec![Entry::of(&s.members[0])], rejected: vec![] })
                .unwrap();
        assert!(a.link.call("publish", &serde_json::to_string(&forged).unwrap()).unwrap_err().to_string().contains("bad signature"));
        assert_eq!(store.read().unwrap().members.len(), 2);
        assert!(node.signed_members(2, &s.members, &forged).unwrap_err().to_string().contains("bad signature"));
    }

    #[test]
    fn failed_send_is_recovered() {
        let dir = TempDir::new();
        let (mut a, store, fails) = setup_failing(&dir);
        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        *fails.lock().unwrap() = true;
        assert!(a.approve(&id).unwrap_err().to_string().contains("cannot reach"));
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
}
