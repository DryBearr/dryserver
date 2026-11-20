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
    fn call(&self, command: &str, stdin: &str) -> Result<String>;
    /// The coordinator's SSH host key ("type base64") that this desktop
    /// pinned on first contact.
    fn host_key(&self) -> Result<String>;
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
    /// The host as known_hosts writes it.
    fn known_name(&self) -> String {
        if self.port.is_empty() || self.port == "22" { self.host.clone() } else { format!("[{}]:{}", self.host, self.port) }
    }
}

impl Link for SshLink {
    fn call(&self, command: &str, stdin: &str) -> Result<String> {
        use std::io::Write;
        let kh = format!("UserKnownHostsFile={}", self.known_hosts.display());
        let port = if self.port.is_empty() { "22" } else { &self.port };
        let mut child = Command::new("ssh")
            .arg("-i")
            .arg(&self.key)
            .args(["-p", port])
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "IdentitiesOnly=yes"])
            .args(["-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "StrictHostKeyChecking=accept-new", "-o", "HashKnownHosts=no"])
            .args(["-o", &kh, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
            .args(["-o", "ForwardAgent=no", "-o", "ProxyJump=none"])
            .arg(format!("{}@{}", sysconf::REGISTRY_USER, self.host))
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
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if msg.contains("Host key verification failed") || msg.contains("HOST IDENTIFICATION HAS CHANGED") {
            bail!(
                "the machine at {} does not have the SSH key this computer saw before. Either the coordinator was \
                 reinstalled, or something else answers at its address. Nothing was sent.",
                self.host
            );
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
}

/// What the approval screen shows.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// Waiting requests, with pairing codes computed on this desktop.
    pub pending: Vec<Request>,
    /// Members on the coordinator, and whether this desktop signed them.
    pub members: Vec<(Member, bool)>,
    pub unknown: Vec<Device>,
    pub scanned: Time,
    /// Version of the newest valid signed list; 0 when nothing is signed.
    pub version: u64,
    pub warnings: Vec<String>,
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
        }
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
        let mut v = View { unknown: st.unknown, scanned: st.scanned, ..View::default() };
        let coord_key = self.link.host_key()?;

        let (members, problems) = registry::check_members(st.members, |h| self.fits(h));
        v.warnings.extend(problems.into_iter().map(|p| format!("The coordinator lists a bad entry, ignored: {p}")));
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

        // Requests are untrusted too; the code is computed here from the
        // keys in the request and the coordinator key this desktop pinned.
        for mut r in st.requests {
            if let Err(e) = registry::validate_request(&r) {
                v.warnings.push(format!("The coordinator sent a bad join request, ignored: {e}"));
                continue;
            }
            r.code = registry::pairing_code(&r.wg_key, &r.ssh_host_key, &coord_key);
            v.pending.push(r);
        }
        self.members = members;
        self.pending = v.pending.clone();
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

    /// Signs members that are on the coordinator but not in the signed
    /// list: all of them when names is empty.
    pub fn sign(&mut self, names: &[String]) -> Result<usize> {
        let add: Vec<Member> = self
            .members
            .iter()
            .filter(|m| !self.base.has(m) && m.host != 1 && (names.is_empty() || names.contains(&m.name)))
            .cloned()
            .collect();
        if add.is_empty() && self.base.members.iter().any(|e| e.host == 1) {
            bail!("nothing to sign");
        }
        // The first signature also signs the coordinator's own entry.
        let n = add.len() + usize::from(!self.base.members.iter().any(|e| e.host == 1));
        self.publish(|list, _| {
            for m in &add {
                // A changed key under a signed name or number replaces the
                // old entry: the admin is looking at the new one.
                list.members.retain(|e| e.host != m.host && e.name != m.name && e.wg_key != m.wg_key);
                list.members.push(Entry::of(m));
            }
            Ok(())
        })?;
        Ok(n)
    }

    /// Signs and sends the current list again under a new version, for
    /// when the coordinator lost it or serves an older one.
    pub fn resend(&mut self) -> Result<u64> {
        if self.base.version == 0 {
            bail!("nothing is signed yet");
        }
        self.publish(|_, _| Ok(()))
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
    }

    impl Link for Direct {
        fn call(&self, command: &str, stdin: &str) -> Result<String> {
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
            Ok(self.host_key.clone())
        }
    }

    pub fn request(name: &str, seed: u8) -> Request {
        Request {
            name: name.into(),
            wg_key: key32(seed),
            ssh_host_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{} root@{name}", name.replace('-', "")),
            lan_ip: "192.168.1.23".into(),
            ..Request::default()
        }
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
                Ok(())
            })
            .unwrap();
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let fails: Arc<Mutex<bool>> = Arc::default();
        let link = Direct { store: Store::new(&store.path), host_key: COORD_KEY.into(), publish_fails: fails.clone(), verifier: None };
        let a = Admin::new(Box::new(link), Box::new(Key("admin")), Box::new(Key("admin")), &secrets, "10.66.0.0/24");
        (a, store, fails)
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
    fn existing_swarm_is_taken_over() {
        let dir = TempDir::new();
        let (mut a, store) = setup(&dir);
        // Members approved the old way, on the coordinator.
        store
            .update(|s| {
                for (host, name, seed) in [(2, "node-a", 2), (3, "node-b", 3), (4, "rogue", 4)] {
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
        assert_eq!(v.unsigned().len(), 4);
        // Signing one would drop the others: the screen asks first.
        assert_eq!(a.would_drop(&["node-a".to_string()]), vec!["node-b".to_string(), "rogue".into()]);

        // Sign the two known ones; the rogue is left out and dropped.
        assert_eq!(a.sign(&["node-a".to_string(), "node-b".to_string()]).unwrap(), 3, "two machines and the coordinator");
        let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["coord", "node-a", "node-b"]);
        let v = a.load().unwrap();
        assert!(v.unsigned().is_empty() && a.would_drop(&[]).is_empty());
        assert!(a.sign(&[]).unwrap_err().to_string().contains("nothing to sign"));
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
        });

        let id = ask(&store, "node-a", 2);
        a.load().unwrap();
        assert_eq!(a.approve(&id).unwrap(), 2);
        let s = store.read().unwrap();
        assert_eq!(s.members.len(), 2);

        // A node checks what the coordinator hands out.
        let node = crate::node::Node {
            cfg: crate::config::Config::default(),
            hostname: "node-a".into(),
            root: dir.join("node"),
            run: Arc::new(crate::runner::ExecRunner::silent()),
            tmp_dir: None,
        };
        let v = checker();
        let status = node.check_signed(&s.members, &s.signed, Some(&v));
        assert!(status.starts_with("ok: member list matches"), "{status}");
        let mut more = s.members.clone();
        more.push(Member { host: 9, name: "rogue".into(), wg_key: key32(9), ..Member::default() });
        assert!(node.check_signed(&more, &s.signed, Some(&v)).contains("not signed by you: rogue"));

        // Someone with the registry key but another signing key gets nothing.
        a.signer = Box::new(SshSigner { key: thief });
        assert!(a.load().unwrap_err().to_string().contains("bad signature"), "the registry opened for a wrong key");
        let forged =
            signed::seal(a.signer.as_ref(), &List { version: u64::MAX, members: vec![Entry::of(&s.members[0])], rejected: vec![] })
                .unwrap();
        assert!(a.link.call("publish", &serde_json::to_string(&forged).unwrap()).unwrap_err().to_string().contains("bad signature"));
        assert_eq!(store.read().unwrap().members.len(), 2);
        assert!(node.check_signed(&s.members, &forged, Some(&v)).starts_with("NOT VALID"));
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
