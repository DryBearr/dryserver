//! Other people on the machines: the admin lets someone log in with their
//! own SSH key (`dryserver people add`), and every machine the signed list
//! names gives them an account of their own.
//!
//! What such an account can do: log in with one of its keys and use a
//! shell. Not sudo (it is not in wheel), not docker (not in docker), not
//! the cluster (the kubeconfig is wheel's), no forwarding of any kind
//! (sshd: Match Group dryserver-people, DisableForwarding). Its keys are in
//! /etc/ssh/authorized_keys.d/NAME, a file only root writes: the person
//! cannot add another key, and root never writes into the person's home.
//!
//! Someone the admin takes out (or who is not let in on this machine any
//! more) is locked: no key, no shell, the account expired, its sessions
//! ended. The home stays, with whatever is in it. Only accounts dryserver
//! made are touched: a name that is an account of the machine already is
//! refused, never taken over.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::err::{Error, Result};
use crate::runner::{Cmd, Runner};
use crate::signed::{self, Person};
use crate::{errf, fsx};

/// The group every person's account is in; sshd limits it.
pub const GROUP: &str = "dryserver-people";
/// Each person's keys, one file per account (sshd: %u).
pub const KEYS_DIR: &str = "/etc/ssh/authorized_keys.d";
/// Lets the people in: their names, added to the admin's in AllowUsers.
/// Included before the main file (05 < 10), and without a Match block.
pub const SSHD_CONF: &str = "/etc/ssh/sshd_config.d/05-dryserver-people.conf";
/// The accounts dryserver made, so that it never touches another.
pub const STATE: &str = "/var/lib/dryserver/people.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct State {
    /// Names of the accounts dryserver made here.
    made: BTreeSet<String>,
}

/// What a machine knows to put people in place.
pub struct Here<'a> {
    pub root: &'a Path,
    pub run: &'a dyn Runner,
    /// This machine's name, as the signed list has it.
    pub name: &'a str,
    pub coordinator: bool,
    /// The admin's account, never a person's.
    pub admin: &'a str,
}

/// What reconcile did, for the sync's log.
#[derive(Debug, Default, PartialEq)]
pub struct Done {
    /// Accounts that may log in here now.
    pub active: Vec<String>,
    /// Accounts locked now.
    pub locked: Vec<String>,
    /// Names refused, and why.
    pub refused: Vec<String>,
}

impl Here<'_> {
    fn path(&self, p: &str) -> PathBuf {
        fsx::under(self.root, p)
    }

    fn cmd(&self, ctx: &Ctx, name: &str, args: &[&str]) -> Result<String> {
        let (out, res) = self.run.run(ctx, &Cmd::new(name, args).quiet());
        res.map(|_| out)
    }

    fn load(&self) -> State {
        std::fs::read(self.path(STATE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, s: &State) -> Result<()> {
        let p = self.path(STATE);
        fsx::mkdir_all(fsx::dir(&p), 0o755)?;
        let tmp = PathBuf::from(format!("{}.tmp", p.display()));
        fsx::write_new(&tmp, serde_json::to_string(s)? + "\n", 0o600)?;
        fsx::rename(&tmp, &p)
    }

    /// Writes path with mode when its contents differ; whether it did.
    fn put(&self, p: &str, mode: u32, text: &str) -> Result<bool> {
        let dst = self.path(p);
        if std::fs::read_to_string(&dst).is_ok_and(|t| t == text) {
            return Ok(false);
        }
        fsx::mkdir_all(fsx::dir(&dst), 0o755)?;
        let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
        fsx::write_new(&tmp, text, mode)?;
        fsx::rename(&tmp, &dst)?;
        Ok(true)
    }

    fn remove(&self, p: &str) -> Result<bool> {
        match std::fs::remove_file(self.path(p)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::from(e).wrap(format!("remove {p}"))),
        }
    }

    /// Puts the people of the list in place on this machine: accounts for
    /// those let in here, locked ones for the rest dryserver made, and
    /// sshd told, checked first (a config sshd refuses is taken back, so
    /// nobody is locked out by it).
    pub fn reconcile(&self, ctx: &Ctx, people: &[Person]) -> Result<Done> {
        let mut st = self.load();
        let mut done = Done::default();
        let mine: Vec<&Person> = people.iter().filter(|p| p.may_log_in(self.name, self.coordinator)).collect();
        if !mine.is_empty() {
            self.cmd(ctx, "groupadd", &["-f", GROUP])?;
        }
        for p in &mine {
            if !signed::valid_person_name(&p.name) || p.name == self.admin {
                done.refused.push(format!("{}: not a name a person's account may have", p.name));
                continue;
            }
            let exists = self.cmd(ctx, "getent", &["passwd", &p.name]).is_ok();
            if exists && !st.made.contains(&p.name) {
                done.refused.push(format!("{}: an account of this machine already, not made by dryserver", p.name));
                continue;
            }
            if exists {
                // In its group only, a shell, not expired, no password.
                self.cmd(ctx, "usermod", &["-s", "/bin/bash", "-G", GROUP, "-e", "", "-p", "*", &p.name])?;
            } else {
                self.cmd(ctx, "useradd", &["-m", "-s", "/bin/bash", "-G", GROUP, "-p", "*", "-c", "dryserver person", &p.name])?;
                st.made.insert(p.name.clone());
                self.save(&st)?;
            }
            let keys: String = p.keys.iter().map(|k| format!("{} {}\n", signed::key_body(k), p.name)).collect();
            self.put(&format!("{KEYS_DIR}/{}", p.name), 0o644, &keys)?;
            done.active.push(p.name.clone());
        }
        let active: BTreeSet<&str> = done.active.iter().map(String::as_str).collect();
        for name in st.made.iter().filter(|n| !active.contains(n.as_str())) {
            let had = self.remove(&format!("{KEYS_DIR}/{name}"))?;
            // Locked again each time: an account someone unlocked by hand
            // stays shut. Its sessions end once, when its key goes.
            self.cmd(ctx, "usermod", &["-L", "-e", "1", "-s", "/usr/bin/nologin", name])?;
            if had {
                let _ = self.cmd(ctx, "pkill", &["-KILL", "-u", name]);
                done.locked.push(name.clone());
            }
        }
        self.sshd(ctx, &done.active)?;
        Ok(done)
    }

    /// Lets the active people past sshd's AllowUsers, or none.
    fn sshd(&self, ctx: &Ctx, active: &[String]) -> Result<()> {
        let before = std::fs::read_to_string(self.path(SSHD_CONF)).ok();
        let changed = if active.is_empty() {
            self.remove(SSHD_CONF)?
        } else {
            let text = format!(
                "# dryserver people: the accounts the admin's signed list lets in here.\n\
                 # Written by dryserver sync; their limits are in 10-dryserver.conf.\n\
                 AllowUsers {}\n",
                active.join(" ")
            );
            self.put(SSHD_CONF, 0o644, &text)?
        };
        if !changed {
            return Ok(());
        }
        if let Err(e) = self.cmd(ctx, "sshd", &["-t"]) {
            // Back as it was: sshd keeps running with what worked.
            match &before {
                Some(t) => {
                    self.put(SSHD_CONF, 0o644, t)?;
                }
                None => {
                    self.remove(SSHD_CONF)?;
                }
            }
            return Err(errf!("sshd refused the people's config, left as it was: {e}"));
        }
        self.cmd(ctx, "systemctl", &["reload", "sshd"]).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, get};
    use std::sync::Mutex;

    /// Records commands; getent answers for the accounts in have.
    #[derive(Default)]
    struct Fake {
        ran: Mutex<Vec<String>>,
        have: Mutex<BTreeSet<String>>,
        sshd_fails: Mutex<bool>,
    }

    impl Runner for Fake {
        fn run(&self, _: &Ctx, c: &Cmd) -> (String, Result<()>) {
            let line = format!("{} {}", c.name, c.args.join(" "));
            self.ran.lock().unwrap().push(line);
            match c.name.as_str() {
                "getent" if self.have.lock().unwrap().contains(&c.args[1]) => {
                    (format!("{}:x:1001:1001::/home/x:/bin/bash\n", c.args[1]), Ok(()))
                }
                "getent" => (String::new(), Err("exit status 2".into())),
                "useradd" => {
                    self.have.lock().unwrap().insert(c.args.last().unwrap().clone());
                    (String::new(), Ok(()))
                }
                "sshd" if *self.sshd_fails.lock().unwrap() => (String::new(), Err("bad configuration option".into())),
                _ => (String::new(), Ok(())),
            }
        }
    }

    fn person(name: &str, key: &str, on: &[&str]) -> Person {
        Person { name: name.into(), keys: vec![format!("ssh-ed25519 {key}")], on: on.iter().map(|s| s.to_string()).collect() }
    }

    fn here<'a>(root: &'a Path, run: &'a Fake, name: &'a str, coordinator: bool) -> Here<'a> {
        Here { root, run, name, coordinator, admin: "admin" }
    }

    fn ran(f: &Fake) -> Vec<String> {
        std::mem::take(&mut *f.ran.lock().unwrap())
    }

    #[test]
    fn people_get_an_account_with_their_keys_and_nothing_more() {
        let t = TempDir::new();
        let f = Fake::default();
        let h = here(t.path(), &f, "node-a", false);
        let people = [person("alice", "AAAAalice", &[]), person("bob", "AAAAbob", &["node-b"])];
        let d = h.reconcile(&Ctx::new(), &people).unwrap();
        assert_eq!(d.active, vec!["alice"], "bob is let in on node-b only");
        let r = ran(&f);
        assert!(r.contains(&"groupadd -f dryserver-people".to_string()), "{r:?}");
        assert!(r.contains(&"useradd -m -s /bin/bash -G dryserver-people -p * -c dryserver person alice".to_string()), "{r:?}");
        assert!(!r.iter().any(|l| l.contains("wheel") || l.contains("docker")), "{r:?}");
        assert_eq!(get(t.path(), "/etc/ssh/authorized_keys.d/alice"), "ssh-ed25519 AAAAalice alice\n");
        assert_eq!(get(t.path(), SSHD_CONF).lines().last(), Some("AllowUsers alice"));
        assert!(r.contains(&"sshd -t".to_string()) && r.contains(&"systemctl reload sshd".to_string()), "{r:?}");
        // Again: the account is set right, the files stay, sshd is not
        // reloaded for nothing.
        h.reconcile(&Ctx::new(), &people).unwrap();
        let r = ran(&f);
        assert!(r.contains(&"usermod -s /bin/bash -G dryserver-people -e  -p * alice".to_string()), "{r:?}");
        assert!(!r.iter().any(|l| l.starts_with("useradd") || l.starts_with("systemctl")), "{r:?}");
        // A new key: the file follows.
        h.reconcile(&Ctx::new(), &[person("alice", "AAAAnew", &[])]).unwrap();
        assert_eq!(get(t.path(), "/etc/ssh/authorized_keys.d/alice"), "ssh-ed25519 AAAAnew alice\n");
    }

    #[test]
    fn the_coordinator_lets_in_only_who_is_named_for_it() {
        let t = TempDir::new();
        let f = Fake::default();
        let h = here(t.path(), &f, "coord", true);
        let d = h.reconcile(&Ctx::new(), &[person("alice", "AAAAa", &[]), person("bob", "AAAAb", &["coord", "node-a"])]).unwrap();
        assert_eq!(d.active, vec!["bob"]);
    }

    #[test]
    fn someone_taken_out_is_locked_and_their_sessions_end() {
        let t = TempDir::new();
        let f = Fake::default();
        let h = here(t.path(), &f, "node-a", false);
        h.reconcile(&Ctx::new(), &[person("alice", "AAAAa", &[]), person("bob", "AAAAb", &[])]).unwrap();
        ran(&f);
        let d = h.reconcile(&Ctx::new(), &[person("bob", "AAAAb", &[])]).unwrap();
        assert_eq!((d.active.clone(), d.locked.clone()), (vec!["bob".to_string()], vec!["alice".to_string()]));
        let r = ran(&f);
        assert!(r.contains(&"usermod -L -e 1 -s /usr/bin/nologin alice".to_string()), "{r:?}");
        assert!(r.contains(&"pkill -KILL -u alice".to_string()), "{r:?}");
        assert!(!t.path().join("etc/ssh/authorized_keys.d/alice").exists());
        assert_eq!(get(t.path(), SSHD_CONF).lines().last(), Some("AllowUsers bob"));
        // Nobody left: sshd lets in only the admin again.
        let d = h.reconcile(&Ctx::new(), &[]).unwrap();
        assert_eq!(d.locked, vec!["bob"]);
        assert!(!t.path().join(SSHD_CONF.trim_start_matches('/')).exists());
        let r = ran(&f);
        assert!(r.contains(&"systemctl reload sshd".to_string()) && !r.iter().any(|l| l.starts_with("groupadd")), "{r:?}");
        // Locked again at every sync, sessions ended only once.
        h.reconcile(&Ctx::new(), &[]).unwrap();
        let r = ran(&f);
        assert!(r.contains(&"usermod -L -e 1 -s /usr/bin/nologin alice".to_string()) && !r.iter().any(|l| l.starts_with("pkill")), "{r:?}");
        // Back in: the same account, opened again.
        let d = h.reconcile(&Ctx::new(), &[person("alice", "AAAAa", &[])]).unwrap();
        assert_eq!(d.active, vec!["alice"]);
        assert!(ran(&f).iter().any(|l| l.starts_with("usermod -s /bin/bash")));
    }

    #[test]
    fn an_account_of_the_machine_is_never_taken_over() {
        let t = TempDir::new();
        let f = Fake::default();
        f.have.lock().unwrap().insert("alice".into());
        let h = here(t.path(), &f, "node-a", false);
        let d = h.reconcile(&Ctx::new(), &[person("alice", "AAAAa", &[]), person("admin", "AAAAx", &[])]).unwrap();
        assert!(d.active.is_empty());
        assert_eq!(d.refused.len(), 2, "{:?}", d.refused);
        assert!(d.refused[0].contains("already") && d.refused[1].contains("not a name"), "{:?}", d.refused);
        let r = ran(&f);
        assert!(!r.iter().any(|l| l.starts_with("usermod") || l.starts_with("useradd")), "{r:?}");
        assert!(!t.path().join("etc/ssh/authorized_keys.d/alice").exists());
        // Never locked either: dryserver did not make it.
        h.reconcile(&Ctx::new(), &[]).unwrap();
        assert!(!ran(&f).iter().any(|l| l.contains("alice")));
    }

    #[test]
    fn a_config_sshd_refuses_is_taken_back() {
        let t = TempDir::new();
        let f = Fake::default();
        let h = here(t.path(), &f, "node-a", false);
        h.reconcile(&Ctx::new(), &[person("alice", "AAAAa", &[])]).unwrap();
        *f.sshd_fails.lock().unwrap() = true;
        ran(&f);
        let e = h.reconcile(&Ctx::new(), &[person("alice", "AAAAa", &[]), person("bob", "AAAAb", &[])]).unwrap_err().to_string();
        assert!(e.contains("left as it was"), "{e}");
        assert_eq!(get(t.path(), SSHD_CONF).lines().last(), Some("AllowUsers alice"));
        assert!(!ran(&f).iter().any(|l| l.starts_with("systemctl")));
    }
}
