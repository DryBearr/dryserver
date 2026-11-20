//! The admin's screen for join requests and members, on the desktop.
//! Every decision made here is signed before it reaches the coordinator.

use std::time::{Duration, Instant};

use super::approve::ago;
use super::{Doc, Emit, Event, Flow, Key, Model, dim, err, ok, sel, title};
use crate::admin::{Admin, View};
use crate::err::{Error, Result};
use crate::gotime::Time;
use crate::mesh;

const REFRESH: Duration = Duration::from_secs(5);
/// After a failed load: do not freeze the screen on every tick.
const RETRY: Duration = Duration::from_secs(15);

pub enum Msg {}

#[derive(Debug, Clone, PartialEq)]
enum Action {
    Approve {
        id: String,
        name: String,
    },
    Reject {
        id: String,
        name: String,
    },
    Remove(String),
    /// Names to sign; empty means every unsigned member.
    Sign(Vec<String>),
    Resend,
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
        }
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
            Action::Approve { id, name } => {
                self.admin.approve(id).map(|host| format!("{name} approved and signed as {}.", mesh::ip(&self.subnet, host)))
            }
            Action::Reject { id, name } => self.admin.reject(id).map(|_| format!("{name} rejected.")),
            Action::Remove(name) => self.admin.remove(name).map(|_| format!("{name} removed; servers drop it within a minute.")),
            Action::Sign(names) => self.admin.sign(names).map(|n| format!("{n} machine(s) signed.")),
            Action::Resend => self.admin.resend().map(|v| format!("Signed list sent again as version {v}.")),
        };
        self.notice = res.unwrap_or_else(|e| format!("Failed: {e}"));
        self.load();
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
        match k {
            Key::Char('q') | Key::Esc | Key::Ctrl('c') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(n.saturating_sub(1)),
            Key::Char(c @ ('a' | 'r')) => {
                let Some(r) = pending.get(self.cursor).cloned() else {
                    self.notice = "Select a waiting request first.".into();
                    return Flow::Continue;
                };
                let a = if c == 'a' { Action::Approve { id: r.id, name: r.name } } else { Action::Reject { id: r.id, name: r.name } };
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
            Key::Char('s') => match member {
                Some((m, false)) => self.decide(Action::Sign(vec![m.name.clone()]), None, std::slice::from_ref(&m.name)),
                Some(_) => self.notice = "That machine is signed already.".into(),
                None => self.notice = "Select a member marked NOT SIGNED first.".into(),
            },
            Key::Char('S') => {
                let names = self.view.unsigned();
                if names.is_empty() {
                    self.notice = "Every member is signed.".into();
                } else {
                    let q =
                        format!("Sign all {} machine(s) marked NOT SIGNED ({})? Only if you know each one.", names.len(), names.join(", "));
                    self.confirm = Some((format!("{q} y to confirm"), Action::Sign(Vec::new())));
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

    fn init(&mut self, _: &Emit<Msg>) {
        self.load();
    }

    fn update(&mut self, ev: Event<Msg>, _: &Emit<Msg>) -> Flow {
        match ev {
            Event::Key(k) => self.key(k),
            Event::Tick => {
                let wait = if self.err.is_some() { RETRY } else { REFRESH };
                if self.confirm.is_none() && self.last_load.is_none_or(|t| t.elapsed() >= wait) {
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
        b.add(title("dryserver · machines")).s("  ").add(dim("decisions here are signed with this computer's key")).s("\n\n");
        if let Some(e) = &self.err {
            b.add(err(format!("Cannot talk to the coordinator: {e}"))).s("\n\n");
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
            line(&mut b, i, format!("{:<14} {:<15} code {}   {}", r.name, r.lan_ip, r.code, ago(r.created, now)));
        }
        if !pending.is_empty() {
            b.add(dim("  Approve only if the code matches the one on the new machine's screen.")).nl();
        }

        b.s("\nMembers:\n");
        for (i, (m, signed)) in self.view.members.iter().enumerate() {
            let link = if m.switch { "switch" } else { "WiFi/router" };
            let text = format!(
                "{:<14} {:<12} LAN {:<15} {:<11} seen {:<10}",
                m.name,
                mesh::ip(&self.subnet, m.host),
                m.lan_ip,
                link,
                ago(m.last_seen, now)
            );
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
        }
        if !self.view.unsigned().is_empty() {
            b.add(dim("  NOT SIGNED: on the coordinator, but you never signed it here. Sign it (s) only if you know the machine.")).nl();
        }

        if !self.view.unknown.is_empty() {
            b.s(format!("\nUnknown devices on the network (scan {}):\n", ago(self.view.scanned, now)));
            for d in &self.view.unknown {
                let ssh = if d.ssh { "  SSH open" } else { "" };
                b.add(dim(format!("  {:<15} {}  {}{ssh}", d.ip, d.mac, d.vendor))).nl();
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
        if let Some((q, _)) = &self.confirm {
            b.nl().add(err(q.clone())).nl();
        } else if !self.notice.is_empty() {
            b.nl().s(&self.notice).nl();
        }
        b.nl().add(dim("↑/↓ select · a approve · r reject · d remove · s sign · S sign all · p send list again · q quit")).nl();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::tests::{COORD_KEY, key32, request, setup};
    use crate::registry::{Member, Status};
    use crate::testutil::TempDir;

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
    fn unsigned_members_need_a_decision() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store
            .update(|s| {
                for (host, name, seed) in [(2, "node-a", 2), (3, "rogue", 3)] {
                    s.members.push(Member { host, name: name.into(), wg_key: key32(seed), ..Member::default() });
                }
                s.add_request(request("node-n", 9), COORD_KEY, Time::now())?;
                Ok(())
            })
            .unwrap();
        let mut s = Screen::new(admin);
        s.load();

        // Approving would drop the two unsigned machines: asked first.
        s.key(Key::Char('a'));
        let v = s.view().plain();
        assert!(v.contains("This also drops node-a, rogue from the swarm") && v.contains("y to confirm"), "{v}");
        s.key(Key::Esc);
        assert_eq!(store.read().unwrap().members.len(), 3);
        assert_eq!(store.read().unwrap().requests[0].status, Status::Pending);

        // Sign node-a only (cursor: request, coord, node-a): rogue goes.
        s.key(Key::Down);
        s.key(Key::Down);
        s.key(Key::Char('s'));
        assert!(s.view().plain().contains("This also drops rogue from the swarm"), "{}", s.view().plain());
        s.key(Key::Char('y'));
        let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["coord", "node-a"]);
        s.key(Key::Char('s'));
        assert!(s.notice.contains("signed already"), "{:?}", s.notice);
        s.key(Key::Char('S'));
        assert!(s.notice.contains("Every member is signed"));
    }

    #[test]
    fn sign_all_and_errors() {
        let dir = TempDir::new();
        let (admin, store) = setup(&dir);
        store
            .update(|s| {
                s.members.push(Member { host: 2, name: "node-a".into(), wg_key: key32(2), ..Member::default() });
                Ok(())
            })
            .unwrap();
        let mut s = Screen::new(admin);
        s.load();
        s.key(Key::Char('S'));
        assert!(s.view().plain().contains("Sign all 2 machine(s) marked NOT SIGNED (coord, node-a)?"), "{}", s.view().plain());
        s.key(Key::Char('y'));
        assert!(s.notice.contains("signed"), "{:?}", s.notice);
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
        assert_eq!(store.read().unwrap().members.len(), 2);
    }
}
