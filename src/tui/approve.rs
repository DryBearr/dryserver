//! The coordinator's screen for join requests and members.

use std::time::{Duration, Instant};

use super::{Doc, Emit, Event, Flow, Key, Model, dim, err, sel, title};
use crate::err::{Error, Result};
use crate::gotime::{Time, duration_string, round_ms};
use crate::mesh;
use crate::registry::{Member, Request, State, Store};

const REFRESH: Duration = Duration::from_secs(2);

pub enum Msg {}

pub struct Approve {
    store: Store,
    subnet: String,
    max_host: u32,
    now: fn() -> Time,
    st: State,
    err: Option<Error>,
    cursor: usize,
    /// Member name awaiting remove confirmation.
    pub confirm: String,
    pub notice: String,
    last_load: Option<Instant>,
}

impl Approve {
    pub fn new(store: Store, subnet: &str, max_host: u32) -> Approve {
        Approve {
            store,
            subnet: subnet.into(),
            max_host,
            now: Time::now,
            st: State::default(),
            err: None,
            cursor: 0,
            confirm: String::new(),
            notice: String::new(),
            last_load: None,
        }
    }

    pub fn load(&mut self) {
        self.last_load = Some(Instant::now());
        match self.store.read() {
            Ok(st) => {
                self.st = st;
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
        let n = self.items().0.len() + self.st.members.len();
        self.cursor = self.cursor.min(n.saturating_sub(1));
    }

    /// Pending requests first, then members.
    fn items(&self) -> (Vec<Request>, Vec<Member>) {
        (self.st.pending(), self.st.members.clone())
    }

    fn update_store(&mut self, f: impl FnOnce(&mut State) -> Result<()>) -> Result<()> {
        let res = self.store.update(f);
        self.load();
        res
    }

    pub fn key(&mut self, k: Key) -> Flow {
        let (pending, members) = self.items();
        let n = pending.len() + members.len();
        if !self.confirm.is_empty() {
            let name = std::mem::take(&mut self.confirm);
            if k == Key::Char('y') {
                self.notice = match self.update_store(|s| s.remove(&name)) {
                    Ok(()) => format!("{name} removed; servers drop it within a minute."),
                    Err(e) => format!("Remove failed: {e}"),
                };
            } else {
                self.notice = "Not removed.".into();
            }
            return Flow::Continue;
        }
        match k {
            Key::Char('q') | Key::Esc | Key::Ctrl('c') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(n.saturating_sub(1)),
            Key::Char(c @ ('a' | 'r')) => {
                let Some(req) = pending.get(self.cursor).cloned() else {
                    self.notice = "Select a waiting request first.".into();
                    return Flow::Continue;
                };
                let res = if c == 'a' {
                    let (max, now) = (self.max_host, (self.now)());
                    let mut host = 0;
                    self.update_store(|s| {
                        host = s.approve(&req.id, max, now)?.host;
                        Ok(())
                    })
                    .map(|_| format!("{} approved as {}.", req.name, mesh::ip(&self.subnet, host)))
                } else {
                    self.update_store(|s| s.reject(&req.id)).map(|_| format!("{} rejected.", req.name))
                };
                self.notice = res.unwrap_or_else(|e| format!("Failed: {e}"));
            }
            Key::Char('d') => {
                if self.cursor < pending.len() {
                    return Flow::Continue;
                }
                let m = &members[self.cursor - pending.len()];
                if m.host == 1 {
                    self.notice = "The coordinator cannot be removed.".into();
                    return Flow::Continue;
                }
                self.confirm = m.name.clone();
            }
            _ => {}
        }
        Flow::Continue
    }
}

pub(super) fn ago(t: Time, now: Time) -> String {
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

impl Model for Approve {
    type Msg = Msg;

    fn init(&mut self, _: &Emit<Msg>) {
        self.load();
    }

    fn update(&mut self, ev: Event<Msg>, _: &Emit<Msg>) -> Flow {
        match ev {
            Event::Key(k) => self.key(k),
            Event::Tick => {
                if self.last_load.is_none_or(|t| t.elapsed() >= REFRESH) {
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
        b.add(title("dryserver · machines")).s("\n\n");
        if let Some(e) = &self.err {
            b.add(err(format!("Cannot read the registry: {e}"))).nl();
            return b;
        }
        let (pending, members) = self.items();
        let line = |b: &mut Doc, i: usize, text: String| {
            if i == self.cursor {
                b.add(sel(format!("> {text}"))).nl();
            } else {
                b.s(format!("  {text}")).nl();
            }
        };

        b.s("Waiting to join:\n");
        if pending.is_empty() {
            b.add(dim("  none. New machines show up here after their setup finishes.")).nl();
        }
        for (i, r) in pending.iter().enumerate() {
            let text = format!("{:<14} {:<15} code {}   {}", r.name, r.lan_ip, r.code, ago(r.created, now));
            line(&mut b, i, text);
        }
        if !pending.is_empty() {
            b.add(dim("  Approve only if the code matches the one on the new machine's screen.")).nl();
        }

        b.s("\nMembers:\n");
        for (i, m) in members.iter().enumerate() {
            let link = if m.switch { "switch" } else { "WiFi/router" };
            let text = format!(
                "{:<14} {:<12} LAN {:<15} {:<11} seen {}",
                m.name,
                mesh::ip(&self.subnet, m.host),
                m.lan_ip,
                link,
                ago(m.last_seen, now)
            );
            line(&mut b, pending.len() + i, text);
        }

        if !self.st.unknown.is_empty() {
            b.s(format!("\nUnknown devices on the network (scan {}):\n", ago(self.st.scanned, now)));
            for d in &self.st.unknown {
                let ssh = if d.ssh { "  SSH open" } else { "" };
                b.add(dim(format!("  {:<15} {}  {}{ssh}", d.ip, d.mac, d.vendor))).nl();
            }
        }

        if !self.confirm.is_empty() {
            b.nl().add(err(format!("Remove {} from the mesh? y to confirm", self.confirm))).nl();
        } else if !self.notice.is_empty() {
            b.nl().s(&self.notice).nl();
        }
        b.nl().add(dim("↑/↓ select · a approve · r reject · d remove member · q quit")).nl();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use base64::Engine;

    fn wg_key() -> String {
        base64::engine::general_purpose::STANDARD.encode(crate::fsx::random_bytes(32))
    }

    #[test]
    fn approve_screen() {
        let dir = TempDir::new();
        let store = Store::new(dir.join("registry.json"));
        let now = Time::now();
        store
            .update(|s| {
                s.members = vec![Member {
                    host: 1,
                    name: "coord".into(),
                    lan_ip: "192.168.1.50".into(),
                    switch: true,
                    last_seen: now,
                    ..Member::default()
                }];
                for n in ["node-a", "node-b"] {
                    let r = Request {
                        name: n.into(),
                        wg_key: wg_key(),
                        ssh_host_key: "ssh-ed25519 AAAAnode".into(),
                        lan_ip: "192.168.1.23".into(),
                        ..Request::default()
                    };
                    s.add_request(r, "ssh-ed25519 AAAAcoord", now)?;
                }
                Ok(())
            })
            .unwrap();
        let mut a = Approve::new(store.clone(), "10.66.0.0/24", 254);
        a.load();
        let v = a.view().plain();
        assert!(v.contains("node-a") && v.contains("code ") && v.contains("coord"), "view:\n{v}");

        a.key(Key::Char('a'));
        assert!(a.notice.contains("node-a approved as 10.66.0.2"), "notice {:?}", a.notice);
        a.key(Key::Char('r'));
        assert!(a.notice.contains("node-b rejected"), "notice {:?}", a.notice);
        let st = store.read().unwrap();
        assert_eq!(st.members.len(), 2);
        assert!(st.pending().is_empty());

        // Remove needs confirmation; the coordinator cannot be removed.
        a.key(Key::Char('d'));
        assert!(a.notice.contains("cannot be removed"), "{:?}", a.notice);
        a.key(Key::Down);
        a.key(Key::Char('d'));
        assert_eq!(a.confirm, "node-a");
        a.key(Key::Char('y'));
        assert_eq!(store.read().unwrap().members.len(), 1, "node-a not removed");
    }

    #[test]
    fn ago_like_go() {
        let t = Time::ymd_hms(2026, 1, 1, 12, 0, 0);
        assert_eq!(ago(Time::zero(), t), "never");
        assert_eq!(ago(t, t.add(chrono::TimeDelta::seconds(42))), "42s ago");
        assert_eq!(ago(t, t.add(chrono::TimeDelta::seconds(150))), "3m0s ago");
    }
}
