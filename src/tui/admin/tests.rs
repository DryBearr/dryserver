use super::*;
use crate::admin::Link;
use crate::admin::tests::{COORD_KEY, Direct, SECRET, key32, move_to, reinstalled, request, setup};
use crate::publish::tests::{FakeDays, Sent, days_ago, desk, today, twin};
use crate::registry::{CutReport, Device, Heartbeat, Store};
use crate::report::Report;
use crate::rollout::Rollout;
use crate::testutil::TempDir;
use crate::tui::collector;
use crate::tui::frame::Scroll;
use crate::tui::frame::tests::rows;
use crate::tui::theme::Tier;
use std::sync::Mutex;
use unicode_width::UnicodeWidthStr;

// ---- the harness ----

/// The key files Machines looks for, beside the join secret setup makes.
fn keys(dir: &TempDir) {
    let s = dir.join("secrets");
    for k in crate::tui::home::ADMIN_KEYS {
        if !s.join(k).exists() {
            std::fs::write(s.join(k), "k").unwrap();
        }
    }
}

/// A screen with its thread, and the answers it sends.
struct Run {
    s: Screen,
    rx: mpsc::Receiver<Msg>,
    emit: Emit<Msg>,
    scroll: Scroll,
}

impl Run {
    /// Started, without waiting for the first answer.
    fn start(s: Screen) -> Run {
        let (emit, rx) = collector();
        let mut r = Run { s: s.at("192.168.1.50"), rx, emit, scroll: Scroll::default() };
        let e = r.emit.clone();
        r.s.init(&e);
        r
    }

    fn open(s: Screen) -> Run {
        let mut r = Run::start(s);
        r.settle();
        r
    }

    /// Feeds the thread's answers to the screen until nothing waits.
    fn settle(&mut self) {
        while !self.s.queue.is_empty() {
            let m = self.rx.recv_timeout(Duration::from_secs(10)).expect("the screen's thread did not answer");
            let e = self.emit.clone();
            self.s.update(Event::Msg(m), &e);
        }
    }

    fn key(&mut self, k: Key) -> Flow {
        let e = self.emit.clone();
        self.s.update(Event::Key(k), &e)
    }

    /// Each key, then every answer.
    fn press(&mut self, ks: &[Key]) -> Flow {
        let mut f = Flow::Continue;
        for k in ks {
            f = self.key(k.clone());
            self.settle();
        }
        f
    }

    fn draw(&self, w: u16, h: u16) -> Doc {
        let page = self.s.page(Size { width: frame::body_width(w), rows: frame::body_rows(h) });
        frame::draw(&page, &self.scroll, w, h)
    }

    /// The whole screen, tall enough for everything.
    fn screen(&self) -> String {
        let page = self.s.page(Size { width: frame::body_width(120), rows: 400 });
        rows(&frame::draw(&page, &Scroll::default(), 120, 400)).join("\n")
    }

    /// The screen's words, the spaces squeezed: wrapped text reads as written.
    fn flat(&self) -> String {
        self.screen().replace('▌', " ").split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn notice(&self) -> String {
        self.s.notice.as_ref().map(|n| n.text.clone()).unwrap_or_default()
    }

    fn confirm(&self) -> Option<String> {
        self.s.ask.as_ref().map(|a| format!("{} {}", a.question, a.consequences.join(" ")))
    }
}

fn ch(c: char) -> Key {
    Key::Char(c)
}

// ---- machines ----

#[test]
fn ago_like_go() {
    let t = Time::ymd_hms(2026, 1, 1, 12, 0, 0);
    assert_eq!(ago(Time::zero(), t), "never");
    assert_eq!(ago(t, t.add(chrono::TimeDelta::seconds(42))), "42s ago");
    assert_eq!(ago(t, t.add(chrono::TimeDelta::seconds(150))), "3m0s ago");
}

#[test]
fn approve_reject_remove_each_ask_first() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store
        .update(|s| {
            for (name, seed) in [("node-a", 2), ("node-b", 3)] {
                s.add_request(request(name, seed), COORD_KEY, Time::now())?;
            }
            Ok(())
        })
        .unwrap();
    let mut s = Run::open(Screen::new(admin));
    let code = s.s.view.pending[0].code.clone();
    let t = s.screen();
    assert!(t.contains("Waiting to join  2") && t.contains(&format!("code {code}")) && t.contains("node-a"), "{t}");
    assert!(t.contains("✓ answers") && t.contains("coordinator 192.168.1.50"), "the header says it answers: {t}");
    assert!(rows(&s.draw(100, 32)).last().unwrap().contains("a  approve   x  reject"), "{t}");

    // a asks first, with the code; anything but y signs nothing.
    s.press(&[ch('a')]);
    let q = s.confirm().expect("a asks first");
    assert!(q.contains("Approve node-a?") && q.contains(&format!("Its screen must show the code {code}")), "{q}");
    assert!(q.contains("It also signs the coordinator coord"), "nothing is signed yet: {q}");
    s.press(&[ch('n')]);
    assert!(s.notice().contains("Nothing was signed") && store.read().unwrap().signed_version == 0);
    // First run: the coordinator first.
    s.press(&[ch('s'), ch('y')]);
    assert!(s.notice().contains("Coordinator signed"), "{}", s.notice());
    s.press(&[ch('a'), ch('y')]);
    assert!(s.notice().contains("node-a approved and signed as 10.66.0.2"), "{}", s.notice());
    s.press(&[ch('x')]);
    assert!(s.confirm().unwrap().contains("Reject node-b?"));
    s.press(&[ch('y')]);
    assert!(s.notice().contains("node-b rejected"), "{}", s.notice());
    let st = store.read().unwrap();
    assert_eq!(st.members.len(), 2);
    assert!(st.pending().is_empty() && st.signed_version > 0);
    let t = s.screen();
    assert!(!t.contains("not signed") && t.contains("Signed list version") && t.contains("No machine waits to join"), "{t}");

    // The coordinator stays; removing a member asks first.
    s.press(&[ch('d')]);
    assert!(s.notice().contains("cannot be removed") && s.confirm().is_none(), "{}", s.notice());
    s.press(&[Key::Down, ch('d')]);
    assert!(s.confirm().unwrap().contains("Remove node-a from the swarm?"), "{:?}", s.confirm());
    s.press(&[Key::Esc]);
    assert_eq!(store.read().unwrap().members.len(), 2, "anything but y must change nothing");
    s.press(&[ch('d'), ch('y')]);
    assert!(s.notice().contains("node-a removed"), "{}", s.notice());
    assert_eq!(store.read().unwrap().members.len(), 1);
    s.press(&[ch('a')]);
    assert!(s.notice().contains("Select a machine that waits to join first"), "{}", s.notice());
}

#[test]
fn unsigned_members_are_never_signed_here() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store
        .update(|s| {
            s.members.push(Member { host: 3, name: "rogue".into(), wg_key: key32(3), ..Member::default() });
            s.add_request(request("node-n", 9), COORD_KEY, Time::now())?;
            Ok(())
        })
        .unwrap();
    let mut s = Run::open(Screen::new(admin));
    let code = crate::registry::coordinator_code(&key32(1), COORD_KEY);
    let t = s.flat();
    assert!(
        t.contains(&format!("Sign your coordinator: its screen shows the code {code}.")) && t.contains("s sign the coordinator"),
        "{t}"
    );

    // The first signature asks for the coordinator's code and says that
    // the machine nobody approved is dropped.
    s.press(&[ch('s')]);
    let q = s.confirm().unwrap();
    assert!(q.contains(&format!("Its screen must show the code {code}")) && q.contains("It also drops rogue from the swarm"), "{q}");
    s.press(&[Key::Esc]);
    assert_eq!(store.read().unwrap().signed_version, 0, "anything but y must sign nothing");
    s.press(&[ch('s'), ch('y')]);
    assert!(s.notice().contains("Coordinator signed"), "{}", s.notice());
    let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
    assert_eq!(names, vec!["coord"]);

    // Later a machine appears on the coordinator without a request: no key
    // signs it; s signs the list again, which drops it.
    store
        .update(|st| {
            st.members.push(Member { host: 7, name: "late".into(), wg_key: key32(7), ..Member::default() });
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r')]);
    let t = s.flat();
    assert!(t.contains("Not signed by you: late.") && t.contains("s sign your list again"), "{t}");
    assert!(t.contains("not signed: put on the coordinator without you"), "the row says so too: {t}");
    s.press(&[ch('s')]);
    assert!(s.confirm().unwrap().contains("Sign your list again and send it?") && s.confirm().unwrap().contains("drops late"));
    s.press(&[ch('n')]);
    // Approving the real request drops it, after asking.
    s.press(&[Key::Up, Key::Up, Key::Up, ch('a')]);
    assert!(s.confirm().unwrap().contains("It also drops late from the swarm"), "{:?}", s.confirm());
    s.press(&[ch('y')]);
    let names: Vec<String> = store.read().unwrap().members.iter().map(|m| m.name.clone()).collect();
    assert_eq!(names, vec!["coord", "node-n"]);
}

#[test]
fn unproved_requests_are_marked_and_can_only_be_rejected() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store
        .update(|s| {
            let mut r = request("node-x", 5);
            r.wg_key = key32(55);
            s.add_request(r, COORD_KEY, Time::now())?;
            Ok(())
        })
        .unwrap();
    let mut s = Run::open(Screen::new(admin));
    s.press(&[ch('s'), ch('y')]);
    let t = s.flat();
    assert!(t.contains("node-x") && t.contains("no proof: reject only") && t.contains("It can only be rejected (x)"), "{t}");
    let foot = rows(&s.draw(100, 32)).last().unwrap().clone();
    assert!(!foot.contains("approve") && foot.contains("x  reject"), "no approve in the footer: {foot}");
    s.press(&[ch('a')]);
    assert!(s.notice().contains("node-x has no valid proof from your USB stick") && s.confirm().is_none(), "{}", s.notice());
    assert_eq!(store.read().unwrap().members.len(), 1);
    // In its sheet, approve is listed with the reason.
    s.press(&[Key::Enter]);
    let t = s.flat();
    assert!(t.contains("approve node-x: node-x has no valid proof") && t.contains("x reject node-x"), "{t}");
    s.press(&[Key::Down, Key::Enter, ch('y')]);
    assert!(s.notice().contains("node-x rejected"), "{}", s.notice());
    assert!(s.s.opened.is_none(), "the sheet of a request that is gone closes");
}

#[test]
fn a_reinstalled_coordinator_is_offered_and_taken() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (mut admin, store) = setup(&dir);
    keys(&dir);
    store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    admin.load().unwrap();
    admin.sign_coordinator().unwrap();
    admin.load().unwrap();
    admin.approve(&store.read().unwrap().requests[0]).unwrap();

    // Something without the stick's proof answers at the address.
    let (fake, key) = reinstalled(&dir, "coord", "another-secret-another-secret-another-secret");
    move_to(&mut admin, &fake, &key);
    let mut s = Run::open(Screen::new(admin));
    let t = s.flat();
    assert!(t.contains("oes not have the SSH key this computer saw before") && t.contains("n look at the new coordinator"), "{t}");
    assert!(t.contains("! another SSH key"), "the header says it: {t}");
    s.press(&[ch('a')]);
    assert!(s.notice().contains("another SSH key"), "nothing is signed for it: {}", s.notice());
    s.press(&[ch('n')]);
    assert!(s.notice().contains("Not a coordinator of yours") && s.notice().contains("no valid proof"), "{}", s.notice());
    assert!(s.confirm().is_none());

    // The real reinstall.
    let dir2 = TempDir::new();
    let (mut admin, store) = setup(&dir2);
    keys(&dir2);
    store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    admin.load().unwrap();
    admin.sign_coordinator().unwrap();
    admin.load().unwrap();
    admin.approve(&store.read().unwrap().requests[0]).unwrap();
    let (new_store, key) = reinstalled(&dir2, "coord", SECRET);
    let pinned = move_to(&mut admin, &new_store, &key);
    let mut s = Run::open(Screen::new(admin));
    s.press(&[ch('n')]);
    let code = crate::registry::coordinator_code(&key32(41), &key);
    let q = s.confirm().expect("n asks first");
    assert!(q.contains("Make coord your coordinator?") && q.contains(&format!("Its screen must show the code {code}")), "{q}");
    s.press(&[ch('x')]);
    assert_eq!(*pinned.lock().unwrap(), COORD_KEY, "saying no must change nothing");
    s.press(&[ch('n'), ch('y')]);
    assert!(s.notice().contains("coord is your coordinator now") && s.notice().contains("Kill switch (9)"), "{}", s.notice());
    assert_eq!(new_store.read().unwrap().members.len(), 2);
    let t = s.flat();
    assert!(!t.contains("Cannot talk") && !t.contains("another SSH key") && t.contains("node-a") && !t.contains("not signed"), "{t}");
    // With a coordinator that answers, n does nothing.
    s.press(&[ch('n')]);
    assert!(s.notice().contains("answers with the SSH key this computer knows"), "{}", s.notice());
}

/// A healthy machine's report, as gather makes it.
fn healthy(now: i64) -> Report {
    Report {
        format: report::FORMAT,
        time: now,
        dryserver: "0.1.0".into(),
        k3s: "v1.31.4+k3s1".into(),
        kernel: "6.12.1-arch1-1".into(),
        kernel_installed: "6.12.1-arch1-1".into(),
        upgraded: now - 2 * 86_400,
        uptime: 3 * 86_400,
        load: [0.5, 0.4, 0.3],
        cpus: 4,
        mem_used: 1 << 30,
        mem_total: 4 << 30,
        disk_used: 20 << 30,
        disk_total: 50 << 30,
        temp: Some(48),
        k3s_active: Some(true),
        firewall: Some(true),
        peers: vec![report::Peer { host: 2, age: Some(12) }],
        ..Report::default()
    }
}

/// The styles of the pieces of a doc that hold text.
fn styled(d: &Doc, text: &str) -> Vec<ratatui::style::Style> {
    d.lines.iter().flatten().filter(|s| s.0.contains(text)).map(|s| s.1).collect()
}

/// A coordinator, signed, and node-a approved.
fn signed_with_node_a(dir: &TempDir) -> (Run, Store) {
    let (admin, store) = setup(dir);
    keys(dir);
    store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    let mut s = Run::open(Screen::new(admin));
    s.press(&[ch('s'), ch('y'), ch('a'), ch('y')]);
    assert!(s.notice().contains("approved"), "{}", s.notice());
    (s, store)
}

#[test]
fn members_show_what_they_report() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (mut s, store) = signed_with_node_a(&dir);
    // Nobody has sent a report yet (an older dryserver sends none).
    assert!(s.flat().contains("no report: its dryserver is older"), "{}", s.flat());

    let now = Time::now().0.timestamp();
    let sick = Report {
        time: now - 600,
        reboot: true,
        kernel_installed: "6.12.4-arch1-1".into(),
        disk_used: 95,
        disk_total: 100,
        k3s_active: Some(false),
        firewall: Some(false),
        peers: vec![report::Peer { host: 1, age: None }],
        boot: "fallback".into(),
        ..healthy(now)
    };
    store
        .update(|st| {
            let hb = |lan: &str, r: Report| Heartbeat { lan_ip: lan.into(), report: Some(r), ..Heartbeat::default() };
            st.heartbeat(1, hb("192.168.1.50", healthy(now)), Time::now())?;
            st.heartbeat(2, hb("192.168.1.23", sick), Time::now())
        })
        .unwrap();
    s.press(&[ch('r')]);
    let doc = s.draw(160, 60);
    let t = rows(&doc).join("\n");
    assert!(t.contains("✓  coord") && t.contains("healthy · 0.1.0 · disk 40% · mem 25% · 48°C"), "{t}");
    for want in ["disk 95%", "k3s off", "firewall off", "reboot needed"] {
        assert!(t.contains(want), "{want}: {t}");
    }
    assert_eq!(styled(&doc, "k3s off").first().copied(), Some(theme::palette().alarm()), "an alarm in the row");
    // One line each, whole at 80 columns: cut, never wrapped.
    let r = rows(&s.draw(80, 24));
    let node = r.iter().find(|l| l.contains("node-a")).unwrap();
    assert!(node.contains("! ") && node.contains('…'), "{node}");

    // The sheet of the coordinator, then of node-a: whole, with what can be done.
    s.press(&[Key::Enter]);
    let t = s.flat();
    for want in [
        "As it reports itself, relayed by the coordinator",
        "dryserver 0.1.0 k3s v1.31.4+k3s1, running firewall loaded",
        "kernel 6.12.1-arch1-1",
        "up 3d upgraded 2d ago load 0.50 0.40 0.30 on 4 CPUs",
        "memory 1.0 GiB of 4.0 GiB (25%) disk 20.0 GiB of 50.0 GiB (40%) 48°C",
        "WireGuard, last handshake: node-a 12s",
        "remove coord from the swarm: The coordinator cannot be removed",
        "s sign your list again and send it",
        "n look at a new coordinator, after a reinstall: The coordinator answers with the SSH key",
    ] {
        assert!(t.contains(want), "{want}: {t}");
    }
    s.press(&[Key::Esc, Key::Down, Key::Enter]);
    let doc = s.draw(160, 60);
    let t = rows(&doc).join(" ").split_whitespace().collect::<Vec<_>>().join(" ");
    for want in [
        "k3s v1.31.4+k3s1, stopped",
        "firewall not loaded",
        "kernel 6.12.1-arch1-1 running, 6.12.4-arch1-1 installed: reboot needed",
        "clock 10m behind the coordinator's",
        "WireGuard, last handshake: coord never",
        "d remove node-a from the swarm",
    ] {
        assert!(t.contains(want), "{want}: {t}");
    }
    assert_eq!(styled(&doc, "firewall not loaded").first().map(|s| s.fg), Some(theme::palette().alarm().fg), "alarm, on the panel");
    // ↓ moves in the sheet; enter does the action under the cursor.
    s.press(&[Key::Down, Key::Enter]);
    assert!(s.confirm().unwrap().contains("Sign your list again"), "{:?}", s.confirm());
    s.press(&[ch('n')]);
    // esc closes the sheet first; it leaves only after that.
    assert_eq!(s.key(Key::Esc), Flow::Continue);
    assert!(s.s.opened.is_none());
    assert_eq!(s.key(Key::Esc), Flow::Quit);
}

#[test]
fn a_report_is_the_machines_word_and_only_about_itself() {
    let dir = TempDir::new();
    let (mut s, store) = signed_with_node_a(&dir);
    // A hacked coordinator writes what it likes into a report, past the
    // checks on its own heartbeat path.
    let now = Time::now().0.timestamp();
    store
        .update(|st| {
            let m = st.members.iter_mut().find(|m| m.host == 2).unwrap();
            m.last_seen = Time::now();
            m.report = Some(Report {
                dryserver: "0.1.0\u{1b}]52;c;ZXZpbA==\u{7}".into(),
                kernel: "x".repeat(300),
                temp: Some(9999),
                peers: (0..2000).map(|h| report::Peer { host: h, age: Some(5) }).collect(),
                ..healthy(now)
            });
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r'), Key::Down, Key::Enter]);
    let t = s.flat();
    assert!(!t.contains('\u{1b}') && !t.contains("xxxx") && !t.contains("9999"), "{t}");
    assert!(t.contains("WireGuard, last handshake: coord 5s"), "only members are peers, never itself: {t}");
    // The coordinator's own sheet is untouched by it.
    s.press(&[Key::Esc, Key::Up, Key::Enter]);
    assert!(s.flat().contains("coord sends no report"), "{}", s.flat());
    // A machine that went quiet: its report is old news.
    store
        .update(|st| {
            st.members.iter_mut().find(|m| m.host == 2).unwrap().last_seen = Time::now().add(chrono::TimeDelta::minutes(-10));
            Ok(())
        })
        .unwrap();
    s.press(&[Key::Esc, ch('r')]);
    assert!(s.flat().contains("silent for 10m"), "{}", s.flat());
}

#[test]
fn resend_drops_what_nobody_signed() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    let mut s = Run::open(Screen::new(admin));
    s.press(&[ch('s'), ch('y')]);
    assert!(!s.flat().contains("not signed"));

    // The coordinator's list was tampered with.
    store
        .update(|st| {
            st.members.push(Member { host: 7, name: "late".into(), wg_key: key32(7), ..Member::default() });
            st.signed_version = 0;
            st.signed = Default::default();
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r')]);
    let t = s.flat();
    assert!(t.contains("Not signed by you: late.") && t.contains("1 warning on the Network tab"), "{t}");
    s.press(&[Key::Tab, Key::Tab]);
    assert!(s.flat().contains("The coordinator has no valid signed list"), "{}", s.flat());
    // s signs the list again; the machine nobody signed goes.
    s.press(&[ch('s')]);
    assert!(s.confirm().unwrap().contains("It also drops late"), "{:?}", s.confirm());
    s.press(&[ch('y')]);
    assert!(s.notice().contains("sent again as version"), "{}", s.notice());
    assert_eq!(store.read().unwrap().members.len(), 1);
}

#[test]
fn a_signed_list_the_coordinator_lost_is_a_card_with_its_key() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    let mut s = Run::open(Screen::new(admin));
    s.press(&[ch('s'), ch('y')]);
    store
        .update(|st| {
            st.signed_version = 0;
            st.signed = Default::default();
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r')]);
    let t = s.flat();
    assert!(t.contains("The coordinator has no valid signed list") && t.contains("s sign your list again"), "{t}");
    s.press(&[ch('s'), ch('y')]);
    assert!(s.notice().contains("sent again"), "{}", s.notice());
    assert!(!s.flat().contains("no valid signed list"), "{}", s.flat());
}

#[test]
fn a_missing_key_file_is_a_card_that_says_what_fixes_it() {
    let dir = TempDir::new();
    let (admin, _) = setup(&dir);
    keys(&dir);
    std::fs::remove_file(dir.join("secrets").join(crate::iso::SIGNING_KEY_NAME)).unwrap();
    let s = Run::open(Screen::new(admin));
    let t = s.flat();
    assert!(t.contains("A key is missing:") && t.contains("signing_ed25519 is not there") && t.contains("secrets/ back"), "{t}");
}

#[test]
fn a_coordinator_that_lists_nobody_says_so_and_signs_nothing() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store
        .update(|s| {
            s.members.clear();
            Ok(())
        })
        .unwrap();
    let mut s = Run::open(Screen::new(admin));
    let t = s.flat();
    assert!(t.contains("The coordinator sent no entry for itself. There is nothing to sign."), "{t}");
    assert!(t.contains("Members 0") && t.contains("The coordinator lists no machine, not even itself"), "{t}");
    assert!(t.contains("No machine waits to join"), "{t}");
    s.press(&[ch('s')]);
    assert!(s.notice().contains("sent no entry for itself") && s.confirm().is_none(), "{}", s.notice());
    s.press(&[Key::Enter, Key::Down, ch('d')]);
    assert!(s.confirm().is_none(), "nothing to select, nothing asked");
}

// ---- the coordinator does not answer ----

/// A coordinator that answers only when let go, and fails when told to.
struct Gate {
    inner: Direct,
    hold: Arc<AtomicBool>,
    fail: Arc<AtomicBool>,
}

impl Link for Gate {
    fn call(&self, command: &str, stdin: &str) -> Result<String> {
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err("cannot reach the coordinator at 192.168.1.50: Connection timed out".into());
        }
        self.inner.call(command, stdin)
    }
    fn upload(&self, command: &str, header: &str, files: &[&std::path::Path]) -> Result<String> {
        self.inner.upload(command, header, files)
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

fn gated(dir: &TempDir) -> (Screen, Store, Arc<AtomicBool>, Arc<AtomicBool>) {
    let (mut admin, store) = setup(dir);
    keys(dir);
    let (hold, fail) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicBool::new(false)));
    admin.link = Box::new(Gate {
        inner: Direct {
            store: Store::new(&store.path),
            host_key: COORD_KEY.into(),
            publish_fails: Arc::default(),
            verifier: None,
            pinned: Arc::new(Mutex::new(COORD_KEY.into())),
        },
        hold: hold.clone(),
        fail: fail.clone(),
    });
    (Screen::new(admin), store, hold, fail)
}

#[test]
fn a_slow_or_silent_coordinator_never_holds_the_screen() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (screen, _, hold, fail) = gated(&dir);
    let t0 = Instant::now();
    let mut s = Run::start(screen);
    // The screen draws and takes keys while the coordinator is silent.
    let t = s.flat();
    assert!(t.contains("Asking the coordinator at 192.168.1.50") && t.contains("○ asking"), "{t}");
    assert!(!t.contains("No machine waits to join") && !t.contains("Members"), "no empty lists before an answer: {t}");
    s.key(Key::Tab);
    assert_eq!(s.s.tab, Tab::Updates);
    let t = s.flat();
    assert!(t.contains("Asking the coordinator") && !t.contains("No release published yet"), "nothing that is not known: {t}");
    s.key(Key::BackTab);
    s.key(ch('s'));
    assert!(s.notice().contains("has not answered yet"), "{}", s.notice());
    assert!(t0.elapsed() < Duration::from_secs(2), "a key waited for the coordinator");
    // After a while it says how long it waits.
    s.s.queue.since = Some(Instant::now() - Duration::from_secs(7));
    let t = s.flat();
    assert!(t.contains("asking 7s") && t.contains("It takes longer than usual"), "{t}");
    // It does not answer: a card, and the header says for how long.
    fail.store(true, Ordering::SeqCst);
    hold.store(false, Ordering::SeqCst);
    s.settle();
    let t = s.flat();
    assert!(t.contains("Cannot talk to the coordinator. Cannot reach the coordinator at 192.168.1.50"), "{t}");
    assert!(t.contains("! no answer for") && t.contains("r look again now"), "{t}");
    s.press(&[ch('a')]);
    assert!(s.notice().contains("does not answer, so nothing can be signed now"), "{}", s.notice());
    // It answers again: r looks at once.
    fail.store(false, Ordering::SeqCst);
    s.press(&[ch('r')]);
    let t = s.flat();
    assert!(!t.contains("Cannot talk") && t.contains("✓ answers") && t.contains("Sign your coordinator"), "{t}");
    // A slow answer later: the last view stays, and the header says it waits.
    hold.store(true, Ordering::SeqCst);
    s.key(ch('r'));
    s.s.queue.since = Some(Instant::now() - Duration::from_secs(6));
    assert!(s.flat().contains("slow: waiting 6s") && s.flat().contains("coord"), "{}", s.flat());
    s.key(ch('r'));
    assert!(s.notice().contains("Already asking"), "{}", s.notice());
    // Closing the screen while it waits does not wait.
    let t = Instant::now();
    drop(s);
    assert!(t.elapsed() < Duration::from_secs(1), "closing waited {:?}", t.elapsed());
    hold.store(false, Ordering::SeqCst);
}

#[test]
fn a_thread_that_stops_says_so_and_the_screen_goes_on() {
    let dir = TempDir::new();
    let (admin, _) = setup(&dir);
    keys(&dir);
    let mut s = Run::open(Screen::new(admin));
    s.s.queue.push("approving node-a".into(), true);
    let e = s.emit.clone();
    s.s.update(Event::Msg(Msg::Lost("index out of bounds".into())), &e);
    assert!(s.notice().contains("link to the coordinator stopped (index out of bounds)"), "{}", s.notice());
    assert!(s.s.busy().is_none(), "nothing waits any more");
    s.key(ch('r'));
    assert!(s.notice().contains("open Machines (4) again"), "{}", s.notice());
    assert_eq!(s.key(Key::Esc), Flow::Quit);
}

// ---- updates ----

/// A release on the coordinator, its rollout as given.
fn with_release(store: &Store, rollout: Rollout, failed_on: Option<u32>) -> u64 {
    let now = Time::now().0.timestamp();
    let r = crate::release::Release {
        serial: 1_795_000_000,
        created: now - 3600,
        expires: now + crate::release::LIFETIME,
        dryserver: crate::release::Binary { version: "0.2.0".into(), sha256: "a".repeat(64), size: 10 },
        k3s: crate::release::K3s { version: crate::iso::K3S_VERSION.into(), sha256: crate::iso::K3S_SHA256.into() },
        arch_date: "2026/11/19".into(),
        rollback: false,
        urgent: true,
        notes: "fixes the relay timeout that drops long uploads on slow links".into(),
    };
    let served = crate::fsx::dir(&store.path).join(crate::rollout::SERVED_DIR);
    let at = served.join(r.serial.to_string());
    std::fs::create_dir_all(&at).unwrap();
    let env = crate::release::seal(&crate::signed::fake::Key("admin"), &r).unwrap();
    std::fs::write(at.join(crate::rollout::RELEASE_FILE), serde_json::to_string(&env).unwrap()).unwrap();
    std::fs::write(served.join("current"), format!("{}\n", r.serial)).unwrap();
    store
        .update(|st| {
            if let Some(host) = failed_on {
                let failed = Report {
                    update: "failed".into(),
                    update_serial: r.serial,
                    update_note: "dryserver failed: exit status 1: no space left on device".into(),
                    ..healthy(now)
                };
                st.heartbeat(host, Heartbeat { lan_ip: "192.168.1.23".into(), report: Some(failed), ..Heartbeat::default() }, Time::now())?;
            }
            st.rollout = Rollout { serial: r.serial, ..rollout };
            Ok(())
        })
        .unwrap();
    r.serial
}

fn stopped_at_node_a() -> Rollout {
    Rollout {
        urgent: true,
        phase: Phase::Servers,
        paused: "node-a (the canary): update failed: dryserver failed: exit status 1: no space left on device".into(),
        pause: Pause::Failed,
        pause_host: 2,
        pause_name: "node-a".into(),
        cordoned: vec!["node-a".into()],
        ..Rollout::default()
    }
}

#[test]
fn the_release_and_a_stopped_rollout_are_shown() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (mut s, store) = signed_with_node_a(&dir);
    s.press(&[Key::Tab]);
    let t = s.flat();
    assert!(t.contains("No release published yet.") && !t.contains("p publishes"), "no p without a publisher: {t}");
    assert!(!t.contains("dryserver release"), "the screen names its keys, not commands: {t}");

    let serial = with_release(&store, stopped_at_node_a(), Some(2));
    s.press(&[ch('r')]);
    let t = s.flat();
    for want in [
        "Release 1795000000 (urgent), made",
        ": fixes the relay timeout that drops long uploads on slow links",
        "dryserver 0.2.0 · k3s",
        &format!("The rollout of release {serial} stopped at node-a. The coordinator says: node-a (the canary): update failed"),
        "enter try again or skip this machine",
        "0 of 1 servers on this release.",
        "node-a server update failed (release 1795000000): dryserver failed",
    ] {
        assert!(t.contains(want), "{want}: {t}");
    }
    assert!(!t.contains("dryserver release") && !t.contains("PAUSED"), "{t}");
    assert_eq!(s.s.selected(), Some(Row::Stopped), "the card is selected first");
    let foot = rows(&s.draw(100, 32)).last().unwrap().clone();
    assert!(foot.contains("enter  try again or skip") && !foot.contains("publish"), "{foot}");
    // enter: the card's sheet, with both ways on and a fixed release.
    s.press(&[Key::Enter]);
    let t = s.flat();
    assert!(t.contains("Release 1795000000 stopped") && t.contains("t try again: the coordinator gives node-a its turn again"), "{t}");
    assert!(t.contains("o skip this machine: the coordinator passes node-a over") && t.contains("p publish a fixed release"), "{t}");
    // node-a's own sheet has them too.
    s.press(&[Key::Esc, Key::Down, Key::Down, Key::Enter]);
    let t = s.flat();
    assert!(t.contains("the rollout stopped here") && t.contains("t try again") && t.contains("o skip this machine"), "{t}");
    for l in rows(&s.draw(80, 24)) {
        assert_eq!(l.width(), 80, "{l:?}");
    }
}

/// The screen of a desktop made by desk, with a publisher whose jobs
/// wait while hold is set.
fn publishing(dir: &TempDir, days: &Arc<FakeDays>) -> (Run, Store, Sent, Arc<AtomicBool>) {
    let (admin, store, sent, fail, parts) = desk(dir);
    keys(dir);
    let hold = Arc::new(AtomicBool::new(false));
    let (path, s, f, h) = (dir.path().to_path_buf(), sent.clone(), fail.clone(), hold.clone());
    let p = Publisher {
        admin: Arc::new(move || {
            while h.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(twin(&path, &s, &f))
        }),
        days: days.clone(),
        parts,
        today,
    };
    (Run::open(Screen::new(admin).with_publisher(p)), store, sent, hold)
}

#[test]
fn an_update_is_chosen_checked_shown_confirmed_and_published() {
    let dir = TempDir::new();
    let days = Arc::new(FakeDays::with(&[days_ago(1)]));
    let (mut s, _store, sent, hold) = publishing(&dir, &days);
    // p works from any tab: it goes to Updates.
    s.press(&[ch('p')]);
    assert_eq!(s.s.tab, Tab::Updates);
    let t = s.flat();
    for want in ["Step 1 of 3 What it is for", "A release of this dryserver (0.2.0)", "Notes", "enter next", "esc cancel"] {
        assert!(t.contains(want), "{want}: {t}");
    }
    assert!(s.s.typing(), "q and ? are letters in the notes");
    for k in crate::tui::type_text("fixes the join timeout") {
        s.key(k);
    }
    s.press(&[Key::Enter]);
    assert!(s.flat().contains("Step 2 of 3 How it rolls out") && !s.s.typing(), "{}", s.flat());
    s.press(&[Key::Down, Key::Enter, Key::Enter]);
    let t = s.flat();
    assert!(t.contains("Step 3 of 3 Review") && t.contains("fixes the join timeout") && t.contains("enter check the release"), "{t}");
    s.key(Key::Enter);
    assert!(s.s.queue.has(CHECKING), "it checks on the thread");
    s.settle();

    // What changes, before anything is signed.
    let t = s.flat();
    for want in [
        "checked and ready to sign",
        "for 3 machines, urgent:",
        "dryserver 0.1.0 -> 0.2.0",
        "urgent yes: the rollout starts at once",
        "notes fixes the join timeout",
        "enter sign and send it",
    ] {
        assert!(t.contains(want), "{want}: {t}");
    }
    assert!(sent.lock().unwrap().is_empty());
    // esc goes back to the choices, which are kept.
    s.press(&[Key::Esc]);
    assert!(s.s.form.is_some() && s.flat().contains("fixes the join timeout"), "{}", s.flat());
    s.press(&[Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
    assert!(s.s.plan.is_some(), "{}", s.flat());
    // enter asks once more; anything but y signs nothing.
    s.press(&[Key::Enter]);
    let q = s.confirm().expect("a confirm before signing");
    assert!(q.contains("Sign and send release") && q.contains("It goes to 3 machines") && q.contains("Urgent"), "{q}");
    s.press(&[ch('n')]);
    assert!(s.notice().contains("Nothing was signed") && s.s.plan.is_some() && sent.lock().unwrap().is_empty());
    hold.store(true, Ordering::SeqCst);
    s.key(Key::Enter);
    s.key(ch('y'));
    assert!(s.s.busy().unwrap().starts_with("publishing release"), "{:?}", s.s.busy());
    // The screen goes on while it sends.
    s.key(Key::Tab);
    assert_eq!(s.s.tab, Tab::Network);
    assert!(s.flat().contains("publishing release"), "the notice says what runs: {}", s.flat());
    s.key(ch('p'));
    assert!(s.notice().contains("Still publishing release") && s.s.form.is_none(), "one release at a time: {}", s.notice());
    s.key(ch('d'));
    assert!(s.notice().contains("one change at a time"), "{}", s.notice());
    hold.store(false, Ordering::SeqCst);
    s.settle();
    assert!(s.notice().contains("is on the coordinator. It updates itself first"), "{}", s.notice());
    assert_eq!(sent.lock().unwrap().len(), 1);
    s.press(&[Key::BackTab]);
    let t = s.flat();
    assert!(t.contains("(urgent), made") && t.contains("fixes the join timeout"), "the release shows under Updates: {t}");
    assert!(t.contains("Not started yet: the coordinator takes the release up") && !t.contains("No release published yet"), "{t}");
    // The next release starts from fresh choices.
    s.press(&[ch('p')]);
    let f = s.s.form.as_ref().unwrap();
    assert!(f.state.notes.is_empty() && !f.state.urgent, "{}", s.flat());
    s.press(&[Key::Esc]);
    assert!(s.s.form.is_none() && s.notice().contains("Nothing was signed"));
}

#[test]
fn a_refused_update_is_a_card_that_says_why() {
    let dir = TempDir::new();
    let days = Arc::new(FakeDays::with(&[]));
    *days.fail.lock().unwrap() = Some("cannot find archive.archlinux.org (is this computer online?)".into());
    let (mut s, _, sent, _) = publishing(&dir, &days);
    // The selection is low on the tab: the card that comes is still seen first.
    s.press(&[Key::Tab, Key::Down, Key::Down]);
    rows(&s.draw(80, 24));
    s.press(&[ch('p'), Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
    let r = rows(&s.draw(80, 24)).join("\n");
    assert!(r.contains("! Not published, nothing was signed."), "the card's first line is in view:\n{r}");
    s.press(&[Key::Down]);
    let r = rows(&s.draw(80, 24));
    assert!(r.iter().any(|l| l.starts_with(" ▌") && l.contains("node-b")), "a key brings the selection back:\n{r:#?}");
    let t = s.flat();
    assert!(t.contains("Not published, nothing was signed. Cannot find the newest Arch snapshot"), "{t}");
    assert!(t.contains("is this computer online?") && t.contains("p publish again"), "{t}");
    assert!(s.s.plan.is_none() && sent.lock().unwrap().is_empty());
    // Notes that are not plain text: said at the notes, before anything else.
    s.press(&[ch('p'), Key::Paste("caf\u{e9}".into()), Key::Enter]);
    let t = s.flat();
    assert!(t.contains("not printable ASCII") && t.contains("Step 1 of 3"), "{t}");
    assert!(!t.contains("Not published"), "a new try clears the old card: {t}");
}

#[test]
fn leaving_while_it_publishes_asks_once_and_says_what_happens() {
    let dir = TempDir::new();
    let days = Arc::new(FakeDays::with(&[days_ago(0)]));
    let (mut s, _, _, hold) = publishing(&dir, &days);
    s.press(&[ch('p'), Key::Enter, Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
    hold.store(true, Ordering::SeqCst);
    s.key(ch('y'));
    assert_eq!(s.key(Key::Esc), Flow::Continue);
    assert!(s.notice().contains("Still publishing release") && s.notice().contains("esc again leaves"), "{}", s.notice());
    assert!(s.s.after().is_none());
    assert_eq!(s.key(Key::Esc), Flow::Quit);
    let after = s.s.after().unwrap().text;
    assert!(
        after.contains("Machines closed while publishing release") && after.contains("Updates (7) shows whether it arrived"),
        "{after}"
    );
    hold.store(false, Ordering::SeqCst);
    // ctrl+c (the hub asked first) quits at once, and says the upload stopped.
    let dir = TempDir::new();
    let (mut s, _, _, hold) = publishing(&dir, &days);
    s.press(&[ch('p'), Key::Enter, Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
    hold.store(true, Ordering::SeqCst);
    s.key(ch('y'));
    assert_eq!(s.key(Key::Ctrl('c')), Flow::Quit);
    let after = s.s.after().unwrap().text;
    assert!(after.contains("The upload stopped half way") && !after.contains("dryserver release"), "{after}");
    hold.store(false, Ordering::SeqCst);
    // Nothing running: esc leaves at once, with nothing to say.
    let dir = TempDir::new();
    let (mut s, _, _, _) = publishing(&dir, &days);
    assert!(s.s.busy().is_none());
    assert_eq!(s.key(Key::Esc), Flow::Quit);
    assert!(s.s.after().is_none());
}

#[test]
fn try_again_and_skip_ask_first_and_only_when_stopped() {
    let dir = TempDir::new();
    let days = Arc::new(FakeDays::with(&[days_ago(0)]));
    let (mut s, store, _, _) = publishing(&dir, &days);
    s.press(&[Key::Tab, ch('t')]);
    assert!(s.notice().contains("Nothing to try again: there is no rollout to resume"), "{}", s.notice());
    store
        .update(|st| {
            st.rollout = Rollout { serial: 5, phase: Phase::Servers, ..Rollout::default() };
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r'), ch('t')]);
    assert!(s.notice().contains("is not stopped") && s.confirm().is_none(), "{}", s.notice());
    s.press(&[ch('o')]);
    assert!(s.notice().contains("Nothing to skip"), "{}", s.notice());
    store
        .update(|st| {
            st.rollout.paused = "node-a: update failed: no space left on device".into();
            st.rollout.pause = Pause::Failed;
            st.rollout.pause_host = 2;
            st.rollout.pause_name = "node-a".into();
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r')]);
    assert!(s.flat().contains("The rollout of release 5 stopped at node-a"), "{}", s.flat());
    s.press(&[ch('t')]);
    let q = s.confirm().unwrap();
    assert!(q.contains("Try release 5 again?") && q.contains("The coordinator gives node-a its turn again"), "{q}");
    s.press(&[ch('n')]);
    assert_eq!(store.read().unwrap().rollout.resume_asked, 0, "anything but y asks nothing");
    s.press(&[ch('t'), ch('y')]);
    assert!(s.notice().contains("Resumed: the coordinator gives node-a its turn again"), "{}", s.notice());
    assert_eq!(store.read().unwrap().rollout.resume_asked, 1);
    // Skip, from the card's sheet.
    s.press(&[Key::Home, Key::Enter, Key::Down, Key::Enter]);
    let q = s.confirm().unwrap_or_else(|| panic!("{}", s.flat()));
    assert!(q.contains("Skip node-a for release 5?") && q.contains("keeps the release it runs"), "{q}");
    s.press(&[ch('y')]);
    assert!(s.notice().contains("Skipped: the coordinator passes node-a over"), "{}", s.notice());
    assert_eq!(store.read().unwrap().rollout.skip_asked, 1);
    // A canary is never skipped; the coordinator's own update neither.
    store
        .update(|st| {
            st.rollout.pause = Pause::Canary;
            Ok(())
        })
        .unwrap();
    s.press(&[Key::Esc, ch('r'), ch('o')]);
    assert!(s.notice().contains("The canary stopped the rollout"), "{}", s.notice());
    store
        .update(|st| {
            st.rollout.phase = Phase::Failed;
            st.rollout.pause = Pause::Failed;
            st.rollout.pause_host = 0;
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r'), ch('o')]);
    assert!(s.notice().contains("never passed over: try again (t) does that"), "{}", s.notice());
    assert!(s.flat().contains("The coordinator's own update of release 5 failed"), "{}", s.flat());
}

#[test]
fn a_screen_without_a_publisher_says_where_to_publish() {
    let dir = TempDir::new();
    let (admin, _) = setup(&dir);
    keys(&dir);
    let mut s = Run::open(Screen::new(admin));
    s.press(&[ch('p')]);
    assert!(s.notice().contains("cannot publish") && s.s.form.is_none(), "{}", s.notice());
}

// ---- network, the server list, tabs and keys ----

#[test]
fn the_network_tab_lists_devices_cuts_and_warnings() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (mut s, store) = signed_with_node_a(&dir);
    s.press(&[Key::Right, Key::Right]);
    let t = s.flat();
    assert!(t.contains("No scan yet") && t.contains("No machine has cut another off.") && t.contains("Nothing needs a look."), "{t}");
    store
        .update(|st| {
            st.scanned = Time::now();
            st.unknown = vec![Device {
                ip: "192.168.1.80".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                vendor: "Raspberry Pi Trading Ltd, Cambridge UK".into(),
                ssh: true,
                seen: Time::now(),
            }];
            let m = st.members.iter_mut().find(|m| m.host == 2).unwrap();
            m.cuts = vec![CutReport { name: "coord".into(), auto: true }];
            Ok(())
        })
        .unwrap();
    s.press(&[ch('r')]);
    let t = s.flat();
    assert!(t.contains("Unknown devices 1") && t.contains("192.168.1.80") && t.contains("ssh open"), "{t}");
    assert!(t.contains("node-a cut off coord by itself"), "{t}");
    // Cut in the row at 80 columns, whole in its sheet.
    let r = rows(&s.draw(80, 24)).join("\n");
    assert!(r.contains("Raspberry Pi Trading Ltd,…") && !r.contains("Cambridge UK"), "{r}");
    s.press(&[Key::Enter]);
    let t = s.flat();
    assert!(t.contains("Vendor Raspberry Pi Trading Ltd, Cambridge UK") && t.contains("never lets it into the mesh"), "{t}");
    assert!(rows(&s.draw(80, 24)).last().unwrap().contains("esc  back"));
}

#[test]
fn the_server_list_is_written_from_the_actions() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    let wrote = Arc::new(Mutex::new(0));
    let w = wrote.clone();
    let list: WriteList = Arc::new(move || {
        *w.lock().unwrap() += 1;
        Ok("Wrote the server list ~/.ssh/config.d/dryserver (2 servers).".into())
    });
    let mut s = Run::open(Screen::new(admin).with_write_list(list));
    // Nothing signed yet: it says what first.
    s.press(&[Key::Down, Key::Enter]);
    assert!(s.flat().contains("write the server list, for ssh and the kill switch: Nothing is signed yet"), "{}", s.flat());
    s.press(&[ch('w')]);
    assert!(s.notice().contains("sign the coordinator first (s)") && *wrote.lock().unwrap() == 0, "{}", s.notice());
    s.press(&[ch('s'), ch('y'), ch('w')]);
    assert!(s.notice().contains("Wrote the server list") && *wrote.lock().unwrap() == 1, "{}", s.notice());
}

#[test]
fn tabs_move_and_keep_their_selection() {
    let dir = TempDir::new();
    let (mut s, store) = signed_with_node_a(&dir);
    assert_eq!(s.s.tab, Tab::Machines);
    for (k, want) in [(Key::Tab, Tab::Updates), (Key::Right, Tab::Network), (Key::Tab, Tab::Machines), (Key::Left, Tab::Network)] {
        s.press(&[k]);
        assert_eq!(s.s.tab, want);
    }
    s.press(&[Key::BackTab, Key::BackTab]);
    assert_eq!(s.s.tab, Tab::Machines);
    // node-a is selected; a new request above it does not move the selection.
    s.press(&[Key::Down]);
    assert_eq!(s.s.selected(), Some(Row::Member(1)));
    store.update(|st| st.add_request(request("node-b", 3), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    s.press(&[ch('r')]);
    assert_eq!(s.s.selected(), Some(Row::Member(1)), "still node-a");
    s.press(&[ch('d')]);
    assert!(s.confirm().unwrap().contains("Remove node-a"), "{:?}", s.confirm());
    s.press(&[ch('n')]);
    // Updates opens Machines on its own tab.
    let dir = TempDir::new();
    let (admin, _) = setup(&dir);
    keys(&dir);
    let s = Run::open(Screen::new(admin).on_tab(Tab::Updates));
    assert_eq!(s.s.tab, Tab::Updates);
    assert!(rows(&s.draw(100, 32))[1].contains(" Updates "), "{:?}", rows(&s.draw(100, 32))[1]);
}

#[test]
fn a_paste_where_a_key_is_expected_does_nothing() {
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store.update(|s| s.add_request(request("node-a", 2), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    let mut s = Run::open(Screen::new(admin));
    s.press(&[Key::Paste("s".into())]);
    assert!(s.confirm().is_none() && s.notice().is_empty());
    s.press(&[ch('s'), Key::Paste("y".into())]);
    assert!(s.confirm().is_some(), "a pasted y is no yes, and no no either");
    s.press(&[ch('y')]);
    assert!(s.notice().contains("Coordinator signed"));
    s.press(&[Key::Paste("ay".into())]);
    assert!(s.confirm().is_none() && store.read().unwrap().members.len() == 1);
}

#[test]
fn many_rows_and_long_names_keep_the_selection_in_view() {
    let _g = theme::force(Tier::True, false);
    let dir = TempDir::new();
    let (admin, store) = setup(&dir);
    keys(&dir);
    store
        .update(|s| {
            // As many as the coordinator keeps waiting.
            for i in 0..crate::registry::MAX_PENDING as u8 {
                let name = format!("node-{i:02}-{}", "with-a-very-long-name".repeat(2));
                s.add_request(request(&name, 100 + i), COORD_KEY, Time::now())?;
            }
            Ok(())
        })
        .unwrap();
    let mut s = Run::open(Screen::new(admin));
    assert!(s.flat().contains("Waiting to join 20"), "{}", s.flat());
    for i in 0..19 {
        s.key(Key::Down);
        let r = rows(&s.draw(80, 24));
        let at = r.iter().position(|l| l.starts_with(" ▌")).unwrap_or_else(|| panic!("row {i} is not in view: {r:#?}"));
        assert!(r[at].contains(&format!("node-{:02}", i + 1)) && r[at].contains('…'), "{}", r[at]);
        for l in &r {
            assert_eq!(l.width(), 80);
        }
    }
    // Whole in its sheet.
    s.press(&[Key::Enter]);
    assert!(s.flat().contains(&format!("node-19-{}", "with-a-very-long-name".repeat(2))), "{}", s.flat());
}

#[test]
fn help_fits_the_smallest_window() {
    let dir = TempDir::new();
    let (admin, _) = setup(&dir);
    keys(&dir);
    let s = Run::open(Screen::new(admin));
    let mut page = s.s.page(Size { width: frame::body_width(80), rows: frame::body_rows(24) });
    page.overlay = Some(Overlay::Help);
    for (tier, console) in [(Tier::True, false), (Tier::Console, true)] {
        let _g = theme::force(tier, console);
        let r = rows(&frame::draw(&page, &Scroll::default(), 80, 24)).join("\n");
        assert!(r.contains("Any key closes this.") && r.contains("back; from the list, to Home"), "{tier:?}:\n{r}");
    }
}

#[test]
fn every_tier_and_size_draws_every_state_whole() {
    let dir = TempDir::new();
    let (mut s, store) = signed_with_node_a(&dir);
    with_release(&store, stopped_at_node_a(), Some(2));
    store.update(|st| st.add_request(request("node-b", 3), COORD_KEY, Time::now()).map(|_| ())).unwrap();
    s.press(&[ch('r')]);
    let states: Vec<Vec<Key>> = vec![
        vec![],
        vec![Key::Enter],
        vec![Key::Esc, ch('a')],
        vec![ch('n'), Key::Tab],
        vec![Key::Enter],
        vec![Key::Esc, Key::Tab],
        vec![ch('?')],
    ];
    for keys in states {
        s.press(&keys);
        for (tier, console) in [(Tier::True, false), (Tier::C256, false), (Tier::Console, true), (Tier::Plain, false), (Tier::Plain, true)]
        {
            let _g = theme::force(tier, console);
            for (w, h) in [(80, 24), (100, 32), (200, 60), (79, 24), (60, 20)] {
                let d = s.draw(w, h);
                let r = rows(&d);
                assert_eq!(r.len(), h as usize);
                for l in &r {
                    assert_eq!(l.width(), w as usize, "{tier:?} {w}x{h}: {l:?}");
                }
                if frame::too_small(w, h) {
                    assert!(r.join(" ").contains("Make this window at least"));
                    continue;
                }
                assert!(r[0].contains("dryserver  Machines"), "{:?}", r[0]);
                if tier == Tier::Plain {
                    assert!(d.lines.iter().flatten().all(|s| s.1.fg.is_none() && s.1.bg.is_none()), "NO_COLOR colours nothing");
                }
                if console {
                    let all = r.join("");
                    assert!(!all.contains('✓') && !all.contains('…') && !all.contains('●'), "the console font: {all}");
                }
            }
        }
    }
}
