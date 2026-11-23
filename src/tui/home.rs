//! Home: every place with one line on how it stands, and the next step.
//! Everything here comes from files on this computer (config.env, out/,
//! secrets/), so it shows at once and never waits for the network.

use std::path::Path;
use std::time::SystemTime;

use ratatui::style::Modifier;

use super::app::{Paths, Place};
use super::backups::{self, Copy};
use super::frame::{self, col};
use super::theme::{self, Mark};
use super::{Doc, Seg};
use crate::config::Config;
use crate::{admin, iso, signed};

/// Backups older than this want pulling.
pub const OLD_BACKUP_SECS: u64 = 7 * 86_400;

/// The places of Home, in order: the digit opens it.
pub const ITEMS: [(Place, &str); 9] = [
    (Place::Config, "Config"),
    (Place::Installer, "Installer"),
    (Place::Stick, "USB stick"),
    (Place::Machines, "Machines"),
    (Place::Apps, "Apps"),
    (Place::Outside, "Outside"),
    (Place::Updates, "Updates"),
    (Place::Backups, "Backups"),
    (Place::Kill, "Kill switch"),
];

/// The groups of Home: a title and how many items it has.
const GROUPS: [(&str, usize); 3] = [("Set up", 3), ("Run", 5), ("When something is wrong", 1)];

/// The keys a build makes.
pub const KEYS: [&str; 6] =
    [iso::SIGNING_KEY_NAME, iso::SIGNING_PUB, iso::KEY_NAME, iso::JOIN_SECRET, iso::BACKUP_KEY_NAME, iso::BACKUP_PUB];
/// Of those, what Machines signs and talks to the coordinator with.
pub const ADMIN_KEYS: [&str; 4] = [iso::SIGNING_KEY_NAME, iso::SIGNING_PUB, iso::KEY_NAME, iso::JOIN_SECRET];

#[derive(Debug, Clone)]
pub enum Cfg {
    Missing,
    /// It does not load or does not check out; the first problem.
    Broken(String),
    Ok(Box<Config>),
}

/// Who is in the list this computer signed last.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signed {
    pub coordinator: Option<String>,
    pub servers: usize,
}

/// What Home knows, all of it read from local files.
#[derive(Debug, Clone)]
pub struct Facts {
    pub cfg: Cfg,
    /// The config reads, even if it does not check out: the screens that
    /// talk to the coordinator only need its address.
    pub cfg_loads: bool,
    pub cfg_time: Option<SystemTime>,
    /// The installer image: its size and when it was made.
    pub iso: Option<(u64, SystemTime)>,
    /// When this dryserver was built.
    pub exe_time: Option<SystemTime>,
    /// Keys from KEYS that are not in secrets/.
    pub missing_keys: Vec<String>,
    pub signed: Option<Signed>,
    pub signed_time: Option<SystemTime>,
    /// The serial of the last release signed here.
    pub release: Option<u64>,
    /// The backups here, newest first.
    pub backups: Vec<Copy>,
    /// This computer has met the coordinator (its host key is pinned).
    pub met: bool,
    pub root: bool,
    pub now: SystemTime,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// The list in a signed copy, without checking the signature: this
/// computer wrote it, and Home only counts. Machines checks it.
pub fn read_signed(path: &Path) -> Option<Signed> {
    let env: signed::Envelope = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let list: signed::List = serde_json::from_str(&env.doc).ok()?;
    Some(Signed {
        coordinator: list.members.iter().find(|m| m.host == 1).map(|m| m.name.clone()),
        servers: list.members.iter().filter(|m| m.host != 1).count(),
    })
}

/// The serial of a signed release copy, the same way.
pub fn read_release(path: &Path) -> Option<u64> {
    let env: signed::Envelope = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&env.doc).ok()?;
    doc.get("serial")?.as_u64()
}

impl Facts {
    pub fn read(paths: &Paths, exe_time: Option<SystemTime>, root: bool) -> Facts {
        let mut cfg_loads = false;
        let cfg = if !paths.config.exists() {
            Cfg::Missing
        } else {
            let (c, e) = Config::load_partial(&paths.config);
            cfg_loads = e.is_none();
            match e.or_else(|| c.validate().err()) {
                Some(e) if e.is_not_found() => Cfg::Missing,
                Some(e) => Cfg::Broken(e.to_string().lines().next().unwrap_or("").trim_start_matches("· ").to_string()),
                None => Cfg::Ok(Box::new(c)),
            }
        };
        let iso_path = iso::iso_path(&paths.out_dir);
        let iso =
            std::fs::metadata(&iso_path).ok().filter(|m| m.is_file()).map(|m| (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
        let s = &paths.secrets;
        let signed_path = s.join(admin::SIGNED_COPY);
        Facts {
            cfg,
            cfg_loads,
            cfg_time: mtime(&paths.config),
            iso,
            exe_time,
            missing_keys: KEYS.iter().filter(|k| !s.join(k).exists()).map(|k| k.to_string()).collect(),
            signed: read_signed(&signed_path),
            signed_time: mtime(&signed_path),
            release: read_release(&s.join(admin::RELEASE_COPY)),
            backups: backups::copies(&s.join("backups")),
            met: s.join(admin::KNOWN_HOSTS).exists(),
            root,
            now: SystemTime::now(),
        }
    }

    fn secs_since(&self, t: SystemTime) -> u64 {
        self.now.duration_since(t).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// How the installer image stands against the config and this program.
    pub fn iso_problem(&self) -> Option<&'static str> {
        let (_, made) = self.iso?;
        if self.cfg_time.is_some_and(|c| c > made) {
            return Some("older than the config: build it again");
        }
        if self.exe_time.is_some_and(|e| e > made) {
            return Some("made by an older dryserver: build it again");
        }
        None
    }

    /// The newest backup here is old, or there is none long after the
    /// coordinator was signed. In days.
    fn backups_old(&self) -> Option<u64> {
        // Before the coordinator is signed there is nothing to back up.
        self.signed.as_ref()?.coordinator.as_ref()?;
        match self.backups.first() {
            Some(c) => {
                let age = self.secs_since(c.made);
                (age > OLD_BACKUP_SECS).then_some(age / 86_400)
            }
            None => {
                let age = self.secs_since(self.signed_time?);
                (age > OLD_BACKUP_SECS).then_some(age / 86_400)
            }
        }
    }
}

/// Under sudo only these work: the stick is written as root.
pub fn works_as_root(p: Place) -> bool {
    matches!(p, Place::Installer | Place::Stick)
}

/// "9 days", "5 hours", "a minute".
pub fn age(secs: u64) -> String {
    let n = |n: u64, one: &str, many: &str| if n == 1 { format!("1 {one}") } else { format!("{n} {many}") };
    match secs {
        0..60 => "less than a minute".into(),
        60..3600 => n(secs / 60, "minute", "minutes"),
        3600..86_400 => n(secs / 3600, "hour", "hours"),
        _ => n(secs / 86_400, "day", "days"),
    }
}

/// The mark and the status line of a place.
pub fn line(f: &Facts, place: Place) -> (Mark, String) {
    if f.root && !works_as_root(place) {
        return (Mark::Off, "open dryserver without sudo".into());
    }
    let cfg_ok = matches!(f.cfg, Cfg::Ok(_));
    let keys = f.missing_keys.is_empty();
    let admin_keys = !f.missing_keys.iter().any(|k| ADMIN_KEYS.contains(&k.as_str()));
    let coordinator = f.signed.as_ref().and_then(|s| s.coordinator.clone());
    match place {
        Place::Config => match &f.cfg {
            Cfg::Missing => (Mark::Act, "not made yet: start here".into()),
            Cfg::Broken(e) => (Mark::Bad, format!("has a problem: {e}")),
            Cfg::Ok(c) => {
                let net = if c.wifi_ssid.is_empty() { "Ethernet only".to_string() } else { format!("WiFi {}", c.wifi_ssid) };
                (Mark::Done, format!("coordinator {}, {net}", c.coord_lan_ip))
            }
        },
        Place::Installer => match (f.iso, f.iso_problem()) {
            (None, _) if !cfg_ok => (Mark::Off, "needs the config first (1)".into()),
            (None, _) => (Mark::Act, "not built yet".into()),
            (Some(_), Some(p)) => (Mark::Bad, p.into()),
            (Some(_), None) if !keys => (Mark::Bad, "the keys are missing: build it again".into()),
            (Some((size, made)), None) => {
                let when = chrono::DateTime::<chrono::Local>::from(made).format("%Y-%m-%d %H:%M");
                (Mark::Done, format!("built {when}, {}", crate::disks::human_size(size)))
            }
        },
        Place::Stick => match (f.iso, f.root) {
            (None, _) => (Mark::Off, "build the installer first (2)".into()),
            (Some(_), true) => (Mark::Act, "write the installer to a stick".into()),
            (Some(_), false) => (Mark::Off, "write the installer to a stick (asks for sudo)".into()),
        },
        Place::Machines if !admin_keys => (Mark::Off, "no keys yet: build the installer (2)".into()),
        Place::Machines => match f.signed.as_ref().filter(|s| s.coordinator.is_some()) {
            None => (Mark::Act, "sign your coordinator once it is installed".into()),
            Some(s) if s.servers == 0 => (Mark::Done, "coordinator signed, no server yet".into()),
            Some(s) => (Mark::Done, format!("coordinator and {} {}", s.servers, if s.servers == 1 { "server" } else { "servers" })),
        },
        Place::Apps | Place::Outside => {
            let what = if place == Place::Apps { "what runs on your servers" } else { "the ways in from the internet" };
            if coordinator.is_none() || !f.met {
                (Mark::Off, format!("{what}, once the coordinator is signed (4)"))
            } else {
                (Mark::Blank, what.into())
            }
        }
        Place::Updates => match (f.release, &coordinator) {
            (Some(s), _) => (Mark::Done, format!("release {s}")),
            (None, None) => (Mark::Off, "once the coordinator is signed (4)".into()),
            (None, Some(_)) => (Mark::Off, "no release published yet".into()),
        },
        Place::Backups => match (f.backups.first(), f.backups_old()) {
            (None, Some(days)) => (Mark::Bad, format!("no copy here, and the coordinator was signed {days} days ago: pull them")),
            (Some(_), Some(days)) => (Mark::Bad, format!("newest copy is {days} days old: pull them")),
            (Some(c), None) => (Mark::Done, format!("newest copy is {} old", age(f.secs_since(c.made)))),
            (None, None) => (Mark::Off, "no copy on this computer yet".into()),
        },
        Place::Kill => (Mark::Blank, "cut the coordinator off from every server".into()),
        Place::Home => (Mark::Blank, String::new()),
    }
}

/// What to do next: the place that does it, and the words. None when
/// nothing needs doing.
#[derive(Debug, Clone, PartialEq)]
pub struct Next {
    pub place: Option<Place>,
    pub text: String,
}

/// The first of: no config, a config with errors, no installer or an
/// older one, no keys, no signed coordinator, no server, old backups.
pub fn next(f: &Facts) -> Next {
    let n = |p: Place, t: &str| Next { place: Some(p), text: t.to_string() };
    let mut next = match &f.cfg {
        Cfg::Missing => n(Place::Config, "Make the config (1): the WiFi, the coordinator's address and your SSH key."),
        Cfg::Broken(e) => n(Place::Config, &format!("Fix the config (1): {e}")),
        Cfg::Ok(_) => match (f.iso, f.iso_problem()) {
            (None, _) => n(Place::Installer, "Build the installer (2): it also makes your keys."),
            (Some(_), Some(p)) if p.starts_with("older than the config") => {
                n(Place::Installer, "Build the installer again (2): the config changed since it was built.")
            }
            (Some(_), Some(_)) => n(Place::Installer, "Build the installer again (2): the stick has an older dryserver."),
            (Some(_), None) if !f.missing_keys.is_empty() => {
                n(Place::Installer, "Build the installer again (2): it makes your keys, and some are missing.")
            }
            _ => match &f.signed {
                Some(s) if s.coordinator.is_some() && s.servers > 0 => match f.backups_old() {
                    Some(days) => n(Place::Backups, &format!("Pull the backups (8): the newest here is {days} days old.")),
                    None => Next { place: None, text: "Nothing to do: everything here is up to date.".into() },
                },
                Some(s) if s.coordinator.is_some() => {
                    n(Place::Machines, "Install a server from the stick, then approve it in Machines (4).")
                }
                _ => n(Place::Machines, "Install the coordinator from the stick (3), then sign it in Machines (4)."),
            },
        },
    };
    if f.root && next.place.is_some_and(|p| !works_as_root(p)) {
        next.text += " Open dryserver without sudo for that.";
    }
    next
}

/// Home's body, width cells wide with rows to show it in, and the line of
/// the selected item.
pub fn body(f: &Facts, cursor: usize, width: usize, rows: usize) -> (Doc, usize) {
    let p = theme::palette();
    let nx = next(f);
    let next_segs = match nx.place {
        Some(_) => {
            vec![Seg("Next".into(), p.selected().add_modifier(Modifier::BOLD)), Seg("  ".into(), p.text()), Seg(nx.text.clone(), p.text())]
        }
        None => vec![theme::mark(Mark::Done), Seg(" ".into(), p.text()), Seg(nx.text.clone(), p.fg(p.gold))],
    };
    // The next step in lines of width cells, hanging after "Next".
    let hang = if nx.place.is_some() { 6 } else { 2 };
    let next_lines = |d: &mut Doc, width: usize| {
        for (i, l) in frame::wrap_line(&next_segs[2..], width.saturating_sub(hang)).into_iter().enumerate() {
            if i > 0 {
                d.nl().s(" ".repeat(hang));
            } else {
                d.add(next_segs[0].clone()).add(next_segs[1].clone());
            }
            for s in l {
                d.add(s);
            }
        }
    };
    let mut items = Doc::new();
    let mut focus = 0;
    let mut i = 0;
    for (gi, (group, count)) in GROUPS.iter().enumerate() {
        if gi > 0 {
            items.nl();
        }
        items.add(Seg(group.to_string(), p.title())).nl();
        for _ in 0..*count {
            let (place, name) = ITEMS[i];
            let (m, status) = line(f, place);
            let off = f.root && !works_as_root(place);
            let digit = Seg(format!("{}", i + 1), if off { p.faint() } else { p.fg(p.gold).add_modifier(Modifier::BOLD) });
            let name = Seg(name.into(), if off { p.faint() } else { p.text() });
            let status = Seg(status, if off || m == Mark::Off { p.faint() } else { p.hint() });
            if i == cursor {
                focus = items.lines.len() - 1;
            }
            items.append(frame::row(width, m, vec![col(digit, 1), col(name, 12), col(status, 0)])).nl();
            i += 1;
        }
    }
    // The items end in an empty line.
    let item_rows = items.lines.len() - 1;
    let full = theme::snake_height() + 1 + item_rows + 1 + frame::wrap_line(&next_segs[2..], width.saturating_sub(hang)).len() <= rows;
    // A short window gets the small ring, with the next step beside it,
    // where it is seen without scrolling.
    let (snake, snake_rows, snake_w) = if full { (theme::snake(None), theme::snake_height(), 20) } else { (theme::ring(None), 5, 11) };
    let mut title = Doc::new();
    let title_rows = if full { 2 } else { 3 + frame::wrap_line(&next_segs[2..], width.saturating_sub(snake_w + 3 + hang)).len() };
    for _ in 0..snake_rows.saturating_sub(title_rows) / 2 {
        title.nl();
    }
    title.add(Seg("dryserver".into(), p.title())).nl();
    title.add(Seg("your own server swarm".into(), p.hint()));
    if !full {
        title.nl().nl();
        next_lines(&mut title, width.saturating_sub(snake_w + 3));
    }
    let mut d = Doc::beside(snake, 3, title);
    d.nl().nl();
    let top = d.lines.len() - 1;
    d.append(items);
    if full {
        d.nl();
        next_lines(&mut d, width);
    }
    (d, top + focus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn facts() -> Facts {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        Facts {
            cfg: Cfg::Ok(Box::new(Config { coord_lan_ip: "10.1.0.60".into(), wifi_ssid: "SNET2".into(), ..Config::default() })),
            cfg_loads: true,
            cfg_time: Some(t),
            iso: Some((1_200_000_000, t + Duration::from_secs(60))),
            exe_time: Some(t),
            missing_keys: vec![],
            signed: Some(Signed { coordinator: Some("coord".into()), servers: 2 }),
            signed_time: Some(t),
            release: Some(1_795_400_000),
            backups: vec![Copy { name: "brain-x".into(), made: t + Duration::from_secs(86_400), size: 1 }],
            met: true,
            root: false,
            now: t + Duration::from_secs(2 * 86_400),
        }
    }

    #[test]
    fn next_step_in_order() {
        let ok = facts();
        assert_eq!(next(&ok).place, None, "{:?}", next(&ok));
        assert!(next(&ok).text.contains("Nothing to do"));
        let case = |f: &dyn Fn(&mut Facts), want: Place, words: &str| {
            let mut x = facts();
            f(&mut x);
            let n = next(&x);
            assert_eq!(n.place, Some(want), "{words}: {n:?}");
            assert!(n.text.contains(words), "{words}: {n:?}");
        };
        case(&|f| f.cfg = Cfg::Missing, Place::Config, "Make the config (1)");
        case(&|f| f.cfg = Cfg::Broken("COORD_LAN_IP is empty".into()), Place::Config, "Fix the config (1): COORD_LAN_IP is empty");
        case(&|f| f.iso = None, Place::Installer, "Build the installer (2)");
        case(&|f| f.cfg_time = Some(f.now), Place::Installer, "the config changed since");
        case(&|f| f.exe_time = Some(f.now), Place::Installer, "an older dryserver");
        case(&|f| f.missing_keys = vec![iso::SIGNING_KEY_NAME.into()], Place::Installer, "makes your keys");
        case(&|f| f.signed = None, Place::Machines, "sign it in Machines (4)");
        case(&|f| f.signed = Some(Signed { coordinator: None, servers: 1 }), Place::Machines, "sign it");
        case(&|f| f.signed.as_mut().unwrap().servers = 0, Place::Machines, "Install a server");
        case(&|f| f.now += Duration::from_secs(9 * 86_400), Place::Backups, "Pull the backups (8): the newest here is 10 days old");
        // No backup at all, long after the coordinator was signed.
        case(
            &|f| {
                f.backups.clear();
                f.now += Duration::from_secs(9 * 86_400);
            },
            Place::Backups,
            "Pull the backups (8)",
        );
        // Earlier steps win.
        case(
            &|f| {
                f.cfg = Cfg::Missing;
                f.iso = None;
                f.signed = None;
            },
            Place::Config,
            "Make the config",
        );
        case(
            &|f| {
                f.iso = None;
                f.missing_keys = vec!["x".into()];
            },
            Place::Installer,
            "Build the installer (2)",
        );
        // Under sudo the step says where it can be done.
        let mut f = facts();
        f.signed = None;
        f.root = true;
        assert!(next(&f).text.ends_with("Open dryserver without sudo for that."));
        f.iso = None;
        assert!(!next(&f).text.contains("without sudo"), "the installer works under sudo");
    }

    #[test]
    fn lines_say_how_each_place_stands() {
        let f = facts();
        let l = |f: &Facts, p| line(f, p);
        assert_eq!(l(&f, Place::Config), (Mark::Done, "coordinator 10.1.0.60, WiFi SNET2".into()));
        assert_eq!(l(&f, Place::Installer).0, Mark::Done);
        assert_eq!(l(&f, Place::Machines), (Mark::Done, "coordinator and 2 servers".into()));
        assert_eq!(l(&f, Place::Updates), (Mark::Done, "release 1795400000".into()));
        assert_eq!(l(&f, Place::Backups), (Mark::Done, "newest copy is 1 day old".into()));
        assert_eq!(l(&f, Place::Stick).0, Mark::Off);
        let mut g = facts();
        g.exe_time = Some(g.now);
        assert_eq!(l(&g, Place::Installer), (Mark::Bad, "made by an older dryserver: build it again".into()));
        g.iso = None;
        assert_eq!(l(&g, Place::Installer), (Mark::Act, "not built yet".into()));
        assert_eq!(l(&g, Place::Stick), (Mark::Off, "build the installer first (2)".into()));
        g.cfg = Cfg::Missing;
        assert_eq!(l(&g, Place::Installer).0, Mark::Off);
        assert_eq!(l(&g, Place::Config).0, Mark::Act);
        let mut g = facts();
        g.now += Duration::from_secs(10 * 86_400);
        assert_eq!(l(&g, Place::Backups), (Mark::Bad, "newest copy is 11 days old: pull them".into()));
        g.missing_keys = vec![iso::BACKUP_KEY_NAME.into()];
        assert_eq!(l(&g, Place::Machines).0, Mark::Done, "Machines does not need the backup key");
        g.missing_keys = vec![iso::SIGNING_KEY_NAME.into()];
        assert_eq!(l(&g, Place::Machines).0, Mark::Off);
        let mut g = facts();
        g.met = false;
        assert_eq!(l(&g, Place::Apps).0, Mark::Off);
        // Under sudo only the installer and the stick work.
        let mut g = facts();
        g.root = true;
        for (p, _) in ITEMS {
            let (m, s) = l(&g, p);
            if works_as_root(p) {
                assert!(!s.contains("without sudo"), "{p:?}");
            } else {
                assert_eq!((m, s.as_str()), (Mark::Off, "open dryserver without sudo"), "{p:?}");
            }
        }
        assert_eq!(l(&g, Place::Stick).0, Mark::Act);
        assert_eq!(age(30), "less than a minute");
        assert_eq!(age(3600), "1 hour");
        assert_eq!(age(9 * 86_400 + 5), "9 days");
    }

    #[test]
    fn reads_local_files_only() {
        let dir = crate::testutil::TempDir::new();
        let p = Paths { config: dir.join("config.env"), out_dir: dir.join("out"), secrets: dir.join("secrets") };
        let f = Facts::read(&p, None, false);
        assert!(matches!(f.cfg, Cfg::Missing) && f.iso.is_none() && f.signed.is_none() && f.backups.is_empty());
        assert_eq!(f.missing_keys.len(), KEYS.len());
        std::fs::write(&p.config, "COORD_LAN_IP='nope'\n").unwrap();
        assert!(matches!(Facts::read(&p, None, false).cfg, Cfg::Broken(_)));
        std::fs::create_dir_all(&p.secrets).unwrap();
        let list = signed::List {
            version: 3,
            members: vec![
                signed::Entry { host: 1, name: "coord".into(), ..Default::default() },
                signed::Entry { host: 2, name: "node-a".into(), ..Default::default() },
            ],
            rejected: vec![],
        };
        let env = signed::Envelope { doc: serde_json::to_string(&list).unwrap(), sig: "sig".into() };
        std::fs::write(p.secrets.join(admin::SIGNED_COPY), serde_json::to_string(&env).unwrap()).unwrap();
        let rel = signed::Envelope { doc: r#"{"serial":1795400000}"#.into(), sig: "x".into() };
        std::fs::write(p.secrets.join(admin::RELEASE_COPY), serde_json::to_string(&rel).unwrap()).unwrap();
        std::fs::write(p.secrets.join(admin::SIGNED_COPY.to_string() + "x"), "{broken").unwrap();
        let f = Facts::read(&p, None, false);
        assert_eq!(f.signed, Some(Signed { coordinator: Some("coord".into()), servers: 1 }));
        assert_eq!(f.release, Some(1_795_400_000));
        // A damaged copy is no list.
        std::fs::write(p.secrets.join(admin::SIGNED_COPY), "{broken").unwrap();
        assert_eq!(Facts::read(&p, None, false).signed, None);
    }

    #[test]
    fn body_fits_or_puts_next_up() {
        let _g = theme::force(theme::Tier::True, false);
        let mut f = facts();
        f.iso = None;
        let (d, focus) = body(&f, 0, 95, 28);
        let t = d.plain();
        let lines: Vec<&str> = t.lines().collect();
        assert!(lines.len() <= 28, "{t}");
        assert!(lines[focus].contains("1  Config"), "{:?}", lines[focus]);
        assert!(lines.last().unwrap().starts_with("Next  Build the installer (2)"), "the next step at the bottom: {t}");
        for want in ["Set up", "Run", "When something is wrong", "9  Kill switch", "dryserver", "your own server swarm"] {
            assert!(t.contains(want), "{want:?}:\n{t}");
        }
        // A short window: the next step goes up beside the snake.
        let (d, focus) = body(&f, 8, 75, 20);
        let t = d.plain();
        let lines: Vec<&str> = t.lines().collect();
        let at = lines.iter().position(|l| l.contains("Next  Build")).unwrap();
        assert!(at < 10, "{t}");
        assert!(lines[focus].contains("9  Kill switch"));
        let _g = theme::force(theme::Tier::Console, true);
        let (d, _) = body(&f, 0, 75, 20);
        assert!(d.plain().lines().count() <= 20, "the console's ring fits 80 × 24:\n{}", d.plain());
    }
}
