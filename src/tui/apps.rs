//! The admin's screen for apps on the cluster: what runs where, start one
//! from an image, remove one, and open or close the way in from outside.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::form::{Field, Form, Group, Status};
use super::{Doc, Emit, Event, Flow, Key, Model, dim, err, ok, sel, theme};
use crate::apps::{self, App, Cluster, Overview};
use crate::err::Error;

/// Each refresh is an SSH login, and the coordinator lets one address
/// open 10 a minute.
const REFRESH: Duration = Duration::from_secs(15);

pub enum Msg {}

/// What the admin types for a new app.
#[derive(Debug, Clone, Default)]
struct Draft {
    name: String,
    image: String,
    port: String,
    host: String,
    copies: String,
}

impl Draft {
    fn app(&self) -> App {
        App {
            name: self.name.trim().into(),
            image: self.image.trim().into(),
            port: self.port.trim().parse().unwrap_or(0),
            host: self.host.trim().to_ascii_lowercase(),
            copies: if self.copies.trim().is_empty() { 1 } else { self.copies.trim().parse().unwrap_or(0) },
        }
    }
}

fn new_app_form() -> Form<Draft> {
    type D = Draft;
    Form::new(
        Draft::default(),
        vec![
            Group::new(vec![
                Field::input("Name", |d: &D| d.name.clone(), |d, v| d.name = v)
                    .placeholder("blog")
                    .desc("Starts with a letter; lowercase letters, digits and -. Other apps reach it as http://NAME.")
                    .validate(|v, _| apps::valid_app_name(v.trim())),
                Field::input("Image", |d: &D| d.image.clone(), |d, v| d.image = v)
                    .placeholder("nginx:1.27")
                    .desc("The container image to run, with its tag.")
                    .validate(|v, _| apps::valid_image(v.trim())),
                Field::input("Port", |d: &D| d.port.clone(), |d, v| d.port = v)
                    .placeholder("80")
                    .desc("The port the container listens on.")
                    .validate(|v, _| match v.trim().parse::<u16>() {
                        Ok(p) if p > 0 => Ok(()),
                        _ => Err("a number from 1 to 65535".into()),
                    }),
            ]),
            Group::new(vec![
                Field::input("Public host name (optional)", |d: &D| d.host.clone(), |d, v| d.host = v)
                    .placeholder("blog.example.com")
                    .desc("Leave empty to keep the app inside the cluster. With a name, the ingress\nroutes that name to it; point the name at your tunnel.")
                    .validate(|v, _| apps::valid_host(&v.trim().to_ascii_lowercase())),
                Field::input("Copies", |d: &D| d.copies.clone(), |d, v| d.copies = v)
                    .placeholder("1")
                    .desc("How many to run. More than one spreads over your servers.")
                    .validate(|v, _| match v.trim() {
                        "" => Ok(()),
                        n => match n.parse::<u32>() {
                            Ok(c) if (1..=20).contains(&c) => Ok(()),
                            _ => Err("1 to 20".into()),
                        },
                    }),
            ]),
        ],
        "back",
    )
}

/// What waits for a "y".
#[derive(Debug, Clone, PartialEq)]
enum Confirm {
    None,
    /// Remove this app.
    Remove(String),
    /// Open the tunnel with this token.
    Open(String),
    Close,
}

pub struct Screen {
    cluster: Box<dyn Cluster>,
    /// Where the admin saves the tunnel's token (in secrets/).
    token_file: PathBuf,
    now: Overview,
    err: Option<Error>,
    cursor: usize,
    form: Option<Form<Draft>>,
    confirm: Confirm,
    pub notice: String,
    last_load: Option<Instant>,
}

impl Screen {
    pub fn new(cluster: Box<dyn Cluster>, token_file: PathBuf) -> Screen {
        Screen {
            cluster,
            token_file,
            now: Overview::default(),
            err: None,
            cursor: 0,
            form: None,
            confirm: Confirm::None,
            notice: String::new(),
            last_load: None,
        }
    }

    pub fn load(&mut self) {
        self.last_load = Some(Instant::now());
        match apps::overview(self.cluster.as_ref()) {
            Ok(o) => {
                self.now = o;
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
        self.cursor = self.cursor.min(self.now.apps.len().saturating_sub(1));
    }

    /// "t": reads the token the admin saved and asks before opening.
    fn ask_open(&mut self) {
        let text = match std::fs::read_to_string(&self.token_file) {
            Ok(t) => t,
            Err(_) => {
                self.notice = format!(
                    "No tunnel token yet. In the Cloudflare dashboard (Zero Trust, Networks, Tunnels) create a tunnel\nand save its token as {}. Then press t again.",
                    self.token_file.display()
                );
                return;
            }
        };
        match apps::tunnel_token(&text) {
            Ok(t) => self.confirm = Confirm::Open(t),
            Err(e) => self.notice = format!("{}: {e}", self.token_file.display()),
        }
    }

    fn confirmed(&mut self, what: Confirm) {
        let c = self.cluster.as_ref();
        self.notice = match what {
            Confirm::None => return,
            Confirm::Remove(name) => match apps::remove(c, &name) {
                Ok(()) => format!("{name} removed."),
                Err(e) => format!("Not removed: {e}"),
            },
            Confirm::Open(token) => match apps::connect_tunnel(c, &token) {
                Ok(()) => format!("Tunnel starting. In the Cloudflare dashboard, point each public host name at\n{}", apps::TUNNEL_TARGET),
                Err(e) => format!("Tunnel not started: {e}"),
            },
            Confirm::Close => match apps::remove_tunnel(c) {
                Ok(()) => "Tunnel closed. Nothing from outside reaches your apps.".into(),
                Err(e) => format!("Tunnel not closed: {e}"),
            },
        };
        self.load();
    }

    pub fn key(&mut self, k: Key) -> Flow {
        if let Some(f) = self.form.as_mut() {
            f.update(&k);
            match f.status {
                Status::Completed => {
                    let app = self.form.take().map(|f| f.state.app()).unwrap_or_default();
                    self.notice = match apps::deploy(self.cluster.as_ref(), &app) {
                        Ok(()) => format!("{} is starting. The cluster picks a server for it.", app.name),
                        Err(e) => format!("Not started: {e}"),
                    };
                    self.load();
                }
                Status::Aborted => {
                    self.form = None;
                    self.notice = "Nothing started.".into();
                }
                Status::Active => {}
            }
            return Flow::Continue;
        }
        if self.confirm != Confirm::None {
            let what = std::mem::replace(&mut self.confirm, Confirm::None);
            if k == Key::Char('y') {
                self.confirmed(what);
            } else {
                self.notice = if matches!(what, Confirm::Remove(_)) { "Nothing removed." } else { "Tunnel left as it is." }.into();
            }
            return Flow::Continue;
        }
        match k {
            Key::Char('q') | Key::Esc | Key::Ctrl('c') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.now.apps.len().saturating_sub(1)),
            Key::Char('n') => {
                self.notice.clear();
                self.form = Some(new_app_form());
            }
            Key::Char('d') => match self.now.apps.get(self.cursor) {
                Some(a) => self.confirm = Confirm::Remove(a.name.clone()),
                None => self.notice = "No app selected.".into(),
            },
            Key::Char('t') => {
                self.notice.clear();
                self.ask_open();
            }
            Key::Char('T') => {
                self.notice.clear();
                if self.now.tunnel.is_some() {
                    self.confirm = Confirm::Close;
                } else {
                    self.notice = "No tunnel to close.".into();
                }
            }
            Key::Char('r') => {
                self.notice.clear();
                self.load();
            }
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
                if self.form.is_none() && self.confirm == Confirm::None && self.last_load.is_none_or(|t| t.elapsed() >= REFRESH) {
                    self.load();
                }
                Flow::Continue
            }
            _ => Flow::Continue,
        }
    }

    fn view(&self) -> Doc {
        let mut b = Doc::new();
        if let Some(f) = &self.form {
            b.append(theme::header("new app")).s("\n\n");
            b.append(f.view());
            return b;
        }
        b.append(theme::header("apps")).s("   ").add(dim("the cluster picks a server for each and moves it when one dies")).s("\n\n");
        if let Some(e) = &self.err {
            b.add(err(format!("Cannot reach the cluster: {e}"))).s("\n\n");
        }
        // The way in from outside comes first: it decides who can reach
        // anything below.
        b.s("  From outside: ");
        match self.now.tunnel {
            None => b.add(dim("closed. t opens a Cloudflare Tunnel to the apps with a public name.")),
            Some((ready, want)) if ready > 0 && ready == want => {
                b.add(ok(format!("Cloudflare Tunnel connected, {ready} of {want} copies")))
            }
            Some((0, want)) => {
                b.add(err(format!("Cloudflare Tunnel not connected, 0 of {want} copies (wrong token, or no way out to Cloudflare)")))
            }
            Some((ready, want)) => b.add(err(format!("Cloudflare Tunnel connected with {ready} of {want} copies"))),
        };
        b.s("\n\n");
        if self.now.apps.is_empty() && self.err.is_none() {
            b.add(dim("  No apps yet. Press n to start one from a container image.")).nl();
        }
        for (i, a) in self.now.apps.iter().enumerate() {
            let on = if a.nodes.is_empty() { "-".to_string() } else { a.nodes.join(",") };
            let text = format!("{:<16} {:<18} {:<26} {}", a.name, on, if a.host.is_empty() { "inside only" } else { &a.host }, a.image);
            if i == self.cursor {
                b.add(sel(format!("> {text}")));
            } else {
                b.s(format!("  {text}"));
            }
            let state = format!("  {}/{} running", a.ready, a.copies);
            if a.copies > 0 && a.ready == a.copies {
                b.add(ok(state)).nl()
            } else {
                b.add(err(state)).nl()
            };
        }
        match &self.confirm {
            Confirm::Remove(name) => b.nl().add(err(format!("Remove {name}? Its containers stop. y to confirm"))).nl(),
            Confirm::Open(_) => {
                let what = if self.now.tunnel.is_some() { "Give the tunnel the token from" } else { "Open the tunnel with the token from" };
                b.nl()
                    .add(err(format!(
                        "{what} {}? Cloudflare then sends what arrives for your public host names to the ingress. y to confirm",
                        self.token_file.display()
                    )))
                    .nl()
            }
            Confirm::Close => b.nl().add(err("Close the tunnel? Nothing from outside reaches your apps after that. y to confirm")).nl(),
            Confirm::None if !self.notice.is_empty() => b.nl().s(&self.notice).nl(),
            Confirm::None => &mut b,
        };
        b.nl()
            .append(theme::keys(&[
                ("↑↓", "select"),
                ("n", "new app"),
                ("d", "remove"),
                ("t", "tunnel"),
                ("T", "close tunnel"),
                ("r", "refresh"),
                ("q", "quit"),
            ]))
            .nl();
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::tests::{Fake, LISTING};
    use std::sync::Arc;

    /// A Cluster that shares one Fake with the test.
    struct Shared(Arc<Fake>);
    impl Cluster for Shared {
        fn kubectl(&self, args: &[&str], stdin: &str) -> crate::err::Result<String> {
            self.0.kubectl(args, stdin)
        }
    }

    fn screen(fake: &Arc<Fake>, dir: &crate::testutil::TempDir) -> Screen {
        Screen::new(Box::new(Shared(fake.clone())), dir.join("cloudflare_tunnel_token"))
    }

    fn type_in(s: &mut Screen, text: &str) {
        for k in crate::tui::type_text(text) {
            s.key(k);
        }
        s.key(Key::Enter);
    }

    #[test]
    fn list_new_and_remove() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = screen(&fake, &dir);
        s.load();
        assert!(s.view().plain().contains("No apps yet. Press n"), "{}", s.view().plain());

        // A new app: name, image, port, then no public name and one copy.
        s.key(Key::Char('n'));
        assert!(s.view().plain().contains("dryserver  new app"));
        type_in(&mut s, "blog");
        type_in(&mut s, "ghcr.io/me/blog:v2");
        type_in(&mut s, "8080");
        type_in(&mut s, "Blog.Example.com");
        type_in(&mut s, "");
        assert!(s.notice.contains("blog is starting"), "{:?}\n{}", s.notice, s.view().plain());
        let calls = fake.calls.lock().unwrap().clone();
        let (args, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert_eq!(args, "apply -f -");
        assert!(
            manifest.contains("image: \"ghcr.io/me/blog:v2\"")
                && manifest.contains("- host: \"blog.example.com\"")
                && manifest.contains("replicas: 1"),
            "{manifest}"
        );

        // The cluster now has it (and one that is not healthy).
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        let v = s.view().plain();
        assert!(v.contains("blog") && v.contains("node-a,node-b") && v.contains("blog.example.com") && v.contains("1/2 running"), "{v}");
        assert!(v.contains("api") && v.contains("inside only") && v.contains("0/1 running"), "{v}");

        // Remove asks first; the cursor is on api, the first by name.
        s.key(Key::Char('d'));
        assert!(s.view().plain().contains("Remove api? Its containers stop. y to confirm"));
        s.key(Key::Char('n'));
        assert!(s.notice.contains("Nothing removed") && !fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete")));
        s.key(Key::Down);
        s.key(Key::Char('d'));
        s.key(Key::Char('y'));
        assert!(s.notice.contains("blog removed"), "{:?}", s.notice);
        assert!(fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete") && a.contains("-l app=blog")));
    }

    #[test]
    fn bad_input_and_errors() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let mut s = screen(&fake, &dir);
        s.load();
        s.key(Key::Char('n'));
        // A bad name does not leave the field.
        type_in(&mut s, "My App");
        assert!(s.view().plain().contains("lowercase letters, digits and -"), "{}", s.view().plain());
        s.key(Key::Esc);
        assert!(s.notice.contains("Nothing started") && fake.calls.lock().unwrap().iter().all(|(a, _)| !a.contains("apply")));
        // The cluster is not reachable.
        *fake.fail.lock().unwrap() = Some("cannot log in to the coordinator".into());
        s.key(Key::Char('r'));
        assert!(s.view().plain().contains("Cannot reach the cluster: cannot log in"), "{}", s.view().plain());
        s.key(Key::Char('d'));
        assert!(s.notice.contains("No app selected"));
    }

    #[test]
    fn tunnel_from_the_saved_token() {
        let fake = Arc::new(Fake::default());
        let dir = crate::testutil::TempDir::new();
        let file = dir.join("cloudflare_tunnel_token");
        let mut s = screen(&fake, &dir);
        s.load();
        let applied = |f: &Fake| f.calls.lock().unwrap().iter().filter(|(a, _)| a == "apply -f -").count();
        assert!(s.view().plain().contains("From outside: closed. t opens a Cloudflare Tunnel"), "{}", s.view().plain());

        // No token saved: says where it goes, starts nothing.
        s.key(Key::Char('t'));
        assert!(s.notice.contains("No tunnel token yet") && s.notice.contains("cloudflare_tunnel_token"), "{:?}", s.notice);
        s.key(Key::Char('T'));
        assert!(s.notice.contains("No tunnel to close"));
        // Something that is not a token.
        std::fs::write(&file, "my password\n").unwrap();
        s.key(Key::Char('t'));
        assert!(s.notice.contains("not a tunnel token"), "{:?}", s.notice);
        assert_eq!(applied(&fake), 0);

        // The dashboard's command line, pasted whole. Asks first.
        let token = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmNkZWYiLCJzIjoiWldGemVTQjBieUJ6WldVPSJ9";
        std::fs::write(&file, format!("cloudflared service install {token}\n")).unwrap();
        s.key(Key::Char('t'));
        let v = s.view().plain();
        assert!(v.contains("Open the tunnel with the token from") && v.contains("y to confirm"), "{v}");
        assert!(!v.contains(token), "the token is never shown");
        s.key(Key::Char('x'));
        assert!(s.notice.contains("Tunnel left as it is") && applied(&fake) == 0);
        s.key(Key::Char('t'));
        s.key(Key::Char('y'));
        assert!(
            s.notice.contains("Tunnel starting") && s.notice.contains("http://traefik.kube-system.svc.cluster.local:80"),
            "{:?}",
            s.notice
        );
        let calls = fake.calls.lock().unwrap().clone();
        let (_, manifest) = calls.iter().find(|(a, _)| a == "apply -f -").expect("nothing applied");
        assert!(manifest.contains(&format!("token: \"{token}\"")) && manifest.contains("kind: Secret"), "{manifest}");
        assert!(calls.iter().all(|(a, _)| !a.contains(token)), "the token travels on stdin, never in a command line");

        // One of two copies holds a connection.
        *fake.listing.lock().unwrap() = LISTING.into();
        s.key(Key::Char('r'));
        assert!(s.view().plain().contains("Cloudflare Tunnel connected with 1 of 2 copies"), "{}", s.view().plain());

        // Close asks first.
        s.key(Key::Char('T'));
        assert!(s.view().plain().contains("Close the tunnel? Nothing from outside reaches your apps"));
        s.key(Key::Esc);
        assert!(!fake.calls.lock().unwrap().iter().any(|(a, _)| a.contains("delete")));
        s.key(Key::Char('T'));
        s.key(Key::Char('y'));
        assert!(s.notice.contains("Tunnel closed"), "{:?}", s.notice);
        assert!(
            fake.calls.lock().unwrap().iter().any(|(a, _)| a == "-n edge delete deployment/cloudflared secret/tunnel --ignore-not-found")
        );
    }
}
