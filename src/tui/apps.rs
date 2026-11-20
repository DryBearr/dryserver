//! The admin's screen for apps on the cluster: what runs where, start one
//! from an image, remove one.

use std::time::{Duration, Instant};

use super::form::{Field, Form, Group, Status};
use super::{Doc, Emit, Event, Flow, Key, Model, dim, err, ok, sel, theme};
use crate::apps::{self, App, Cluster, Running};
use crate::err::Error;
use crate::registry;

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
                    .desc("Lowercase letters, digits and -. Other apps reach it as http://NAME.")
                    .validate(|v, _| if registry::valid_name(v.trim()) && v.trim().len() <= 40 { Ok(()) } else { Err("lowercase letters, digits and -, at most 40".into()) }),
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

pub struct Screen {
    cluster: Box<dyn Cluster>,
    apps: Vec<Running>,
    err: Option<Error>,
    cursor: usize,
    form: Option<Form<Draft>>,
    /// App awaiting remove confirmation.
    confirm: String,
    pub notice: String,
    last_load: Option<Instant>,
}

impl Screen {
    pub fn new(cluster: Box<dyn Cluster>) -> Screen {
        Screen {
            cluster,
            apps: Vec::new(),
            err: None,
            cursor: 0,
            form: None,
            confirm: String::new(),
            notice: String::new(),
            last_load: None,
        }
    }

    pub fn load(&mut self) {
        self.last_load = Some(Instant::now());
        match apps::list(self.cluster.as_ref()) {
            Ok(a) => {
                self.apps = a;
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
        self.cursor = self.cursor.min(self.apps.len().saturating_sub(1));
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
        if !self.confirm.is_empty() {
            let name = std::mem::take(&mut self.confirm);
            if k == Key::Char('y') {
                self.notice = match apps::remove(self.cluster.as_ref(), &name) {
                    Ok(()) => format!("{name} removed."),
                    Err(e) => format!("Not removed: {e}"),
                };
                self.load();
            } else {
                self.notice = "Nothing removed.".into();
            }
            return Flow::Continue;
        }
        match k {
            Key::Char('q') | Key::Esc | Key::Ctrl('c') => return Flow::Quit,
            Key::Up | Key::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            Key::Down | Key::Char('j') => self.cursor = (self.cursor + 1).min(self.apps.len().saturating_sub(1)),
            Key::Char('n') => {
                self.notice.clear();
                self.form = Some(new_app_form());
            }
            Key::Char('d') => match self.apps.get(self.cursor) {
                Some(a) => self.confirm = a.name.clone(),
                None => self.notice = "No app selected.".into(),
            },
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
                if self.form.is_none() && self.confirm.is_empty() && self.last_load.is_none_or(|t| t.elapsed() >= REFRESH) {
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
        if self.apps.is_empty() && self.err.is_none() {
            b.add(dim("  No apps yet. Press n to start one from a container image.")).nl();
        }
        for (i, a) in self.apps.iter().enumerate() {
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
        if !self.confirm.is_empty() {
            b.nl().add(err(format!("Remove {}? Its containers stop. y to confirm", self.confirm))).nl();
        } else if !self.notice.is_empty() {
            b.nl().s(&self.notice).nl();
        }
        b.nl().append(theme::keys(&[("↑↓", "select"), ("n", "new app"), ("d", "remove"), ("r", "refresh"), ("q", "quit")])).nl();
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

    fn type_in(s: &mut Screen, text: &str) {
        for k in crate::tui::type_text(text) {
            s.key(k);
        }
        s.key(Key::Enter);
    }

    #[test]
    fn list_new_and_remove() {
        let fake = Arc::new(Fake::default());
        let mut s = Screen::new(Box::new(Shared(fake.clone())));
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
        let mut s = Screen::new(Box::new(Shared(fake.clone())));
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
}
