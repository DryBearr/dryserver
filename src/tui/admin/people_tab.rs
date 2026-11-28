//! The People tab: who else may log in to the machines. Each person has
//! an account of their own on the servers they are let in on, their SSH
//! keys only: no sudo, no docker, no cluster. Every change is in the list
//! you sign, and asks for y first.

use std::path::Path;

use super::{Act, Ask, Do, Entry, Row, Screen, Tab, dim, err, txt};
use crate::err::Result;
use crate::signed::{self, Person, key_body};
use crate::tui::form::{Field, Form, Group, Status};
use crate::tui::frame::{self, Focus, Notice, col};
use crate::tui::theme::{self, Mark};
use crate::tui::{Doc, Seg};
use crate::{bail, fsx, mesh, registry};

/// What the form is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Someone new.
    New,
    /// One more key for someone let in.
    AddKey,
    /// Where someone let in may log in.
    Machines,
}

/// A person's answers, while they are given.
#[derive(Debug, Clone)]
pub struct PersonDraft {
    pub mode: Mode,
    pub name: String,
    /// A public key as pasted, or the path of a .pub file.
    pub key: String,
    /// The machines; none: every server, not the coordinator.
    pub on: Vec<String>,
}

/// The keys in what was typed: pasted key lines, or the path of a file
/// that holds them (~ is the home folder). Each checked; at least one.
pub fn parse_keys(input: &str, home: Option<&Path>) -> Result<Vec<String>> {
    let input = input.trim();
    if input.is_empty() {
        bail!("paste their public key, or type the path of their .pub file");
    }
    let looks_like_key = |s: &str| {
        let t = s.split_whitespace().next().unwrap_or("");
        t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-")
    };
    let text = if looks_like_key(input) {
        input.to_string()
    } else {
        let path = match (input.strip_prefix("~/"), home) {
            (Some(rest), Some(h)) => h.join(rest),
            _ => Path::new(input).to_path_buf(),
        };
        if !path.is_file() {
            bail!("not a key, and no file {}: paste their public key (ssh-ed25519 AAAA...), or the path of their .pub file", path.display());
        }
        let meta = std::fs::metadata(&path)?;
        if meta.len() > 64 * 1024 {
            bail!("{} is too big for a key file", path.display());
        }
        fsx::read_string(&path)?
    };
    let mut keys: Vec<String> = Vec::new();
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if l.contains("PRIVATE KEY") {
            bail!("that is a private key: give the public one (the .pub file); and keep the private one to its owner");
        }
        let body = key_body(l);
        if !registry::valid_ssh_key(&body) {
            bail!("not an SSH public key: {}", frame_cut(l));
        }
        if !keys.iter().any(|k| key_body(k) == body) {
            keys.push(l.to_string());
        }
    }
    if keys.is_empty() {
        bail!("no key in it");
    }
    Ok(keys)
}

fn frame_cut(s: &str) -> String {
    crate::tui::fit(&crate::report::printable(s), 40)
}

/// A key, short: its type, the end of its body and its comment.
pub fn short_key(k: &str) -> String {
    let mut parts = k.split_whitespace();
    let kind = parts.next().unwrap_or("?");
    let body = parts.next().unwrap_or("");
    let tail: String = body.chars().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect();
    let comment: Vec<&str> = parts.collect();
    let comment = if comment.is_empty() { String::new() } else { format!(" {}", crate::report::printable(&comment.join(" "))) };
    format!("{kind} …{tail}{comment}")
}

/// Where someone may log in, in words.
fn on_words(p: &Person) -> String {
    if p.on.is_empty() { "every server (not the coordinator)".into() } else { p.on.join(", ") }
}

fn form(d: PersonDraft, taken: Vec<String>, admin: String, machines: Vec<(String, String)>, home: Option<std::path::PathBuf>) -> Form<PersonDraft> {
    type D = PersonDraft;
    let mode = d.mode;
    let name = Field::input("Name", |d: &D| d.name.clone(), |d, v| d.name = v)
        .placeholder("ana")
        .desc("Their account on the machines: lowercase letters, digits, _ and -, at most 32.")
        .validate(move |v, _| {
            let v = v.trim();
            if !signed::valid_person_name(v) || v == admin {
                bail!("lowercase letters, digits, _ and -, starting with a letter; not your own account ({admin})");
            }
            if taken.iter().any(|t| t == v) {
                bail!("{v} is let in already: its sheet (enter on it) adds a key or changes the machines");
            }
            Ok(())
        });
    let key = Field::input("Their SSH public key", |d: &D| d.key.clone(), |d, v| d.key = v)
        .placeholder("ssh-ed25519 AAAA... ana@laptop, or ~/ana.pub")
        .desc(
            "Paste the line from their .pub file (they make it with ssh-keygen -t ed25519), or type the file's path. Only \
             the public half: their private key never leaves their computer.",
        )
        .validate(move |v, _| parse_keys(v, home.as_deref()).map(|_| ()));
    let on = Field::multi("Machines", move |_| machines.clone(), |d: &D| d.on.clone(), |d, v| d.on = v)
        .when_empty("every server (not the coordinator)")
        .desc(
        "Space chooses. None chosen: every server, not the coordinator, and new servers too. The coordinator only when \
         chosen here.",
    );
    let groups = match mode {
        Mode::New => vec![
            Group::new(vec![name, key]).title("Let someone in"),
            Group::new(vec![on]).title("Where they may log in"),
        ],
        Mode::AddKey => vec![Group::new(vec![key]).title(&format!("One more key for {}", d.name))],
        Mode::Machines => vec![Group::new(vec![on]).title(&format!("Where {} may log in", d.name))],
    };
    Form::new(d, groups, "cancel").done_label("sign it")
}

impl Screen {
    fn person(&self, r: Option<Row>) -> Option<&Person> {
        match r {
            Some(Row::Person(i)) => self.view.people.get(i),
            _ => None,
        }
    }

    /// The machines a form offers, the coordinator named as such.
    fn machine_options(&self) -> Vec<(String, String)> {
        let coord = self.coordinator_name();
        self.view
            .servers
            .iter()
            .map(|s| {
                let label = if Some(&s.name) == coord.as_ref() { format!("{} (the coordinator)", s.name) } else { s.name.clone() };
                (label, s.name.clone())
            })
            .collect()
    }

    pub(super) fn coordinator_name(&self) -> Option<String> {
        let ip = mesh::ip(&self.subnet, 1);
        self.view.servers.iter().find(|s| s.mesh_ip == ip).map(|s| s.name.clone())
    }

    /// The lines for p's ~/.ssh/known_hosts: each machine they may log in
    /// to, at the LAN address it signed, with the host key you signed.
    pub(super) fn known_hosts(&self, p: &Person) -> Vec<String> {
        let coord = self.coordinator_name();
        self.view
            .servers
            .iter()
            .filter(|s| p.may_log_in(&s.name, Some(&s.name) == coord.as_ref()) && !s.lan_ip.is_empty())
            .map(|s| format!("{} {}", s.lan_ip, key_body(&s.host_key)))
            .collect()
    }

    fn open_person_form(&mut self, mut d: PersonDraft) {
        // Machines removed since are no choice any more: the review shows
        // exactly what is chosen.
        d.on.retain(|n| self.view.servers.iter().any(|s| s.name == *n));
        let taken = self.view.people.iter().map(|p| p.name.clone()).collect();
        let admin = self.desk.as_ref().map(|d| d.admin_user.clone()).unwrap_or_default();
        let home = self.desk.as_ref().and_then(|d| d.files.clone());
        self.opened = None;
        self.entry = Some(Entry::Person(form(d, taken, admin, self.machine_options(), home)));
    }

    pub(super) fn person_done(&mut self, d: PersonDraft) {
        let home = self.desk.as_ref().and_then(|d| d.files.clone());
        let name = d.name.trim().to_string();
        let old = self.view.people.iter().find(|p| p.name == name).cloned();
        let keys = match d.mode {
            Mode::Machines => Vec::new(),
            _ => match parse_keys(&d.key, home.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    self.notice = Some(Notice::bad(format!("Nothing was signed: {e}.")));
                    return;
                }
            },
        };
        let gone = || Notice::bad(format!("Nothing was signed: {name} is not let in any more."));
        let (question, consequences, act) = match (d.mode, &old) {
            (Mode::New, _) => {
                let person = Person { name: name.clone(), keys: keys.clone(), on: d.on.clone() };
                (
                    format!("Let {name} in?"),
                    vec![
                        format!("An account {name} on {}, with this key only: {}.", on_words(&person), short_key(&keys[0])),
                        "No sudo, no docker, no cluster, nothing forwarded. The machines follow within a minute.".into(),
                        format!("Then give {name} the lines for their known_hosts: their sheet shows them, f writes them to a file."),
                    ],
                    Act::LetIn(person),
                )
            }
            (Mode::AddKey, Some(p)) => {
                let new: Vec<String> = keys.into_iter().filter(|k| !p.keys.iter().any(|o| key_body(o) == key_body(k))).collect();
                if new.is_empty() {
                    self.notice = Some(Notice::info(format!("Nothing was signed: {name} has that key already.")));
                    return;
                }
                if p.keys.len() + new.len() > signed::MAX_PERSON_KEYS {
                    self.notice = Some(Notice::bad(format!(
                        "Nothing was signed: {name} would have more than {} keys. Take them out (d) and let them in again with the ones they use.",
                        signed::MAX_PERSON_KEYS
                    )));
                    return;
                }
                (
                    format!("Add a key for {name}?"),
                    vec![format!("{name} may log in with {} as well, on {}.", short_key(&new[0]), on_words(p))],
                    Act::AddKeys { name: name.clone(), keys: new },
                )
            }
            (Mode::Machines, Some(p)) => {
                let after = Person { on: d.on.clone(), ..p.clone() };
                (
                    format!("Let {name} in on {}?", on_words(&after)),
                    vec!["Machines no longer named lock the account within a minute; the others let it in.".into()],
                    Act::PersonOn { name: name.clone(), on: d.on.clone() },
                )
            }
            (_, None) => {
                self.notice = Some(gone());
                return;
            }
        };
        self.tab = Tab::People;
        self.pick[Tab::People.at()] = Some(format!("p:{name}"));
        self.ask = Some(self.with_drops(Ask { question, consequences, act }));
    }

    /// Writes p's known_hosts lines into a file for them, in the home
    /// folder.
    fn write_hosts(&mut self, p: &Person) {
        let Some(dir) = self.desk.as_ref().and_then(|d| d.files.clone()) else {
            self.notice = Some(Notice::bad("There is no home folder to write the file in."));
            return;
        };
        let lines = self.known_hosts(p);
        let path = dir.join(format!("dryserver-{}-known_hosts", p.name));
        let text = format!(
            "# Your swarm's machines, for {name}: add these lines to ~/.ssh/known_hosts.\n# Then: ssh {name}@ADDRESS\n{}\n",
            lines.join("\n"),
            name = p.name
        );
        // Its own name: written again after each change (never through a link).
        self.notice = Some(match fsx::write_new(&path, text, 0o644) {
            Ok(()) => Notice::ok(format!("Wrote {} ({} machines): give it to {}.", path.display(), lines.len(), p.name)),
            Err(e) => Notice::bad(format!("{} was not written: {e}", path.display())),
        });
    }

    // ---- the actions ----

    pub(super) fn people_label(&self, d: Do, r: Option<Row>) -> String {
        let name = self.person(r).map(|p| p.name.clone()).unwrap_or_default();
        match d {
            Do::LetIn => "let someone in: their own account, their key only".into(),
            Do::AddKey => format!("add a key for {name}"),
            Do::OnMachines => format!("change where {name} may log in"),
            Do::HostsFile => format!("write {name}'s known_hosts lines to a file"),
            Do::TakeOut => format!("take {name} out"),
            _ => String::new(),
        }
    }

    /// Some: decided here (None in it: it can be done); None: the usual
    /// checks decide.
    pub(super) fn people_why_not(&self, d: Do, r: Option<Row>) -> Option<Option<String>> {
        match d {
            Do::HostsFile => Some(match self.person(r) {
                None => Some("Select a person first (People tab).".into()),
                Some(p) if self.known_hosts(p).is_empty() => {
                    Some("No address on your network is known yet for their machines: they report one within a minute.".into())
                }
                Some(_) if self.desk.as_ref().is_none_or(|d| d.files.is_none()) => Some("There is no home folder to write it in.".into()),
                Some(_) => None,
            }),
            _ => None,
        }
    }

    pub(super) fn people_why_not_signed(&self, d: Do, r: Option<Row>) -> Option<String> {
        if self.desk.is_none() {
            return Some("This screen cannot let people in: dryserver people in a terminal does.".into());
        }
        match d {
            Do::LetIn if self.view.version == 0 => Some("Sign the coordinator first (Machines tab).".into()),
            Do::LetIn => None,
            Do::AddKey | Do::OnMachines | Do::TakeOut => self.person(r).is_none().then(|| "Select a person first (People tab).".into()),
            _ => None,
        }
    }

    pub(super) fn people_act(&mut self, d: Do, r: Option<Row>) -> Option<Ask> {
        let p = self.person(r).cloned();
        let draft = |mode, p: &Option<Person>| PersonDraft {
            mode,
            name: p.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
            key: String::new(),
            on: p.as_ref().map(|p| p.on.clone()).unwrap_or_default(),
        };
        match d {
            Do::LetIn => self.open_person_form(draft(Mode::New, &None)),
            Do::AddKey => self.open_person_form(draft(Mode::AddKey, &p)),
            Do::OnMachines => self.open_person_form(draft(Mode::Machines, &p)),
            Do::HostsFile => {
                if let Some(p) = p {
                    self.write_hosts(&p);
                }
            }
            Do::TakeOut => {
                let p = p.expect("why_not checked it");
                return Some(Ask {
                    question: format!("Take {} out?", p.name),
                    consequences: vec![
                        format!("Within a minute every machine locks the account {} and ends its sessions.", p.name),
                        "Their files stay on the machines.".into(),
                    ],
                    act: Act::TakeOut(p.name),
                });
            }
            _ => {}
        }
        None
    }

    pub(super) fn person_form_key(&mut self, mut f: Form<PersonDraft>, k: &crate::tui::Key) {
        f.update(k);
        match f.status {
            Status::Completed => self.person_done(f.state.clone()),
            Status::Aborted => self.notice = Some(Notice::info("Nothing was signed.")),
            Status::Active => self.entry = Some(Entry::Person(f)),
        }
    }

    // ---- the page ----

    pub(super) fn people_body(&self, w: usize) -> (Doc, Option<Focus>) {
        let p = theme::palette();
        let mut b = Doc::new();
        self.top_cards(&mut b, w);
        if self.answered.is_none() {
            return (b, None);
        }
        let v = &self.view;
        let sel = self.selected();
        let mut focus = None;
        frame::section(&mut b, "People who may log in", Some(v.people.len()));
        if v.people.is_empty() {
            b.append(frame::empty(
                "Nobody else may log in. a lets someone in: an account of their own on your servers, their SSH key only, no sudo.",
            ))
            .nl();
        }
        for (i, person) in v.people.iter().enumerate() {
            if sel == Some(Row::Person(i)) {
                focus = Some(Focus::row(b.lines.len() - 1));
            }
            let n = person.keys.len();
            b.append(frame::row(
                w,
                Mark::Done,
                vec![
                    col(Seg(person.name.clone(), p.text()), 16),
                    col(Seg(format!("{n} key{}", if n == 1 { "" } else { "s" }), p.hint()), 8),
                    col(Seg(format!("on {}", on_words(person)), p.hint()), 0),
                ],
            ))
            .nl();
        }
        b.nl();
        b.add(dim("Each has an account of their own, their keys only: no sudo, no docker, no cluster, nothing forwarded.")).nl();
        if !v.people.is_empty() {
            b.add(dim("enter on one shows the lines their ssh needs to know your machines.")).nl();
        }
        (b, focus)
    }

    /// The sheet's words about person i; returns its title.
    pub(super) fn person_about(&self, i: usize, about: &mut Vec<Vec<Seg>>) -> String {
        let p = theme::palette();
        let Some(person) = self.view.people.get(i) else { return String::new() };
        about.push(vec![txt(format!("May log in on {}.", on_words(person)))]);
        about.push(vec![txt("No sudo, no docker, no cluster, nothing forwarded.")]);
        about.push(Vec::new());
        about.push(vec![Seg("Keys".into(), p.title())]);
        for k in &person.keys {
            about.push(vec![dim(format!("  {}", short_key(k)))]);
        }
        about.push(Vec::new());
        let lines = self.known_hosts(person);
        if lines.is_empty() {
            about.push(vec![err("No address on your network is known yet for their machines; they report one within a minute.")]);
        } else {
            about.push(vec![Seg(format!("For {}'s ~/.ssh/known_hosts", person.name), p.title())]);
            about.push(vec![dim("So their ssh knows the machines are yours (f writes these to a file for them):")]);
            for l in lines {
                about.push(vec![dim(format!("  {l}"))]);
            }
            about.push(vec![txt(format!("Then they log in with: ssh {}@ADDRESS", person.name))]);
        }
        person.name.clone()
    }
}
