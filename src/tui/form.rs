//! A multi-page form: groups of fields shown one group at a time. Fields
//! read and write a state value through closures, so descriptions, options
//! and hidden groups can depend on earlier answers.

use super::{Doc, Key, dim, err, line_view, plain, sel, title};
use crate::err::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Completed,
    Aborted,
}

type Get<S> = Box<dyn Fn(&S) -> String>;
type Set<S> = Box<dyn Fn(&mut S, String)>;
type GetMany<S> = Box<dyn Fn(&S) -> Vec<String>>;
type SetMany<S> = Box<dyn Fn(&mut S, Vec<String>)>;
type Options<S> = Box<dyn Fn(&S) -> Vec<(String, String)>>;
type Validate<S> = Box<dyn Fn(&str, &S) -> Result<()>>;
type TextFn<S> = Box<dyn Fn(&S) -> String>;
type Hide<S> = Box<dyn Fn(&S) -> bool>;

enum Kind<S> {
    Note,
    Input { get: Get<S>, set: Set<S>, password: bool, placeholder: String, validate: Option<Validate<S>>, cursor: usize },
    Select { options: Options<S>, get: Get<S>, set: Set<S> },
    Multi { options: Options<S>, get: GetMany<S>, set: SetMany<S>, cursor: usize },
}

pub struct Field<S> {
    title: String,
    desc: Option<TextFn<S>>,
    kind: Kind<S>,
}

impl<S: 'static> Field<S> {
    pub fn note(title: &str, desc: &str) -> Field<S> {
        let d = desc.to_string();
        Field { title: title.into(), desc: Some(Box::new(move |_| d.clone())), kind: Kind::Note }
    }

    pub fn input(title: &str, get: impl Fn(&S) -> String + 'static, set: impl Fn(&mut S, String) + 'static) -> Field<S> {
        Field {
            title: title.into(),
            desc: None,
            kind: Kind::Input {
                get: Box::new(get),
                set: Box::new(set),
                password: false,
                placeholder: String::new(),
                validate: None,
                cursor: usize::MAX,
            },
        }
    }

    /// Options are (label, value) pairs.
    pub fn select(
        title: &str,
        options: impl Fn(&S) -> Vec<(String, String)> + 'static,
        get: impl Fn(&S) -> String + 'static,
        set: impl Fn(&mut S, String) + 'static,
    ) -> Field<S> {
        Field { title: title.into(), desc: None, kind: Kind::Select { options: Box::new(options), get: Box::new(get), set: Box::new(set) } }
    }

    pub fn multi(
        title: &str,
        options: impl Fn(&S) -> Vec<(String, String)> + 'static,
        get: impl Fn(&S) -> Vec<String> + 'static,
        set: impl Fn(&mut S, Vec<String>) + 'static,
    ) -> Field<S> {
        Field {
            title: title.into(),
            desc: None,
            kind: Kind::Multi { options: Box::new(options), get: Box::new(get), set: Box::new(set), cursor: 0 },
        }
    }

    pub fn desc(mut self, d: &str) -> Field<S> {
        let d = d.to_string();
        self.desc = Some(Box::new(move |_| d.clone()));
        self
    }

    pub fn desc_fn(mut self, f: impl Fn(&S) -> String + 'static) -> Field<S> {
        self.desc = Some(Box::new(f));
        self
    }

    pub fn placeholder(mut self, p: &str) -> Field<S> {
        if let Kind::Input { placeholder, .. } = &mut self.kind {
            *placeholder = p.into();
        }
        self
    }

    pub fn password(mut self) -> Field<S> {
        if let Kind::Input { password, .. } = &mut self.kind {
            *password = true;
        }
        self
    }

    pub fn validate(mut self, f: impl Fn(&str, &S) -> Result<()> + 'static) -> Field<S> {
        if let Kind::Input { validate, .. } = &mut self.kind {
            *validate = Some(Box::new(f));
        }
        self
    }

    fn focusable(&self) -> bool {
        !matches!(self.kind, Kind::Note)
    }
}

pub struct Group<S> {
    fields: Vec<Field<S>>,
    hide: Option<Hide<S>>,
}

impl<S> Group<S> {
    pub fn new(fields: Vec<Field<S>>) -> Group<S> {
        Group { fields, hide: None }
    }

    pub fn hide_if(mut self, f: impl Fn(&S) -> bool + 'static) -> Group<S> {
        self.hide = Some(Box::new(f));
        self
    }
}

pub struct Form<S> {
    pub state: S,
    groups: Vec<Group<S>>,
    gi: usize,
    fi: usize,
    pub status: Status,
    error: Option<String>,
    /// What esc does, for the help line ("cancel", "back").
    esc_label: String,
}

impl<S: 'static> Form<S> {
    pub fn new(state: S, groups: Vec<Group<S>>, esc_label: &str) -> Form<S> {
        let mut f = Form { state, groups, gi: 0, fi: 0, status: Status::Active, error: None, esc_label: esc_label.into() };
        match f.first_from(0) {
            Some((g, i)) => {
                f.gi = g;
                f.fi = i;
                f.enter();
            }
            None => f.status = Status::Completed,
        }
        f
    }

    fn visible(&self, g: usize) -> bool {
        self.groups[g].hide.as_ref().is_none_or(|h| !h(&self.state))
    }

    /// The first focusable field of the first visible group at or after g.
    fn first_from(&self, g: usize) -> Option<(usize, usize)> {
        (g..self.groups.len())
            .filter(|&g| self.visible(g))
            .find_map(|g| self.groups[g].fields.iter().position(|f| f.focusable()).map(|i| (g, i)))
    }

    /// The last focusable field of the last visible group before g.
    fn last_before(&self, g: usize) -> Option<(usize, usize)> {
        (0..g).rev().filter(|&g| self.visible(g)).find_map(|g| self.groups[g].fields.iter().rposition(|f| f.focusable()).map(|i| (g, i)))
    }

    fn field(&self) -> &Field<S> {
        &self.groups[self.gi].fields[self.fi]
    }

    /// Prepares the focused field: a select gets a valid value, an input's
    /// cursor goes to the end.
    fn enter(&mut self) {
        let (gi, fi) = (self.gi, self.fi);
        let state = &mut self.state;
        match &mut self.groups[gi].fields[fi].kind {
            Kind::Select { options, get, set } => {
                let opts = options(state);
                let cur = get(state);
                if !opts.iter().any(|(_, v)| *v == cur)
                    && let Some((_, v)) = opts.first()
                {
                    set(state, v.clone());
                }
            }
            Kind::Input { get, cursor, .. } => *cursor = get(state).chars().count(),
            Kind::Multi { cursor, .. } => *cursor = 0,
            Kind::Note => {}
        }
    }

    fn check(&self) -> Result<()> {
        if let Kind::Input { get, validate: Some(v), .. } = &self.field().kind {
            return v(&get(&self.state), &self.state);
        }
        Ok(())
    }

    fn next(&mut self) {
        if let Err(e) = self.check() {
            self.error = Some(e.to_string());
            return;
        }
        self.error = None;
        let fields = &self.groups[self.gi].fields;
        if let Some(i) = (self.fi + 1..fields.len()).find(|&i| fields[i].focusable()) {
            self.fi = i;
            self.enter();
            return;
        }
        match self.first_from(self.gi + 1) {
            Some((g, i)) => {
                self.gi = g;
                self.fi = i;
                self.enter();
            }
            None => self.status = Status::Completed,
        }
    }

    fn prev(&mut self) {
        self.error = None;
        let fields = &self.groups[self.gi].fields;
        if let Some(i) = (0..self.fi).rev().find(|&i| fields[i].focusable()) {
            self.fi = i;
            self.enter();
            return;
        }
        if let Some((g, i)) = self.last_before(self.gi) {
            self.gi = g;
            self.fi = i;
            self.enter();
        }
    }

    pub fn update(&mut self, k: &Key) {
        if self.status != Status::Active {
            return;
        }
        match k {
            Key::Esc | Key::Ctrl('c') => {
                self.status = Status::Aborted;
                return;
            }
            Key::BackTab => return self.prev(),
            Key::Enter | Key::Tab => return self.next(),
            _ => {}
        }
        let (gi, fi) = (self.gi, self.fi);
        let state = &mut self.state;
        match &mut self.groups[gi].fields[fi].kind {
            Kind::Input { get, set, cursor, .. } => {
                let mut v = get(state);
                if super::edit_line(&mut v, cursor, 0, k) {
                    set(state, v);
                    self.error = None;
                }
            }
            Kind::Select { options, get, set } => {
                let opts = options(state);
                let i = opts.iter().position(|(_, v)| *v == get(state)).unwrap_or(0);
                let j = match k {
                    Key::Up | Key::Char('k') | Key::Ctrl('p') => i.saturating_sub(1),
                    Key::Down | Key::Char('j') | Key::Ctrl('n') => (i + 1).min(opts.len().saturating_sub(1)),
                    _ => i,
                };
                if let Some((_, v)) = opts.get(j) {
                    set(state, v.clone());
                }
            }
            Kind::Multi { options, get, set, cursor } => {
                let opts = options(state);
                match k {
                    Key::Up | Key::Char('k') | Key::Ctrl('p') => *cursor = cursor.saturating_sub(1),
                    Key::Down | Key::Char('j') | Key::Ctrl('n') => *cursor = (*cursor + 1).min(opts.len().saturating_sub(1)),
                    Key::Char(' ') | Key::Char('x') => {
                        if let Some((_, v)) = opts.get(*cursor) {
                            let mut cur = get(state);
                            match cur.iter().position(|c| c == v) {
                                Some(p) => {
                                    cur.remove(p);
                                }
                                None => cur.push(v.clone()),
                            }
                            set(state, cur);
                        }
                    }
                    Key::Ctrl('a') => {
                        let all: Vec<String> = opts.iter().map(|(_, v)| v.clone()).collect();
                        let cur = get(state);
                        set(state, if all.iter().all(|v| cur.contains(v)) { Vec::new() } else { all });
                    }
                    _ => {}
                }
            }
            Kind::Note => {}
        }
    }

    pub fn view(&self) -> Doc {
        let mut d = Doc::new();
        let g = &self.groups[self.gi];
        for (i, f) in g.fields.iter().enumerate() {
            let focused = i == self.fi;
            // A half block: the heavy line the form used is not in the
            // console font.
            let bar = if focused { sel("▌ ") } else { plain("  ") };
            let desc = f.desc.as_ref().map(|d| d(&self.state)).unwrap_or_default();
            let line_start = |d: &mut Doc| {
                d.add(bar.clone());
            };
            match &f.kind {
                Kind::Note => {
                    d.s("  ").add(title(&f.title)).nl();
                    for l in desc.lines() {
                        d.s(format!("  {l}")).nl();
                    }
                }
                _ => {
                    if !f.title.is_empty() {
                        line_start(&mut d);
                        d.add(if focused { title(&f.title) } else { plain(&f.title) }).nl();
                    }
                    for l in desc.lines() {
                        line_start(&mut d);
                        d.add(dim(l)).nl();
                    }
                }
            }
            match &f.kind {
                Kind::Note => {}
                Kind::Input { get, password, placeholder, cursor, .. } => {
                    line_start(&mut d);
                    d.append(line_view(&get(&self.state), *cursor, placeholder, focused, *password)).nl();
                }
                Kind::Select { options, get, .. } => {
                    let cur = get(&self.state);
                    for (label, v) in options(&self.state) {
                        line_start(&mut d);
                        if *v == cur {
                            d.add(sel(format!("> {label}")));
                        } else {
                            d.s(format!("  {label}"));
                        }
                        d.nl();
                    }
                }
                Kind::Multi { options, get, cursor, .. } => {
                    let cur = get(&self.state);
                    for (j, (label, v)) in options(&self.state).iter().enumerate() {
                        line_start(&mut d);
                        let mark = if cur.contains(v) { "[x]" } else { "[ ]" };
                        let pointer = if focused && j == *cursor { ">" } else { " " };
                        let text = format!("{pointer} {mark} {label}");
                        if cur.contains(v) {
                            d.add(sel(text));
                        } else {
                            d.s(text);
                        }
                        d.nl();
                    }
                }
            }
            if focused && let Some(e) = &self.error {
                line_start(&mut d);
                d.add(err(format!("* {e}"))).nl();
            }
            d.nl();
        }
        let mut keys: Vec<(&str, &str)> = match &self.field().kind {
            Kind::Select { .. } => vec![("↑↓", "choose"), ("enter", "next")],
            Kind::Multi { .. } => vec![("↑↓", "move"), ("space", "toggle"), ("enter", "next")],
            _ => vec![("enter", "next")],
        };
        keys.extend([("shift+tab", "back"), ("esc", self.esc_label.as_str())]);
        d.append(super::theme::keys(&keys)).nl();
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct S {
        name: String,
        color: String,
        extras: Vec<String>,
        skip: bool,
    }

    fn form() -> Form<S> {
        let opts = |_: &S| vec![("Red".to_string(), "red".to_string()), ("Blue".to_string(), "blue".to_string())];
        Form::new(
            S::default(),
            vec![
                Group::new(vec![
                    Field::note("Hello", "Some text"),
                    Field::input("Name", |s: &S| s.name.clone(), |s, v| s.name = v)
                        .validate(|v, _| if v.is_empty() { Err("required".into()) } else { Ok(()) }),
                ]),
                Group::new(vec![Field::select("Color", opts, |s: &S| s.color.clone(), |s, v| s.color = v)]),
                Group::new(vec![Field::multi("Extras", opts, |s: &S| s.extras.clone(), |s, v| s.extras = v)]).hide_if(|s| s.skip),
            ],
            "cancel",
        )
    }

    #[test]
    fn walks_groups_and_validates() {
        let mut f = form();
        f.update(&Key::Enter);
        assert!(f.view().plain().contains("* required"));
        for c in "bob".chars() {
            f.update(&Key::Char(c));
        }
        f.update(&Key::Enter);
        assert_eq!(f.state.color, "red", "select gets the first option");
        f.update(&Key::Down);
        assert_eq!(f.state.color, "blue");
        f.update(&Key::Enter);
        f.update(&Key::Char(' '));
        f.update(&Key::Down);
        f.update(&Key::Char(' '));
        assert_eq!(f.state.extras, vec!["red", "blue"]);
        f.update(&Key::BackTab);
        assert!(f.view().plain().contains("> Blue"));
        f.update(&Key::Enter);
        f.update(&Key::Enter);
        assert_eq!(f.status, Status::Completed);
        assert_eq!(f.state.name, "bob");
    }

    #[test]
    fn hidden_groups_are_skipped_and_esc_aborts() {
        let mut f = form();
        f.state.skip = true;
        f.state.name = "x".into();
        f.update(&Key::Enter);
        f.update(&Key::Enter);
        assert_eq!(f.status, Status::Completed);
        let mut f = form();
        f.update(&Key::Esc);
        assert_eq!(f.status, Status::Aborted);
    }
}
