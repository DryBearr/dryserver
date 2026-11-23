//! A form in steps: each group of fields is one step ("Step 2 of 6" with
//! the group's title), and a review of every answer comes before saving.
//! Fields read and write a state value through closures, so descriptions,
//! options and hidden groups can depend on earlier answers.
//!
//! Keys: enter (or tab) goes to the next field, shift+tab to the one
//! before, esc back one step. On the first step esc leaves, and asks first
//! when something was changed. On the review enter saves, esc goes back to
//! the answers.

use std::ops::Range;

use unicode_width::UnicodeWidthStr;

use super::frame;
use super::{Doc, Key, Seg, dim, err, line_view, plain, sel, theme, title};
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

    /// The answer as the review shows it: passwords masked.
    fn answer(&self, s: &S) -> Option<String> {
        Some(match &self.kind {
            Kind::Note => return None,
            Kind::Input { get, password, .. } => {
                let v = get(s);
                match (v.is_empty(), password) {
                    (true, _) => String::new(),
                    (false, true) => "•".repeat(v.chars().count().min(12)),
                    (false, false) => v,
                }
            }
            Kind::Select { options, get, .. } => {
                let v = get(s);
                options(s).into_iter().find(|(_, o)| *o == v).map(|(l, _)| l).unwrap_or(v)
            }
            Kind::Multi { options, get, .. } => {
                let v = get(s);
                options(s).into_iter().filter(|(_, o)| v.contains(o)).map(|(l, _)| l).collect::<Vec<_>>().join(", ")
            }
        })
    }
}

pub struct Group<S> {
    fields: Vec<Field<S>>,
    hide: Option<Hide<S>>,
    title: Option<String>,
}

impl<S> Group<S> {
    pub fn new(fields: Vec<Field<S>>) -> Group<S> {
        Group { fields, hide: None, title: None }
    }

    /// The step's title; without one it is the first field's.
    pub fn title(mut self, t: &str) -> Group<S> {
        self.title = Some(t.into());
        self
    }

    pub fn hide_if(mut self, f: impl Fn(&S) -> bool + 'static) -> Group<S> {
        self.hide = Some(Box::new(f));
        self
    }

    fn name(&self) -> String {
        match &self.title {
            Some(t) => t.clone(),
            None => self.fields.iter().map(|f| f.title.clone()).find(|t| !t.is_empty()).unwrap_or_default(),
        }
    }
}

pub struct Form<S> {
    pub state: S,
    groups: Vec<Group<S>>,
    gi: usize,
    fi: usize,
    pub status: Status,
    error: Option<String>,
    /// What esc does on the first step, for the keys ("cancel", "back").
    esc_label: String,
    /// A review of every answer comes before Completed.
    review: bool,
    reviewing: bool,
    /// Something was typed or chosen.
    changed: bool,
    /// esc on the first step after a change: asking whether to leave.
    leaving: bool,
    /// The screen keeps the answers when the form is left: never ask.
    keeps_answers: bool,
    /// The old way: esc leaves from any step at once.
    esc_cancels: bool,
    /// What enter on the review does ("save").
    done_label: String,
}

impl<S: 'static> Form<S> {
    pub fn new(state: S, groups: Vec<Group<S>>, esc_label: &str) -> Form<S> {
        let mut f = Form {
            state,
            groups,
            gi: 0,
            fi: 0,
            status: Status::Active,
            error: None,
            esc_label: esc_label.into(),
            review: true,
            reviewing: false,
            changed: false,
            leaving: false,
            keeps_answers: false,
            esc_cancels: false,
            done_label: "save".into(),
        };
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

    /// No review: the last enter completes the form (the screen shows the
    /// answers itself before anything happens).
    pub fn without_review(mut self) -> Form<S> {
        self.review = false;
        self
    }

    /// The screen keeps what was typed when the form is left, so leaving
    /// never asks.
    pub fn keeps_answers(mut self) -> Form<S> {
        self.keeps_answers = true;
        self
    }

    /// esc leaves at once from any step. No screen uses it since Apps
    /// got its review; the form's tests keep it working.
    #[allow(dead_code)]
    pub fn esc_cancels(mut self) -> Form<S> {
        self.esc_cancels = true;
        self
    }

    pub fn done_label(mut self, l: &str) -> Form<S> {
        self.done_label = l.into();
        self
    }

    // For the screens that host a form; the hub needs only typing().
    #[allow(dead_code)]
    pub fn reviewing(&self) -> bool {
        self.reviewing
    }

    /// It asks whether to leave without saving: y leaves.
    pub fn leaving(&self) -> bool {
        self.leaving
    }

    #[allow(dead_code)]
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// A text field has the keys: q and ? are typed, not commands.
    pub fn typing(&self) -> bool {
        !self.reviewing && !self.leaving && self.status == Status::Active && matches!(self.field().kind, Kind::Input { .. })
    }

    fn visible(&self, g: usize) -> bool {
        self.groups[g].hide.as_ref().is_none_or(|h| !h(&self.state))
    }

    /// The steps: the visible groups that have something to answer.
    fn steps(&self) -> Vec<usize> {
        (0..self.groups.len()).filter(|&g| self.visible(g) && self.groups[g].fields.iter().any(|f| f.focusable())).collect()
    }

    /// Step n of m and its title; the review is the last step.
    pub fn step(&self) -> (usize, usize, String) {
        let steps = self.steps();
        let m = steps.len() + usize::from(self.review);
        if self.reviewing {
            return (m, m, "Review".into());
        }
        let n = steps.iter().position(|&g| g == self.gi).map(|i| i + 1).unwrap_or(1);
        (n, m, self.groups[self.gi].name())
    }

    fn first_step(&self) -> bool {
        self.steps().first().is_none_or(|&g| g == self.gi)
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

    /// The first focusable field of the last visible group before g.
    fn step_before(&self, g: usize) -> Option<(usize, usize)> {
        (0..g).rev().filter(|&g| self.visible(g)).find_map(|g| self.groups[g].fields.iter().position(|f| f.focusable()).map(|i| (g, i)))
    }

    fn field(&self) -> &Field<S> {
        &self.groups[self.gi].fields[self.fi]
    }

    fn go(&mut self, (g, i): (usize, usize)) {
        self.gi = g;
        self.fi = i;
        self.enter();
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

    fn check_field(&self, g: usize, i: usize) -> Result<()> {
        if let Kind::Input { get, validate: Some(v), .. } = &self.groups[g].fields[i].kind {
            return v(&get(&self.state), &self.state);
        }
        Ok(())
    }

    fn next(&mut self) {
        if let Err(e) = self.check_field(self.gi, self.fi) {
            self.error = Some(e.to_string());
            return;
        }
        self.error = None;
        let fields = &self.groups[self.gi].fields;
        if let Some(i) = (self.fi + 1..fields.len()).find(|&i| fields[i].focusable()) {
            self.go((self.gi, i));
            return;
        }
        match self.first_from(self.gi + 1) {
            Some(at) => self.go(at),
            None if self.review => self.reviewing = true,
            None => self.status = Status::Completed,
        }
    }

    fn prev(&mut self) {
        self.error = None;
        let fields = &self.groups[self.gi].fields;
        if let Some(i) = (0..self.fi).rev().find(|&i| fields[i].focusable()) {
            self.go((self.gi, i));
            return;
        }
        if let Some(at) = self.last_before(self.gi) {
            self.go(at);
        }
    }

    /// Every answer checked once more: a later one may have made an
    /// earlier one wrong. The first that fails is shown with its error.
    fn save(&mut self) {
        for g in self.steps() {
            for i in 0..self.groups[g].fields.len() {
                if let Err(e) = self.check_field(g, i) {
                    self.reviewing = false;
                    self.go((g, i));
                    self.error = Some(e.to_string());
                    return;
                }
            }
        }
        self.status = Status::Completed;
    }

    fn esc(&mut self) {
        self.error = None;
        if self.esc_cancels {
            self.status = Status::Aborted;
        } else if self.first_step() {
            if self.changed && !self.keeps_answers {
                self.leaving = true;
            } else {
                self.status = Status::Aborted;
            }
        } else if let Some(at) = self.step_before(self.gi) {
            self.go(at);
        }
    }

    pub fn update(&mut self, k: &Key) {
        if self.status != Status::Active {
            return;
        }
        if self.leaving {
            self.leaving = false;
            if *k == Key::Char('y') {
                self.status = Status::Aborted;
            }
            return;
        }
        if self.reviewing {
            match k {
                Key::Enter => self.save(),
                Key::Esc | Key::BackTab => {
                    self.reviewing = false;
                    if let Some(at) = self.last_before(self.groups.len()) {
                        self.go(at);
                    }
                }
                Key::Ctrl('c') => self.status = Status::Aborted,
                _ => {}
            }
            return;
        }
        match k {
            Key::Ctrl('c') => {
                self.status = Status::Aborted;
                return;
            }
            Key::Esc => return self.esc(),
            Key::BackTab => return self.prev(),
            Key::Enter | Key::Tab => return self.next(),
            _ => {}
        }
        let (gi, fi) = (self.gi, self.fi);
        let state = &mut self.state;
        let mut changed = false;
        match &mut self.groups[gi].fields[fi].kind {
            Kind::Input { get, set, cursor, .. } => {
                let before = get(state);
                let mut v = before.clone();
                if super::edit_line(&mut v, cursor, 0, k) {
                    changed = v != before;
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
                    changed = j != i;
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
                            changed = true;
                        }
                    }
                    Key::Ctrl('a') => {
                        let all: Vec<String> = opts.iter().map(|(_, v)| v.clone()).collect();
                        let cur = get(state);
                        set(state, if all.iter().all(|v| cur.contains(v)) { Vec::new() } else { all });
                        changed = true;
                    }
                    _ => {}
                }
            }
            Kind::Note => {}
        }
        self.changed |= changed;
    }

    /// What esc does now.
    pub fn esc_label(&self) -> String {
        if self.reviewing {
            "back to the answers".into()
        } else if self.esc_cancels || self.first_step() {
            self.esc_label.clone()
        } else {
            "back one step".into()
        }
    }

    /// The keys that work now, without esc.
    pub fn keys(&self) -> Vec<(String, String)> {
        let pair = |k: &str, d: &str| (k.to_string(), d.to_string());
        if self.reviewing {
            return vec![pair("enter", &self.done_label)];
        }
        let mut keys = match &self.field().kind {
            Kind::Select { .. } => vec![pair("↑↓", "choose"), pair("enter", "next")],
            Kind::Multi { .. } => vec![pair("↑↓", "move"), pair("space", "toggle"), pair("enter", "next")],
            _ => vec![pair("enter", "next")],
        };
        keys.push(pair("shift+tab", "previous"));
        keys
    }

    /// The step for the frame's body, width cells wide, with the lines of
    /// the field being answered (to keep in view).
    pub fn body(&self, width: usize) -> (Doc, Option<Range<usize>>) {
        let p = theme::palette();
        let mut d = Doc::new();
        let (n, m, name) = self.step();
        d.add(Seg(format!("Step {n} of {m}"), p.hint())).s("  ").add(title(&name)).s("\n\n");
        if self.reviewing {
            self.review_body(&mut d, width);
            return (d, None);
        }
        let mut focus = None;
        let g = &self.groups[self.gi];
        for (i, f) in g.fields.iter().enumerate() {
            let focused = i == self.fi;
            let start = d.lines.len() - 1;
            self.field_view(&mut d, f, focused, f.title == name);
            if focused {
                focus = Some(start..d.lines.len() - 1);
            }
            d.nl();
        }
        (d, focus)
    }

    fn review_body(&self, d: &mut Doc, width: usize) {
        let p = theme::palette();
        d.add(dim(format!("Every answer, before anything is done: enter to {}, esc to change one.", self.done_label))).nl();
        let label_w = self
            .steps()
            .iter()
            .flat_map(|&g| self.groups[g].fields.iter().filter(|f| f.focusable()).map(|f| f.title.width()))
            .max()
            .unwrap_or(0)
            .min(width / 2);
        for g in self.steps() {
            let group = &self.groups[g];
            frame::section(d, &group.name(), None);
            for f in group.fields.iter().filter(|f| f.focusable()) {
                let Some(a) = f.answer(&self.state) else { continue };
                let label = if f.title.is_empty() { group.name() } else { f.title.clone() };
                let label = super::fit(&label, label_w);
                d.s(format!("  {label}{}  ", " ".repeat(label_w - label.width())));
                if a.is_empty() {
                    d.add(Seg("not set".into(), p.faint()));
                } else {
                    d.s(a);
                }
                d.nl();
            }
        }
    }

    fn field_view(&self, d: &mut Doc, f: &Field<S>, focused: bool, is_title: bool) {
        // A half block: the heavy line the form used is not in the
        // console font.
        let bar = if focused { sel(format!("{} ", theme::BAR)) } else { plain("  ") };
        let desc = f.desc.as_ref().map(|d| d(&self.state)).unwrap_or_default();
        match &f.kind {
            Kind::Note => {
                if !is_title {
                    d.s("  ").add(title(&f.title)).nl();
                }
                for l in desc.lines() {
                    d.s(format!("  {l}")).nl();
                }
            }
            _ => {
                if !f.title.is_empty() && !is_title {
                    d.add(bar.clone()).add(if focused { title(&f.title) } else { plain(&f.title) }).nl();
                }
                for l in desc.lines() {
                    d.add(bar.clone()).add(dim(l)).nl();
                }
            }
        }
        match &f.kind {
            Kind::Note => {}
            Kind::Input { get, password, placeholder, cursor, .. } => {
                d.add(bar.clone()).append(line_view(&get(&self.state), *cursor, placeholder, focused, *password)).nl();
            }
            Kind::Select { options, get, .. } => {
                let cur = get(&self.state);
                for (label, v) in options(&self.state) {
                    d.add(bar.clone());
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
                    d.add(bar.clone());
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
            d.add(bar).add(err(format!("* {e}"))).nl();
        }
    }

    /// The form on its own, the step then its keys: every screen now draws
    /// it in the frame, so only the tests read it this way.
    #[cfg(test)]
    pub fn view(&self) -> Doc {
        let (mut d, _) = self.body(76);
        if self.leaving {
            d.add(err("Leave without saving? What you changed is lost. y leaves, any other key stays.")).nl();
            return d;
        }
        let keys = self.keys();
        let esc = self.esc_label();
        let mut pairs: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        pairs.push(("esc", esc.as_str()));
        d.append(theme::keys(&pairs)).nl();
        d
    }
}

/// The question a form asks before it is left without saving, for the
/// frame's confirm.
pub fn leave_question() -> (String, Vec<String>) {
    ("Leave without saving?".into(), vec!["What you changed is lost.".into()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct S {
        name: String,
        pass: String,
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
                    Field::input("Password", |s: &S| s.pass.clone(), |s, v| s.pass = v).password(),
                ])
                .title("You"),
                Group::new(vec![Field::select("Color", opts, |s: &S| s.color.clone(), |s, v| s.color = v)]),
                Group::new(vec![Field::multi("Extras", opts, |s: &S| s.extras.clone(), |s, v| s.extras = v)]).hide_if(|s| s.skip),
            ],
            "cancel",
        )
    }

    fn keys(f: &mut Form<S>, ks: &[Key]) {
        for k in ks {
            f.update(k);
        }
    }

    fn text(f: &mut Form<S>, s: &str) {
        for c in s.chars() {
            f.update(&Key::Char(c));
        }
    }

    #[test]
    fn walks_groups_and_validates() {
        let mut f = form().without_review();
        assert_eq!(f.step(), (1, 3, "You".into()));
        f.update(&Key::Enter);
        assert!(f.view().plain().contains("* required"));
        text(&mut f, "bob");
        keys(&mut f, &[Key::Enter, Key::Enter]);
        assert_eq!(f.state.color, "red", "select gets the first option");
        assert_eq!(f.step(), (2, 3, "Color".into()));
        f.update(&Key::Down);
        assert_eq!(f.state.color, "blue");
        f.update(&Key::Enter);
        keys(&mut f, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
        assert_eq!(f.state.extras, vec!["red", "blue"]);
        f.update(&Key::BackTab);
        assert!(f.view().plain().contains("> Blue"));
        keys(&mut f, &[Key::Enter, Key::Enter]);
        assert_eq!(f.status, Status::Completed);
        assert_eq!(f.state.name, "bob");
    }

    #[test]
    fn hidden_groups_are_skipped() {
        let mut f = form().without_review();
        f.state.skip = true;
        f.state.name = "x".into();
        assert_eq!(f.step().1, 2, "a hidden group is no step");
        keys(&mut f, &[Key::Enter, Key::Enter, Key::Enter]);
        assert_eq!(f.status, Status::Completed);
    }

    #[test]
    fn review_before_saving() {
        let mut f = form();
        text(&mut f, "bob");
        f.update(&Key::Enter);
        text(&mut f, "secret");
        keys(&mut f, &[Key::Enter, Key::Down, Key::Enter, Key::Char(' '), Key::Enter]);
        assert!(f.reviewing() && f.status == Status::Active, "the review comes first");
        assert_eq!(f.step(), (4, 4, "Review".into()));
        let v = f.body(80).0.plain();
        for want in ["Name", "bob", "Password", "••••••", "Color", "Blue", "Extras", "Red"] {
            assert!(v.contains(want), "review misses {want:?}:\n{v}");
        }
        assert!(!v.contains("secret"), "a password is never shown:\n{v}");
        assert_eq!(f.keys(), vec![("enter".to_string(), "save".to_string())]);
        assert_eq!(f.esc_label(), "back to the answers");
        // esc goes back to change one; a paste does nothing on the review.
        f.update(&Key::Esc);
        assert!(!f.reviewing() && f.step().2 == "Extras");
        f.update(&Key::Enter);
        f.update(&Key::Paste("x".into()));
        assert!(f.reviewing());
        // An answer that became wrong stops the save at its field.
        f.state.name.clear();
        f.update(&Key::Enter);
        assert!(!f.reviewing() && f.status == Status::Active && f.step().2 == "You");
        assert!(f.view().plain().contains("* required"));
        text(&mut f, "al");
        keys(&mut f, &[Key::Enter, Key::Enter, Key::Enter, Key::Enter]);
        assert!(f.reviewing());
        f.update(&Key::Enter);
        assert_eq!(f.status, Status::Completed);
        assert_eq!(f.state.name, "al");
    }

    #[test]
    fn esc_goes_back_one_step() {
        let mut f = form();
        text(&mut f, "bob");
        keys(&mut f, &[Key::Enter, Key::Enter]);
        assert_eq!(f.step().2, "Color");
        assert_eq!(f.esc_label(), "back one step");
        f.update(&Key::Esc);
        assert_eq!(f.step().2, "You", "back one step");
        assert_eq!(f.status, Status::Active);
        assert_eq!(f.esc_label(), "cancel");
        // Something changed: leaving asks first, and a no stays.
        f.update(&Key::Esc);
        assert!(f.leaving() && f.status == Status::Active);
        assert!(f.view().plain().contains("Leave without saving?"));
        f.update(&Key::Char('n'));
        assert!(!f.leaving() && f.status == Status::Active);
        f.update(&Key::Esc);
        f.update(&Key::Char('y'));
        assert_eq!(f.status, Status::Aborted);
        // Nothing changed: esc leaves at once.
        let mut f = form();
        f.update(&Key::Esc);
        assert_eq!(f.status, Status::Aborted);
        // Moving around changes nothing.
        let mut f = form();
        keys(&mut f, &[Key::Left, Key::Right, Key::Home]);
        f.update(&Key::Esc);
        assert_eq!(f.status, Status::Aborted);
        // A screen that keeps the answers never asks.
        let mut f = form().keeps_answers();
        text(&mut f, "x");
        f.update(&Key::Esc);
        assert_eq!(f.status, Status::Aborted);
        // The old way: esc leaves from any step.
        let mut f = form().esc_cancels();
        text(&mut f, "bob");
        keys(&mut f, &[Key::Enter, Key::Enter, Key::Esc]);
        assert_eq!(f.status, Status::Aborted);
    }

    #[test]
    fn the_field_being_answered_is_kept_in_view() {
        let mut f = form();
        let (d, focus) = f.body(80);
        let lines: Vec<String> = d.plain().lines().map(String::from).collect();
        let r = focus.unwrap();
        assert!(lines[r.start].contains("Name") || lines[r.start].contains('>'), "{lines:#?} {r:?}");
        text(&mut f, "bob");
        f.update(&Key::Enter);
        let (d, focus) = f.body(80);
        let lines: Vec<String> = d.plain().lines().map(String::from).collect();
        assert!(lines[focus.unwrap().start].contains("Password"), "{lines:#?}");
        // The note's title is the step's: it is not said twice.
        assert_eq!(d.plain().matches("Hello").count(), 1);
    }
}
