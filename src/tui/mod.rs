//! The terminal screens. Each screen is a Model: it gets keys, ticks and
//! messages from background work, and renders a Doc (styled lines). The
//! event loop draws it with ratatui.

pub mod admin;
pub mod app;
pub mod apps;
pub mod build;
pub mod flash;
pub mod form;
pub mod outside;
pub mod setup;
pub mod theme;
pub mod worker;

/// The cluster screens, for going from one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Apps,
    Outside,
}

use std::io::stdout;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::crossterm::execute;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use unicode_width::UnicodeWidthStr;

use crate::err::Result;

// ---- keys ----

/// A key press, named like bubbletea names them ("ctrl+c", "enter", "a").
#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    Char(char),
    Ctrl(char),
    Alt(char),
    Paste(String),
    Enter,
    Esc,
    Tab,
    BackTab,
    Backspace,
    Delete,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Other,
}

impl Key {
    pub fn name(&self) -> String {
        match self {
            Key::Char(' ') => " ".into(),
            Key::Char(c) => c.to_string(),
            Key::Ctrl(c) => format!("ctrl+{c}"),
            Key::Alt(c) => format!("alt+{c}"),
            Key::Paste(_) => "paste".into(),
            Key::Enter => "enter".into(),
            Key::Esc => "esc".into(),
            Key::Tab => "tab".into(),
            Key::BackTab => "shift+tab".into(),
            Key::Backspace => "backspace".into(),
            Key::Delete => "delete".into(),
            Key::Up => "up".into(),
            Key::Down => "down".into(),
            Key::Left => "left".into(),
            Key::Right => "right".into(),
            Key::Home => "home".into(),
            Key::End => "end".into(),
            Key::PageUp => "pgup".into(),
            Key::PageDown => "pgdown".into(),
            Key::Other => String::new(),
        }
    }

    fn from_event(k: KeyEvent) -> Key {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let alt = k.modifiers.contains(KeyModifiers::ALT);
        match k.code {
            KeyCode::Char(c) if ctrl => Key::Ctrl(c.to_ascii_lowercase()),
            KeyCode::Char(c) if alt => Key::Alt(c),
            KeyCode::Char(c) => Key::Char(c),
            KeyCode::Enter => Key::Enter,
            KeyCode::Esc => Key::Esc,
            KeyCode::Tab => Key::Tab,
            KeyCode::BackTab => Key::BackTab,
            KeyCode::Backspace => Key::Backspace,
            KeyCode::Delete => Key::Delete,
            KeyCode::Up => Key::Up,
            KeyCode::Down => Key::Down,
            KeyCode::Left => Key::Left,
            KeyCode::Right => Key::Right,
            KeyCode::Home => Key::Home,
            KeyCode::End => Key::End,
            KeyCode::PageUp => Key::PageUp,
            KeyCode::PageDown => Key::PageDown,
            _ => Key::Other,
        }
    }
}

/// The keys for typing s, one per character.
#[cfg(test)]
pub fn type_text(s: &str) -> Vec<Key> {
    s.chars().map(Key::Char).collect()
}

// ---- styled text ----

// The colours and what each one means are in theme.rs.
pub fn title_style() -> Style {
    theme::palette().title()
}
pub fn dim_style() -> Style {
    theme::palette().hint()
}
pub fn sel_style() -> Style {
    theme::palette().selected()
}
pub fn err_style() -> Style {
    theme::palette().alarm()
}
pub fn ok_style() -> Style {
    theme::palette().ok()
}

/// A piece of text with a style.
#[derive(Debug, Clone)]
pub struct Seg(pub String, pub Style);

pub fn plain(s: impl Into<String>) -> Seg {
    Seg(s.into(), Style::new())
}
pub fn title(s: impl Into<String>) -> Seg {
    Seg(s.into(), title_style())
}
pub fn dim(s: impl Into<String>) -> Seg {
    Seg(s.into(), dim_style())
}
pub fn sel(s: impl Into<String>) -> Seg {
    Seg(s.into(), sel_style())
}
pub fn err(s: impl Into<String>) -> Seg {
    Seg(s.into(), err_style())
}
pub fn err_bold(s: impl Into<String>) -> Seg {
    Seg(s.into(), err_style().add_modifier(Modifier::BOLD))
}
/// Structure that should recede: rules, empty progress.
pub fn faint(s: impl Into<String>) -> Seg {
    Seg(s.into(), Style::new().fg(theme::palette().ash))
}
pub fn ok(s: impl Into<String>) -> Seg {
    Seg(s.into(), ok_style())
}

/// Styled lines, built like a string: text with "\n" starts new lines.
#[derive(Debug, Clone)]
pub struct Doc {
    lines: Vec<Vec<Seg>>,
}

impl Default for Doc {
    fn default() -> Self {
        Doc::new()
    }
}

impl Doc {
    pub fn new() -> Doc {
        Doc { lines: vec![Vec::new()] }
    }

    pub fn add(&mut self, seg: Seg) -> &mut Doc {
        let mut parts = seg.0.split('\n');
        if let Some(first) = parts.next()
            && !first.is_empty()
        {
            self.lines.last_mut().unwrap().push(Seg(first.to_string(), seg.1));
        }
        for p in parts {
            self.lines.push(Vec::new());
            if !p.is_empty() {
                self.lines.last_mut().unwrap().push(Seg(p.to_string(), seg.1));
            }
        }
        self
    }

    /// Plain text.
    pub fn s(&mut self, text: impl Into<String>) -> &mut Doc {
        self.add(plain(text))
    }

    pub fn nl(&mut self) -> &mut Doc {
        self.lines.push(Vec::new());
        self
    }

    /// Appends another doc: its first line continues the current line.
    pub fn append(&mut self, other: Doc) -> &mut Doc {
        let mut it = other.lines.into_iter();
        if let Some(first) = it.next() {
            self.lines.last_mut().unwrap().extend(first);
        }
        self.lines.extend(it);
        self
    }

    /// left and right side by side, gap cells apart. left is padded to its
    /// widest line, so the right column starts in one place.
    pub fn beside(left: Doc, gap: usize, right: Doc) -> Doc {
        let width = left.lines.iter().map(|l| Doc::line_width(l)).max().unwrap_or(0);
        let rows = left.lines.len().max(right.lines.len());
        let (mut l, mut r) = (left.lines.into_iter(), right.lines.into_iter());
        let mut out = Doc { lines: Vec::with_capacity(rows) };
        for _ in 0..rows {
            let mut line = l.next().unwrap_or_default();
            let rest = r.next().unwrap_or_default();
            if !rest.is_empty() {
                let pad = width - Doc::line_width(&line) + gap;
                line.push(plain(" ".repeat(pad)));
                line.extend(rest);
            }
            out.lines.push(line);
        }
        out
    }

    /// The text without styles, for tests.
    #[cfg(test)]
    pub fn plain(&self) -> String {
        self.lines.iter().map(|l| l.iter().map(|s| s.0.as_str()).collect::<String>()).collect::<Vec<_>>().join("\n")
    }

    fn line_width(line: &[Seg]) -> usize {
        line.iter().map(|s| s.0.width()).sum()
    }

    /// The doc inside a border, without a trailing empty line.
    pub fn boxed(mut self, border: Border, color: Color, pad_x: usize, pad_y: usize, bold: bool) -> Doc {
        while self.lines.len() > 1 && self.lines.last().is_some_and(|l| l.is_empty()) {
            self.lines.pop();
        }
        let (tl, tr, bl, br, h, v) = match border {
            // The console font has no rounded corners.
            Border::Rounded if theme::palette().console => ('┌', '┐', '└', '┘', '─', '│'),
            Border::Rounded => ('╭', '╮', '╰', '╯', '─', '│'),
            Border::Double => ('╔', '╗', '╚', '╝', '═', '║'),
        };
        let inner = self.lines.iter().map(|l| Doc::line_width(l)).max().unwrap_or(0) + 2 * pad_x;
        let bs = Style::new().fg(color);
        let content_style = |s: Style| if bold { s.add_modifier(Modifier::BOLD) } else { s };
        let mut out = Doc::new();
        out.add(Seg(format!("{tl}{}{tr}", h.to_string().repeat(inner)), bs)).nl();
        let empty = vec![];
        let rows = (0..pad_y).map(|_| &empty).chain(self.lines.iter()).chain((0..pad_y).map(|_| &empty));
        for line in rows {
            out.add(Seg(v.to_string(), bs)).s(" ".repeat(pad_x));
            for seg in line {
                out.add(Seg(seg.0.clone(), content_style(seg.1)));
            }
            out.s(" ".repeat(inner - 2 * pad_x - Doc::line_width(line) + pad_x)).add(Seg(v.to_string(), bs)).nl();
        }
        out.add(Seg(format!("{bl}{}{br}", h.to_string().repeat(inner)), bs));
        out
    }

    pub fn into_text(self) -> Text<'static> {
        Text::from(
            self.lines
                .into_iter()
                .map(|l| Line::from(l.into_iter().map(|s| Span::styled(s.0, s.1)).collect::<Vec<_>>()))
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Border {
    Rounded,
    Double,
}

/// Cuts s to n characters, adding "…" when cut.
pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n).collect::<String>() + "…"
}

/// s in at most n cells: cut with an ellipsis the console font has.
pub fn fit(s: &str, n: usize) -> String {
    if s.width() <= n {
        return s.to_string();
    }
    let dots = theme::ellipsis();
    let mut out = String::new();
    for c in s.chars() {
        if out.width() + c.to_string().width() + dots.width() > n {
            break;
        }
        out.push(c);
    }
    out + dots
}

/// s broken into lines of at most width cells, at spaces where it can;
/// its own line breaks stay. The screens do not wrap by themselves, and
/// a long message would be cut at the edge.
pub fn wrap(s: &str, width: usize) -> String {
    let mut out = Vec::new();
    for para in s.split('\n') {
        // A line's indent starts each of its parts.
        let body = para.trim_start_matches(' ');
        let indent = &para[..para.len() - body.len()];
        let width = width.saturating_sub(indent.len()).max(10);
        let start = out.len();
        let mut line = String::new();
        for word in body.split(' ') {
            let (lw, ww) = (line.width(), word.width());
            if lw > 0 && lw + 1 + ww > width {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
            // A word longer than a line is cut where the line ends.
            while line.width() > width {
                let cut: String = line.chars().take(width).collect();
                line = line.chars().skip(cut.chars().count()).collect();
                out.push(cut);
            }
        }
        out.push(line);
        for l in &mut out[start..] {
            l.insert_str(0, indent);
        }
    }
    out.join("\n")
}

/// The current frame of the busy spinner: an ember that glows and fades.
/// Glyphs of code page 437 only, so it also shows on the Linux console
/// (the braille spinner did not).
pub fn spinner() -> &'static str {
    const FRAMES: [&str; 6] = ["·", "∙", "•", "■", "•", "∙"];
    static START: OnceLock<Instant> = OnceLock::new();
    let ms = START.get_or_init(Instant::now).elapsed().as_millis();
    FRAMES[(ms / 130 % 6) as usize]
}

/// A progress bar of width cells for pct in 0..=1.
pub fn progress_bar(pct: f64, width: usize) -> Doc {
    theme::bar(pct, width)
}

/// Whole seconds since t, formatted like Go durations ("1m5s").
pub fn since(t: Instant) -> String {
    let secs = crate::gotime::round_ms(t.elapsed().as_millis() as i64, 1000) / 1000;
    crate::gotime::duration_string(secs)
}

pub fn dur(d: Duration) -> String {
    let secs = crate::gotime::round_ms(d.as_millis() as i64, 1000) / 1000;
    crate::gotime::duration_string(secs)
}

// ---- text input ----

/// A one-line text field.
#[derive(Debug, Clone, Default)]
pub struct TextInput {
    pub value: String,
    /// Cursor position in characters.
    pub cursor: usize,
    pub placeholder: String,
    /// Maximum characters; 0 = no limit.
    pub limit: usize,
    pub focused: bool,
    pub password: bool,
}

impl TextInput {
    pub fn new(limit: usize) -> TextInput {
        TextInput { limit, ..TextInput::default() }
    }

    pub fn set_value(&mut self, v: &str) {
        self.value = v.to_string();
        self.cursor = v.chars().count();
    }

    pub fn focus(&mut self) {
        self.focused = true;
    }

    pub fn blur(&mut self) {
        self.focused = false;
    }

    /// Edits the value; returns false for keys it does not use.
    pub fn handle(&mut self, k: &Key) -> bool {
        edit_line(&mut self.value, &mut self.cursor, self.limit, k)
    }

    pub fn view(&self) -> Doc {
        line_view(&self.value, self.cursor, &self.placeholder, self.focused, self.password)
    }
}

/// Applies an editing key to a line of text.
pub fn edit_line(value: &mut String, cursor: &mut usize, limit: usize, k: &Key) -> bool {
    let mut chars: Vec<char> = value.chars().collect();
    *cursor = (*cursor).min(chars.len());
    let insert = |chars: &mut Vec<char>, cursor: &mut usize, s: &str| {
        for c in s.chars().filter(|c| !c.is_control()) {
            if limit > 0 && chars.len() >= limit {
                break;
            }
            chars.insert(*cursor, c);
            *cursor += 1;
        }
    };
    match k {
        Key::Char(c) => insert(&mut chars, cursor, &c.to_string()),
        Key::Paste(s) => insert(&mut chars, cursor, &s.replace(['\r', '\n'], " ")),
        Key::Backspace | Key::Ctrl('h') => {
            if *cursor > 0 {
                chars.remove(*cursor - 1);
                *cursor -= 1;
            }
        }
        Key::Delete | Key::Ctrl('d') => {
            if *cursor < chars.len() {
                chars.remove(*cursor);
            }
        }
        Key::Left | Key::Ctrl('b') => *cursor = cursor.saturating_sub(1),
        Key::Right | Key::Ctrl('f') => *cursor = (*cursor + 1).min(chars.len()),
        Key::Home | Key::Ctrl('a') => *cursor = 0,
        Key::End | Key::Ctrl('e') => *cursor = chars.len(),
        Key::Ctrl('u') => {
            chars.drain(..*cursor);
            *cursor = 0;
        }
        Key::Ctrl('k') => chars.truncate(*cursor),
        Key::Ctrl('w') => {
            let mut i = *cursor;
            while i > 0 && chars[i - 1] == ' ' {
                i -= 1;
            }
            while i > 0 && chars[i - 1] != ' ' {
                i -= 1;
            }
            chars.drain(i..*cursor);
            *cursor = i;
        }
        _ => return false,
    }
    *value = chars.into_iter().collect();
    true
}

/// "> value" with a block cursor when focused.
pub fn line_view(value: &str, cursor: usize, placeholder: &str, focused: bool, password: bool) -> Doc {
    let mut d = Doc::new();
    d.add(Seg("> ".into(), if focused { title_style() } else { Style::new() }));
    let rev = Style::new().add_modifier(Modifier::REVERSED);
    if value.is_empty() {
        let mut ph = placeholder.chars();
        match (focused, ph.next()) {
            (true, Some(first)) => {
                d.add(Seg(first.to_string(), rev.fg(Color::DarkGray))).add(dim(ph.collect::<String>()));
            }
            (true, None) => {
                d.add(Seg(" ".into(), rev));
            }
            (false, _) => {
                d.add(dim(placeholder));
            }
        }
        return d;
    }
    let shown: Vec<char> = if password { value.chars().map(|_| '•').collect() } else { value.chars().collect() };
    if !focused {
        d.s(shown.iter().collect::<String>());
        return d;
    }
    let cursor = cursor.min(shown.len());
    d.s(shown[..cursor].iter().collect::<String>());
    match shown.get(cursor) {
        Some(c) => {
            d.add(Seg(c.to_string(), rev)).s(shown[cursor + 1..].iter().collect::<String>());
        }
        None => {
            d.add(Seg(" ".into(), rev));
        }
    }
    d
}

// ---- event loop ----

/// Sends a message to the model from any thread.
pub type Emit<M> = Arc<dyn Fn(M) + Send + Sync>;

pub enum Event<M> {
    Key(Key),
    Msg(M),
    /// About ten times a second, for spinners and timers.
    Tick,
    Resize(u16, u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

pub trait Model {
    type Msg: Send + 'static;

    /// Starts background work when the screen opens.
    fn init(&mut self, _emit: &Emit<Self::Msg>) {}

    fn update(&mut self, ev: Event<Self::Msg>, emit: &Emit<Self::Msg>) -> Flow;

    fn view(&self) -> Doc;
}

/// Runs a model full screen until it quits.
pub fn run<M: Model>(model: &mut M) -> Result<()> {
    let (tx, rx) = mpsc::channel::<M::Msg>();
    let emit: Emit<M::Msg> = Arc::new(move |m| {
        let _ = tx.send(m);
    });
    let mut term = ratatui::try_init()?;
    let _ = execute!(stdout(), EnableBracketedPaste);
    let res = event_loop(model, &mut term, &rx, &emit);
    let _ = execute!(stdout(), DisableBracketedPaste);
    ratatui::restore();
    res
}

fn event_loop<M: Model>(
    model: &mut M,
    term: &mut ratatui::DefaultTerminal,
    rx: &mpsc::Receiver<M::Msg>,
    emit: &Emit<M::Msg>,
) -> Result<()> {
    let size = term.size()?;
    if model.update(Event::Resize(size.width, size.height), emit) == Flow::Quit {
        return Ok(());
    }
    model.init(emit);
    let tick = Duration::from_millis(100);
    let mut last_tick = Instant::now();
    loop {
        term.draw(|f| {
            // With true colour the whole screen is coal with bone text;
            // otherwise the terminal keeps its own colours.
            let p = theme::palette();
            let mut base = Style::new();
            if let Some(c) = p.coal {
                base = base.bg(c);
            }
            if let Some(c) = p.bone {
                base = base.fg(c);
            }
            f.render_widget(Paragraph::new(model.view().into_text()).style(base), f.area());
        })?;
        let wait = tick.saturating_sub(last_tick.elapsed());
        if event::poll(wait)? {
            let ev = match event::read()? {
                event::Event::Key(k) if k.kind != KeyEventKind::Release => Some(Event::Key(Key::from_event(k))),
                event::Event::Paste(s) => Some(Event::Key(Key::Paste(s))),
                event::Event::Resize(w, h) => Some(Event::Resize(w, h)),
                _ => None,
            };
            if let Some(ev) = ev
                && model.update(ev, emit) == Flow::Quit
            {
                return Ok(());
            }
        }
        while let Ok(m) = rx.try_recv() {
            if model.update(Event::Msg(m), emit) == Flow::Quit {
                return Ok(());
            }
        }
        if last_tick.elapsed() >= tick {
            last_tick = Instant::now();
            if model.update(Event::Tick, emit) == Flow::Quit {
                return Ok(());
            }
        }
    }
}

/// An emitter that collects messages, for tests.
#[cfg(test)]
pub fn collector<M: Send + 'static>() -> (Emit<M>, mpsc::Receiver<M>) {
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    (
        Arc::new(move |m| {
            let _ = tx.lock().unwrap().send(m);
        }),
        rx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_lines_and_boxes() {
        let mut d = Doc::new();
        d.add(title("a\nb")).s("c\n").add(dim("d"));
        assert_eq!(d.plain(), "a\nbc\nd");
        let mut inner = Doc::new();
        inner.s("hi\nthere\n");
        let b = inner.boxed(Border::Rounded, Color::Red, 1, 0, false).plain();
        assert_eq!(b, "╭───────╮\n│ hi    │\n│ there │\n╰───────╯");
    }

    #[test]
    fn line_editing() {
        let mut t = TextInput::new(4);
        for k in [Key::Char('a'), Key::Char('b'), Key::Left, Key::Char('x'), Key::Paste("yz\n12".into())] {
            t.handle(&k);
        }
        assert_eq!(t.value, "axyb", "the limit stops the paste");
        t.handle(&Key::Ctrl('u'));
        assert_eq!(t.value, "b");
        assert_eq!(truncate("abcdef", 3), "abc…");
    }

    #[test]
    fn long_lines_wrap() {
        assert_eq!(wrap("one two three four", 10), "one two\nthree four");
        assert_eq!(wrap("keep\nbreaks", 80), "keep\nbreaks");
        assert_eq!(wrap("abcdefghijklmnopqrstuvwxyz", 10), "abcdefghij\nklmnopqrst\nuvwxyz");
        let long =
            "Close Cloudflare Tunnel? blog, shop still come in through it: nothing from outside reaches them after that. y to confirm";
        assert!(wrap(long, 76).lines().all(|l| l.width() <= 76), "{}", wrap(long, 76));
        assert_eq!(wrap("    one two three four", 14), "    one two\n    three four", "the indent stays");
        assert_eq!(fit("short", 10), "short");
        assert!(fit("node-a,node-b,node-c", 12).width() <= 12 && fit("node-a,node-b,node-c", 12).starts_with("node-a,no"));
    }
}
