//! The frame every desktop screen is drawn in (docs/tui-design.md): a
//! header bar, the tabs, a body that scrolls and keeps the selected row in
//! view, the notice line and the footer with the keys that work now.
//! Overlays (confirm, help, the actions sheet) are panels over the body.
//!
//! A screen describes itself as a Page; draw() lays it out for the
//! terminal's size. The scroll position lives in a Scroll the screen
//! keeps, with interior mutability, so that a view(&self) can move it to
//! keep the selection in view.

use std::cell::Cell;
use std::ops::Range;
use std::time::Duration;

use ratatui::style::{Modifier, Style};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::theme::{self, Mark, Tier};
use super::{Doc, Key, Seg};

/// Under this the frame only asks for a bigger window.
pub const MIN_W: u16 = 80;
pub const MIN_H: u16 = 24;
/// The body is never wider than this: long lines are hard to read.
pub const MAX_BODY: usize = 100;
/// The body starts this many columns in; the selected row's bar is at BAR.
const LEFT: usize = 3;
const BAR: usize = 1;
/// A notice longer than this many lines is cut.
const MAX_NOTICE: usize = 3;
/// Panels over the body are at most this wide.
const MAX_PANEL: usize = 76;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Ok,
    Bad,
    Info,
}

/// The answer to what was just done.
#[derive(Debug, Clone, PartialEq)]
pub struct Notice {
    pub tone: Tone,
    pub text: String,
}

impl Notice {
    pub fn ok(t: impl Into<String>) -> Notice {
        Notice { tone: Tone::Ok, text: t.into() }
    }
    pub fn bad(t: impl Into<String>) -> Notice {
        Notice { tone: Tone::Bad, text: t.into() }
    }
    pub fn info(t: impl Into<String>) -> Notice {
        Notice { tone: Tone::Info, text: t.into() }
    }
}

/// What the last key of the footer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Back {
    /// esc back
    Esc,
    /// q quit (Home)
    Quit,
    /// Neither: the screen says what esc does in its own keys.
    Nothing,
}

/// What `?` shows: every key of the place and what it is for.
#[derive(Debug, Clone, Default)]
pub struct Help {
    pub about: String,
    pub keys: Vec<(String, String)>,
}

/// One line of an actions sheet. why_not: it cannot be done now, and why.
#[derive(Debug, Clone)]
pub struct Item {
    pub key: String,
    pub label: String,
    pub why_not: Option<String>,
}

pub enum Overlay {
    /// The question, one line per consequence; y yes, any other key no.
    Confirm { question: String, consequences: Vec<String> },
    /// The page's help.
    Help,
    /// What can be done to the selected row. The redrawn Machines, Apps
    /// and Outside screens use it; nothing here does yet.
    #[allow(dead_code)]
    Sheet { title: String, items: Vec<Item>, cursor: usize },
}

/// The lines of the body to keep in view; painted as the selected row
/// when paint is set.
#[derive(Debug, Clone, PartialEq)]
pub struct Focus {
    pub lines: Range<usize>,
    pub paint: bool,
}

impl Focus {
    /// A selected row.
    pub fn row(line: usize) -> Focus {
        Focus { lines: line..line + 1, paint: true }
    }
    /// Lines to keep in view, not painted (the field being typed in).
    pub fn keep(lines: Range<usize>) -> Focus {
        Focus { lines, paint: false }
    }
}

/// A whole screen, before it is laid out.
pub struct Page {
    /// Where you are, in the header.
    pub place: String,
    /// Right of the header: what the place depends on.
    pub status: Doc,
    pub tabs: Vec<String>,
    pub tab: usize,
    pub body: Doc,
    pub focus: Option<Focus>,
    pub notice: Option<Notice>,
    /// The keys that work now, most used first. `?` and esc or q are
    /// added at the end.
    pub keys: Vec<(String, String)>,
    pub back: Back,
    /// `?` works here.
    pub help: Option<Help>,
    pub overlay: Option<Overlay>,
}

impl Page {
    pub fn new(place: impl Into<String>) -> Page {
        Page {
            place: place.into(),
            status: Doc::new(),
            tabs: Vec::new(),
            tab: 0,
            body: Doc::new(),
            focus: None,
            notice: None,
            keys: Vec::new(),
            back: Back::Esc,
            help: None,
            overlay: None,
        }
    }

    pub fn key(&mut self, key: &str, does: &str) -> &mut Page {
        self.keys.push((key.into(), does.into()));
        self
    }
}

// ---- scrolling ----

/// Where the body is scrolled to. The screen keeps one and hands it to
/// draw(), which moves it to keep the focus in view whenever the focus
/// moved or the window changed; between those, pgup and pgdn are free to
/// look elsewhere.
#[derive(Debug, Default)]
pub struct Scroll {
    top: Cell<usize>,
    /// Rows of the body and lines in it, at the last draw.
    rows: Cell<usize>,
    total: Cell<usize>,
    /// The focus and the window it was last kept in view for.
    seen: Cell<Option<(usize, usize, usize, usize)>>,
}

impl Scroll {
    /// pgup, pgdn, home and end. False for any other key.
    pub fn key(&self, k: &Key) -> bool {
        let page = self.rows.get().saturating_sub(1).max(1);
        let most = self.total.get().saturating_sub(self.rows.get());
        let top = self.top.get();
        let to = match k {
            Key::PageUp => top.saturating_sub(page),
            Key::PageDown => (top + page).min(most),
            Key::Home => 0,
            Key::End => most,
            _ => return false,
        };
        self.top.set(to);
        true
    }

    /// Back to the top, for a new place.
    pub fn reset(&self) {
        self.top.set(0);
        self.seen.set(None);
    }

    #[allow(dead_code)]
    pub fn top(&self) -> usize {
        self.top.get()
    }

    /// Body rows at the last draw: how far a page goes, for a screen that
    /// moves its selection a page at a time.
    #[allow(dead_code)]
    pub fn rows(&self) -> usize {
        self.rows.get()
    }

    /// The first line to show of total, rows at a time.
    fn place(&self, total: usize, rows: usize, width: usize, focus: Option<&Range<usize>>) -> usize {
        self.rows.set(rows);
        self.total.set(total);
        let mut top = self.top.get();
        if let Some(f) = focus {
            let key = (f.start, f.end, rows, width);
            if self.seen.get() != Some(key) {
                self.seen.set(Some(key));
                if f.end > top + rows {
                    top = f.end.saturating_sub(rows);
                }
                // A focus taller than the window shows from its start.
                if f.start < top {
                    top = f.start;
                }
            }
        }
        top = top.min(total.saturating_sub(rows));
        self.top.set(top);
        top
    }
}

// ---- sizes ----

/// The window is too small for the frame.
pub fn too_small(w: u16, h: u16) -> bool {
    w < MIN_W || h < MIN_H
}

/// How wide the body is in a window w columns wide.
/// The rows the body gets in a window h rows high, with no tabs and a
/// notice of one line: all but the bars, the blank line under them and
/// the notice.
pub fn body_rows(h: u16) -> usize {
    (h as usize).saturating_sub(4)
}

pub fn body_width(w: u16) -> usize {
    (w as usize).saturating_sub(LEFT + 2).clamp(10, MAX_BODY)
}

// ---- cells ----

#[derive(Debug, Clone)]
struct Cell2 {
    /// "" for the right half of a wide character.
    sym: String,
    style: Style,
}

/// The screen as cells, so panels can go over what is under them.
struct Grid {
    w: usize,
    rows: Vec<Vec<Cell2>>,
}

impl Grid {
    fn new(w: usize, h: usize) -> Grid {
        Grid { w, rows: vec![vec![Cell2 { sym: " ".into(), style: Style::new() }; w]; h] }
    }

    /// Writes segs at row, col, cut at end. Returns the column after them.
    fn put(&mut self, row: usize, col: usize, segs: &[Seg], end: usize) -> usize {
        let end = end.min(self.w);
        let Some(line) = self.rows.get_mut(row) else { return col };
        let mut c = col;
        for s in segs {
            for ch in s.0.chars() {
                let cw = ch.width().unwrap_or(0);
                if cw == 0 {
                    continue;
                }
                if c + cw > end {
                    return c;
                }
                // Over half of a wide character: the other half goes.
                if line[c].sym.is_empty() && c > 0 {
                    line[c - 1].sym = " ".into();
                }
                if c + cw < line.len() && line[c + cw].sym.is_empty() {
                    line[c + cw].sym = " ".into();
                }
                line[c] = Cell2 { sym: ch.to_string(), style: s.1 };
                if cw == 2 {
                    line[c + 1] = Cell2 { sym: String::new(), style: s.1 };
                }
                c += cw;
            }
        }
        c
    }

    /// Gives the cells from..to a background where they have none.
    fn shade(&mut self, row: usize, from: usize, to: usize, style: Style) {
        if let Some(line) = self.rows.get_mut(row) {
            for cell in &mut line[from.min(self.w)..to.min(self.w)] {
                if cell.style.bg.is_none() {
                    cell.style = style.patch(cell.style);
                    if let Some(bg) = style.bg {
                        cell.style.bg = Some(bg);
                    }
                }
            }
        }
    }

    /// Pushes a row back behind a panel.
    fn dim(&mut self, row: usize) {
        if let Some(line) = self.rows.get_mut(row) {
            for cell in line.iter_mut() {
                let picture = matches!(cell.sym.as_str(), "▀" | "▄" | "█");
                cell.style = theme::dimmed(cell.style, picture);
            }
        }
    }

    /// Sets the cells from..to to style, blank.
    fn fill(&mut self, row: usize, from: usize, to: usize, style: Style) {
        if let Some(line) = self.rows.get_mut(row) {
            for cell in &mut line[from.min(self.w)..to.min(self.w)] {
                *cell = Cell2 { sym: " ".into(), style };
            }
        }
    }

    fn into_doc(self) -> Doc {
        let mut d = Doc { lines: Vec::with_capacity(self.rows.len()) };
        for row in self.rows {
            let mut line: Vec<Seg> = Vec::new();
            for cell in row {
                if cell.sym.is_empty() {
                    continue;
                }
                match line.last_mut() {
                    Some(last) if last.1 == cell.style => last.0.push_str(&cell.sym),
                    _ => line.push(Seg(cell.sym, cell.style)),
                }
            }
            d.lines.push(line);
        }
        d
    }
}

fn seg_width(segs: &[Seg]) -> usize {
    segs.iter().map(|s| s.0.width()).sum()
}

// ---- wrapping ----

/// One line of styled text broken into lines of at most width cells, at
/// spaces where it can; the parts after the first keep the line's indent.
pub fn wrap_line(line: &[Seg], width: usize) -> Vec<Vec<Seg>> {
    let width = width.max(1);
    if seg_width(line) <= width {
        return vec![line.to_vec()];
    }
    let chars: Vec<(char, Style, usize)> = line.iter().flat_map(|s| s.0.chars().map(move |c| (c, s.1, c.width().unwrap_or(0)))).collect();
    let mut indent = chars.iter().take_while(|c| c.0 == ' ').count();
    // An indent that leaves no room for words is dropped.
    if indent * 2 > width {
        indent = 0;
    }
    let mut out = Vec::new();
    let mut i = 0;
    let mut first = true;
    while i < chars.len() {
        let avail = if first { width } else { width - indent };
        let (mut j, mut w) = (i, 0);
        while j < chars.len() && w + chars[j].2 <= avail {
            w += chars[j].2;
            j += 1;
        }
        let (end, at_space) = if j >= chars.len() {
            (j, false)
        } else {
            // Never break inside the indent of the first part.
            let lo = if first { i + indent + 1 } else { i + 1 };
            match (lo..=j).rev().find(|&k| chars[k].0 == ' ') {
                Some(k) => (k, true),
                // A word longer than the line is cut where the line ends.
                None => (j.max(i + 1), false),
            }
        };
        let mut l: Vec<Seg> = Vec::new();
        if !first && indent > 0 {
            l.push(Seg(" ".repeat(indent), Style::new()));
        }
        let mut part: &[(char, Style, usize)] = &chars[i..end];
        if at_space {
            while let Some(((' ', _, _), rest)) = part.split_last() {
                part = rest;
            }
        }
        for (c, st, _) in part {
            match l.last_mut() {
                Some(last) if last.1 == *st => last.0.push(*c),
                _ => l.push(Seg(c.to_string(), *st)),
            }
        }
        out.push(l);
        i = end;
        while i < chars.len() && chars[i].0 == ' ' {
            i += 1;
        }
        first = false;
    }
    out
}

/// Styled text cut to n cells, ending in an ellipsis when cut.
pub fn cut(segs: &[Seg], n: usize) -> Vec<Seg> {
    if seg_width(segs) <= n {
        return segs.to_vec();
    }
    let dots = theme::ellipsis();
    let room = n.saturating_sub(dots.width());
    let mut out: Vec<Seg> = Vec::new();
    let mut w = 0;
    let mut style = segs.first().map(|s| s.1).unwrap_or_default();
    for s in segs {
        let mut t = String::new();
        let mut full = false;
        for c in s.0.chars() {
            let cw = c.width().unwrap_or(0);
            if w + cw > room {
                full = true;
                break;
            }
            w += cw;
            t.push(c);
        }
        style = s.1;
        if !t.is_empty() {
            out.push(Seg(t, s.1));
        }
        if full {
            break;
        }
    }
    if dots.width() <= n {
        out.push(Seg(dots.into(), style));
    }
    out
}

// ---- panels ----

/// Lines on the raised surface, width cells wide, with a cell of padding
/// all round; where no surface is painted, inside a border instead.
fn panel(lines: &[Vec<Seg>], width: usize) -> Vec<Vec<Seg>> {
    let p = theme::palette();
    let width = width.max(8);
    let inner = width - 4;
    let mut body: Vec<Vec<Seg>> = Vec::new();
    for l in lines {
        body.extend(wrap_line(l, inner));
    }
    let mut out = Vec::new();
    match p.raised {
        Some(bg) => {
            let fill = Style::new().bg(bg);
            let blank = vec![Seg(" ".repeat(width), fill)];
            out.push(blank.clone());
            for l in body {
                let mut row = vec![Seg("  ".into(), fill)];
                let l = cut(&l, inner);
                let pad = inner - seg_width(&l);
                row.extend(l.into_iter().map(|s| Seg(s.0, fill.patch(s.1))));
                row.push(Seg(" ".repeat(pad + 2), fill));
                out.push(row);
            }
            out.push(blank);
        }
        None => {
            let b = p.faint();
            let (tl, tr, bl, br, h, v) = ('┌', '┐', '└', '┘', '─', '│');
            out.push(vec![Seg(format!("{tl}{}{tr}", h.to_string().repeat(width - 2)), b)]);
            for l in body {
                let l = cut(&l, inner);
                let pad = inner - seg_width(&l);
                let mut row = vec![Seg(v.to_string(), b), Seg(" ".into(), Style::new())];
                row.extend(l);
                row.push(Seg(" ".repeat(pad + 1), Style::new()));
                row.push(Seg(v.to_string(), b));
                out.push(row);
            }
            out.push(vec![Seg(format!("{bl}{}{br}", h.to_string().repeat(width - 2)), b)]);
        }
    }
    out
}

/// The overlay's lines, before they go into a panel.
fn overlay_lines(o: &Overlay, help: Option<&Help>) -> Vec<Vec<Seg>> {
    let p = theme::palette();
    let mut out: Vec<Vec<Seg>> = Vec::new();
    match o {
        Overlay::Confirm { question, consequences } => {
            out.push(vec![Seg(question.clone(), p.text().add_modifier(Modifier::BOLD))]);
            if !consequences.is_empty() {
                out.push(Vec::new());
            }
            for c in consequences {
                out.push(vec![Seg("  · ".into(), p.faint()), Seg(c.clone(), p.text())]);
            }
            out.push(Vec::new());
            let mut keys = vec![theme::cap("y"), Seg(" yes   ".into(), p.hint())];
            keys.push(Seg("any other key: no".into(), p.hint()));
            out.push(keys);
        }
        Overlay::Help => {
            let help = help.cloned().unwrap_or_default();
            out.push(vec![Seg("Help".into(), p.title())]);
            if !help.about.is_empty() {
                out.push(Vec::new());
                for para in help.about.split('\n') {
                    out.push(vec![Seg(para.into(), p.text())]);
                }
            }
            out.push(Vec::new());
            let kw = help.keys.iter().map(|(k, _)| k.width()).max().unwrap_or(0).min(16);
            for (k, does) in &help.keys {
                let pad = kw.saturating_sub(k.width());
                out.push(vec![Seg(format!("{k}{}", " ".repeat(pad)), p.fg(p.gold)), Seg(format!("  {does}"), p.hint())]);
            }
            out.push(Vec::new());
            out.push(vec![Seg("Any key closes this.".into(), p.hint())]);
        }
        Overlay::Sheet { title, items, cursor } => {
            out.push(vec![Seg(title.clone(), p.title())]);
            out.push(Vec::new());
            for (i, it) in items.iter().enumerate() {
                let pointer = if i == *cursor { Seg(format!("{} ", theme::BAR), p.selected()) } else { Seg("  ".into(), Style::new()) };
                match &it.why_not {
                    None => out.push(vec![pointer, theme::cap(&it.key), Seg(format!(" {}", it.label), p.text())]),
                    Some(why) => {
                        out.push(vec![pointer, Seg(format!(" {} ", it.key), p.faint()), Seg(format!(" {}: {why}", it.label), p.faint())])
                    }
                }
            }
        }
    }
    out
}

// ---- the parts ----

/// A heading in flame, sentence case, with a count in violet when it
/// lists things. One blank line before it, but at the top.
pub fn section(d: &mut Doc, title: &str, count: Option<usize>) {
    let p = theme::palette();
    if !(d.lines.len() == 1 && d.lines[0].is_empty()) {
        if d.lines.last().is_some_and(|l| !l.is_empty()) {
            d.nl();
        }
        d.nl();
    }
    d.add(Seg(title.into(), p.title()));
    if let Some(n) = count {
        d.add(Seg(format!("  {n}"), p.hint()));
    }
    d.nl();
}

/// A table cell: its text and how wide the column is (0: the rest).
pub struct Col {
    pub seg: Seg,
    pub width: usize,
}

pub fn col(seg: Seg, width: usize) -> Col {
    Col { seg, width }
}

/// A row: the mark, then the columns, each cut with an ellipsis to its
/// width, the whole at most width cells. Returns the row as one line.
pub fn row(width: usize, m: Mark, cols: Vec<Col>) -> Doc {
    let mut segs = vec![theme::mark(m), Seg("  ".into(), Style::new())];
    let mut used = 3;
    let n = cols.len();
    for (i, c) in cols.into_iter().enumerate() {
        let last = i + 1 == n;
        let room = width.saturating_sub(used);
        let w = if last || c.width == 0 { room } else { c.width.min(room) };
        let cell = cut(std::slice::from_ref(&c.seg), w);
        let cw = seg_width(&cell);
        segs.extend(cell);
        used += cw;
        if !last {
            let pad = w - cw + 2;
            segs.push(Seg(" ".repeat(pad), Style::new()));
            used += pad;
        }
    }
    // Trailing spaces would only widen the line.
    while segs.len() > 1 && segs.last().is_some_and(|s| s.0.trim().is_empty()) {
        segs.pop();
    }
    Doc { lines: vec![segs] }
}

/// What is missing, why, and the key that fixes it: never a bare "none".
pub fn empty(text: &str) -> Doc {
    let mut d = Doc::new();
    d.add(Seg(text.into(), theme::palette().hint()));
    d
}

/// A problem card, width cells wide: what happened, then what to do, then
/// the key that does it.
pub fn card(width: usize, problem: &str, todo: &str, key: Option<(&str, &str)>) -> Doc {
    let p = theme::palette();
    // The problem hangs after its mark: "! " starts only the first line,
    // and its own line breaks stay.
    // Its first sentence is the alarm; what follows explains it, and reads
    // better in plain text.
    let mut lines: Vec<Vec<Seg>> = Vec::new();
    let inner = width.max(8) - 4;
    let alarm = p.fg(alarm_fg()).add_modifier(Modifier::BOLD);
    for (i, para) in problem.split('\n').enumerate() {
        let segs = match (i, para.find(". ")) {
            (0, Some(end)) => vec![Seg(para[..=end].into(), alarm), Seg(para[end + 1..].into(), p.text())],
            (0, None) => vec![Seg(para.into(), alarm)],
            _ => vec![Seg(para.into(), p.text())],
        };
        for part in wrap_line(&segs, inner.saturating_sub(2)) {
            let first = lines.is_empty();
            let mut l = vec![if first { theme::mark(Mark::Bad) } else { Seg(" ".into(), Style::new()) }, Seg(" ".into(), Style::new())];
            l.extend(part);
            lines.push(l);
        }
    }
    if !todo.is_empty() {
        for para in todo.split('\n') {
            lines.push(vec![Seg(format!("  {para}"), p.text())]);
        }
    }
    if let Some((k, does)) = key {
        lines.push(Vec::new());
        lines.push(vec![Seg("  ".into(), Style::new()), theme::cap(k), Seg(format!(" {does}"), p.hint())]);
    }
    Doc { lines: panel(&lines, width) }
}

/// The alarm's colour without its background, for sentences.
fn alarm_fg() -> ratatui::style::Color {
    let p = theme::palette();
    match (p.tier, p.alarm().fg) {
        // Light red is ember there: the alarm's own red, without its
        // background.
        (Tier::Console, _) => ratatui::style::Color::Red,
        (_, Some(c)) => c,
        (_, None) => ratatui::style::Color::Reset,
    }
}

/// Progress: the snake grown as far as the work (in pixels where the
/// colours allow), beside the step, the time it has taken and a bar.
/// None: how far is not known; the snake is whole and there is no bar.
pub fn progress(width: usize, pct: Option<f64>, step: &str, elapsed: Duration) -> Doc {
    let p = theme::palette();
    let snake = theme::snake(pct);
    let snake_w = snake.lines.iter().map(|l| seg_width(l)).max().unwrap_or(0);
    let room = width.saturating_sub(snake_w + 3).max(10);
    let mut text = Doc::new();
    let rows = theme::snake_height();
    // The text sits in the middle of the snake.
    for _ in 0..rows.saturating_sub(4) / 2 {
        text.nl();
    }
    // Without a bar, the spinner says the work goes on.
    if pct.is_none() {
        text.add(Seg(super::spinner().into(), p.selected())).s(" ");
    }
    let step = cut(&[Seg(step.into(), p.text().add_modifier(Modifier::BOLD))], room.saturating_sub(2));
    for s in step {
        text.add(s);
    }
    text.nl();
    text.add(Seg(super::dur(elapsed), p.hint())).nl();
    if let Some(x) = pct {
        let x = x.clamp(0.0, 1.0);
        let bar_w = room.saturating_sub(6).min(48);
        text.nl().append(theme::bar(x, bar_w)).add(Seg(format!(" {:>3.0}%", x * 100.0), p.hint()));
    }
    Doc::beside(snake, 3, text)
}

// ---- drawing ----

/// The page laid out for a window of w × h cells: exactly h lines of w
/// cells each.
pub fn draw(page: &Page, scroll: &Scroll, w: u16, h: u16) -> Doc {
    if too_small(w, h) {
        return small(w, h);
    }
    let p = theme::palette();
    let (w, h) = (w as usize, h as usize);
    let mut g = Grid::new(w, h);
    let bw = body_width(w as u16);
    let bar_style = p.on_raised(Style::new());

    // The header.
    g.fill(0, 0, w, bar_style);
    let mut left = vec![Seg(" ".into(), bar_style), Seg("dryserver".into(), p.on_raised(p.title()))];
    if !page.place.is_empty() {
        left.push(Seg("  ".into(), bar_style));
        left.push(Seg(page.place.clone(), p.on_raised(p.text())));
    }
    let left_end = g.put(0, 0, &left, w);
    if let Some(first) = page.status.lines.first() {
        let room = w.saturating_sub(left_end + 4);
        let status: Vec<Seg> = cut(first, room).into_iter().map(|s| Seg(s.0, p.on_raised(s.1))).collect();
        let sw = seg_width(&status);
        g.put(0, w - 1 - sw, &status, w - 1);
    }
    let mut row = 1;

    // The tabs.
    if !page.tabs.is_empty() {
        let mut col = 1;
        for (i, t) in page.tabs.iter().enumerate() {
            let style = if i == page.tab {
                let s = p.text().add_modifier(Modifier::BOLD);
                match p.shade {
                    Some(bg) => s.bg(bg),
                    None => s.add_modifier(Modifier::UNDERLINED),
                }
            } else {
                p.hint()
            };
            col = g.put(row, col, &[Seg(format!(" {t} "), style)], w);
            col = g.put(row, col, &[Seg(" ".into(), Style::new())], w);
        }
        row += 1;
    }
    // A blank line under the bars.
    row += 1;
    let body_top = row;

    // The notice and footer at the bottom.
    let notice = page.notice.as_ref().map(|n| notice_lines(n, w.saturating_sub(4))).unwrap_or_default();
    let notice_rows = notice.len().clamp(1, MAX_NOTICE);
    let footer_row = h - 1;
    let notice_top = footer_row - notice_rows;
    let rows = notice_top.saturating_sub(body_top);

    // The body.
    let mut body: Vec<Vec<Seg>> = Vec::new();
    let mut starts = Vec::with_capacity(page.body.lines.len() + 1);
    let mut lines = page.body.lines.as_slice();
    while let Some((last, rest)) = lines.split_last() {
        if !last.is_empty() {
            break;
        }
        lines = rest;
    }
    for l in lines {
        starts.push(body.len());
        body.extend(wrap_line(l, bw));
    }
    starts.push(body.len());
    let focus = page.focus.as_ref().map(|f| {
        let at = |i: usize| starts[i.min(starts.len() - 1)];
        (at(f.lines.start)..at(f.lines.end).max(at(f.lines.start) + 1), f.paint)
    });
    let top = scroll.place(body.len(), rows, bw, focus.as_ref().map(|f| &f.0));
    for (i, l) in body.iter().enumerate().skip(top).take(rows) {
        let r = body_top + i - top;
        g.put(r, LEFT, l, LEFT + bw);
        if let Some((f, true)) = &focus
            && f.contains(&i)
        {
            if let Some(bg) = p.shade {
                g.shade(r, BAR, LEFT + bw, Style::new().bg(bg));
            }
            let mut st = p.selected();
            if let Some(bg) = p.shade {
                st = st.bg(bg);
            }
            g.put(r, BAR, &[Seg(theme::BAR.into(), st)], BAR + 1);
        }
    }
    // The thumb, when there is more than shows.
    if body.len() > rows && rows > 0 {
        let size = (rows * rows / body.len()).max(1);
        let most = body.len() - rows;
        let at = (top * (rows - size)).checked_div(most).unwrap_or(0);
        for r in at..at + size {
            g.put(body_top + r, w - 1, &[Seg("▐".into(), p.faint())], w);
        }
    }

    // An overlay over the body: what is under it recedes, and a cell of
    // plain screen round the panel keeps the two apart.
    if let Some(o) = &page.overlay {
        for r in body_top..notice_top {
            g.dim(r);
        }
        let pw = bw.saturating_sub(2).min(MAX_PANEL);
        let lines = panel(&overlay_lines(o, page.help.as_ref()), pw);
        let col = LEFT + (bw - pw) / 2;
        let shown = lines.len().min(rows);
        let first = body_top + (rows - shown) / 2;
        for r in first.saturating_sub(1).max(body_top)..(first + shown + 1).min(notice_top) {
            g.fill(r, col.saturating_sub(2), col + pw + 2, Style::new());
        }
        for (i, l) in lines.iter().take(shown).enumerate() {
            g.fill(first + i, col, col + pw, Style::new());
            g.put(first + i, col, l, col + pw);
        }
    }

    // The notice.
    for (i, l) in notice.iter().take(notice_rows).enumerate() {
        g.put(notice_top + i, 1, l, w - 1);
    }

    // The footer.
    g.fill(footer_row, 0, w, bar_style);
    let keys = footer(page, w.saturating_sub(2));
    let keys: Vec<Seg> = keys.into_iter().map(|s| Seg(s.0, p.on_raised(s.1))).collect();
    g.put(footer_row, 1, &keys, w - 1);

    g.into_doc()
}

fn notice_lines(n: &Notice, width: usize) -> Vec<Vec<Seg>> {
    let p = theme::palette();
    let (m, text) = match n.tone {
        Tone::Ok => (theme::mark(Mark::Done), p.fg(p.gold)),
        Tone::Bad => (theme::mark(Mark::Bad), p.fg(alarm_fg())),
        Tone::Info => (Seg("·".into(), p.hint()), p.hint()),
    };
    let mut out = Vec::new();
    for (i, para) in n.text.split('\n').enumerate() {
        let first = vec![if i == 0 { m.clone() } else { Seg(" ".into(), Style::new()) }, Seg(format!(" {para}"), text)];
        out.extend(wrap_line(&first, width));
    }
    if out.len() > MAX_NOTICE {
        out.truncate(MAX_NOTICE);
        if let Some(l) = out.last_mut() {
            let w = seg_width(l);
            *l = cut(l, w.saturating_sub(1));
        }
    }
    out
}

/// The footer's keys for width cells: the page's own first, `?` and the
/// way back last. What does not fit is dropped from the middle: the most
/// used keys and the way out stay.
fn footer(page: &Page, width: usize) -> Vec<Seg> {
    let tail: Vec<(String, String)> = match &page.overlay {
        Some(Overlay::Confirm { .. }) => return keys_segs(&[("y".into(), "yes".into()), ("any other key".into(), "no".into())]),
        Some(Overlay::Help) => return keys_segs(&[("any key".into(), "close".into())]),
        Some(Overlay::Sheet { .. }) => {
            return keys_segs(&[("↑↓".into(), "move".into()), ("enter".into(), "choose".into()), ("esc".into(), "close".into())]);
        }
        None => {
            let mut t = Vec::new();
            if page.help.is_some() {
                t.push(("?".to_string(), "help".to_string()));
            }
            match page.back {
                Back::Esc => t.push(("esc".into(), "back".into())),
                Back::Quit => t.push(("q".into(), "quit".into())),
                Back::Nothing => {}
            }
            t
        }
    };
    let mut keys = page.keys.clone();
    loop {
        let mut all = keys.clone();
        all.extend(tail.iter().cloned());
        let segs = keys_segs(&all);
        if seg_width(&segs) <= width || keys.is_empty() {
            return cut(&segs, width);
        }
        keys.pop();
    }
}

fn keys_segs(pairs: &[(String, String)]) -> Vec<Seg> {
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, d)| (k.as_str(), d.as_str())).collect();
    theme::caps(&refs).lines.into_iter().next().unwrap_or_default()
}

/// The window is too small: only that, and how to leave.
fn small(w: u16, h: u16) -> Doc {
    let p = theme::palette();
    let x = theme::times();
    let msg = format!("Make this window at least {MIN_W} {x} {MIN_H} (it is {w} {x} {h}).");
    let (w, h) = (w as usize, h as usize);
    let mut lines: Vec<Vec<Seg>> = wrap_line(&[Seg(msg, p.text())], w.saturating_sub(2).max(1));
    lines.push(Vec::new());
    lines.extend(wrap_line(&[Seg("q quits".into(), p.hint())], w.saturating_sub(2).max(1)));
    let mut g = Grid::new(w, h);
    let first = h.saturating_sub(lines.len()) / 2;
    for (i, l) in lines.iter().enumerate().take(h) {
        let lw = seg_width(l);
        g.put(first + i, w.saturating_sub(lw) / 2, l, w);
    }
    g.into_doc()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tui::{dim, plain, title};

    /// The text of a drawn frame, one string per row.
    pub fn rows(d: &Doc) -> Vec<String> {
        d.lines.iter().map(|l| l.iter().map(|s| s.0.as_str()).collect()).collect()
    }

    fn page_with(n: usize) -> Page {
        let mut p = Page::new("Machines");
        p.status.add(plain("coordinator 10.1.0.60"));
        for i in 0..n {
            p.body.add(plain(format!("line {i}"))).nl();
        }
        p.key("a", "approve").key("x", "reject");
        p.help = Some(Help { about: "What this is for.".into(), keys: vec![("a".into(), "approve".into())] });
        p
    }

    #[test]
    fn every_tier_fills_the_window() {
        for (tier, console) in [(Tier::True, false), (Tier::C256, false), (Tier::Console, true), (Tier::Plain, false), (Tier::Plain, true)]
        {
            let _g = theme::force(tier, console);
            for (w, h) in [(80, 24), (100, 32), (200, 60)] {
                let d = draw(&page_with(50), &Scroll::default(), w, h);
                let r = rows(&d);
                assert_eq!(r.len(), h as usize, "{tier:?}");
                for l in &r {
                    assert_eq!(l.width(), w as usize, "{tier:?} {w}x{h}: {l:?}");
                }
                assert!(r[0].starts_with(" dryserver  Machines") && r[0].trim_end().ends_with("coordinator 10.1.0.60"), "{:?}", r[0]);
                let foot = r[h as usize - 1].clone();
                assert!(foot.contains("help") && foot.trim_end().ends_with("back"), "{tier:?}: {foot:?}");
                let painted = d.lines.iter().flatten().any(|s| s.1.bg.is_some());
                let coloured = d.lines.iter().flatten().any(|s| s.1.fg.is_some());
                match tier {
                    Tier::True | Tier::C256 => assert!(painted, "the bars are raised"),
                    Tier::Console => assert!(!painted && coloured, "the console paints no background"),
                    Tier::Plain => assert!(!painted && !coloured, "NO_COLOR colours nothing"),
                }
                if tier == Tier::Console || tier == Tier::Plain {
                    assert!(foot.contains("[a] approve"), "{foot:?}");
                }
            }
        }
    }

    #[test]
    fn too_small_says_so() {
        let _g = theme::force(Tier::True, false);
        for (w, h) in [(79, 24), (80, 23), (40, 10), (1, 1), (0, 0)] {
            let d = draw(&page_with(3), &Scroll::default(), w, h);
            let r = rows(&d);
            assert_eq!(r.len(), h as usize);
            let all = r.join(" ");
            if h > 3 {
                assert!(all.contains("Make this window") && all.contains("q quits"), "{w}x{h}: {all}");
            }
            assert!(!all.contains("line 0"), "nothing else shows");
        }
        let r = rows(&draw(&page_with(3), &Scroll::default(), 79, 30)).join("\n");
        assert!(r.contains("at least 80 × 24 (it is 79 × 30)"), "{r}");
        let _g = theme::force(Tier::Console, true);
        let r = rows(&draw(&page_with(3), &Scroll::default(), 60, 20)).join("\n");
        assert!(r.contains("80 x 24 (it is 60 x 20)"), "the console font has no ×: {r}");
    }

    #[test]
    fn wrapping_keeps_indent_and_styles() {
        let t = title("x").1;
        let line = vec![Seg("    ".into(), Style::new()), Seg("one two".into(), t), Seg(" three four five".into(), Style::new())];
        let w = wrap_line(&line, 14);
        let text: Vec<String> = w.iter().map(|l| l.iter().map(|s| s.0.as_str()).collect()).collect();
        assert_eq!(text, vec!["    one two", "    three four", "    five"]);
        assert!(w[0].iter().any(|s| s.0 == "one two" && s.1 == t), "the style stays: {:?}", w[0]);
        for l in &w {
            assert!(seg_width(l) <= 14);
        }
        // A word longer than the line is cut where it ends.
        let w = wrap_line(&[plain("abcdefghijklmnopqrstuvwxyz")], 10);
        assert_eq!(w.len(), 3);
        // Short lines stay as they are, even with wide characters.
        assert_eq!(wrap_line(&[plain("名前 ok")], 10).len(), 1);
        let w = wrap_line(&[plain("名前名前名前名前")], 5);
        assert!(w.iter().all(|l| seg_width(l) <= 5), "{w:?}");
        // An indent wider than half the line is not kept.
        let w = wrap_line(&[plain(format!("{}a b c d e f", " ".repeat(8)))], 12);
        assert!(w.iter().all(|l| seg_width(l) <= 12));
    }

    #[test]
    fn long_body_lines_wrap_in_the_frame() {
        let _g = theme::force(Tier::True, false);
        let mut p = Page::new("x");
        p.body.add(plain(format!("  {}", "word ".repeat(40))));
        let r = rows(&draw(&p, &Scroll::default(), 80, 24));
        let body: Vec<&String> = r.iter().filter(|l| l.contains("word")).collect();
        assert!(body.len() >= 3, "{r:#?}");
        for l in body {
            assert!(l.starts_with("     word"), "indent kept: {l:?}");
        }
    }

    #[test]
    fn scrolling_keeps_the_focus_in_view() {
        let _g = theme::force(Tier::True, false);
        let s = Scroll::default();
        let mut p = page_with(100);
        for i in [0usize, 30, 99, 10, 50] {
            p.focus = Some(Focus::row(i));
            let r = rows(&draw(&p, &s, 80, 24));
            let shown = r.iter().position(|l| l.contains(&format!("line {i} ")) || l.trim_end().ends_with(&format!("line {i}")));
            let row = shown.unwrap_or_else(|| panic!("line {i} not in view: {r:#?}"));
            assert!(r[row].starts_with(" ▌ line"), "the selected row has the bar: {:?}", r[row]);
        }
        // pgdn looks further; the focus did not move, so it stays there.
        p.focus = Some(Focus::row(0));
        draw(&p, &s, 80, 24);
        assert_eq!(s.top(), 0);
        assert!(s.key(&Key::PageDown));
        let r = rows(&draw(&p, &s, 80, 24));
        assert!(s.top() > 0 && !r.iter().any(|l| l.ends_with("line 0") || l.contains("line 0 ")));
        assert!(s.key(&Key::End));
        draw(&p, &s, 80, 24);
        let r = rows(&draw(&p, &s, 80, 24));
        assert!(r.iter().any(|l| l.contains("line 99")), "end shows the last line");
        assert!(s.key(&Key::Home));
        draw(&p, &s, 80, 24);
        assert_eq!(s.top(), 0);
        assert!(!s.key(&Key::Char('j')));
        // A resize brings the focus back into view.
        p.focus = Some(Focus::row(80));
        draw(&p, &s, 100, 40);
        s.key(&Key::Home);
        let r = rows(&draw(&p, &s, 80, 24));
        assert!(r.iter().any(|l| l.contains("line 80")), "{r:#?}");
        // The thumb shows where it is.
        assert!(r.iter().any(|l| l.ends_with('▐')));
        // A body that fits has no thumb and does not scroll.
        let s = Scroll::default();
        let r = rows(&draw(&page_with(3), &s, 80, 24));
        assert!(!r.iter().any(|l| l.ends_with('▐')));
        s.key(&Key::PageDown);
        draw(&page_with(3), &s, 80, 24);
        assert_eq!(s.top(), 0);
    }

    #[test]
    fn selection_is_painted_across_the_body() {
        let _g = theme::force(Tier::True, false);
        let mut p = page_with(5);
        p.focus = Some(Focus::row(2));
        let d = draw(&p, &Scroll::default(), 100, 30);
        let r = rows(&d);
        let i = r.iter().position(|l| l.contains("line 2")).unwrap();
        let shade = theme::palette().shade;
        let painted: usize = d.lines[i].iter().filter(|s| s.1.bg == shade).map(|s| s.0.width()).sum();
        assert_eq!(painted, body_width(100) + LEFT - BAR, "{:?}", d.lines[i]);
        // Kept in view, not painted.
        p.focus = Some(Focus::keep(2..3));
        let d = draw(&p, &Scroll::default(), 100, 30);
        assert!(!d.lines[i].iter().any(|s| s.1.bg == shade));
    }

    #[test]
    fn footer_fits_and_keeps_the_way_out() {
        let _g = theme::force(Tier::True, false);
        let mut p = page_with(3);
        for i in 0..20 {
            p.key(&format!("{i}"), "something long to do");
        }
        let r = rows(&draw(&p, &Scroll::default(), 80, 24));
        let foot = r.last().unwrap().trim_end().to_string();
        assert!(foot.contains(" a  approve") && foot.contains(" ?  help") && foot.ends_with(" esc  back"), "{foot}");
        assert!(!foot.contains(" 19 "), "the last of the many keys went: {foot}");
        // Home says q quit.
        p.back = Back::Quit;
        let r = rows(&draw(&p, &Scroll::default(), 80, 24));
        assert!(r.last().unwrap().trim_end().ends_with(" q  quit"));
        // No help: no ?.
        p.help = None;
        let r = rows(&draw(&p, &Scroll::default(), 80, 24));
        assert!(!r.last().unwrap().contains("help"));
    }

    #[test]
    fn overlays_are_panels_over_the_body() {
        for (tier, console) in [(Tier::True, false), (Tier::Console, true), (Tier::Plain, false)] {
            let _g = theme::force(tier, console);
            let mut p = page_with(40);
            p.overlay = Some(Overlay::Confirm { question: "Remove node-a?".into(), consequences: vec!["It leaves the mesh.".into()] });
            let d = draw(&p, &Scroll::default(), 80, 24);
            let r = rows(&d).join("\n");
            assert!(r.contains("Remove node-a?") && r.contains("It leaves the mesh."), "{r}");
            let foot = rows(&d).last().unwrap().clone();
            assert!(foot.contains("yes") && foot.contains("any other key") && !foot.contains("back"), "{foot}");
            if tier == Tier::True {
                assert!(d.lines.iter().flatten().any(|s| s.0.contains("Remove") && s.1.bg == theme::palette().raised));
            } else {
                assert!(r.contains('┌') && r.contains('┘'), "a border where nothing is painted: {r}");
            }
            p.overlay = Some(Overlay::Help);
            let r = rows(&draw(&p, &Scroll::default(), 80, 24)).join("\n");
            assert!(r.contains("What this is for.") && r.contains("Any key closes this."), "{r}");
            p.overlay = Some(Overlay::Sheet {
                title: "node-a".into(),
                items: vec![
                    Item { key: "d".into(), label: "remove".into(), why_not: None },
                    Item { key: "s".into(), label: "sign".into(), why_not: Some("it is signed".into()) },
                ],
                cursor: 0,
            });
            let r = rows(&draw(&p, &Scroll::default(), 80, 24)).join("\n");
            assert!(r.contains("remove") && r.contains("sign: it is signed"), "{r}");
        }
    }

    #[test]
    fn notice_tones_and_tabs() {
        let _g = theme::force(Tier::True, false);
        let mut p = page_with(3);
        p.tabs = vec!["Machines".into(), "Updates".into(), "Network".into()];
        p.tab = 1;
        p.notice = Some(Notice::ok("Approved node-a."));
        let d = draw(&p, &Scroll::default(), 80, 24);
        let r = rows(&d);
        assert!(r[1].contains(" Machines ") && r[1].contains(" Updates "));
        let open = d.lines[1].iter().find(|s| s.0.contains("Updates")).unwrap();
        assert_eq!(open.1.bg, theme::palette().shade, "the open tab is on shade");
        assert!(r[22].contains("✓ Approved node-a."), "{:?}", r[22]);
        p.notice = Some(Notice::bad(format!("Not approved: {}", "the coordinator did not answer ".repeat(10))));
        let r = rows(&draw(&p, &Scroll::default(), 80, 24));
        let bang = r.iter().position(|l| l.contains("! Not approved")).unwrap();
        assert!((23 - MAX_NOTICE..23).contains(&bang), "a long notice takes at most three lines");
    }

    #[test]
    fn parts() {
        let _g = theme::force(Tier::True, false);
        let mut d = Doc::new();
        section(&mut d, "Members", Some(3));
        d.append(row(60, Mark::Done, vec![col(plain("coord"), 10), col(dim("10.66.0.1"), 12), col(plain("signed"), 0)])).nl();
        d.append(row(30, Mark::Bad, vec![col(plain("a-very-long-machine-name"), 10), col(plain("disk 93% full and more"), 0)])).nl();
        section(&mut d, "Waiting to join", Some(0));
        d.append(empty("No machine waits to join. Boot the USB stick on another laptop and choose server."));
        let t = d.plain();
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "Members  3", "no blank line at the top");
        assert_eq!(lines[1], "✓  coord       10.66.0.1     signed");
        assert!(lines[2].starts_with("!  a-very-lo…") && lines[2].width() <= 30, "{:?}", lines[2]);
        assert_eq!(lines[3], "", "a blank line before a section");
        assert_eq!(lines[4], "Waiting to join  0");
        let c =
            card(50, "The coordinator does not answer.", "Is it on? It answers within a minute of starting.", Some(("r", "look again")));
        for l in &c.lines {
            assert_eq!(seg_width(l), 50);
            assert!(l.iter().all(|s| s.1.bg == theme::palette().raised));
        }
        assert!(c.plain().contains("! The coordinator does not answer.") && c.plain().contains(" r  look again"));
        // Its own line breaks stay, under the first line's words.
        let c = card(50, "not done on 2 server(s):\n  node-a: cannot connect\n  node-b: cannot connect", "", None).plain();
        let lines: Vec<&str> = c.lines().map(str::trim_end).collect();
        assert_eq!(&lines[1..4], &["  ! not done on 2 server(s):", "      node-a: cannot connect", "      node-b: cannot connect"], "{c}");
        let pr = progress(90, Some(0.5), "Running mkarchiso", Duration::from_secs(75)).plain();
        assert!(pr.contains("Running mkarchiso") && pr.contains("1m15s") && pr.contains("50%"), "{pr}");
        assert_eq!(pr.lines().count(), 10);
    }

    #[test]
    fn cut_marks_the_cut() {
        assert_eq!(cut(&[plain("short")], 10)[0].0, "short");
        let c: String = cut(&[plain("node-a,node-b,node-c")], 12).iter().map(|s| s.0.clone()).collect();
        assert!(c.width() <= 12 && c.ends_with('…'), "{c}");
        assert!(cut(&[plain("abc")], 0).is_empty(), "no room, not even for the ellipsis");
    }
}
