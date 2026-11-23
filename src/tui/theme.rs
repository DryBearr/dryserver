//! The look of every screen: an ouroboros on coal. The snake's colours run
//! from the ember-red head through flame and gold to the violet tail, and
//! each has one job (docs/tui-design.md has the table):
//!
//!   coal    the screen
//!   raised  header and footer bars, panels, key caps
//!   shade   the selected row's background
//!   bone    body text
//!   ember   what you act on: the selected row's mark, the next step
//!   flame   titles and headings
//!   gold    done, signed, healthy; the keys you can press
//!   violet  hints, secondary text, waiting
//!   ash     structure: rules, empty progress, disabled
//!   alarm   something is wrong
//!
//! The snake is the one decoration, and it carries meaning: it is the
//! emblem on Home and the progress ring everywhere else. It grows around
//! the ring as work completes and bites its tail when it is done.
//!
//! Four tiers: true colour, 256 colours, the 16 colours of the Linux
//! console (where the installer runs: only the glyphs of code page 437,
//! and no background is painted), and NO_COLOR, where nothing is coloured
//! or painted and the marks and words carry the meaning alone.

use std::sync::LazyLock;

use ratatui::style::{Color, Modifier, Style};

use super::{Doc, Seg, sprite};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// 24-bit colour.
    True,
    /// The xterm 256-colour palette.
    C256,
    /// 16 colours and code page 437: the Linux console.
    Console,
    /// NO_COLOR: no colour and no background at all.
    Plain,
}

pub struct Palette {
    pub tier: Tier,
    pub ember: Color,
    pub flame: Color,
    pub gold: Color,
    pub violet: Color,
    pub ash: Color,
    /// Body text; None keeps the terminal's own.
    pub bone: Option<Color>,
    /// Screen background; None keeps the terminal's own.
    pub coal: Option<Color>,
    /// Bars, panels and key caps; None where the tier paints no background.
    pub raised: Option<Color>,
    /// The selected row's background; None where the tier paints none.
    pub shade: Option<Color>,
    alarm: Style,
    /// The snake from head to tail, for the ring and the progress bar.
    body: [Color; 8],
    /// Only the glyphs of code page 437 (the Linux console's font).
    pub console: bool,
}

/// The snake's body, head to tail.
pub const TRUE_BODY: [Color; 8] = [
    Color::Rgb(0xF2, 0x5C, 0x38),
    Color::Rgb(0xE0, 0x45, 0x2A),
    Color::Rgb(0xEE, 0x84, 0x34),
    Color::Rgb(0xE2, 0x9A, 0x36),
    Color::Rgb(0xD2, 0xA2, 0x3A),
    Color::Rgb(0xB0, 0x8A, 0x6E),
    Color::Rgb(0x8E, 0x77, 0xC9),
    Color::Rgb(0x6A, 0x58, 0xA6),
];

/// On the Linux console colour 3 ("yellow") is a brown close to flame.
const ANSI_BODY: [Color; 8] =
    [Color::LightRed, Color::Red, Color::Yellow, Color::Yellow, Color::LightYellow, Color::LightYellow, Color::Magenta, Color::Magenta];

fn true_color() -> Palette {
    Palette {
        tier: Tier::True,
        ember: Color::Rgb(0xF2, 0x5C, 0x38),
        flame: Color::Rgb(0xEE, 0x84, 0x34),
        gold: Color::Rgb(0xD2, 0xA2, 0x3A),
        violet: Color::Rgb(0x9A, 0x85, 0xD0),
        ash: Color::Rgb(0x5E, 0x53, 0x4F),
        bone: Some(Color::Rgb(0xE6, 0xDC, 0xCF)),
        coal: Some(Color::Rgb(0x14, 0x0C, 0x0A)),
        raised: Some(Color::Rgb(0x1E, 0x15, 0x13)),
        shade: Some(Color::Rgb(0x3A, 0x1A, 0x12)),
        alarm: Style::new().fg(Color::Rgb(0xFF, 0x5E, 0x4D)).add_modifier(Modifier::BOLD),
        body: TRUE_BODY,
        console: false,
    }
}

/// The indices are the design's, picked by eye; the snake's own colours
/// go to the nearest the palette has.
fn color256() -> Palette {
    let body = TRUE_BODY.map(|c| match c {
        Color::Rgb(r, g, b) => Color::Indexed(nearest_256(r, g, b)),
        c => c,
    });
    Palette {
        tier: Tier::C256,
        ember: Color::Indexed(203),
        flame: Color::Indexed(208),
        gold: Color::Indexed(178),
        violet: Color::Indexed(140),
        ash: Color::Indexed(240),
        bone: Some(Color::Indexed(253)),
        coal: Some(Color::Indexed(233)),
        raised: Some(Color::Indexed(234)),
        shade: Some(Color::Indexed(52)),
        alarm: Style::new().fg(Color::Indexed(203)).add_modifier(Modifier::BOLD),
        body,
        console: false,
    }
}

fn ansi16() -> Palette {
    Palette {
        tier: Tier::Console,
        ember: Color::LightRed,
        flame: Color::Yellow,
        gold: Color::LightYellow,
        violet: Color::Magenta,
        ash: Color::DarkGray,
        bone: None,
        coal: None,
        raised: None,
        shade: None,
        // Ember is already the brightest red there is: an alarm gets a
        // background, so it never looks like a selected line.
        alarm: Style::new().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD),
        body: ANSI_BODY,
        console: true,
    }
}

/// NO_COLOR: Reset is the terminal's own colour, so nothing is coloured.
fn plain(console: bool) -> Palette {
    Palette {
        tier: Tier::Plain,
        ember: Color::Reset,
        flame: Color::Reset,
        gold: Color::Reset,
        violet: Color::Reset,
        ash: Color::Reset,
        bone: None,
        coal: None,
        raised: None,
        shade: None,
        alarm: Style::new().add_modifier(Modifier::BOLD),
        body: [Color::Reset; 8],
        console,
    }
}

/// Which tier a terminal gets, and whether it draws with the console's
/// glyphs. NO_COLOR counts when it is set to anything but empty
/// (no-color.org).
pub fn detect(no_color: &str, colorterm: &str, term: &str) -> (Tier, bool) {
    if !no_color.is_empty() {
        return (Tier::Plain, term == "linux");
    }
    if matches!(colorterm, "truecolor" | "24bit") && term != "linux" {
        (Tier::True, false)
    } else if term.contains("256color") {
        (Tier::C256, false)
    } else {
        (Tier::Console, true)
    }
}

static TRUE: LazyLock<Palette> = LazyLock::new(true_color);
static C256: LazyLock<Palette> = LazyLock::new(color256);
static CONSOLE: LazyLock<Palette> = LazyLock::new(ansi16);
static PLAIN: LazyLock<Palette> = LazyLock::new(|| plain(false));
static PLAIN_CONSOLE: LazyLock<Palette> = LazyLock::new(|| plain(true));

fn of(tier: Tier, console: bool) -> &'static Palette {
    match (tier, console) {
        (Tier::True, _) => &TRUE,
        (Tier::C256, _) => &C256,
        (Tier::Console, _) => &CONSOLE,
        (Tier::Plain, false) => &PLAIN,
        (Tier::Plain, true) => &PLAIN_CONSOLE,
    }
}

#[cfg(test)]
thread_local! {
    static FORCED: std::cell::Cell<Option<(Tier, bool)>> = const { std::cell::Cell::new(None) };
}

/// For tests: this thread draws with tier until the guard goes.
#[cfg(test)]
pub fn force(tier: Tier, console: bool) -> impl Drop {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FORCED.with(|f| f.set(None));
        }
    }
    FORCED.with(|f| f.set(Some((tier, console))));
    Reset
}

pub fn palette() -> &'static Palette {
    #[cfg(test)]
    if let Some((t, c)) = FORCED.with(|f| f.get()) {
        return of(t, c);
    }
    static DETECTED: LazyLock<(Tier, bool)> = LazyLock::new(|| {
        let env = |k: &str| std::env::var(k).unwrap_or_default();
        detect(&env("NO_COLOR"), &env("COLORTERM"), &env("TERM"))
    });
    of(DETECTED.0, DETECTED.1)
}

impl Palette {
    /// A colour as the text's colour; nothing under NO_COLOR.
    pub fn fg(&self, c: Color) -> Style {
        if self.tier == Tier::Plain { Style::new() } else { Style::new().fg(c) }
    }
    pub fn title(&self) -> Style {
        self.fg(self.flame).add_modifier(Modifier::BOLD)
    }
    /// Ember is not bold: in 256 colours the alarm is the same red, and
    /// bold is what tells them apart.
    pub fn selected(&self) -> Style {
        self.fg(self.ember)
    }
    pub fn ok(&self) -> Style {
        self.fg(self.gold).add_modifier(Modifier::BOLD)
    }
    pub fn hint(&self) -> Style {
        self.fg(self.violet)
    }
    pub fn faint(&self) -> Style {
        self.fg(self.ash)
    }
    pub fn alarm(&self) -> Style {
        self.alarm
    }
    /// Body text: bone where the tier has it.
    pub fn text(&self) -> Style {
        match self.bone {
            Some(c) => Style::new().fg(c),
            None => Style::new(),
        }
    }
    /// The whole screen's style: coal under bone, or the terminal's own.
    pub fn base(&self) -> Style {
        let mut s = self.text();
        if let Some(c) = self.coal {
            s = s.bg(c);
        }
        s
    }
    /// s on the raised surface, where the tier paints one.
    pub fn on_raised(&self, s: Style) -> Style {
        match self.raised {
            Some(c) => s.bg(c),
            None => s,
        }
    }
    /// The colour of the snake at t, 0 the head and 1 the tail.
    fn along(&self, t: f64) -> Color {
        let i = (t.clamp(0.0, 1.0) * (self.body.len() - 1) as f64).round() as usize;
        self.body[i]
    }
}

// ---- glyphs and marks ----

/// What a row's mark says. A mark never stands alone: its words say the
/// same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Done, signed, healthy.
    Done,
    /// Needs you; the next step.
    Act,
    /// Waiting, in progress.
    Wait,
    /// Something is wrong.
    Bad,
    /// Not yet, not available.
    Off,
    /// No mark, only its space.
    Blank,
}

/// The mark as one cell, in its colour.
pub fn mark(m: Mark) -> Seg {
    let p = palette();
    let c = p.console;
    let (glyph, style) = match m {
        Mark::Done => (if c { "√" } else { "✓" }, p.ok()),
        Mark::Act => (if c { "•" } else { "●" }, p.selected()),
        Mark::Wait => (if c { "o" } else { "○" }, p.hint()),
        Mark::Bad => ("!", p.alarm()),
        Mark::Off => ("·", p.faint()),
        Mark::Blank => (" ", Style::new()),
    };
    Seg(glyph.into(), style)
}

/// The mark in front of a finished step. The console font has no check
/// mark; it has the root sign.
pub fn done_mark() -> &'static str {
    if palette().console { "√" } else { "✓" }
}

/// "…", which the console font does not have.
pub fn ellipsis() -> &'static str {
    if palette().console { "..." } else { "…" }
}

/// "×", which the console font does not have.
pub fn times() -> &'static str {
    if palette().console { "x" } else { "×" }
}

/// The selected row's bar at the left edge.
pub const BAR: &str = "▌";

/// A key as a cap: gold on the raised surface with a space either side,
/// or "[a]" where no surface is painted.
pub fn cap(key: &str) -> Seg {
    let p = palette();
    match p.raised {
        Some(_) => Seg(format!(" {key} "), p.on_raised(p.fg(p.gold).add_modifier(Modifier::BOLD))),
        None => Seg(format!("[{key}]"), p.fg(p.gold).add_modifier(Modifier::BOLD)),
    }
}

/// Keys as caps, each followed by what it does in violet.
pub fn caps(pairs: &[(&str, &str)]) -> Doc {
    let p = palette();
    let mut d = Doc::new();
    for (i, (key, does)) in pairs.iter().enumerate() {
        if i > 0 {
            d.s("  ");
        }
        d.add(cap(key)).s(" ").add(Seg(does.to_string(), p.hint()));
    }
    d
}

// ---- the snake ----

/// The ring, 5 lines of 11 cells. Full and half blocks only.
const RING: [&str; 5] = ["  ▄▄███▄▄  ", " ██▀   ▀██ ", " ██     ██ ", " ██▄   ▄██ ", "  ▀▀███▀▀  "];
#[cfg(test)]
const RING_WIDTH: usize = 11;

/// How far around the ring a cell is, 0..1, clockwise from the head at the
/// top right. A cell is twice as high as wide, hence the 2.
fn around(row: usize, col: usize) -> f64 {
    let (dy, dx) = ((row as f64 - 2.0) * 2.0, col as f64 - 5.0);
    // 0 at the head, a little right of the top; grows clockwise.
    let angle = dx.atan2(-dy) - 0.5;
    (angle / std::f64::consts::TAU).rem_euclid(1.0)
}

/// The ouroboros in blocks, for the console. With progress in 0..=1 the
/// snake has grown that far around the ring and the rest is ash; at 1 it
/// has bitten its tail. With None the whole snake is there (the emblem).
/// Under NO_COLOR what has not grown is a lighter shade instead.
pub fn ring(progress: Option<f64>) -> Doc {
    let p = palette();
    let grown = progress.map(|x| x.clamp(0.0, 1.0)).unwrap_or(1.0);
    let mut d = Doc::new();
    for (row, line) in RING.iter().enumerate() {
        if row > 0 {
            d.nl();
        }
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                d.s(" ");
                continue;
            }
            let t = around(row, col);
            // Nothing has grown at 0: not even the head.
            if grown > 0.0 && t <= grown {
                d.add(Seg(ch.to_string(), p.fg(p.along(if grown >= 1.0 { t } else { t / grown.max(0.2) }))));
            } else if p.tier == Tier::Plain {
                d.add(Seg("░".into(), Style::new()));
            } else {
                d.add(Seg(ch.to_string(), p.fg(p.ash)));
            }
        }
    }
    d
}

/// The xterm-256 colour nearest to an RGB colour: the 6×6×6 cube or the
/// grey ramp. The first 16 are left out, each terminal sets them its own way.
pub fn nearest_256(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let dist = |a: (i32, i32, i32)| {
        let (dr, dg, db) = (a.0 - r as i32, a.1 - g as i32, a.2 - b as i32);
        // The eye weighs green most and blue least.
        2 * dr * dr + 4 * dg * dg + 3 * db * db
    };
    let near = |v: u8| LEVELS.iter().enumerate().min_by_key(|(_, l)| (**l - v as i32).abs()).map(|(i, _)| i).unwrap_or(0);
    let (ri, gi, bi) = (near(r), near(g), near(b));
    let cube = (LEVELS[ri], LEVELS[gi], LEVELS[bi]);
    let cube_index = 16 + 36 * ri + 6 * gi + bi;
    let mean = (r as i32 + g as i32 + b as i32) / 3;
    let gi = ((mean - 8 + 5) / 10).clamp(0, 23);
    let gv = 8 + 10 * gi;
    if dist((gv, gv, gv)) < dist(cube) { (232 + gi) as u8 } else { cube_index as u8 }
}

/// The sprite's colour for one palette letter, in this tier's terms; None
/// for no pixel.
fn pixel(letter: char, tier: Tier) -> Option<Color> {
    let i = match letter {
        'A'..='Z' => letter as usize - 'A' as usize,
        'a'..='z' => 26 + letter as usize - 'a' as usize,
        '0'..='9' => 52 + letter as usize - '0' as usize,
        _ => return None,
    };
    let (r, g, b) = *sprite::PALETTE.get(i)?;
    Some(if tier == Tier::C256 { Color::Indexed(nearest_256(r, g, b)) } else { Color::Rgb(r, g, b) })
}

/// One frame of the pixel snake: each cell is two pixels, the upper one
/// the half block's colour and the lower one its background. A missing
/// pixel shows the screen behind it.
fn pixels(rows: &[&str], tier: Tier) -> Doc {
    let mut d = Doc::new();
    for y in 0..rows.len() / 2 {
        if y > 0 {
            d.nl();
        }
        for (t, b) in rows[2 * y].chars().zip(rows[2 * y + 1].chars()) {
            let seg = match (pixel(t, tier), pixel(b, tier)) {
                (Some(t), Some(b)) => Seg("▀".into(), Style::new().fg(t).bg(b)),
                (Some(t), None) => Seg("▀".into(), Style::new().fg(t)),
                (None, Some(b)) => Seg("▄".into(), Style::new().fg(b)),
                (None, None) => Seg(" ".into(), Style::new()),
            };
            d.add(seg);
        }
    }
    d
}

/// Which frame shows progress p: the snake grown round(p × 20) of 20.
pub fn frame_of(progress: Option<f64>) -> usize {
    let last = sprite::FRAMES.len() - 1;
    match progress {
        None => last,
        Some(p) => (p.clamp(0.0, 1.0) * last as f64).round() as usize,
    }
}

/// The ouroboros: in pixels where the terminal has the colours for it
/// (20 × 10 cells), else the block ring (11 × 5). None is the whole snake,
/// the emblem; Some(p) the snake grown that far round.
pub fn snake(progress: Option<f64>) -> Doc {
    let p = palette();
    match p.tier {
        Tier::True | Tier::C256 => pixels(&sprite::FRAMES[frame_of(progress)], p.tier),
        Tier::Console | Tier::Plain => ring(progress),
    }
}

/// The whole snake for a short window: 12 × 6 cells in pixels, else the
/// block ring.
pub fn small_snake() -> Doc {
    let p = palette();
    match p.tier {
        Tier::True | Tier::C256 => pixels(&sprite::SMALL, p.tier),
        Tier::Console | Tier::Plain => ring(None),
    }
}

/// How many rows and columns small_snake() takes.
pub fn small_snake_size() -> (usize, usize) {
    match palette().tier {
        Tier::True | Tier::C256 => (sprite::SMALL_SIZE / 2, sprite::SMALL_SIZE),
        Tier::Console | Tier::Plain => (RING.len(), RING[0].chars().count()),
    }
}

/// A style pushed back behind a panel: its colours faded toward the
/// screen (to ash where they cannot be mixed), no bold, and no selection
/// background, so only the panel reads. A picture (a cell of the pixel
/// snake) keeps its shape as one flat dark colour where colours cannot be
/// mixed.
pub fn dimmed(s: Style, picture: bool) -> Style {
    let p = palette();
    let mut out = s.remove_modifier(Modifier::BOLD);
    if s.bg.is_some() && s.bg == p.shade {
        out.bg = None;
    }
    match p.tier {
        Tier::Plain => {}
        Tier::True => {
            let coal = match p.coal {
                Some(Color::Rgb(r, g, b)) => (r, g, b),
                _ => (20, 12, 10),
            };
            let fade = |c: Color| match c {
                Color::Rgb(r, g, b) => {
                    let m = |a: u8, b: u8| ((a as f64) * 0.32 + (b as f64) * 0.68).round() as u8;
                    Color::Rgb(m(r, coal.0), m(g, coal.1), m(b, coal.2))
                }
                _ => p.ash,
            };
            out.fg = out.fg.map(fade);
            out.bg = out.bg.map(fade);
        }
        // Indexed colours do not mix: text goes ash, a picture one dark
        // grey, so it keeps its shape.
        Tier::C256 => {
            out.fg = out.fg.map(|_| if picture { Color::Indexed(236) } else { p.ash });
            out.bg = out.bg.map(|_| Color::Indexed(236));
        }
        Tier::Console => {
            out.fg = out.fg.map(|_| p.ash);
            out.bg = None;
        }
    }
    out
}

/// How many rows snake() takes.
pub fn snake_height() -> usize {
    match palette().tier {
        Tier::True | Tier::C256 => sprite::SIZE / 2,
        Tier::Console | Tier::Plain => RING.len(),
    }
}

// ---- older parts, for the screens not redrawn in the frame yet ----

/// The top of a working screen: the product, then where you are.
pub fn header(place: &str) -> Doc {
    let p = palette();
    let mut d = Doc::new();
    d.add(Seg("dryserver".into(), p.title())).s("  ").s(place);
    d
}

/// The top of an entry screen: the ring with the name and one line about
/// the screen beside it.
pub fn brand(place: &str, line: &str) -> Doc {
    let p = palette();
    let mut text = Doc::new();
    text.nl();
    text.add(Seg("dryserver".into(), p.title())).nl();
    text.s(place).nl();
    text.add(Seg(line.into(), p.hint()));
    Doc::beside(ring(None), 3, text)
}

/// The keys of a screen: each key in gold, what it does in violet.
pub fn keys(pairs: &[(&str, &str)]) -> Doc {
    let p = palette();
    let mut d = Doc::new();
    for (i, (key, does)) in pairs.iter().enumerate() {
        if i > 0 {
            d.s("   ");
        }
        d.add(Seg(key.to_string(), p.fg(p.gold))).s(" ").add(Seg(does.to_string(), p.hint()));
    }
    d
}

/// A bar of width cells for pct in 0..=1, coloured like the snake: thin
/// half blocks where there are colours to tell done from not done, full
/// blocks and a light shade on the console and without colour.
pub fn bar(pct: f64, width: usize) -> Doc {
    let p = palette();
    let filled = (pct.clamp(0.0, 1.0) * width as f64).round() as usize;
    let (done, rest) = match p.tier {
        Tier::True | Tier::C256 => ("▄", "▄"),
        Tier::Console | Tier::Plain => ("█", "░"),
    };
    let mut d = Doc::new();
    for i in 0..filled {
        d.add(Seg(done.into(), p.fg(p.along(i as f64 / width.max(2) as f64))));
    }
    d.add(Seg(rest.repeat(width - filled), p.fg(p.ash)));
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_by_terminal() {
        assert_eq!(detect("", "truecolor", "xterm-256color"), (Tier::True, false));
        assert_eq!(detect("", "24bit", "foot"), (Tier::True, false));
        assert_eq!(detect("", "", "xterm-256color"), (Tier::C256, false));
        assert_eq!(detect("", "truecolor", "linux"), (Tier::Console, true), "the console never gets true colour");
        assert_eq!(detect("", "", "linux"), (Tier::Console, true));
        assert_eq!(detect("", "yes", "xterm"), (Tier::Console, true));
        assert_eq!(detect("1", "truecolor", "xterm-256color"), (Tier::Plain, false));
        assert_eq!(detect("1", "", "linux"), (Tier::Plain, true), "the console's glyphs stay without colour");
        // An empty NO_COLOR does not count.
        assert_eq!(detect("", "truecolor", "foot"), (Tier::True, false));
    }

    #[test]
    fn tokens_keep_their_values() {
        let t = true_color();
        assert_eq!(t.coal, Some(Color::Rgb(0x14, 0x0C, 0x0A)));
        assert_eq!(t.raised, Some(Color::Rgb(0x1E, 0x15, 0x13)));
        assert_eq!(t.shade, Some(Color::Rgb(0x3A, 0x1A, 0x12)));
        assert_eq!(t.bone, Some(Color::Rgb(0xE6, 0xDC, 0xCF)));
        assert_eq!(t.ember, Color::Rgb(0xF2, 0x5C, 0x38));
        assert_eq!(t.flame, Color::Rgb(0xEE, 0x84, 0x34));
        assert_eq!(t.gold, Color::Rgb(0xD2, 0xA2, 0x3A));
        assert_eq!(t.violet, Color::Rgb(0x9A, 0x85, 0xD0));
        assert_eq!(t.ash, Color::Rgb(0x5E, 0x53, 0x4F));
        assert_eq!(t.alarm().fg, Some(Color::Rgb(0xFF, 0x5E, 0x4D)));
        let c = color256();
        let idx = [c.coal, c.raised, c.shade, c.bone, Some(c.ember), Some(c.flame), Some(c.gold), Some(c.violet), Some(c.ash)];
        let want = [233, 234, 52, 253, 203, 208, 178, 140, 240];
        for (got, want) in idx.iter().zip(want) {
            assert_eq!(*got, Some(Color::Indexed(want)));
        }
        assert_eq!(c.alarm().fg, Some(Color::Indexed(203)));
        assert!(c.alarm().add_modifier.contains(Modifier::BOLD));
        let k = ansi16();
        assert!(k.coal.is_none() && k.raised.is_none() && k.shade.is_none() && k.bone.is_none());
        assert_eq!(k.alarm().bg, Some(Color::Red), "an alarm must never look like a selected line");
        for p in [true_color(), color256(), ansi16()] {
            assert_ne!(p.alarm(), p.selected());
        }
    }

    #[test]
    fn no_color_paints_nothing() {
        for console in [false, true] {
            let _g = force(Tier::Plain, console);
            let p = palette();
            assert!(p.coal.is_none() && p.raised.is_none() && p.shade.is_none() && p.bone.is_none());
            let mut d = caps(&[("a", "approve")]);
            d.append(ring(Some(0.4))).append(bar(0.5, 6));
            for m in [Mark::Done, Mark::Act, Mark::Wait, Mark::Bad, Mark::Off] {
                d.add(mark(m));
            }
            for s in d.lines.iter().flatten() {
                assert!(s.1.fg.is_none() && s.1.bg.is_none(), "{s:?} is coloured");
            }
            assert!(d.plain().contains("[a] approve"), "{}", d.plain());
            assert!(d.plain().contains('░'), "without colour, what has not grown needs its own shape");
        }
    }

    #[test]
    fn marks_and_caps_per_tier() {
        let glyphs = |tier, console| {
            let _g = force(tier, console);
            [Mark::Done, Mark::Act, Mark::Wait, Mark::Bad, Mark::Off].map(|m| mark(m).0).join("")
        };
        assert_eq!(glyphs(Tier::True, false), "✓●○!·");
        assert_eq!(glyphs(Tier::C256, false), "✓●○!·");
        assert_eq!(glyphs(Tier::Console, true), "√•o!·");
        assert_eq!(glyphs(Tier::Plain, true), "√•o!·");
        assert_eq!(glyphs(Tier::Plain, false), "✓●○!·");
        {
            let _g = force(Tier::True, false);
            let c = cap("a");
            assert_eq!(c.0, " a ");
            assert_eq!(c.1.bg, Some(Color::Rgb(0x1E, 0x15, 0x13)), "a cap is gold on raised");
            assert_eq!(c.1.fg, Some(Color::Rgb(0xD2, 0xA2, 0x3A)));
            assert_eq!(mark(Mark::Act).1.fg, Some(Color::Rgb(0xF2, 0x5C, 0x38)));
        }
        let _g = force(Tier::Console, true);
        assert_eq!(cap("a").0, "[a]");
        assert_eq!(caps(&[("a", "approve"), ("x", "reject")]).plain(), "[a] approve  [x] reject");
        assert_eq!(ellipsis(), "...");
        assert_eq!(times(), "x");
    }

    #[test]
    fn nearest_xterm_colour() {
        assert_eq!(nearest_256(0, 0, 0), 16);
        assert_eq!(nearest_256(255, 255, 255), 231);
        assert_eq!(nearest_256(255, 0, 0), 196);
        assert_eq!(nearest_256(0, 0, 255), 21);
        assert_eq!(nearest_256(128, 128, 128), 244, "a grey goes to the grey ramp");
        assert_eq!(nearest_256(0x14, 0x0C, 0x0A), 233, "coal");
        assert_eq!(nearest_256(0x1E, 0x15, 0x13), 234, "raised");
        assert_eq!(nearest_256(0xE6, 0xDC, 0xCF), 253, "bone");
        // The cube: flame's nearest has a little blue in it.
        assert_eq!(nearest_256(0xEE, 0x84, 0x34), 209);
        assert_eq!(nearest_256(0xD2, 0xA2, 0x3A), 179);
        // Every pixel of the snake has a colour in the palette's range.
        for (r, g, b) in sprite::PALETTE {
            assert!(nearest_256(r, g, b) >= 16);
        }
    }

    #[test]
    fn pixel_snake() {
        assert_eq!(sprite::FRAMES.len(), 21);
        for tier in [Tier::True, Tier::C256] {
            let _g = force(tier, false);
            assert_eq!(snake_height(), 10);
            for f in 0..sprite::FRAMES.len() {
                let d = pixels(&sprite::FRAMES[f], tier);
                let text = d.plain();
                let lines: Vec<&str> = text.lines().collect();
                assert_eq!(lines.len(), 10, "frame {f}");
                for l in &lines {
                    assert_eq!(l.chars().count(), 20, "frame {f}: {l:?}");
                    assert!(l.chars().all(|c| matches!(c, '▀' | '▄' | ' ')), "frame {f}: only half blocks: {l:?}");
                }
                for s in d.lines.iter().flatten() {
                    let ok = |c: Option<Color>| match (tier, c) {
                        (_, None) => true,
                        (Tier::True, Some(Color::Rgb(..))) => true,
                        (Tier::C256, Some(Color::Indexed(i))) => i >= 16,
                        _ => false,
                    };
                    assert!(ok(s.1.fg) && ok(s.1.bg), "frame {f}: {s:?}");
                    // A blank cell has no colour: the screen behind shows.
                    if s.0 == " " {
                        assert!(s.1.fg.is_none() && s.1.bg.is_none());
                    }
                }
            }
        }
        // The pixels are the sprite's: the cell for rows 2 and 3, column 9
        // of the whole snake.
        let last = &sprite::FRAMES[20];
        let d = pixels(&sprite::FRAMES[20], Tier::True);
        let cell = d.lines[1].iter().flat_map(|s| s.0.chars().map(move |c| (c, s.1))).nth(9).unwrap();
        let (t, b) = (last[2].as_bytes()[9] as char, last[3].as_bytes()[9] as char);
        assert_eq!(cell.1.fg, pixel(t, Tier::True).or(pixel(b, Tier::True)));
        // The snake grows with the frames.
        let lit = |f: usize| sprite::FRAMES[f].iter().flat_map(|r| r.chars()).filter(|c| *c != '.').count();
        assert!(lit(0) < lit(10) && lit(10) <= lit(20));
        assert_eq!(frame_of(None), 20);
        assert_eq!(frame_of(Some(0.0)), 0);
        assert_eq!(frame_of(Some(0.5)), 10);
        assert_eq!(frame_of(Some(0.524)), 10);
        assert_eq!(frame_of(Some(0.53)), 11);
        assert_eq!(frame_of(Some(7.0)), 20);
        assert_eq!(frame_of(Some(-1.0)), 0);
    }

    #[test]
    fn small_snake_for_short_windows() {
        for tier in [Tier::True, Tier::C256] {
            let _g = force(tier, false);
            let (rows, cols) = small_snake_size();
            assert_eq!((rows, cols), (6, 12));
            let text = small_snake().plain();
            assert_eq!(text.lines().count(), rows);
            assert!(text.lines().all(|l| l.chars().count() == cols));
        }
        // The small snake is a whole ring: every row and column has pixels.
        for (y, r) in sprite::SMALL.iter().enumerate() {
            assert!(r.chars().any(|c| c != '.'), "row {y} is empty");
        }
        let _g = force(Tier::Console, true);
        assert_eq!(small_snake().plain(), RING.join("\n"));
        assert_eq!(small_snake_size(), (5, 11));
    }

    #[test]
    fn dimmed_behind_a_panel() {
        let _g = force(Tier::True, false);
        let p = palette();
        let s = dimmed(p.selected().bg(p.shade.unwrap()).add_modifier(Modifier::BOLD), false);
        assert!(s.bg.is_none(), "the selection's shade goes");
        assert!(!s.add_modifier.contains(Modifier::BOLD));
        match (s.fg, p.ember) {
            (Some(Color::Rgb(r, ..)), Color::Rgb(er, ..)) => assert!(r < er / 2, "faded toward the coal"),
            other => panic!("{other:?}"),
        }
        let _g = force(Tier::C256, false);
        let s = dimmed(Style::new().fg(Color::Indexed(203)).bg(Color::Indexed(208)), true);
        assert_eq!((s.fg, s.bg), (Some(Color::Indexed(236)), Some(Color::Indexed(236))), "a picture keeps its shape");
        let _g = force(Tier::Console, true);
        let s = dimmed(Style::new().fg(Color::LightRed).bg(Color::Red), false);
        assert_eq!((s.fg, s.bg), (Some(palette().ash), None));
    }

    #[test]
    fn console_keeps_the_ring() {
        let _g = force(Tier::Console, true);
        assert_eq!(snake(None).plain(), RING.join("\n"));
        assert_eq!(snake_height(), 5);
        let _g = force(Tier::Plain, true);
        assert_eq!(snake(None).plain(), RING.join("\n"));
    }

    #[test]
    fn ring_shape_and_growth() {
        let _g = force(Tier::Console, true);
        let full = ring(None);
        assert_eq!(full.plain(), RING.join("\n"));
        for line in RING {
            assert_eq!(line.chars().count(), RING_WIDTH);
            // Only glyphs the Linux console font has.
            assert!(line.chars().all(|c| matches!(c, ' ' | '█' | '▀' | '▄')), "{line}");
        }
        let ash = palette().ash;
        let lit = |d: &Doc| d.lines.iter().flatten().filter(|s| s.0 != " " && s.1.fg != Some(ash)).count();
        let cells = RING.join("").chars().filter(|c| *c != ' ').count();
        assert_eq!(lit(&ring(Some(0.0))), 0, "nothing has grown at the start");
        assert_eq!(lit(&ring(Some(1.0))), cells, "the snake bites its tail when done");
        assert_eq!(lit(&full), cells);
        let (quarter, half, most) = (lit(&ring(Some(0.25))), lit(&ring(Some(0.5))), lit(&ring(Some(0.9))));
        assert!(0 < quarter && quarter < half && half < most && most < cells, "{quarter} {half} {most} {cells}");
        // Out of range values do not panic.
        assert_eq!(lit(&ring(Some(7.0))), cells);
        assert_eq!(lit(&ring(Some(-1.0))), 0);
    }

    #[test]
    fn positions_run_once_around() {
        // Every cell has its own place on the way from head to tail.
        let mut ts = Vec::new();
        for (r, line) in RING.iter().enumerate() {
            for (c, ch) in line.chars().enumerate() {
                if ch != ' ' {
                    ts.push(around(r, c));
                }
            }
        }
        assert!(ts.iter().all(|t| (0.0..1.0).contains(t)));
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!(ts.windows(2).all(|w| w[1] - w[0] < 0.12), "a gap in the ring: {ts:?}");
    }

    #[test]
    fn header_keys_and_bar() {
        assert_eq!(header("machines").plain(), "dryserver  machines");
        assert_eq!(keys(&[("↑↓", "select"), ("q", "quit")]).plain(), "↑↓ select   q quit");
        {
            let _g = force(Tier::Console, true);
            assert_eq!(bar(0.5, 8).plain(), "████░░░░");
            assert_eq!(bar(2.0, 4).plain(), "████");
            assert_eq!(bar(0.0, 3).plain(), "░░░");
        }
        let _g = force(Tier::True, false);
        let b = bar(0.5, 8);
        assert_eq!(b.plain(), "▄▄▄▄▄▄▄▄", "thin half blocks");
        let ash = palette().ash;
        let done = b.lines[0].iter().filter(|s| s.1.fg != Some(ash)).map(|s| s.0.chars().count()).sum::<usize>();
        assert_eq!(done, 4);
        let b = brand("server setup", "hello").plain();
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 5, "{b}");
        assert!(lines[1].ends_with("   dryserver") && lines[2].ends_with("   server setup") && lines[3].ends_with("   hello"), "{b}");
    }
}
