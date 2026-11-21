//! The look of every screen: an ouroboros on coal. The snake's colours run
//! from the ember-red head through flame and gold to the violet tail, and
//! each has one job:
//!
//!   ember   what you act on (the selected line)
//!   flame   titles
//!   gold    done, signed, the keys you can press
//!   violet  hints and other quiet text (the tail)
//!   ash     structure: empty progress, rules
//!   alarm   something is wrong
//!
//! The ring itself is the one decoration, and it carries meaning: it is the
//! emblem on the entry screens and the progress indicator everywhere else.
//! The snake grows around the ring as work completes and bites its tail
//! when it is done.
//!
//! The installer runs on the bare Linux console: 16 colours and the glyphs
//! of code page 437. So the ring is built from full and half blocks only,
//! and without true colour the palette falls back to the terminal's own
//! 16 colours and no background is painted.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

use super::{Doc, Seg};

pub struct Palette {
    pub ember: Color,
    pub flame: Color,
    pub gold: Color,
    pub violet: Color,
    pub ash: Color,
    /// Body text; None keeps the terminal's own.
    pub bone: Option<Color>,
    /// Screen background; None keeps the terminal's own.
    pub coal: Option<Color>,
    alarm: Style,
    /// The snake from head to tail, for the ring and the progress bar.
    body: &'static [Color],
    /// The bare Linux console: only the glyphs of code page 437.
    pub console: bool,
}

const TRUE_BODY: [Color; 8] = [
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
        ember: Color::Rgb(0xF2, 0x5C, 0x38),
        flame: Color::Rgb(0xEE, 0x84, 0x34),
        gold: Color::Rgb(0xD2, 0xA2, 0x3A),
        violet: Color::Rgb(0x9A, 0x85, 0xD0),
        ash: Color::Rgb(0x5E, 0x53, 0x4F),
        bone: Some(Color::Rgb(0xE6, 0xDC, 0xCF)),
        coal: Some(Color::Rgb(0x14, 0x0C, 0x0A)),
        alarm: Style::new().fg(Color::Rgb(0xFF, 0x5E, 0x4D)).add_modifier(Modifier::BOLD),
        body: &TRUE_BODY,
        console: false,
    }
}

fn ansi16(console: bool) -> Palette {
    Palette {
        ember: Color::LightRed,
        flame: Color::Yellow,
        gold: Color::LightYellow,
        violet: Color::Magenta,
        ash: Color::DarkGray,
        bone: None,
        coal: None,
        // Ember is already the brightest red there is: an alarm gets a
        // background, so it never looks like a selected line.
        alarm: Style::new().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD),
        body: &ANSI_BODY,
        console,
    }
}

/// True colour only where the terminal says it can; the Linux console and
/// anything unknown get 16 colours.
fn detect(colorterm: &str, term: &str) -> Palette {
    let rich = matches!(colorterm, "truecolor" | "24bit") && term != "linux";
    if rich { true_color() } else { ansi16(term == "linux") }
}

pub fn palette() -> &'static Palette {
    static P: OnceLock<Palette> = OnceLock::new();
    P.get_or_init(|| detect(&std::env::var("COLORTERM").unwrap_or_default(), &std::env::var("TERM").unwrap_or_default()))
}

impl Palette {
    pub fn title(&self) -> Style {
        Style::new().fg(self.flame).add_modifier(Modifier::BOLD)
    }
    pub fn selected(&self) -> Style {
        Style::new().fg(self.ember).add_modifier(Modifier::BOLD)
    }
    pub fn ok(&self) -> Style {
        Style::new().fg(self.gold).add_modifier(Modifier::BOLD)
    }
    pub fn hint(&self) -> Style {
        Style::new().fg(self.violet)
    }
    pub fn alarm(&self) -> Style {
        self.alarm
    }
    /// The colour of the snake at t, 0 the head and 1 the tail.
    fn along(&self, t: f64) -> Color {
        let i = (t.clamp(0.0, 1.0) * (self.body.len() - 1) as f64).round() as usize;
        self.body[i]
    }
}

/// The mark in front of a finished step. The console font has no check
/// mark; it has the root sign.
pub fn done_mark() -> &'static str {
    if palette().console { "√" } else { "✓" }
}

/// "…", which the console font may not have.
pub fn ellipsis() -> &'static str {
    if palette().console { "..." } else { "…" }
}

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

/// The ouroboros. With progress in 0..=1 the snake has grown that far
/// around the ring and the rest is ash; at 1 it has bitten its tail. With
/// None the whole snake is there (the emblem).
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
            let style = if grown > 0.0 && t <= grown {
                Style::new().fg(p.along(if grown >= 1.0 { t } else { t / grown.max(0.2) }))
            } else {
                Style::new().fg(p.ash)
            };
            d.add(Seg(ch.to_string(), style));
        }
    }
    d
}

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
        d.add(Seg(key.to_string(), Style::new().fg(p.gold))).s(" ").add(Seg(does.to_string(), p.hint()));
    }
    d
}

/// A bar of width cells for pct in 0..=1, coloured like the snake.
pub fn bar(pct: f64, width: usize) -> Doc {
    let p = palette();
    let filled = (pct.clamp(0.0, 1.0) * width as f64).round() as usize;
    let mut d = Doc::new();
    for i in 0..filled {
        d.add(Seg("█".into(), Style::new().fg(p.along(i as f64 / width.max(2) as f64))));
    }
    d.add(Seg("░".repeat(width - filled), Style::new().fg(p.ash)));
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_by_terminal() {
        assert!(detect("truecolor", "xterm-256color").coal.is_some());
        assert!(detect("24bit", "foot").coal.is_some());
        // The installer's console, and anything that does not say.
        for (ct, term) in [("", "linux"), ("truecolor", "linux"), ("", "xterm-256color"), ("yes", "xterm")] {
            let p = detect(ct, term);
            assert!(p.coal.is_none() && p.bone.is_none(), "{ct:?} {term:?} must keep the terminal's own colours");
            assert!(matches!(p.ember, Color::LightRed));
        }
        // An alarm must never look like a selected line.
        assert!(detect("", "linux").console && !detect("", "xterm").console && !detect("truecolor", "foot").console);
        for p in [true_color(), ansi16(true)] {
            assert_ne!(p.alarm(), p.selected());
        }
    }

    #[test]
    fn ring_shape_and_growth() {
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
        assert_eq!(bar(0.5, 8).plain(), "████░░░░");
        assert_eq!(bar(2.0, 4).plain(), "████");
        assert_eq!(bar(0.0, 3).plain(), "░░░");
        let b = brand("server setup", "hello").plain();
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 5, "{b}");
        assert!(lines[1].ends_with("   dryserver") && lines[2].ends_with("   server setup") && lines[3].ends_with("   hello"), "{b}");
    }
}
