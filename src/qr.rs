//! QR codes for the terminal: a device's VPN config, scanned by the
//! WireGuard app, so no file with its private key has to travel and no
//! key has to be typed. Byte mode, error correction level L, versions 1
//! to 20 (up to 858 bytes): what ISO/IEC 18004 says, nothing more.

/// The largest version made, and what it carries.
const MAX_VERSION: usize = 20;

/// Error correction codewords per block, then (blocks, data codewords per
/// block) of the two groups.
type Blocks = (usize, (usize, usize), (usize, usize));

/// Per version (1 to 20), level L.
const BLOCKS_L: [Blocks; MAX_VERSION] = [
    (7, (1, 19), (0, 0)),
    (10, (1, 34), (0, 0)),
    (15, (1, 55), (0, 0)),
    (20, (1, 80), (0, 0)),
    (26, (1, 108), (0, 0)),
    (18, (2, 68), (0, 0)),
    (20, (2, 78), (0, 0)),
    (24, (2, 97), (0, 0)),
    (30, (2, 116), (0, 0)),
    (18, (2, 68), (2, 69)),
    (20, (4, 81), (0, 0)),
    (24, (2, 92), (2, 93)),
    (26, (4, 107), (0, 0)),
    (30, (3, 115), (1, 116)),
    (22, (5, 87), (1, 88)),
    (24, (5, 98), (1, 99)),
    (28, (1, 107), (5, 108)),
    (30, (5, 120), (1, 121)),
    (28, (3, 113), (4, 114)),
    (28, (3, 107), (5, 108)),
];

/// Where the alignment patterns' centres are, per version.
const ALIGN: [&[usize]; MAX_VERSION] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
    &[6, 30, 54],
    &[6, 32, 58],
    &[6, 34, 62],
    &[6, 26, 46, 66],
    &[6, 26, 48, 70],
    &[6, 26, 50, 74],
    &[6, 30, 54, 78],
    &[6, 30, 56, 82],
    &[6, 30, 58, 86],
    &[6, 34, 62, 90],
];

/// A QR code: dark modules are true.
#[derive(Debug, Clone, PartialEq)]
pub struct Code {
    pub size: usize,
    dark: Vec<bool>,
    /// Modules that are not data (patterns, timing, format, version).
    fixed: Vec<bool>,
}

impl Code {
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.size + x]
    }

    fn set(&mut self, x: usize, y: usize, dark: bool) {
        self.dark[y * self.size + x] = dark;
        self.fixed[y * self.size + x] = true;
    }
}

fn data_capacity(v: usize) -> usize {
    let (_, (b1, d1), (b2, d2)) = BLOCKS_L[v - 1];
    b1 * d1 + b2 * d2
}

/// The smallest version that carries len bytes in byte mode.
fn version_for(len: usize) -> Option<usize> {
    (1..=MAX_VERSION).find(|&v| {
        let count_bits = if v <= 9 { 8 } else { 16 };
        4 + count_bits + 8 * len <= 8 * data_capacity(v)
    })
}

// ---- Reed-Solomon over GF(256), polynomial 0x11d ----

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    p
}

/// The generator polynomial of degree n, highest power first (leading 1
/// left out).
fn generator(n: usize) -> Vec<u8> {
    let mut g = vec![1u8];
    let mut root = 1u8;
    for _ in 0..n {
        // g *= (x - root)
        let mut next = vec![0u8; g.len() + 1];
        for (i, c) in g.iter().enumerate() {
            next[i] ^= *c;
            next[i + 1] ^= gf_mul(*c, root);
        }
        g = next;
        root = gf_mul(root, 2);
    }
    g[1..].to_vec()
}

/// The error correction codewords of data.
fn ec_codewords(data: &[u8], n: usize) -> Vec<u8> {
    let g = generator(n);
    let mut rem = vec![0u8; n];
    for d in data {
        let factor = d ^ rem[0];
        rem.remove(0);
        rem.push(0);
        for (r, c) in rem.iter_mut().zip(&g) {
            *r ^= gf_mul(*c, factor);
        }
    }
    rem
}

// ---- the code words ----

fn codewords(text: &[u8], v: usize) -> Vec<u8> {
    let cap = data_capacity(v);
    let mut bits: Vec<bool> = Vec::new();
    let push = |value: usize, n: usize, bits: &mut Vec<bool>| {
        for i in (0..n).rev() {
            bits.push((value >> i) & 1 == 1);
        }
    };
    push(0b0100, 4, &mut bits);
    push(text.len(), if v <= 9 { 8 } else { 16 }, &mut bits);
    for b in text {
        push(*b as usize, 8, &mut bits);
    }
    let room = 8 * cap - bits.len();
    push(0, room.min(4), &mut bits);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut data: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b))).collect();
    let mut pad = [0xEC, 0x11].into_iter().cycle();
    while data.len() < cap {
        data.push(pad.next().expect("cycles"));
    }
    // Split into blocks, add each one's error correction, interleave.
    let (ec, (b1, d1), (b2, d2)) = BLOCKS_L[v - 1];
    let mut blocks: Vec<&[u8]> = Vec::new();
    let mut at = 0;
    for (n, len) in [(b1, d1), (b2, d2)] {
        for _ in 0..n {
            blocks.push(&data[at..at + len]);
            at += len;
        }
    }
    let ecs: Vec<Vec<u8>> = blocks.iter().map(|b| ec_codewords(b, ec)).collect();
    let mut out = Vec::new();
    for i in 0..d1.max(d2) {
        for b in &blocks {
            if let Some(c) = b.get(i) {
                out.push(*c);
            }
        }
    }
    for i in 0..ec {
        for e in &ecs {
            out.push(e[i]);
        }
    }
    out
}

// ---- the matrix ----

fn finder(c: &mut Code, x0: isize, y0: isize) {
    for dy in -1..=7isize {
        for dx in -1..=7isize {
            let (x, y) = (x0 + dx, y0 + dy);
            if x < 0 || y < 0 || x >= c.size as isize || y >= c.size as isize {
                continue;
            }
            let ring = dx.max(dy).max(6 - dx).max(6 - dy);
            let inside = (0..=6).contains(&dx) && (0..=6).contains(&dy);
            let dark = inside && (ring == 6 || (2..=4).contains(&dx) && (2..=4).contains(&dy));
            c.set(x as usize, y as usize, dark);
        }
    }
}

fn function_patterns(v: usize) -> Code {
    let size = 17 + 4 * v;
    let mut c = Code { size, dark: vec![false; size * size], fixed: vec![false; size * size] };
    finder(&mut c, 0, 0);
    finder(&mut c, size as isize - 7, 0);
    finder(&mut c, 0, size as isize - 7);
    for i in 8..size - 8 {
        c.set(i, 6, i % 2 == 0);
        c.set(6, i, i % 2 == 0);
    }
    let al = ALIGN[v - 1];
    for &ay in al {
        for &ax in al {
            // Not over the finders.
            let near_finder = (ax < 9 && ay < 9) || (ax > size - 10 && ay < 9) || (ax < 9 && ay > size - 10);
            if near_finder {
                continue;
            }
            for dy in -2..=2isize {
                for dx in -2..=2isize {
                    let ring = dx.abs().max(dy.abs());
                    c.set((ax as isize + dx) as usize, (ay as isize + dy) as usize, ring != 1);
                }
            }
        }
    }
    // Room for the format (written with the mask) and the dark module.
    for i in 0..9 {
        if !c.fixed[8 * size + i] {
            c.set(i, 8, false);
        }
        if !c.fixed[i * size + 8] {
            c.set(8, i, false);
        }
    }
    for i in 0..8 {
        c.set(size - 1 - i, 8, false);
        c.set(8, size - 1 - i, false);
    }
    c.set(8, size - 8, true);
    if v >= 7 {
        let bits = version_bits(v);
        for i in 0..18 {
            let dark = (bits >> i) & 1 == 1;
            let (a, b) = (i / 3, size - 11 + i % 3);
            c.set(a, b, dark);
            c.set(b, a, dark);
        }
    }
    c
}

/// BCH(18,6) of the version number.
fn version_bits(v: usize) -> u32 {
    let mut rem = v as u32;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    ((v as u32) << 12) | rem
}

/// BCH(15,5) of level L (01) and the mask, masked with 0x5412.
fn format_bits(mask: u8) -> u32 {
    let data = (0b01u32 << 3) | mask as u32;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

fn draw_format(c: &mut Code, mask: u8) {
    let bits = format_bits(mask);
    let size = c.size;
    let bit = |i: u32| (bits >> i) & 1 == 1;
    for i in 0..6 {
        c.set(8, i, bit(i as u32));
    }
    c.set(8, 7, bit(6));
    c.set(8, 8, bit(7));
    c.set(7, 8, bit(8));
    for i in 9..15 {
        c.set(14 - i, 8, bit(i as u32));
    }
    for i in 0..8 {
        c.set(size - 1 - i, 8, bit(i as u32));
    }
    for i in 8..15 {
        c.set(8, size - 15 + i, bit(i as u32));
    }
    c.set(8, size - 8, true);
}

fn masked(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y).is_multiple_of(2),
        1 => y.is_multiple_of(2),
        2 => x.is_multiple_of(3),
        3 => (x + y).is_multiple_of(3),
        4 => (y / 2 + x / 3).is_multiple_of(2),
        5 => (x * y) % 2 + (x * y) % 3 == 0,
        6 => ((x * y) % 2 + (x * y) % 3).is_multiple_of(2),
        _ => ((x + y) % 2 + (x * y) % 3).is_multiple_of(2),
    }
}

/// The data bits in their zigzag, two columns at a time from the right.
fn place(c: &mut Code, words: &[u8]) {
    let size = c.size;
    let mut bits = words.iter().flat_map(|w| (0..8).rev().map(move |i| (w >> i) & 1 == 1));
    let mut right = size as isize - 1;
    let mut upward = true;
    while right > 0 {
        if right == 6 {
            right -= 1;
        }
        for step in 0..size {
            let y = if upward { size - 1 - step } else { step };
            for dx in 0..2 {
                let x = (right - dx) as usize;
                if !c.fixed[y * size + x] {
                    c.dark[y * size + x] = bits.next().unwrap_or(false);
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

/// How hard the code is to read (ISO 18004's four penalty rules).
fn penalty(c: &Code) -> usize {
    let n = c.size;
    let mut p = 0;
    for line in 0..n {
        for horizontal in [true, false] {
            let at = |i: usize| if horizontal { c.get(i, line) } else { c.get(line, i) };
            let mut run = 1;
            for i in 1..n {
                if at(i) == at(i - 1) {
                    run += 1;
                } else {
                    if run >= 5 {
                        p += run - 2;
                    }
                    run = 1;
                }
            }
            if run >= 5 {
                p += run - 2;
            }
            for i in 0..n.saturating_sub(10) {
                let w: Vec<bool> = (i..i + 11).map(at).collect();
                let a = [true, false, true, true, true, false, true, false, false, false, false];
                let b = [false, false, false, false, true, false, true, true, true, false, true];
                if w == a || w == b {
                    p += 40;
                }
            }
        }
    }
    for y in 0..n - 1 {
        for x in 0..n - 1 {
            let d = c.get(x, y);
            if c.get(x + 1, y) == d && c.get(x, y + 1) == d && c.get(x + 1, y + 1) == d {
                p += 3;
            }
        }
    }
    let dark = c.dark.iter().filter(|d| **d).count();
    let pct = dark * 100 / (n * n);
    p + (pct.abs_diff(50) / 5) * 10
}

/// The QR code of text, or None when it is too long for version 20.
pub fn encode(text: &[u8]) -> Option<Code> {
    encode_with(text, 0..8u8)
}

fn encode_with(text: &[u8], masks: std::ops::Range<u8>) -> Option<Code> {
    let v = version_for(text.len())?;
    let words = codewords(text, v);
    let base = function_patterns(v);
    let mut best: Option<(usize, Code)> = None;
    for mask in masks {
        let mut c = base.clone();
        place(&mut c, &words);
        for y in 0..c.size {
            for x in 0..c.size {
                if !c.fixed[y * c.size + x] && masked(mask, x, y) {
                    c.dark[y * c.size + x] ^= true;
                }
            }
        }
        draw_format(&mut c, mask);
        let p = penalty(&c);
        if best.as_ref().is_none_or(|(bp, _)| p < *bp) {
            best = Some((p, c));
        }
    }
    best.map(|(_, c)| c)
}

/// The code for a terminal: two rows per line with half blocks, dark on
/// light, with the quiet zone a scanner needs around it.
pub fn terminal(c: &Code) -> String {
    let quiet = 2;
    let n = c.size as isize;
    let dark = |x: isize, y: isize| x >= 0 && y >= 0 && x < n && y < n && c.get(x as usize, y as usize);
    let mut s = String::new();
    let mut y = -quiet;
    while y < n + quiet {
        for x in -quiet..n + quiet {
            // Light modules are printed bright: most terminals are dark.
            s.push(match (dark(x, y), dark(x, y + 1)) {
                (false, false) => '█',
                (true, false) => '▄',
                (false, true) => '▀',
                (true, true) => ' ',
            });
        }
        s.push('\n');
        y += 2;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reed_solomon_and_bch_as_the_standard_has_them() {
        // ISO 18004 Annex I: "01234567" at 1-M gives these codewords; here
        // the field and generator are checked with a known 1-L remainder.
        assert_eq!(generator(7), vec![127, 122, 154, 164, 11, 68, 117]);
        // Format of level L, mask 4 (a value from the standard's table).
        assert_eq!(format_bits(4), 0b110011000101111);
        assert_eq!(format_bits(0), 0b111011111000100);
        // Version 7's information.
        assert_eq!(version_bits(7), 0b000111110010010100);
    }

    #[test]
    fn sizes_and_capacity() {
        assert_eq!(version_for(17), Some(1));
        assert_eq!(version_for(18), Some(2));
        assert_eq!(version_for(858), Some(20));
        assert_eq!(version_for(859), None);
        let c = encode(b"hello").unwrap();
        assert_eq!(c.size, 21);
        let c = encode(&[b'x'; 300]).unwrap();
        assert_eq!(c.size, 17 + 4 * 11);
        assert!(encode(&[b'x'; 900]).is_none());
        let t = terminal(&encode(b"hello").unwrap());
        assert_eq!(t.lines().count(), 13);
        assert!(t.lines().all(|l| l.chars().count() == 25));
    }
}

#[cfg(test)]
mod dump {
    /// Writes codes as PGM files to $QR_DUMP, for checking with a real
    /// decoder (zbarimg): cargo test qr::dump -- --ignored.
    #[test]
    #[ignore]
    fn write_codes() {
        let dir = std::env::var("QR_DUMP").expect("QR_DUMP");
        let texts: Vec<Vec<u8>> = vec![
            b"hello".to_vec(),
            b"https://example.com/".to_vec(),
            (0..60).map(|i| b'a' + (i % 26) as u8).collect(),
            (0..150).map(|i| b'A' + (i % 26) as u8).collect(),
            (0..300).map(|i| b'0' + (i % 10) as u8).collect(),
            (0..500).map(|i| b' ' + (i * 7 % 90) as u8).collect(),
            (0..850).map(|i| b'z' - (i % 26) as u8).collect(),
        ];
        // And each version at its fullest.
        let mut texts = texts;
        for v in 1..=super::MAX_VERSION {
            let cap = super::data_capacity(v);
            let len = (8 * cap - if v <= 9 { 12 } else { 20 }) / 8;
            texts.push((0..len).map(|i| b'a' + ((i * 5 + v) % 26) as u8).collect());
        }
        let mut codes: Vec<(Vec<u8>, super::Code)> = texts.iter().map(|t| (t.clone(), super::encode(t).unwrap())).collect();
        // One version-15 text with each mask.
        let v15: Vec<u8> = (0..520).map(|i| b'a' + ((i * 5 + 15) % 26) as u8).collect();
        for m in 0..8u8 {
            codes.push((v15.clone(), super::encode_with(&v15, m..m + 1).unwrap()));
        }
        // Every version and mask as rows of 0 and 1, for comparing with
        // another encoder.
        for v in 1..=super::MAX_VERSION {
            let cap = super::data_capacity(v);
            let len = (8 * cap - if v <= 9 { 12 } else { 20 }) / 8;
            let t: Vec<u8> = (0..len).map(|i| b'a' + ((i * 3 + v) % 26) as u8).collect();
            std::fs::write(format!("{dir}/m{v}.txt"), &t).unwrap();
            for m in 0..8u8 {
                let c = super::encode_with(&t, m..m + 1).unwrap();
                let rows: Vec<String> = (0..c.size).map(|y| (0..c.size).map(|x| if c.get(x, y) { '1' } else { '0' }).collect()).collect();
                std::fs::write(format!("{dir}/m{v}_{m}.mat"), rows.join("\n")).unwrap();
            }
        }
        for (n, (t, c)) in codes.iter().enumerate() {
            let scale = 6;
            let q = 4;
            let w = (c.size + 2 * q) * scale;
            let mut px = Vec::with_capacity(w * w);
            for y in 0..w {
                for x in 0..w {
                    let (mx, my) = ((x / scale) as isize - q as isize, (y / scale) as isize - q as isize);
                    let dark = mx >= 0 && my >= 0 && (mx as usize) < c.size && (my as usize) < c.size && c.get(mx as usize, my as usize);
                    px.push(if dark { 0u8 } else { 255u8 });
                }
            }
            let mut f = format!("P5\n{w} {w}\n255\n").into_bytes();
            f.extend(px);
            std::fs::write(format!("{dir}/qr{n}.pgm"), f).unwrap();
            std::fs::write(format!("{dir}/qr{n}.txt"), t).unwrap();
        }
    }
}
