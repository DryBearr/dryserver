"""Draws the README's ouroboros art as SVG pixel art: the banner and five
progress rings.

Run from the repository root: python3 docs/img/draw.py docs/img
It also writes src/tui/sprite.rs, the same snake for the terminal screens.

The snake of src/tui/theme.rs as a sprite: the head at the top right, the
body growing clockwise through the eight colours the installer uses, from
ember through flame and gold to the violet tail, which ends in the snake's
own open jaws. Simple, dark pixel art: one pixel size throughout, three
tones per colour (a plum shadow, a deep base, a light edge where the light
from the top left falls), no dither, and an outline darker than the
background. The progress rings grow the way the installer's ring
does (theme::ring): the snake reaches further around an ash track, its
colours squeezed into the part that has grown.
"""
import math
import sys

OUT = sys.argv[1]

BODY = ["#F25C38", "#E0452A", "#EE8434", "#E29A36", "#D2A23A", "#B08A6E", "#8E77C9", "#6A58A6"]
COAL = "#140C0A"
BONE = "#E6DCCF"
GOLD = "#E8B341"
ASH = "#5E534F"
PLUM = "#2A0E24"  # where shadows lean
OUTLINE = "#070304"  # darker than the background
MOUTH_IN = "#5A1622"
PUPIL = "#160A0C"

def rgb(h):
    return [int(h[i:i + 2], 16) for i in (1, 3, 5)]


def mix(a, b, f):
    a, b = rgb(a), rgb(b)
    return "#%02X%02X%02X" % tuple(round(x + (y - x) * f) for x, y in zip(a, b))


def ramp(base):
    """Three tones of one colour, kept dark: shadow, base, light."""
    return [mix(base, PLUM, 0.55), mix(base, COAL, 0.2), base]


RAMPS = [ramp(c) for c in BODY]
LIGHT = (lambda v: [x / math.sqrt(sum(y * y for y in v)) for x in v])([-0.55, -0.62, 0.56])


def tone(value):
    """Which of the three tones a lit value takes."""
    for i, edge in enumerate((0.3, 0.93)):
        if value < edge:
            return i
    return 2


class Sprite:
    """The snake on a square grid of n cells. Angles run clockwise from the
    top; the head points counter-clockwise, at its own tail."""

    def __init__(self, n, r, width, grown=1.0, detail=True):
        self.n, self.c = n, n / 2
        self.r, self.w = r, width
        self.k = width / 10.0  # the head is drawn for a body 10 cells wide
        self.grown = grown
        self.detail = detail
        self.neck = 0.86
        self.head_len = 17.0 * self.k
        self.mouth = 10.0 * self.k  # mouth corner, from the neck

    def span(self):
        return 2 * math.pi - self.mouth / self.r

    def body_half(self, u):
        """Half width at u, 0 at the neck and 1 at the tail tip."""
        tip = 0.22
        return self.w / 2 * (tip + (1 - tip) * (1 - u ** 2.2))

    def head_half(self, x):
        k = self.k
        x = x / k
        if x <= 0:
            h = 5.0
        elif x <= 7:
            h = 5.0 + 0.9 * (1 - math.cos(math.pi * x / 7))
        else:
            u = min(1.0, (x - 7) / 10.2)
            h = 6.8 * math.sqrt(max(0.0, 1 - u * u))
        return h * k

    def polar(self, px, py):
        dx, dy = px + 0.5 - self.c, py + 0.5 - self.c
        return dx, dy, math.hypot(dx, dy), math.atan2(dx, -dy) % (2 * math.pi)

    def cell(self, px, py):
        """What is at the centre of cell (px, py): None, or (part, u, y, half)."""
        _, _, rad, theta = self.polar(px, py)
        y = rad - self.r
        # The head, on top of everything.
        x = ((self.neck - theta + math.pi) % (2 * math.pi) - math.pi) * self.r
        if -0.8 * self.k <= x <= self.head_len:
            half = self.head_half(x)
            if abs(y) <= half:
                # The open jaws: a wedge from the mouth corner to the snout.
                if x > self.mouth:
                    f = (x - self.mouth) / (self.head_len - self.mouth)
                    if -2.3 * self.k * f <= y <= 1.9 * self.k * f:
                        return self.body_at(theta, y) or ("mouth", 0.0, y, half)
                return ("head", 0.0, y, half)
        return self.body_at(theta, y)

    def body_at(self, theta, y):
        s = ((theta - self.neck) % (2 * math.pi)) / self.span()
        if s > self.grown:
            return None
        u = s / max(self.grown, 1e-9)
        half = self.body_half(u)
        if abs(y) <= half:
            return ("body", u, y, half)
        return None

    def track(self, px, py):
        """The ash ring the snake has not grown over yet."""
        if self.grown >= 1:
            return False
        return abs(self.polar(px, py)[2] - self.r) <= max(0.9, self.w * 0.16)

    def lit(self, px, py, y, half):
        """How brightly a tube's surface at y across it is lit, -1..1."""
        dx, dy, rad, _ = self.polar(px, py)
        rx, ry = dx / (rad or 1.0), dy / (rad or 1.0)
        u = max(-1.0, min(1.0, y / max(half, 0.01)))
        z = math.sqrt(max(0.0, 1 - u * u))
        return rx * u * LIGHT[0] + ry * u * LIGHT[1] + z * LIGHT[2]

    def head_local(self, px, py):
        _, _, rad, theta = self.polar(px, py)
        x = ((self.neck - theta + math.pi) % (2 * math.pi) - math.pi) * self.r
        return x / self.k, (rad - self.r) / self.k

    def render(self):
        """The grid: a colour, ("ash",) or None per cell."""
        n = self.n
        info = [[self.cell(x, y) for x in range(n)] for y in range(n)]
        # Clean the edge: a cell with fewer than two neighbours of the snake
        # is a stray step, not part of the shape.
        changed = True
        while changed:
            changed = False
            for py in range(n):
                for px in range(n):
                    if info[py][px] is None or info[py][px][0] == "head":
                        continue
                    count = sum(
                        1
                        for ax, ay in ((1, 0), (-1, 0), (0, 1), (0, -1))
                        if 0 <= px + ax < n and 0 <= py + ay < n and info[py + ay][px + ax] is not None
                    )
                    if count < 2:
                        info[py][px] = None
                        changed = True
        # And fill a one-cell dent: an empty cell with three neighbours of
        # the body takes the body's place.
        for py in range(n):
            for px in range(n):
                if info[py][px] is not None:
                    continue
                around = [
                    info[py + ay][px + ax]
                    for ax, ay in ((1, 0), (-1, 0), (0, 1), (0, -1))
                    if 0 <= px + ax < n and 0 <= py + ay < n and info[py + ay][px + ax] is not None
                ]
                if len(around) >= 3 and all(a[0] == "body" for a in around):
                    info[py][px] = around[0]
        near = lambda px, py: [
            info[py + ay][px + ax] if 0 <= px + ax < n and 0 <= py + ay < n else None
            for ax, ay in ((1, 0), (-1, 0), (0, 1), (0, -1))
        ]
        grid = [[None] * n for _ in range(n)]
        for py in range(n):
            for px in range(n):
                c = info[py][px]
                if c is None:
                    if self.track(px, py):
                        grid[py][px] = ("ash",)
                    continue
                part, u, y, half = c
                if part == "mouth":
                    grid[py][px] = MOUTH_IN
                    continue
                band = 0
                if part == "body":
                    band = max(0, min(len(BODY) - 1, round(u * (len(BODY) - 1))))
                level = tone(self.lit(px, py, y, half))
                around = near(px, py)
                # A lip where the head closes on the tail.
                if part == "head" and any(a and a[0] in ("body", "mouth") and (a[0] == "mouth" or a[1] > 0.5) for a in around):
                    level = 0
                grid[py][px] = RAMPS[band][level]
        self.face(grid, info)
        # The outline: every empty cell that touches the snake.
        for py in range(n):
            for px in range(n):
                if info[py][px] is None and any(a and a[0] != "mouth" for a in near(px, py)):
                    grid[py][px] = OUTLINE
        return grid

    def face(self, grid, info):
        """The eye: the one head cell nearest to where it sits, in gold."""
        best = None
        for py in range(self.n):
            for px in range(self.n):
                c = info[py][px]
                if c and c[0] == "head":
                    x, y = self.head_local(px, py)
                    d = math.hypot(x - 11.8, y - 2.4)
                    if best is None or d < best[0]:
                        best = (d, px, py)
        if best:
            grid[best[2]][best[1]] = GOLD


def rects(grid, x0, y0, px):
    out = []
    for gy, row in enumerate(grid):
        gx = 0
        while gx < len(row):
            c = row[gx]
            if c is None:
                gx += 1
                continue
            start = gx
            while gx < len(row) and row[gx] == c:
                gx += 1
            x, y, w = x0 + start * px, y0 + gy * px, (gx - start) * px
            if c == ("ash",):
                out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{px}" fill="{ASH}" fill-opacity=".6"/>')
            else:
                out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{px}" fill="{c}"/>')
    return out


# Lowercase pixel font, 5 cells wide; rows 0-6 sit on the baseline, 7-8
# descend. Each glyph pixel is a block of sprite cells, with a plum
# shadow one cell down.
FONT = {
    "d": ["....#", "....#", ".####", "#...#", "#...#", "#...#", ".####", ".....", "....."],
    "r": [".....", ".....", "#.##.", "##..#", "#....", "#....", "#....", ".....", "....."],
    "y": [".....", ".....", "#...#", "#...#", "#...#", "#...#", ".####", "....#", ".###."],
    "s": [".....", ".....", ".####", "#....", ".###.", "....#", "####.", ".....", "....."],
    "e": [".....", ".....", ".###.", "#...#", "#####", "#....", ".###.", ".....", "....."],
    "v": [".....", ".....", "#...#", "#...#", "#...#", ".#.#.", "..#..", ".....", "....."],
}


def word_cells(word, scale):
    """The word on a grid of sprite cells: each glyph pixel is scale x scale cells."""
    cells = set()
    x = 0
    for ch in word:
        g = FONT[ch]
        on = lambda r, c: 0 <= r < len(g) and 0 <= c < 5 and g[r][c] == "#"
        for r in range(len(g)):
            for c in range(5):
                if not on(r, c):
                    continue
                for sy in range(scale):
                    for sx in range(scale):
                        cells.add((x + c * scale + sx, r * scale + sy))
        x += 6 * scale
    return cells, x - scale


def write_banner():
    px = 5
    n = 40
    grid = Sprite(n, 13.4, 6.4).render()
    width, height = 860, 240
    sx, sy = 30, (height - n * px) // 2
    body = rects(grid, sx, sy, px)
    scale = 2
    cells, wcells = word_cells("dryserver", scale)
    left = sx + n * px + 40
    wx = left + ((width - 30 - left) - wcells * px) // 2
    wx -= wx % px
    wy = sy + (n * px) // 2 - 4 * scale * px
    wy -= wy % px
    rows = 9 * scale + 1
    shadow = [[None] * (wcells + 1) for _ in range(rows)]
    text = [[None] * (wcells + 1) for _ in range(rows)]
    for x, y in cells:
        shadow[y + 1][x] = PLUM
        text[y][x] = BONE
    body += rects(shadow, wx, wy, px) + rects(text, wx, wy, px)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" shape-rendering="crispEdges">
  <title>dryserver</title>
  <desc>An ouroboros in pixel art, a snake biting its own tail: ember red at the head, gold along the body, violet at the tail, beside the word dryserver.</desc>
  <rect width="{width}" height="{height}" rx="12" fill="{COAL}"/>
  {chr(10).join("  " + e for e in body).lstrip()}
</svg>
'''
    open(f"{OUT}/banner.svg", "w").write(svg)


def write_ring(k):
    px = 2
    grid = Sprite(20, 6.4, 3.4, grown=k / 5, detail=False).render()
    done = "the snake bites its tail" if k == 5 else f"the snake {k} fifths of the way around"
    size = 20 * px
    body = rects(grid, 0, 0, px)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" shape-rendering="crispEdges">
  <title>Stage {k} of 5: {done}</title>
  {chr(10).join("  " + e for e in body).lstrip()}
</svg>
'''
    open(f"{OUT}/ring-{k}.svg", "w").write(svg)


def write_rust(path, steps=20):
    """The 20-cell snake for the terminal: one frame per step of growth,
    each pixel a letter of the palette ('.' is empty)."""
    frames = [Sprite(20, 6.4, 3.4, grown=k / steps, detail=False).render() for k in range(steps + 1)]
    palette = []
    rows_out = []
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for grid in frames:
        rows = []
        for row in grid:
            line = ""
            for c in row:
                if c is None:
                    line += "."
                    continue
                # The ash track is drawn at 60% on coal.
                col = mix(ASH, COAL, 0.4) if c == ("ash",) else c
                if col not in palette:
                    palette.append(col)
                line += letters[palette.index(col)]
            rows.append(line)
        rows_out.append(rows)
    out = [
        "//! The ouroboros as pixels, for the screens. Generated by",
        "//! docs/img/draw.py from the same drawing as the README's art; do not",
        "//! edit by hand.",
        "",
        "/// Pixels per side.",
        f"pub const SIZE: usize = {len(frames[0])};",
        "",
        "/// The colours, as (r, g, b); a pixel's letter is its index here",
        "/// (A-Z, then a-z, then 0-9), and '.' is no pixel.",
        f"pub const PALETTE: [(u8, u8, u8); {len(palette)}] = [",
    ]
    for col in palette:
        r, g, b = rgb(col)
        out.append(f"    ({r}, {g}, {b}),")
    out += [
        "];",
        "",
        f"/// Frame k shows the snake grown k/{steps} of the way round; the last is",
        "/// the whole snake, biting its tail.",
        f"pub const FRAMES: [[&str; SIZE]; {steps + 1}] = [",
    ]
    for rows in rows_out:
        out.append("    [")
        for r in rows:
            out.append(f'        "{r}",')
        out.append("    ],")
    out.append("];")
    open(path, "w").write("\n".join(out) + "\n")


write_banner()
for k in range(1, 6):
    write_ring(k)
write_rust("src/tui/sprite.rs")
