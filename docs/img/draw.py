"""Draws the README's ouroboros art as SVG pixel art: the banner and five
progress rings.

Run from the repository root: python3 docs/img/draw.py docs/img

The snake of src/tui/theme.rs as a sprite: the head at the top right, the
body growing clockwise through the eight colours the installer uses, from
ember through flame and gold to the violet tail, which ends in the snake's
own open jaws. Each pixel is one cell of a grid, all of one size; the body
is lit from the top left like a tube (plum in the shadows, warm in the
light), its colour bands meet in an ordered dither, and its shadow side
has a darker edge. The progress rings grow the way the installer's ring
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
WARM = "#FFE4AE"  # where light leans
MOUTH_IN = "#5A1622"
PUPIL = "#160A0C"

# Ordered dither, 4x4 Bayer.
BAYER = [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]]


def rgb(h):
    return [int(h[i:i + 2], 16) for i in (1, 3, 5)]


def mix(a, b, f):
    a, b = rgb(a), rgb(b)
    return "#%02X%02X%02X" % tuple(round(x + (y - x) * f) for x, y in zip(a, b))


def ramp(base):
    """Five tones of one colour: deep shadow, shadow, base, light, highlight."""
    return [mix(base, PLUM, 0.58), mix(base, PLUM, 0.3), base, mix(base, WARM, 0.3), mix(base, WARM, 0.62)]


RAMPS = [ramp(c) for c in BODY]
LIGHT = (lambda v: [x / math.sqrt(sum(y * y for y in v)) for x in v])([-0.55, -0.62, 0.56])


def tone(value):
    """Which of the five tones a lit value takes."""
    for i, edge in enumerate((0.08, 0.42, 0.8, 0.94)):
        if value < edge:
            return i
    return 4


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
        u = s / self.grown
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
                    f = u * (len(BODY) - 1) + (BAYER[py % 4][px % 4] / 16 - 0.47) * 0.55
                    band = max(0, min(len(BODY) - 1, round(f)))
                level = tone(self.lit(px, py, y, half))
                around = near(px, py)
                # The shadow side's edge is darker; the lit side keeps its light.
                if any(a is None for a in around) and level <= 2:
                    level = max(0, level - 1)
                # A lip where the head closes on the tail.
                if part == "head" and any(a and a[0] in ("body", "mouth") and (a[0] == "mouth" or a[1] > 0.5) for a in around):
                    level = 0
                grid[py][px] = RAMPS[band][level]
        self.face(grid, info)
        return grid

    def scales(self, grid, info):
        """A lattice of scale edges along the body's middle."""
        for py in range(self.n):
            for px in range(self.n):
                c = info[py][px]
                if not c or c[0] != "body" or c[1] > 0.9:
                    continue
                _, u, y, half = c
                if abs(y) > half * 0.62:
                    continue
                a = u * self.span() * self.r / 2.2
                b = (y + half) / 2.2
                if (math.floor(a + b) + math.floor(a - b)) % 2 == 0 and (a + b) % 1 < 0.42:
                    grid[py][px] = mix(grid[py][px], PLUM, 0.22)

    def face(self, grid, info):
        for py in range(self.n):
            for px in range(self.n):
                c = info[py][px]
                if not c or c[0] != "head":
                    continue
                x, y = self.head_local(px, py)
                if ((x - 11.6) / 1.7) ** 2 + ((y - 2.1) / 1.3) ** 2 <= 1:
                    grid[py][px] = PUPIL if abs(x - 11.9) < 0.55 else GOLD
                elif self.detail and math.hypot(x - 15.4, y - 1.6) <= 0.6:
                    grid[py][px] = mix(BODY[0], PLUM, 0.6)


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
    px = 3
    n = 72
    grid = Sprite(n, 24.5, 11.0).render()
    width, height = 800, 240
    sx, sy = 18, (height - n * px) // 2
    body = rects(grid, sx, sy, px)
    scale = 3
    cells, wcells = word_cells("dryserver", scale)
    left = sx + n * px + 30
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
    grid = Sprite(28, 9.6, 5.0, grown=k / 5, detail=False).render()
    done = "the snake bites its tail" if k == 5 else f"the snake {k} fifths of the way around"
    size = 28 * px
    body = rects(grid, 0, 0, px)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" shape-rendering="crispEdges">
  <title>Stage {k} of 5: {done}</title>
  {chr(10).join("  " + e for e in body).lstrip()}
</svg>
'''
    open(f"{OUT}/ring-{k}.svg", "w").write(svg)


write_banner()
for k in range(1, 6):
    write_ring(k)
