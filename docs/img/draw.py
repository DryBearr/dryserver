"""Draws the README's ouroboros art as SVG: the banner and five progress rings.

Run from the repository root: python3 docs/img/draw.py docs/img

The snake of src/tui/theme.rs, drawn smooth: the head at the top right,
the body growing clockwise from ember through flame and gold to the violet
tail, which ends in the snake's own mouth. The progress rings grow the way
the installer's ring does (theme::ring): the snake reaches further around
an ash track, its colours squeezed into the part that has grown.
"""
import math
import sys

OUT = sys.argv[1]

BODY = ["#F25C38", "#E0452A", "#EE8434", "#E29A36", "#D2A23A", "#B08A6E", "#8E77C9", "#6A58A6"]
COAL = "#140C0A"
BONE = "#E6DCCF"
GOLD = "#D2A23A"
ASH = "#5E534F"


def colour(t):
    """The snake's colour at t, 0 the head and 1 the tail, blended smoothly."""
    t = max(0.0, min(1.0, t)) * (len(BODY) - 1)
    i = min(int(t), len(BODY) - 2)
    f = t - i
    a = [int(BODY[i][k:k + 2], 16) for k in (1, 3, 5)]
    b = [int(BODY[i + 1][k:k + 2], 16) for k in (1, 3, 5)]
    return "#%02X%02X%02X" % tuple(round(x + (y - x) * f) for x, y in zip(a, b))


def f(v):
    return f"{v:.2f}".rstrip("0").rstrip(".")


def poly(points):
    return "M" + " L".join(f"{f(x)} {f(y)}" for x, y in points) + " Z"


class Snake:
    """A snake around a circle. Angles run clockwise from the top; the head
    points counter-clockwise, towards its own tail.

    Local head coordinates: x forward from the neck along the ring, y
    outward from the centre line. They are bent along the circle, so the
    head follows the ring and the tail meets the mouth.
    """

    HEAD = 45.0  # head length, in body widths of 24
    MOUTH = 26.0  # mouth corner, from the neck

    def __init__(self, cx, cy, r, width, neck=0.78):
        self.cx, self.cy, self.r, self.w = cx, cy, r, width
        self.k = width / 24.0  # head drawn at width 24, scaled
        self.neck = neck

    def at(self, theta, rad):
        return (self.cx + rad * math.sin(theta), self.cy - rad * math.cos(theta))

    def local(self, x, y):
        x, y = x * self.k, y * self.k
        return self.at(self.neck - x / self.r, self.r + y)

    # The body: s from 0 at the neck to 1 at the tail tip.
    def theta(self, s):
        return self.neck + s * (2 * math.pi - self.MOUTH * self.k / self.r)

    def width(self, s, tip=0.19):
        return self.w * (tip + (1 - tip) * (1 - s ** 2.2))

    def body_slices(self, grown=1.0, n=260):
        """Quads along the grown part, each its own colour."""
        out = []
        steps = max(2, int(n * grown))
        for i in range(steps):
            s0, s1 = grown * i / steps, grown * (i + 1) / steps
            u0, u1 = s0 / grown, s1 / grown  # where along this snake
            w0, w1 = self.width(u0) / 2, self.width(u1) / 2
            a0, a1 = self.theta(s0), self.theta(s1)
            pts = [self.at(a0, self.r + w0), self.at(a1, self.r + w1), self.at(a1, self.r - w1), self.at(a0, self.r - w0)]
            c = colour((u0 + u1) / 2)
            out.append(f'<path d="{poly(pts)}" fill="{c}" stroke="{c}" stroke-width="0.6"/>')
        return out

    def body_outline(self, grown=1.0, n=200):
        outer, inner = [], []
        for i in range(n + 1):
            s = grown * i / n
            w = self.width(s / grown) / 2
            outer.append(self.at(self.theta(s), self.r + w))
            inner.append(self.at(self.theta(s), self.r - w))
        return poly(outer + inner[::-1])

    @staticmethod
    def half(x):
        """Half width of the head at x (width 24): a neck that swells into
        the jaws and rounds off into the snout."""
        if x <= 0:
            return 12.0
        if x <= 20:
            return 12 + 2 * (1 - math.cos(math.pi * x / 20))
        u = min(1.0, (x - 20) / 25)
        return 16 * math.sqrt(max(0.0, 1 - u * u))

    def head_outline(self, n=60):
        """The head, with its jaws open around the tail."""
        tip_up, tip_down, end = 4.6, -5.4, 43.6
        # From a little behind the neck, a hair wider than the body there,
        # so no seam shows where the two meet.
        xs = [-2 + (end + 2) * i / n for i in range(n + 1)]
        upper = [(x, self.half(x) + 0.35) for x in xs]
        lower = [(x, -self.half(x) - 0.35) for x in xs]
        upper[-1] = (end + 0.6, tip_up)
        lower[-1] = (end, tip_down)
        pts = upper + [(self.MOUTH, 0.0)] + lower[::-1]
        return poly([self.local(x, y) for x, y in pts])

    def scales(self, grown=1.0, every=10.0):
        """Chevrons pointing at the head, like overlapping scales."""
        out = []
        length = self.r * (self.theta(grown) - self.theta(0))
        count = int(length / every)
        for i in range(1, count):
            s = grown * i / count
            u = s / grown
            if u > 0.93:
                break
            w = self.width(u) / 2
            a = self.theta(s)
            back = a + 4.2 * self.k / self.r
            p0 = self.at(back, self.r + 0.42 * w)
            p1 = self.at(a, self.r)
            p2 = self.at(back, self.r - 0.42 * w)
            out.append(f"M{f(p0[0])} {f(p0[1])} L{f(p1[0])} {f(p1[1])} L{f(p2[0])} {f(p2[1])}")
        return out

    def eye(self):
        cx, cy = self.local(29.5, 6.2)
        tangent = math.degrees(-(self.neck - 29.5 * self.k / self.r))
        k = self.k
        return [
            f'<ellipse cx="{f(cx)}" cy="{f(cy)}" rx="{f(4.1 * k)}" ry="{f(3.3 * k)}" fill="{GOLD}" transform="rotate({f(-tangent)} {f(cx)} {f(cy)})"/>',
            f'<ellipse cx="{f(cx)}" cy="{f(cy)}" rx="{f(1.0 * k)}" ry="{f(3.0 * k)}" fill="{COAL}" transform="rotate({f(-tangent)} {f(cx)} {f(cy)})"/>',
        ]

    def nostril(self):
        x, y = self.local(39.0, 5.4)
        return f'<circle cx="{f(x)}" cy="{f(y)}" r="{f(1.05 * self.k)}" fill="{COAL}" fill-opacity=".7"/>'


def shading(snake, gid):
    """Round the body: lit along its outer side, shadowed on the inner."""
    r, w = snake.r, snake.w
    rad = r + w
    stops = [
        (r - w * 0.55, COAL, 0.42),
        (r - w * 0.15, COAL, 0.0),
        (r + w * 0.12, "#FFFFFF", 0.0),
        (r + w * 0.26, "#FFFFFF", 0.20),
        (r + w * 0.42, "#FFFFFF", 0.0),
        (r + w * 0.75, COAL, 0.25),
    ]
    s = "".join(f'<stop offset="{f(max(0.0, d / rad))}" stop-color="{c}" stop-opacity="{o}"/>' for d, c, o in stops)
    return f'<radialGradient id="{gid}" gradientUnits="userSpaceOnUse" cx="{f(snake.cx)}" cy="{f(snake.cy)}" r="{f(rad)}">{s}</radialGradient>'


def draw_snake(snake, grown, detail, gid):
    """The snake as SVG: the grown body, the head on top, then shading."""
    out = []
    defs = []
    out += snake.body_slices(grown)
    if detail:
        out.append(f'<path d="{" ".join(snake.scales(grown))}" fill="none" stroke="{COAL}" stroke-opacity=".14" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/>')
    out.append(f'<path d="{snake.head_outline()}" fill="{BODY[0]}"/>')
    # One silhouette, so the light lies on the head and body alike. A mask,
    # not a clip path: where head and body overlap, a mask stays whole.
    defs.append(f'<mask id="{gid}-mask" maskUnits="userSpaceOnUse"><path d="{snake.body_outline(grown)}" fill="#fff"/><path d="{snake.head_outline()}" fill="#fff"/></mask>')
    defs.append(shading(snake, f"{gid}-shade"))
    out.append(f'<circle cx="{f(snake.cx)}" cy="{f(snake.cy)}" r="{f(snake.r + snake.w)}" fill="url(#{gid}-shade)" mask="url(#{gid}-mask)"/>')
    # The jaw line, and the eye above the light.
    out += snake.eye()
    if detail:
        out.append(snake.nostril())
    return defs, out


# A monoline wordmark: x-height 46, stroke 7.5, round ends. Each glyph is
# its centre line from the baseline (y up is negative) and its width.
S = 7.0
TOP, MID, BOT = -46 + S / 2, -23.0, -S / 2
R = (BOT - TOP) / 2
GLYPHS = {
    "d": (46, f"M{23 + R} -70 V{BOT} M{23 + R} {MID} A{R} {R} 0 1 0 {23 + R} {MID + 0.01}"),
    "r": (30, f"M{S / 2} {TOP} V{BOT} M{S / 2} {MID + 3} C{S / 2} -36 14 {TOP} 27 {TOP}"),
    "y": (44, f"M{S / 2} {TOP} L24.9 {BOT} M40.25 {TOP} L13 24"),
    "s": (38, f"M33.5 -36.5 C30.5 -41 24.5 {TOP} 18.5 {TOP} C10 {TOP} 4.5 -38 4.5 -32.5 "
              f"C4.5 -26 11 -24.6 18.5 -23 C27 -21.4 33.8 -19.5 33.8 -13 C33.8 -7 27 {BOT} 18.5 {BOT} "
              f"C12 {BOT} 6.5 -5.6 3.9 -9.2"),
    "e": (46, f"M{S / 2} {MID} H{23 + R} A{R} {R} 0 1 0 {23 + R * math.cos(math.radians(40)):.2f} {MID + R * math.sin(math.radians(40)):.2f}"),
    "v": (44, f"M{S / 2} {TOP} L22 {BOT} L40.25 {TOP}"),
}


def wordmark(word, x, baseline, tracking=9.0):
    paths = []
    for ch in word:
        w, d = GLYPHS[ch]
        paths.append(f'<path transform="translate({f(x)} {f(baseline)})" d="{d}"/>')
        x += w + tracking
    return (f'<g fill="none" stroke="{BONE}" stroke-width="{S}" stroke-linecap="round" stroke-linejoin="round">'
            + "".join(paths) + "</g>"), x - tracking


def write_banner():
    width, height = 736, 240
    snake = Snake(126, 120, 76, 24)
    defs, body = draw_snake(snake, 1.0, True, "s")
    word, end = wordmark("dryserver", 0, 0)
    x0 = 252 + (width - 252 - 40 - end) / 2
    word, _ = wordmark("dryserver", x0, 143)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img">
  <title>dryserver</title>
  <desc>An ouroboros, a snake biting its own tail: ember red at the head, gold along the body, violet at the tail, beside the word dryserver.</desc>
  <defs>{"".join(defs)}</defs>
  <rect width="{width}" height="{height}" rx="14" fill="{COAL}"/>
  {chr(10).join("  " + e for e in body).lstrip()}
  {word}
</svg>
'''
    open(f"{OUT}/banner.svg", "w").write(svg)


def write_ring(k):
    grown = k / 5
    snake = Snake(32, 32, 22.5, 9.2)
    defs, body = draw_snake(snake, grown, False, f"r{k}")
    track = ""
    if grown < 1:
        track = f'<circle cx="32" cy="32" r="22.5" fill="none" stroke="{ASH}" stroke-opacity=".55" stroke-width="3"/>'
    done = "the snake bites its tail" if k == 5 else f"the snake {k} fifths of the way around"
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img">
  <title>Stage {k} of 5: {done}</title>
  <defs>{"".join(defs)}</defs>
  {track}
  {chr(10).join("  " + e for e in body).lstrip()}
</svg>
'''
    open(f"{OUT}/ring-{k}.svg", "w").write(svg)


write_banner()
for k in range(1, 6):
    write_ring(k)
