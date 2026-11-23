"""Draws the README's ouroboros art as SVG: the banner and five progress rings.

Run from the repository root: python3 docs/img/draw.py docs/img

Same snake as src/tui/theme.rs: head ember at the top right, growing
clockwise through flame and gold to the violet tail, built from console
blocks (square pixels, two per character cell).
"""
import math
import sys

OUT = sys.argv[1]

BODY = ["#F25C38", "#E0452A", "#EE8434", "#E29A36", "#D2A23A", "#B08A6E", "#8E77C9", "#6A58A6"]
COAL = "#140C0A"
BONE = "#E6DCCF"
ASH = "#5E534F"  # drawn at 60% so it reads as empty on light and dark pages


def hexrgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


def along_discrete(t):
    i = round(max(0.0, min(1.0, t)) * (len(BODY) - 1))
    return BODY[i]


def along_smooth(t):
    t = max(0.0, min(1.0, t)) * (len(BODY) - 1)
    i = min(int(t), len(BODY) - 2)
    f = t - i
    a, b = hexrgb(BODY[i]), hexrgb(BODY[i + 1])
    return "#%02X%02X%02X" % tuple(round(x + (y - x) * f) for x, y in zip(a, b))


def around(dx, dy):
    """0 at the head, a little right of the top, growing clockwise (dy down)."""
    angle = math.atan2(dx, -dy) - 0.5
    return (angle / math.tau) % 1.0


def rects(cells, px):
    """cells: list of (x, y, colour) in pixel units; merges runs per row."""
    out = []
    rows = {}
    for x, y, c in cells:
        rows.setdefault(y, []).append((x, c))
    for y in sorted(rows):
        run = sorted(rows[y])
        start, prev, col = run[0][0], run[0][0], run[0][1]
        for x, c in run[1:] + [(None, None)]:
            if x is not None and x == prev + 1 and c == col:
                prev = x
                continue
            dim = ' fill-opacity=".6"' if col == ASH else ""
            out.append(f'<rect x="{start * px}" y="{y * px}" width="{(prev - start + 1) * px}" height="{px}" fill="{col}"{dim}/>')
            if x is not None:
                start, prev, col = x, x, c
    return out


# The TUI ring: 5 lines of 11 cells, full and half blocks only.
RING = ["  ▄▄███▄▄  ", " ██▀   ▀██ ", " ██     ██ ", " ██▄   ▄██ ", "  ▀▀███▀▀  "]


def small_ring(progress):
    """The TUI's ring at 11x10 square pixels, coloured as theme::ring does."""
    grown = progress
    cells = []
    for row, line in enumerate(RING):
        for col, ch in enumerate(line):
            if ch == " ":
                continue
            dy, dx = (row - 2.0) * 2.0, col - 5.0
            t = around(dx, dy)
            if grown > 0 and t <= grown:
                colour = along_discrete(t if grown >= 1 else t / max(grown, 0.2))
            else:
                colour = ASH
            top = ch in "█▀"
            bottom = ch in "█▄"
            if top:
                cells.append((col, row * 2, colour))
            if bottom:
                cells.append((col, row * 2 + 1, colour))
    return cells


def write_small(k):
    px = 4
    cells = small_ring(k / 5)
    done = "the snake bites its tail" if k == 5 else f"the snake {k} fifths of the way around"
    body = "\n  ".join(rects(cells, px))
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {11 * px} {10 * px}" width="{11 * px}" height="{10 * px}" role="img" shape-rendering="crispEdges">
  <title>Stage {k} of 5: {done}</title>
  {body}
</svg>
'''
    open(f"{OUT}/ring-{k}.svg", "w").write(svg)


# Lowercase pixel font, 5 wide; rows 0-6 sit on the baseline, 7-8 descend.
FONT = {
    "d": ["....#", "....#", ".####", "#...#", "#...#", "#...#", ".####", ".....", "....."],
    "r": [".....", ".....", "#.##.", "##..#", "#....", "#....", "#....", ".....", "....."],
    "y": [".....", ".....", "#...#", "#...#", "#...#", "#...#", ".####", "....#", ".###."],
    "s": [".....", ".....", ".####", "#....", ".###.", "....#", "####.", ".....", "....."],
    "e": [".....", ".....", ".###.", "#...#", "#####", "#....", ".###.", ".....", "....."],
    "v": [".....", ".....", "#...#", "#...#", "#...#", ".#.#.", "..#..", ".....", "....."],
}


def big_ring(cx, cy, outer, inner):
    cells = []
    n = int(outer) + 1
    for y in range(-n, n):
        for x in range(-n, n):
            # Pixel centres.
            dx, dy = x + 0.5, y + 0.5
            r = math.hypot(dx, dy)
            if inner <= r <= outer:
                t = around(dx, dy)
                cells.append((cx + x, cy + y, along_smooth(t)))
    # The eye: one coal pixel just behind the head, in the middle of the band.
    mid = (outer + inner) / 2
    a = 0.5 + 0.07 * math.tau
    ex, ey = mid * math.sin(a), -mid * math.cos(a)
    eye = (cx + math.floor(ex), cy + math.floor(ey))
    cells = [c for c in cells if (c[0], c[1]) != eye]
    cells.append((eye[0], eye[1], COAL))
    return cells


def write_banner():
    px = 8
    outer, inner = 12.0, 7.4
    width, height = 92, 30
    ring_cx, ring_cy = 5 + 12, 15
    cells = big_ring(ring_cx, ring_cy, outer, inner)
    word = "dryserver"
    x0 = ring_cx + 12 + 7
    y0 = 15 - 4  # x-height (rows 2-6) centred on the ring
    y0 -= 2
    for i, ch in enumerate(word):
        g = FONT[ch]
        for row, line in enumerate(g):
            for col, bit in enumerate(line):
                if bit == "#":
                    cells.append((x0 + i * 6 + col, y0 + row, BONE))
    body = "\n  ".join(rects(cells, px))
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width * px} {height * px}" width="{width * px}" height="{height * px}" role="img" shape-rendering="crispEdges">
  <title>dryserver</title>
  <desc>A snake made of console blocks biting its own tail: ember red at the head, gold along the body, violet at the tail, beside the word dryserver.</desc>
  <rect width="{width * px}" height="{height * px}" rx="12" fill="{COAL}"/>
  {body}
</svg>
'''
    open(f"{OUT}/banner.svg", "w").write(svg)


write_banner()
for k in range(1, 6):
    write_small(k)
