#!/usr/bin/env python3
"""Generate the BlastRadius marks.

Four files from one geometry, so the light and dark variants cannot drift.
Run after changing anything here:  python3 assets/generate.py

The mark is the mechanism: a filled centre (the artifact), concentric rings
(distance), consumer nodes sitting on those rings, faint spokes tying them back
to the centre, and one node in amber — the consumer that is exposed. Rings alone
would read as a target; spokes alone as a generic network diagram.
"""
from __future__ import annotations

import math
from pathlib import Path

HERE = Path(__file__).parent

# Palette taken from the project's own artifact-type colours.
INK_LIGHT, INK_DARK = "#0f2830", "#e8f2f5"
MUTED_LIGHT, MUTED_DARK = "#5c7885", "#8fadb9"
ACCENT_LIGHT, ACCENT_DARK = "#0e7490", "#3bb3cc"
FLAG = "#e08c1a"          # the exposed consumer — attention, not failure

SIZE = 256
CX = CY = SIZE / 2
RINGS = (38, 72, 106)
CENTER_R = 17

# Heavier than felt necessary at full size, because the mark has to survive a
# 16px favicon. Thin rings and small nodes dissolve completely at that scale.
RING_WIDTH = 4.5
NODE_R = 10
FLAG_R = 12.5

# (ring index, degrees, is_flagged). Spread so nothing sits dead-bottom, and the
# flagged node sits lower-right where the eye lands last — a consequence, not a
# headline.
NODES = (
    (2,  25, False),
    (1,  95, False),
    (2, 150, False),
    (1, 215, False),
    (2, 320, True),
)

# A second geometry for small renders: fewer elements, proportionally heavier.
SMALL_RINGS = (46, 92)
SMALL_NODES = ((1, 35, False), (0, 145, False), (1, 290, True))


def at(ring: int, degrees: float, rings: tuple[float, ...] = RINGS) -> tuple[float, float]:
    radius = rings[ring]
    theta = math.radians(degrees)
    return CX + radius * math.cos(theta), CY - radius * math.sin(theta)


def mark(accent: str, muted: str, background: str, small: bool = False) -> str:
    """The symbol alone. `small` uses the reduced geometry for favicon sizes."""
    rings = SMALL_RINGS if small else RINGS
    nodes = SMALL_NODES if small else NODES
    ring_width = 7 if small else RING_WIDTH
    node_r = 15 if small else NODE_R
    flag_r = 17 if small else FLAG_R
    center_r = 22 if small else CENTER_R
    parts: list[str] = []

    # Spokes first, so nodes sit on top of them.
    if not small:      # at favicon scale a spoke is one grey pixel of mud
        for ring, degrees, _ in nodes:
            x, y = at(ring, degrees, rings)
            parts.append(
                f'<line x1="{CX:.1f}" y1="{CY:.1f}" x2="{x:.1f}" y2="{y:.1f}" '
                f'stroke="{muted}" stroke-width="2.5" opacity="0.5"/>'
            )

    for index, radius in enumerate(rings):
        opacity = (0.9, 0.62, 0.36)[index] if not small else (0.95, 0.6)[index]
        parts.append(
            f'<circle cx="{CX}" cy="{CY}" r="{radius}" fill="none" '
            f'stroke="{accent}" stroke-width="{ring_width}" opacity="{opacity}"/>'
        )

    for ring, degrees, flagged in nodes:
        x, y = at(ring, degrees, rings)
        colour = FLAG if flagged else accent
        r = flag_r if flagged else node_r
        # A background-coloured halo punches the node out of the ring behind it.
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r + 4}" fill="{background}"/>')
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{colour}"/>')

    parts.append(f'<circle cx="{CX}" cy="{CY}" r="{center_r}" fill="{accent}"/>')

    return "\n    ".join(parts)


def logo(accent: str, muted: str, background: str, small: bool = False) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}"
     width="{SIZE}" height="{SIZE}" role="img" aria-label="BlastRadius">
  <rect width="{SIZE}" height="{SIZE}" fill="{background}"/>
  {mark(accent, muted, background, small)}
</svg>
"""


FONT = ("ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI', "
        "Helvetica, Arial, sans-serif")
MONO = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace")


def banner(ink: str, muted: str, accent: str, background: str) -> str:
    width, height = 760, 236
    scale = 0.66
    mark_x, mark_y = 34, (height - SIZE * scale) / 2
    text_x = mark_x + SIZE * scale + 38
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"
     width="{width}" height="{height}" role="img"
     aria-label="BlastRadius — cross-repo infrastructure memory for coding agents">
  <rect width="{width}" height="{height}" fill="{background}"/>
  <g transform="translate({mark_x} {mark_y:.1f}) scale({scale})">
    {mark(accent, muted, background)}
  </g>
  <text x="{text_x}" y="112" font-family="{FONT}" font-size="54"
        font-weight="700" letter-spacing="-1.6" fill="{ink}">Blast<tspan
        fill="{accent}">Radius</tspan></text>
  <text x="{text_x}" y="150" font-family="{FONT}" font-size="19"
        fill="{muted}">Cross-repo infrastructure memory for coding agents</text>
  <text x="{text_x + 2}" y="186" font-family="{MONO}" font-size="15"
        fill="{muted}" opacity="0.85">if I bump this, who breaks?</text>
</svg>
"""


def main() -> None:
    files = {
        "logo.svg":        logo(ACCENT_LIGHT, MUTED_LIGHT, "#ffffff"),
        "logo-dark.svg":   logo(ACCENT_DARK, MUTED_DARK, "#0d1519"),
        "icon.svg":        logo(ACCENT_LIGHT, MUTED_LIGHT, "#ffffff", small=True),
        "icon-dark.svg":   logo(ACCENT_DARK, MUTED_DARK, "#0d1519", small=True),
        "banner.svg":      banner(INK_LIGHT, MUTED_LIGHT, ACCENT_LIGHT, "#ffffff"),
        "banner-dark.svg": banner(INK_DARK, MUTED_DARK, ACCENT_DARK, "#0d1519"),
    }
    for name, content in files.items():
        (HERE / name).write_text(content)
        print(f"  wrote {name} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
