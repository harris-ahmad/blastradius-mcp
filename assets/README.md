# Brand assets

Generated, not hand-edited. Change `generate.py` and re-run it:

```bash
python3 assets/generate.py
```

| File | Use |
|---|---|
| `banner.svg` / `banner-dark.svg` | README header, social preview |
| `logo.svg` / `logo-dark.svg` | Full mark, 48px and above |
| `icon.svg` / `icon-dark.svg` | Favicon and avatar, below 48px |

## The mark

One filled centre (the artifact), concentric rings (distance), consumer nodes
sitting on those rings, faint spokes tying them back, and one node in amber —
the consumer that is exposed.

Rings alone would read as a target. Spokes alone as a generic network diagram.
Together they are the thing the tool actually does.

`icon.svg` is a separate, reduced geometry rather than a scaled copy: two rings,
three nodes, no spokes, proportionally much heavier strokes. The full mark
dissolves into grey mud at 16px, and a favicon that only works at 128px is not
a favicon.

## Palette

| | Light | Dark | |
|---|---|---|---|
| Accent | `#0e7490` | `#3bb3cc` | rings, nodes, the "Radius" half of the wordmark |
| Ink | `#0f2830` | `#e8f2f5` | wordmark |
| Muted | `#5c7885` | `#8fadb9` | tagline, spokes |
| Flag | `#e08c1a` | `#e08c1a` | the exposed consumer — attention, not failure |

The accent is the project's own `docker_image` colour, carried over from the
original BlastRadius graph view.
