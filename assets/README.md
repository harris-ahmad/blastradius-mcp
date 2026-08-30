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
| `social.png` | GitHub social preview — 1280x640, uploaded by hand |

## Social preview

`social.png` is 1280x640 (the 2:1 ratio GitHub's crop expects) and is the one
asset that must be raster — GitHub rejects SVG there. It is generated from
`social.svg` by rasterising at exactly 1280x640.

It cannot be set from the API: GitHub exposes the social preview only through
**Settings → General → Social preview → Upload an image**. Re-upload it by hand
after regenerating.

Type is sized for a feed, not a screen. These cards are seen around 440-600px
wide, so the wordmark carries and everything else is secondary.

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
