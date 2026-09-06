"""Version comparison, and deciding whether a pinned spec is inside an advisory.

The hard part is that a manifest holds a *range*, not a version. `^4.17.20`
could resolve to 4.17.20 or 4.17.31 depending on when someone last installed,
so "is this repo affected?" often has no yes/no answer.

So the verdict is three-valued, and the uncertain case is treated as affected.
Hiding a possible vulnerability is a much worse failure than showing one that
turns out not to apply.
"""
from __future__ import annotations

import re

# 1.2.3, v1.2.3, 1.2.3-beta.1, 1.2 and 4 (padded with zeros)
_VERSION_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+]([0-9A-Za-z.\-+]*))?$"
)
_LEADING_OPERATOR_RE = re.compile(r"^\s*(\^|~>|~|>=|<=|>|<|=)\s*")

from . import ranges
from .ranges import AFFECTED, NOT_AFFECTED, UNKNOWN  # noqa: F401  (re-exported)


def parse(version: str | None) -> tuple[int, int, int, str] | None:
    """(major, minor, patch, prerelease) or None if it is not a version."""
    if not version:
        return None
    match = _VERSION_RE.match(version.strip())
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    return (int(major), int(minor or 0), int(patch or 0), pre or "")


def compare(a: str, b: str) -> int | None:
    """-1, 0, 1 — or None if either side is not comparable.

    A prerelease sorts below its own release, per semver.
    """
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    for x, y in zip(pa[:3], pb[:3]):
        if x != y:
            return -1 if x < y else 1
    # 1.0.0-beta < 1.0.0
    if pa[3] and not pb[3]:
        return -1
    if pb[3] and not pa[3]:
        return 1
    if pa[3] != pb[3]:
        return -1 if pa[3] < pb[3] else 1
    return 0


def floor_of(spec: str | None) -> str | None:
    """Lowest version a spec permits — the one most likely to still be vulnerable.

    `^4.17.20` -> 4.17.20, `>=1.2.3` -> 1.2.3, `4.17.21` -> 4.17.21.
    Returns None for anything without a usable lower bound (`latest`, `*`, `main`).
    """
    if not spec:
        return None
    text = spec.strip()
    if not text:
        return None

    # Strip the leading operator first: Terraform writes "~> 5.0" with a space,
    # so splitting on whitespace before this would discard the version itself.
    text = _LEADING_OPERATOR_RE.sub("", text).strip()

    # Compound ranges (">=1.0.0 <2.0.0", "1 || 2") — the first bound is the floor.
    for separator in ("||", " - ", " "):
        if separator in text:
            text = text.split(separator)[0].strip()
            break
    # `1.x` / `1.2.*` have a floor of 1.0.0 / 1.2.0
    text = re.sub(r"[.\-]?[xX*]", "", text).strip(".")
    return text if parse(text) else None


def _affected_by_range(version: str, events: list[dict]) -> bool:
    return ranges.affected_by_range(version, events, compare)


def version_is_affected(version: str, affected: list[dict]) -> bool | None:
    """Is this exact version covered by an advisory's `affected` entries?"""
    return ranges.version_is_affected(version, affected, parse, compare)


def spec_is_affected(spec: str | None, affected: list[dict]) -> str:
    """Verdict for a manifest spec against an advisory."""
    return ranges.spec_is_affected(spec, affected, floor_of, parse, compare)
