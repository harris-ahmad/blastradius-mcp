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

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNKNOWN = "unknown"


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
    """Walk one OSV range's introduced/fixed/last_affected events in order."""
    inside = False
    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
            if introduced == "0" or (compare(version, introduced) or -1) >= 0:
                inside = True
        elif "fixed" in event:
            result = compare(version, event["fixed"])
            if result is not None and result >= 0:
                inside = False
        elif "last_affected" in event:
            result = compare(version, event["last_affected"])
            if result is not None and result > 0:
                inside = False
    return inside


def version_is_affected(version: str, affected: list[dict]) -> bool | None:
    """Is this exact version covered by an advisory's `affected` entries?

    None means the ranges could not be evaluated — an unparseable version, a
    GIT-only range, or no range data at all.
    """
    if parse(version) is None:
        return None

    saw_usable_data = False
    for entry in affected:
        explicit = entry.get("versions") or []
        if explicit:
            saw_usable_data = True
            if any(compare(version, v) == 0 for v in explicit):
                return True

        for range_ in entry.get("ranges") or []:
            if str(range_.get("type", "")).upper() == "GIT":
                continue  # commit ranges say nothing about a semver pin
            events = range_.get("events") or []
            if not events:
                continue
            saw_usable_data = True
            if _affected_by_range(version, events):
                return True

    return False if saw_usable_data else None


def spec_is_affected(spec: str | None, affected: list[dict]) -> str:
    """Verdict for a manifest spec against an advisory.

    A range is judged by its lowest permitted version: if even that is already
    fixed, nothing the range can resolve to is vulnerable. If the floor is
    vulnerable the range *may* resolve to it, so the advisory stands.

    Anything unparseable — a floating tag, a digest, a git ref — returns
    UNKNOWN, which callers must treat as affected.
    """
    floor = floor_of(spec)
    if floor is None:
        return UNKNOWN
    verdict = version_is_affected(floor, affected)
    if verdict is None:
        return UNKNOWN
    return AFFECTED if verdict else NOT_AFFECTED
