"""Deciding whether a version sits inside an advisory's affected ranges.

OSV's event semantics — introduced / fixed / last_affected, walked in order —
are the same whatever the ecosystem. Only *comparison* differs: npm sorts
`1.0.0-beta` below `1.0.0`, PyPI sorts `1.0.dev1` below `1.0a1` below `1.0`.

So the walk lives here once and takes the ecosystem's parse and compare as
arguments. Two copies of this that drifted apart would be a silent way to miss
a vulnerability in one ecosystem while catching it in the other.
"""
from __future__ import annotations

from typing import Callable

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNKNOWN = "unknown"

Compare = Callable[[str, str], "int | None"]
Parse = Callable[["str | None"], object]
FloorOf = Callable[["str | None"], "str | None"]


def affected_by_range(version: str, events: list[dict], compare: Compare) -> bool:
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


def version_is_affected(version: str, affected: list[dict],
                        parse: Parse, compare: Compare) -> bool | None:
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
                continue  # commit ranges say nothing about a version pin
            events = range_.get("events") or []
            if not events:
                continue
            saw_usable_data = True
            if affected_by_range(version, events, compare):
                return True

    return False if saw_usable_data else None


def spec_is_affected(spec: str | None, affected: list[dict], floor_of: FloorOf,
                     parse: Parse, compare: Compare) -> str:
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
    verdict = version_is_affected(floor, affected, parse, compare)
    if verdict is None:
        return UNKNOWN
    return AFFECTED if verdict else NOT_AFFECTED


def scheme_for(artifact_type: str | None):
    """The version module that governs this artifact type.

    npm and PyPI answer "is 1.0.0-beta before 1.0.0" differently, and judging a
    Python pin with semver's rules would quietly mis-evaluate every advisory
    boundary that lands on a pre-release or a four-segment release.
    """
    from . import pep440, semver
    return pep440 if artifact_type == "python_package" else semver
