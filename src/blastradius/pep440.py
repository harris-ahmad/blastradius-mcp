"""Python version comparison, and floors for Python and Poetry specs.

Python does not use semver. A release can have any number of segments
(`1.2.3.4`), can carry an epoch (`2!1.0`), and orders its suffixes
dev < pre < release < post — the opposite shape to semver, where a prerelease
is the only thing below its release.

Specs come in two dialects that appear in the same file. PEP 440 writes
`>=1.0,<2.0`, `==1.2.3`, `~=1.4.2`; Poetry's `[tool.poetry.dependencies]`
writes `^1.2.3` and `~1.2.3`, which are npm's operators with Python's version
syntax. Both are handled, because both turn up in a pyproject.toml.

Rigour matches semver.py deliberately: exact on the release numbers, which is
what almost every advisory boundary turns on, and simplified on the suffix
ordering. Anything this cannot parse returns None, which the caller turns into
UNKNOWN and treats as affected.
"""
from __future__ import annotations

import re

from . import ranges
from .ranges import AFFECTED, NOT_AFFECTED, UNKNOWN  # noqa: F401  (re-exported)

_VERSION_RE = re.compile(
    r"""^\s*v?
        (?:(?P<epoch>\d+)!)?
        (?P<release>\d+(?:\.\d+)*)
        (?P<pre>[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?
        (?P<post>[-_.]?(?:post|rev|r)[-_.]?\d*)?
        (?P<dev>[-_.]?dev[-_.]?\d*)?
        (?:\+(?P<local>[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*))?
        \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

# PEP 440 operators plus Poetry's two. Longest first, so `>=` is not read as `>`.
_LEADING_OPERATOR_RE = re.compile(r"^\s*(===|==|!=|~=|>=|<=|\^|~|>|<|=)\s*")

# `requests[security]>=2.0 ; python_version < "3.9"` — neither the extras nor
# the environment marker says anything about which version is permitted.
_EXTRAS_RE = re.compile(r"\[[^\]]*\]")

# A requirements.txt line is `requests>=2.0`, and a model recording the whole
# line rather than just the constraint is a plausible mistake to survive.
_LEADING_NAME_RE = re.compile(
    r"^[A-Za-z0-9._-]+(?=\s*(?:===|==|!=|~=|>=|<=|\^|~|>|<|=))")

_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2,
             "pre": 2, "preview": 2}

# dev < pre < final < post
_PHASE_DEV, _PHASE_PRE, _PHASE_FINAL, _PHASE_POST = 0, 1, 2, 3


def _suffix_number(text: str | None) -> int:
    if not text:
        return 0
    digits = re.search(r"\d+", text)
    return int(digits.group()) if digits else 0


def parse(version: str | None) -> tuple | None:
    """A sortable key, or None if this is not a Python version.

    The key is (epoch, release tuple, phase, phase rank, phase number) — the
    release tuple compares element-wise, and shorter releases are padded so
    `1.2` and `1.2.0` compare equal, as PEP 440 requires.
    """
    if not version:
        return None
    match = _VERSION_RE.match(str(version))
    if not match:
        return None

    epoch = int(match.group("epoch") or 0)
    release = tuple(int(part) for part in match.group("release").split("."))
    pre, post, dev = match.group("pre"), match.group("post"), match.group("dev")

    if post:
        phase, rank, number = _PHASE_POST, 0, _suffix_number(post)
    elif pre:
        letters = re.search(r"[A-Za-z]+", pre)
        phase = _PHASE_PRE
        rank = _PRE_RANK.get((letters.group() if letters else "").lower(), 2)
        number = _suffix_number(pre)
    elif dev:
        phase, rank, number = _PHASE_DEV, 0, _suffix_number(dev)
    else:
        phase, rank, number = _PHASE_FINAL, 0, 0

    # A dev suffix on a pre-release sorts below that pre-release.
    if dev and pre:
        number -= 1000000

    return (epoch, release, phase, rank, number)


def compare(a: str, b: str) -> int | None:
    """-1, 0, 1 — or None if either side is not comparable."""
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None

    if pa[0] != pb[0]:
        return -1 if pa[0] < pb[0] else 1

    # 1.2 == 1.2.0: pad the shorter release rather than comparing lengths.
    ra, rb = pa[1], pb[1]
    width = max(len(ra), len(rb))
    ra = ra + (0,) * (width - len(ra))
    rb = rb + (0,) * (width - len(rb))
    if ra != rb:
        return -1 if ra < rb else 1

    rest_a, rest_b = pa[2:], pb[2:]
    if rest_a == rest_b:
        return 0
    return -1 if rest_a < rest_b else 1


def floor_of(spec: str | None) -> str | None:
    """Lowest version a spec permits — the one most likely to still be vulnerable.

    `>=1.0,<2.0` -> 1.0, `==1.2.3` -> 1.2.3, `~=1.4.2` -> 1.4.2,
    `^1.2.3` -> 1.2.3 (Poetry). None when there is no usable lower bound, which
    the caller treats as affected rather than as safe.

    `>1.0` yields 1.0 even though the range excludes it. That errs toward
    reporting, which is the direction this tool is meant to err in.
    """
    if not spec:
        return None
    text = _EXTRAS_RE.sub("", str(spec))
    text = text.split(";")[0]           # drop the environment marker
    text = text.split("#")[0].strip()   # and a trailing comment
    text = _LEADING_NAME_RE.sub("", text).strip()
    if not text:
        return None

    # Compound specs: `>=1.0,<2.0` and `>= 1.0, < 2.0`. The first clause
    # carrying a lower bound is the floor; a leading `!=` or `<` is not one.
    for clause in text.split(","):
        clause = clause.strip()
        if not clause:
            continue
        operator = _LEADING_OPERATOR_RE.match(clause)
        symbol = operator.group(1) if operator else ""
        if symbol in ("!=", "<", "<="):
            continue
        candidate = _LEADING_OPERATOR_RE.sub("", clause).strip()
        candidate = candidate.split()[0] if candidate.split() else ""
        candidate = re.sub(r"\.\*$", "", candidate)   # `==1.4.*` floors at 1.4
        if parse(candidate):
            return candidate
    return None


def version_is_affected(version: str, affected: list[dict]) -> bool | None:
    return ranges.version_is_affected(version, affected, parse, compare)


def spec_is_affected(spec: str | None, affected: list[dict]) -> str:
    return ranges.spec_is_affected(spec, affected, floor_of, parse, compare)
