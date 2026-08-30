"""Pinning classification.

This operates on the RAW version spec as written in the manifest, never on a
normalised one. Stripping `^` off `^18.2.0` before classifying is what made the
original BlastRadius report 128 of 129 npm packages as exactly pinned when most
of them were caret ranges that auto-absorb minor releases.
"""
from __future__ import annotations

import re

# ── Recognisers ───────────────────────────────────────────────────────────────

_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_DOCKER_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
_EXACT_SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+([.\-+][a-z0-9._+\-]*)?$", re.IGNORECASE)
_MINOR_ONLY_RE = re.compile(r"^v?\d+\.\d+$")
_MAJOR_ONLY_RE = re.compile(r"^v?\d+$")

# Anything that makes a spec a RANGE rather than a point.
_RANGE_LEAD_RE = re.compile(r"^\s*[\^~><]")
_RANGE_ANYWHERE_RE = re.compile(r"(\|\||\s-\s|\.[xX*]|\*)")

_FLOATING_TAGS = frozenset(
    {"latest", "main", "master", "develop", "dev", "edge", "stable",
     "nightly", "head", "next", "canary", "beta", "alpha"}
)
_UNPINNABLE_SPECS = frozenset({"*", "x", "X", "", "latest", "next"})

# Types where a missing version means "implicitly latest", not "unknown".
_IMPLICIT_LATEST_TYPES = frozenset({"docker_image"})

PINNING_QUALITIES = ("sha", "exact", "partial", "unknown", "unpinned")

# Worst-first ordering, for sorting hygiene reports.
QUALITY_RANK: dict[str, int] = {
    "unpinned": 4, "partial": 3, "unknown": 2, "exact": 1, "sha": 0,
}


def classify_pinning(version_spec: str | None, dependency_type: str) -> str:
    """Classify how tightly a consumer pins an artifact.

    Pass the spec exactly as it appears in the manifest — `^18.2.0`, `~> 3.0`,
    `>=1.0.0 <2.0.0`, `v4`, `sha256:abc…`. Do not normalise it first.

    Returns one of:
      'sha'      cryptographically locked; immune until an explicit update
      'exact'    a single point version; will not move on its own
      'partial'  a range or floating-major; absorbs some upstream changes
      'unpinned' fully floating; takes every upstream change immediately
      'unknown'  no version data captured for this reference
    """
    dep_type = (dependency_type or "").lower().strip()

    if version_spec is None:
        return "unpinned" if dep_type in _IMPLICIT_LATEST_TYPES else "unknown"

    spec = version_spec.strip()
    if spec in _UNPINNABLE_SPECS:
        return "unpinned"

    if _SHA_RE.match(spec) or _DOCKER_DIGEST_RE.match(spec):
        return "sha"

    if spec.lower() in _FLOATING_TAGS:
        return "unpinned"

    # A leading operator or an embedded range token means it is a range, full
    # stop — regardless of how precise the number after it looks.
    if _RANGE_LEAD_RE.search(spec) or _RANGE_ANYWHERE_RE.search(spec):
        # Terraform's `= 1.0.0` is the one operator form that pins a point.
        compact = spec.replace(" ", "")
        if compact.startswith("=") and not compact.startswith((">=", "<=", "==", "!=")):
            return "exact"
        return "partial"

    if spec.startswith("="):
        return "exact"

    if _EXACT_SEMVER_RE.match(spec):
        return "exact"
    if _MINOR_ONLY_RE.match(spec) or _MAJOR_ONLY_RE.match(spec):
        return "partial"

    # A docker tag like `bookworm-20260112` is a point; `bookworm` is not.
    return "partial"


def worst_quality(qualities: list[str]) -> str:
    """Return the worst pinning quality in a set, by QUALITY_RANK."""
    if not qualities:
        return "unknown"
    return max(qualities, key=lambda q: QUALITY_RANK.get(q, 2))
