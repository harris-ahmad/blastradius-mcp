"""CVSS v3.x base score from a vector string.

OSV usually reports severity as a vector, not a number. The original BlastRadius
had a loop here that matched the vector and then did nothing with it, so almost
every CVE came back 'unknown'. The formula is fully specified — compute it.

Reference: https://www.first.org/cvss/v3.1/specification-document (section 8.1)
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A: smallest number to one decimal place >= value."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str | None) -> float | None:
    """Base score for a CVSS v3.x vector, or None if it cannot be parsed."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None

    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, val = part.partition(":")
        if key and val:
            metrics[key.upper()] = val.upper()

    try:
        scope_changed = metrics["S"] == "C"
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        conf, integ, avail = (_CIA[metrics[m]] for m in ("C", "I", "A"))
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def severity_label(score: float) -> str:
    """CVSS qualitative severity rating."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"
