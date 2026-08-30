"""OSV.dev client.

Discovery is batched and detail-fetching is not: `querybatch` returns only IDs,
so we use it to find what exists cheaply, then fetch full records only for the
IDs we have never seen. On a steady-state index that is one batch call and zero
detail calls per cycle.
"""
from __future__ import annotations

from typing import Iterable

import httpx

from .cvss import base_score, severity_label

OSV_BASE = "https://api.osv.dev/v1"

# Ecosystems OSV covers for the artifact types we index. Docker images, Terraform
# modules and Helm charts have no OSV ecosystem — they are not monitorable, and
# claiming otherwise would mean silently reporting "no known CVEs" for them.
ECOSYSTEMS: dict[str, str] = {
    "github_action": "GitHub Actions",
    "npm_package": "npm",
}

# GitHub advisories use MODERATE where CVSS says MEDIUM.
_LABELS = {
    "CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
    "MEDIUM": "medium", "LOW": "low",
}


def package_name(identifier: str, artifact_type: str) -> str:
    """OSV package name for an artifact. Actions carry no version suffix."""
    if artifact_type == "github_action":
        return identifier.split("@")[0]
    return identifier


def parse_vuln(raw: dict) -> dict:
    """Normalise one OSV record.

    Severity resolution, best source first:
      1. an explicit label in database_specific.severity
      2. a CVSS vector in severity[], scored with the real formula
      3. a numeric cvss_score under affected[].database_specific
    """
    severity: str | None = None
    score: float | None = None

    label = (raw.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        severity = _LABELS.get(label.strip().upper())

    for entry in raw.get("severity") or []:
        if not str(entry.get("type", "")).upper().startswith("CVSS_V3"):
            continue
        score = base_score(entry.get("score"))
        if score is not None:
            severity = severity or severity_label(score)
            break

    if severity is None:
        for affected in raw.get("affected") or []:
            numeric = (affected.get("database_specific") or {}).get("cvss_score")
            if isinstance(numeric, (int, float)):
                score = float(numeric)
                severity = severity_label(score)
                break

    url = ""
    for ref in raw.get("references") or []:
        if ref.get("type") in ("ADVISORY", "WEB"):
            url = ref.get("url", "")
            break

    aliases = [a for a in raw.get("aliases") or [] if a.startswith("CVE-")]
    summary = raw.get("summary") or (raw.get("details") or "")[:200]

    return {
        # Kept structured rather than flattened to strings: deciding whether a
        # pinned spec falls inside the advisory needs the events, not a label.
        "affected": raw.get("affected") or [],
        "id": raw.get("id", ""),
        "cve_id": aliases[0] if aliases else None,
        "severity": severity or "unknown",
        "cvss_score": score,
        "summary": summary.strip(),
        "url": url,
        "published": raw.get("published", ""),
    }


class OsvClient:
    def __init__(self, base_url: str = OSV_BASE, timeout: float = 20.0,
                 client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client = client

    def _post(self, path: str, payload: dict) -> dict:
        if self._client is not None:
            response = self._client.post(f"{self.base_url}{path}", json=payload,
                                         timeout=self._timeout)
        else:
            response = httpx.post(f"{self.base_url}{path}", json=payload,
                                  timeout=self._timeout)
        response.raise_for_status()
        return response.json()

    def _get(self, path: str) -> dict:
        if self._client is not None:
            response = self._client.get(f"{self.base_url}{path}", timeout=self._timeout)
        else:
            response = httpx.get(f"{self.base_url}{path}", timeout=self._timeout)
        response.raise_for_status()
        return response.json()

    def discover(self, artifacts: Iterable[dict]) -> dict[int, list[str]]:
        """Batch-query OSV. Returns {artifact_id: [osv_id, ...]}.

        Artifacts in ecosystems OSV does not cover are skipped entirely rather
        than reported as clean.
        """
        supported = [a for a in artifacts if a["type"] in ECOSYSTEMS]
        if not supported:
            return {}

        queries = [
            {"package": {"name": package_name(a["identifier"], a["type"]),
                         "ecosystem": ECOSYSTEMS[a["type"]]}}
            for a in supported
        ]
        results = self._post("/querybatch", {"queries": queries}).get("results", [])

        discovered: dict[int, list[str]] = {}
        for index, artifact in enumerate(supported):
            if index >= len(results):
                break
            vulns = results[index].get("vulns") or []
            ids = [v["id"] for v in vulns if v.get("id")]
            if ids:
                discovered[artifact["id"]] = ids
        return discovered

    def fetch(self, osv_id: str) -> dict:
        """Full record for one advisory, normalised."""
        return parse_vuln(self._get(f"/vulns/{osv_id}"))
