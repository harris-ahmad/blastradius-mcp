"""The push lane.

MCP tools are model-elective: Claude may or may not call them. Hooks are not —
the harness runs them. So the two things that must always happen (noticing a
blast radius, and keeping the index current) are hooks, and only the optional
question-asking is MCP.

inject  → PreToolUse on Read/Edit. Claude is about to open a manifest; tell it
          who else depends on what is in that file, before it reads a line.
capture → Stop. The session touched manifests; flag anything the index has not
          seen so the next turn records it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .repo import find_manifests, is_manifest, repo_root, resolve_repository
from .scoring import QUALITY_RANK, classify_pinning
from .store import Store

# Keep injected context small — it is spent on every matching read.
MAX_ARTIFACTS_SHOWN = 8
MAX_CONSUMERS_PER_ARTIFACT = 5

_PASS = {"continue": True, "suppressOutput": True}


def _emit(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _context(event: str, text: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "continue": True,
        "suppressOutput": True,
        "hookSpecificOutput": {"hookEventName": event, "additionalContext": text},
    }
    if event == "PreToolUse":
        out["hookSpecificOutput"]["permissionDecision"] = "allow"
    return out


# ── inject: PreToolUse on Read/Edit ───────────────────────────────────────────

def inject(payload: dict[str, Any]) -> dict[str, Any]:
    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path")
    cwd = payload.get("cwd") or "."

    if not file_path or not is_manifest(file_path):
        return _PASS

    repository = resolve_repository(cwd)
    if not repository:
        return _PASS

    root = repo_root(cwd)
    try:
        relative = Path(file_path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        relative = Path(file_path).name

    store = Store()
    artifacts = store.artifacts_in_file(repository, relative)
    if not artifacts:
        return _PASS

    lines: list[str] = []
    for artifact in artifacts[:MAX_ARTIFACTS_SHOWN]:
        others = store.consumers(
            artifact["identifier"], artifact["type"], exclude_repository=repository
        )
        alerts = store.alerts_for(artifact["identifier"], artifact["type"])
        if not others and not alerts:
            continue

        by_repo: dict[str, dict[str, Any]] = {}
        for row in others:
            entry = by_repo.setdefault(row["repository"], {
                "spec": row["version_spec"],
                "pinning": classify_pinning(row["version_spec"], row["type"]),
                "where": [],
            })
            entry["where"].append(f"{row['file_path']}:{row['line_number']}")

        header = f"`{artifact['identifier']}` (line {artifact['line_number']})"
        if by_repo:
            ranked = sorted(
                by_repo.items(),
                key=lambda kv: -QUALITY_RANK.get(kv[1]["pinning"], 2),
            )[:MAX_CONSUMERS_PER_ARTIFACT]
            lines.append(f"- {header} — also used by {len(by_repo)} other repo(s):")
            for name, info in ranked:
                spec = info["spec"] or "unpinned"
                lines.append(f"    {name} @ {spec} ({info['pinning']}) — {info['where'][0]}")
            if len(by_repo) > MAX_CONSUMERS_PER_ARTIFACT:
                lines.append(f"    …and {len(by_repo) - MAX_CONSUMERS_PER_ARTIFACT} more")
        else:
            lines.append(f"- {header}")

        for alert in alerts[:3]:
            ident = alert.get("cve_id") or alert.get("osv_id")
            lines.append(f"    ⚠ {alert['severity'].upper()} {ident}")

    if not lines:
        return _PASS

    body = (
        f"BlastRadius — cross-repo impact for {relative}:\n"
        + "\n".join(lines)
        + "\n\nChanging a version here affects the repos listed above. "
          "Call blast_radius for the full picture before making a change."
    )
    return _context("PreToolUse", body)


# ── capture: Stop ─────────────────────────────────────────────────────────────

def capture(payload: dict[str, Any]) -> dict[str, Any]:
    """Flag manifests the index has not seen, so the next turn records them.

    Extraction itself is the model's job — it handles multi-stage aliases,
    templated base images and heredocs that a regex parser gets wrong. This hook
    only decides *when* extraction is owed, which is the part that must not be
    left to chance.
    """
    cwd = payload.get("cwd") or "."
    repository = resolve_repository(cwd)
    if not repository:
        return _PASS

    root = repo_root(cwd)
    manifests = find_manifests(root)
    if not manifests:
        return _PASS

    store = Store()
    known = {row["file_path"] for row in store.all_dependencies()
             if row["repository"] == repository}
    unseen = [
        m.relative_to(root).as_posix()
        for m in manifests
        if m.relative_to(root).as_posix() not in known
    ]
    if not unseen:
        return _PASS

    shown = unseen[:20]
    body = (
        f"BlastRadius: {len(unseen)} manifest file(s) in {repository} are not yet "
        f"in the cross-repo index:\n"
        + "\n".join(f"  {p}" for p in shown)
        + (f"\n  …and {len(unseen) - len(shown)} more" if len(unseen) > len(shown) else "")
        + "\n\nRead them and call record_dependencies to index them. Pass each "
          "version_spec exactly as written — keep `^`, `~>`, `>=` intact."
    )
    return _context("Stop", body)


# ── dispatch ──────────────────────────────────────────────────────────────────

HANDLERS = {"inject": inject, "capture": capture}


def run(name: str) -> None:
    """Read the hook payload on stdin, emit a response on stdout. Never fails loudly:
    a broken hook must not break the user's session."""
    handler = HANDLERS.get(name)
    if handler is None:
        _emit(_PASS)
        return
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        _emit(handler(payload))
    except Exception:
        _emit(_PASS)
