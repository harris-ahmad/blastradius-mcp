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
import os
import sys
from pathlib import Path
from typing import Any

from .config import load as load_config
from .repo import find_manifests, is_manifest, repo_root, resolve_repository
from .scoring import QUALITY_RANK, classify_pinning
from .store import Store

_PASS = {"continue": True, "suppressOutput": True}

DEBUG = bool(os.environ.get("BLASTRADIUS_DEBUG"))


def _debug(message: str) -> None:
    """Say why a hook stayed quiet.

    Both hooks pass through silently by design, so 'nothing happened' is
    ambiguous: no matching artifacts, an unresolvable repo, and a genuine crash
    all look identical. BLASTRADIUS_DEBUG=1 tells them apart.
    """
    if DEBUG:
        print(f"[blastradius] {message}", file=sys.stderr)


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

    if not file_path:
        _debug("no file_path in tool_input — nothing to look up")
        return _PASS
    if not is_manifest(file_path):
        _debug(f"not a manifest file: {file_path}")
        return _PASS

    config = load_config()
    if not config.inject.enabled:
        _debug("injection disabled in config")
        return _PASS

    repository = resolve_repository(cwd)
    if not repository:
        _debug(f"could not resolve a repository from cwd: {cwd}")
        return _PASS
    if config.exclude.repository(repository):
        _debug(f"{repository!r} excluded by config")
        return _PASS
    _debug(f"repository resolved as {repository!r}")

    root = repo_root(cwd)
    try:
        relative = Path(file_path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        relative = Path(file_path).name

    store = Store()
    _debug(f"looking up {repository!r} / {relative!r} in {store.db_path}")
    artifacts = store.artifacts_in_file(repository, relative)
    if not artifacts:
        stats = store.stats()
        if not stats["references"]:
            _debug("the index is EMPTY — nothing has been captured yet")
        else:
            known = sorted({
                row["file_path"] for row in store.all_dependencies()
                if row["repository"] == repository
            })
            if known:
                _debug(f"no artifacts recorded for this file. "
                       f"{repository} has: {', '.join(known)}")
            else:
                _debug(f"{repository!r} is not in the index "
                       f"(index holds {stats['repositories']} repo(s))")
        return _PASS
    _debug(f"{len(artifacts)} artifact(s) in this file")

    if config.exclude.path(relative):
        _debug(f"{relative!r} excluded by config")
        return _PASS

    artifacts = [
        a for a in artifacts
        if a["type"] in config.inject.types and not config.exclude.artifact(a["identifier"])
    ]
    if not artifacts:
        _debug("every artifact in this file is filtered out by config")
        return _PASS

    lines: list[str] = []
    for artifact in artifacts[:config.inject.max_artifacts]:
        others = store.consumers(
            artifact["identifier"], artifact["type"], exclude_repository=repository
        )
        alerts = [
            a for a in store.alerts_for(artifact["identifier"], artifact["type"])
            if config.severity_at_least(a["severity"], config.inject.min_cve_severity)
        ]
        if not others and (config.inject.only_when_shared or not alerts):
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
            )[:config.inject.max_consumers]
            lines.append(f"- {header} — also used by {len(by_repo)} other repo(s):")
            for name, info in ranked:
                spec = info["spec"] or "unpinned"
                lines.append(f"    {name} @ {spec} ({info['pinning']}) — {info['where'][0]}")
            if len(by_repo) > config.inject.max_consumers:
                lines.append(f"    …and {len(by_repo) - config.inject.max_consumers} more")
        else:
            lines.append(f"- {header}")

        for alert in alerts[:3]:
            ident = alert.get("cve_id") or alert.get("osv_id")
            lines.append(f"    ⚠ {alert['severity'].upper()} {ident}")

    if not lines:
        _debug("artifacts found, but no OTHER repo consumes them and there are "
               "no open CVEs — staying quiet is correct here")
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
    config = load_config()
    cwd = payload.get("cwd") or "."
    repository = resolve_repository(cwd)
    if not repository:
        _debug(f"could not resolve a repository from cwd: {cwd}")
        return _PASS
    if config.exclude.repository(repository):
        _debug(f"{repository!r} excluded from capture by config")
        return _PASS

    root = repo_root(cwd)
    manifests = find_manifests(root)
    if not manifests:
        _debug(f"no manifest files found under {root}")
        return _PASS
    _debug(f"{len(manifests)} manifest(s) under {root}")

    store = Store()
    known = {row["file_path"] for row in store.all_dependencies()
             if row["repository"] == repository}
    unseen = [
        path for path in (m.relative_to(root).as_posix() for m in manifests)
        if path not in known and not config.exclude.path(path)
    ]
    if not unseen:
        _debug(f"every manifest in {repository} is already indexed")
        return _PASS

    shown = unseen[:20]
    body = (
        f"BlastRadius: {len(unseen)} manifest file(s) in {repository} are not yet "
        f"in the cross-repo index:\n"
        + "\n".join(f"  {p}" for p in shown)
        + (f"\n  …and {len(unseen) - len(shown)} more" if len(unseen) > len(shown) else "")
        + "\n\nRead them and call record_dependencies to index them.\n"
          "\n"
          "Record only what resolves from OUTSIDE this repository. Skip anything "
          "local or vendored, because it has no cross-repo blast radius: relative "
          "paths (./ or ../), file:// and workspace: protocols, github: and git "
          "URL refs, and multi-stage build stage aliases (FROM <earlier-stage>).\n"
          "\n"
          "Pass each version_spec exactly as written — keep `^`, `~>`, `>=` "
          "intact. They are the signal; normalising them destroys it.\n"
          "\n"
          f"Pass root_path as {root} so lockfiles can be read: they say which "
          "version is actually installed, which turns vulnerability matching "
          "from conservative into exact."
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
        if DEBUG:
            import traceback
            traceback.print_exc()
        else:
            _debug("crashed — rerun with BLASTRADIUS_DEBUG=1 for the traceback")
        _emit(_PASS)
