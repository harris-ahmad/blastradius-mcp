"""Resolving which repository a working directory actually is."""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

# The pure predicates live apart so the Bash matcher's hot path can import
# them without dragging in subprocess, datetime, or anything below.
from .manifest import (MANIFEST_GLOBS, SKIP_DIRS, is_manifest,  # noqa: F401
                       manifest_in_command)

_SSH_RE = re.compile(r"^git@[^:]+:(?P<path>.+?)(?:\.git)?$")
_URL_RE = re.compile(r"^(?:https?|ssh)://[^/]+/(?P<path>.+?)(?:\.git)?$")



def resolve_repository(cwd: str | Path) -> str | None:
    """Canonical 'owner/name' from the git remote, or the directory name."""
    cwd = Path(cwd)
    try:
        remote = subprocess.run(
            ["git", "-C", str(cwd), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        )
        if remote.returncode == 0:
            url = remote.stdout.strip()
            for pattern in (_SSH_RE, _URL_RE):
                match = pattern.match(url)
                if match:
                    parts = [p for p in match.group("path").split("/") if p]
                    if len(parts) >= 2:
                        return f"{parts[-2]}/{parts[-1]}"
    except (subprocess.SubprocessError, OSError):
        pass

    try:
        root = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if root.returncode == 0:
            return Path(root.stdout.strip()).name
    except (subprocess.SubprocessError, OSError):
        pass

    return cwd.name or None


def repo_root(cwd: str | Path) -> Path:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except (subprocess.SubprocessError, OSError):
        pass
    return Path(cwd)



def find_manifests(root: str | Path, limit: int = 500) -> list[Path]:
    """Every manifest file under a repo root, skipping vendored trees.

    os.walk rather than rglob, because rglob has no way to *not descend*. It
    walked all of node_modules and .git and then discarded the results by
    path — 180ms and 11,000 stat calls to find two files in a small repo, and
    seconds in a real monorepo. Pruning `dirnames` in place means those trees
    are never entered at all.
    """
    root = Path(root)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # In-place, so os.walk itself skips them. Rebinding the name would not.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        directory = Path(dirpath)
        for name in sorted(filenames):
            if is_manifest(name) or is_manifest(directory / name):
                found.append(directory / name)
                if len(found) >= limit:
                    return found
    return found


def unread_manifests(root, repository, known_paths, last_scanned,
                     exclude=None) -> list[str]:
    """Manifests worth spending a read on, relative to the repo root.

    A file qualifies when the index holds nothing from it AND either the
    repository has never been scanned, or the file has changed since it was.
    The mtime half is what stops a manifest that legitimately declares nothing
    — a local Terraform module holding a single variable — from being offered
    up forever, while still catching one that was added or edited after the
    last pass.

    Both the capture hook and `blastradius index` ask this question, and they
    have to answer it the same way: the hook flags what it flags at every Stop,
    and the bootstrap spends a paid session on whatever it believes is unread.
    """
    root = Path(root)
    scanned_at = None
    if last_scanned:
        try:
            scanned_at = datetime.fromisoformat(last_scanned).timestamp()
        except ValueError:
            scanned_at = None

    unread = []
    for manifest in find_manifests(root):
        relative = manifest.relative_to(root).as_posix()
        if relative in known_paths:
            continue
        if exclude and exclude(relative):
            continue
        if scanned_at is not None:
            try:
                if manifest.stat().st_mtime <= scanned_at:
                    continue    # looked at already, and unchanged since
            except OSError:
                pass
        unread.append(relative)
    return unread

