"""Resolving which repository a working directory actually is."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

_SSH_RE = re.compile(r"^git@[^:]+:(?P<path>.+?)(?:\.git)?$")
_URL_RE = re.compile(r"^(?:https?|ssh)://[^/]+/(?P<path>.+?)(?:\.git)?$")

MANIFEST_GLOBS = (
    "**/Dockerfile", "**/Dockerfile.*",
    "**/*.tf", "**/*.tfvars",
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    "**/Chart.yaml",
    "**/package.json",
)

_SKIP_DIRS = {".git", "node_modules", "vendor", ".terraform", "dist", "build",
              "__pycache__", ".venv", "target"}


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


def is_manifest(file_path: str | Path) -> bool:
    """Does this file declare infrastructure dependencies?"""
    path = Path(file_path)
    name = path.name.lower()
    if name == "dockerfile" or name.startswith("dockerfile."):
        return True
    if path.suffix.lower() in {".tf", ".tfvars"}:
        return True
    if name in {"chart.yaml", "package.json"}:
        return True
    posix = path.as_posix()
    if ".github/workflows/" in posix and path.suffix.lower() in {".yml", ".yaml"}:
        return True
    return False


def find_manifests(root: str | Path, limit: int = 500) -> list[Path]:
    """Every manifest file under a repo root, skipping vendored trees."""
    root = Path(root)
    found: list[Path] = []
    for path in root.rglob("*"):
        if len(found) >= limit:
            break
        if not path.is_file():
            continue
        if _SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        if is_manifest(path):
            found.append(path)
    return found
