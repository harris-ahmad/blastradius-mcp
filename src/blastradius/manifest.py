"""Is this file — or this shell command — about infrastructure dependencies?

Deliberately dependency-free. The Bash matcher means every shell command an
agent runs pays this module's import cost, and almost every one of them is
answered "no". Importing config, the store, or anything pulling in dataclasses
to decide that would tax the whole session for nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

MANIFEST_GLOBS = (
    "**/Dockerfile", "**/Dockerfile.*",
    "**/*.tf", "**/*.tfvars",
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    "**/Chart.yaml",
    "**/package.json",
)

SKIP_DIRS = {".git", "node_modules", "vendor", ".terraform", "dist", "build",
             "__pycache__", ".venv", "target"}


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


# A cheap pre-filter. Bash fires on every shell command an agent runs, so the
# overwhelming majority of calls must be rejected before anything expensive
# happens — no config load, no database, no path resolution.
_MANIFEST_HINT = re.compile(
    r"dockerfile|\.tf\b|\.tfvars\b|chart\.yaml|package\.json|\.github/workflows",
    re.IGNORECASE,
)

# Changing a dependency through a package manager never names package.json,
# but it is exactly the moment the warning is worth having.
_PACKAGE_MANAGER = re.compile(
    r"\b(?:npm|yarn|pnpm)\s+(?:install|add|remove|uninstall|un|upgrade|up|i|ci|rm)\b",
    re.IGNORECASE,
)

_COMMAND_SPLIT = re.compile(r"""[\s;|&()<>"']+""")


def manifest_in_command(command: str | None) -> str | None:
    """The manifest a shell command reads or changes, if any.

    An agent does not only reach for the Read tool. It runs `cat package.json`,
    it pipes a Dockerfile through grep, and it bumps a dependency with
    `npm install react@19` — which rewrites package.json without ever going
    through Edit. A hook matching only Read and Edit is blind to all of it,
    which makes "the agent is always told" false in exactly the cases where
    the agent is about to change something.

    Returns the first manifest named in the command, or `package.json` for a
    package-manager invocation that implies it. Returns None for the ordinary
    shell command, which is almost all of them.
    """
    if not command:
        return None

    if _PACKAGE_MANAGER.search(command):
        return "package.json"

    if not _MANIFEST_HINT.search(command):
        return None

    for token in _COMMAND_SPLIT.split(command):
        token = token.strip().rstrip(",:")
        # Flags can carry a manifest-looking value (`--file=package.json`), but
        # a bare flag never is one.
        if not token or token.startswith("-"):
            continue
        if is_manifest(token):
            return token
    return None
