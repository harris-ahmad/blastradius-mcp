"""Reading resolved versions out of lockfiles.

Everywhere else in BlastRadius, extraction is the model's job — manifests are
full of templating, aliases and heredocs that regexes get wrong. Lockfiles are
the opposite: machine-generated, schema-stable, and unambiguous. Parsing them
here is deterministic, free, and needs no session.

Why it matters: a manifest says `^5.2.0`, which permits 5.2.0 and therefore
every advisory affecting it. The lockfile says 5.4.19, which permits nothing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# yarn.lock:  "lodash@^4.17.20:"  then  '  version "4.17.21"'
_YARN_ENTRY_RE = re.compile(r'^"?((?:@[^/\s,"]+/)?[^@\s,"]+)@[^\n]*:$')
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')

_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv"}


def _from_package_lock(path: Path) -> dict[str, str]:
    """npm's package-lock.json, both the v1 and the v2/v3 layouts."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}

    resolved: dict[str, str] = {}

    # v2 / v3: keys are install paths — "node_modules/lodash".
    packages = data.get("packages")
    if isinstance(packages, dict):
        for install_path, meta in packages.items():
            if not install_path or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            # The last node_modules segment is the package; anything before it
            # is a nesting path we do not care about.
            name = install_path.rsplit("node_modules/", 1)[-1]
            # A transitive copy must not overwrite the top-level install.
            top_level = install_path.startswith("node_modules/") and \
                install_path.count("node_modules/") == 1
            if name not in resolved or top_level:
                resolved[name] = version

    # v1: a nested dependency tree keyed by name.
    def walk(tree: object, top: bool) -> None:
        if not isinstance(tree, dict):
            return
        for name, meta in tree.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and (top or name not in resolved):
                resolved[name] = version
            walk(meta.get("dependencies"), False)

    walk(data.get("dependencies"), True)
    return resolved


def _from_yarn_lock(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {}

    resolved: dict[str, str] = {}
    pending: list[str] = []
    for line in lines:
        match = _YARN_ENTRY_RE.match(line.strip())
        if match:
            # One entry can cover several specs: "lodash@^4.0.0, lodash@^4.17.0:"
            pending = [
                part.strip().strip('"').rsplit("@", 1)[0]
                for part in line.strip().rstrip(":").split(",")
                if part.strip()
            ]
            continue
        version_match = _YARN_VERSION_RE.match(line)
        if version_match and pending:
            for name in pending:
                if name:
                    resolved.setdefault(name, version_match.group(1))
            pending = []
    return resolved


def npm_resolved_versions(root: str | Path) -> dict[str, str]:
    """{package name: version actually installed} for a repository.

    package-lock.json wins over yarn.lock where both exist. pnpm-lock.yaml is
    not read — it needs a YAML parser and this module stays dependency-free.
    """
    root = Path(root)
    resolved: dict[str, str] = {}

    for lock_name, reader in (("yarn.lock", _from_yarn_lock),
                              ("package-lock.json", _from_package_lock)):
        for path in root.rglob(lock_name):
            if _SKIP_DIRS & set(path.relative_to(root).parts[:-1]):
                continue
            resolved.update(reader(path))

    return resolved
