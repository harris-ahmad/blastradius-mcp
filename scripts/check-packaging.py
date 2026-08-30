#!/usr/bin/env python3
"""Check that the three things describing this package still agree.

    python3 scripts/check-packaging.py

Shipping it means the version now lives in three files — pyproject.toml, the
plugin manifest, and the marketplace entry — and nothing forces them to move
together. A plugin pinned to a version the package no longer publishes
installs the wrong thing, and the failure appears on a stranger's machine
rather than here.

The other half is the seam between the two halves of the install: the plugin
declares hooks and an MCP server that both shell out to `blastradius`, which
exists only because pyproject declares that console script. Rename it on one
side and every hook fails silently, since they are written to swallow errors
rather than break a session.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"

CONSOLE_SCRIPT = "blastradius"


def pyproject_field(name: str) -> str | None:
    """Read one top-level [project] string. Avoids a tomllib import so this
    runs the same on every interpreter the package supports."""
    text = PYPROJECT.read_text()
    project = text.split("[project]", 1)[-1].split("\n[", 1)[0]
    match = re.search(rf'^{name}\s*=\s*"([^"]+)"', project, re.MULTILINE)
    return match.group(1) if match else None


def check() -> list[str]:
    problems: list[str] = []

    if not MARKETPLACE.exists():
        return [f"{MARKETPLACE.relative_to(ROOT)} is missing"]

    marketplace = json.loads(MARKETPLACE.read_text())
    entries = marketplace.get("plugins") or []
    if len(entries) != 1:
        problems.append(f"expected exactly one plugin entry, found {len(entries)}")
        return problems
    entry = entries[0]

    source = entry.get("source")
    if not isinstance(source, str):
        return [f"plugin source must be a relative path, got {source!r}"]
    plugin_root = (ROOT / source).resolve()
    manifest_path = plugin_root / ".claude-plugin" / "plugin.json"
    if not manifest_path.exists():
        return [f"{source} has no .claude-plugin/plugin.json"]
    manifest = json.loads(manifest_path.read_text())

    # 1. One version, three files.
    versions = {
        "pyproject.toml": pyproject_field("version"),
        "plugin.json": manifest.get("version"),
        "marketplace.json": entry.get("version"),
    }
    if len(set(versions.values())) != 1:
        problems.append("versions disagree: "
                        + ", ".join(f"{k}={v}" for k, v in versions.items()))

    # 2. The marketplace entry names the plugin the manifest declares.
    if entry.get("name") != manifest.get("name"):
        problems.append(f"marketplace calls it {entry.get('name')!r} but "
                        f"plugin.json calls it {manifest.get('name')!r}")

    # 3. Components sit where Claude Code looks for them by default. A manifest
    #    that overrides a path is fine; one that silently ships nothing is not.
    for label, relative, override in (
        ("hooks", "hooks/hooks.json", "hooks"),
        ("MCP servers", ".mcp.json", "mcpServers"),
        ("skills", "skills", "skills"),
    ):
        if override in manifest:
            continue
        if not (plugin_root / relative).exists():
            problems.append(f"{label}: {source}/{relative} not found, and "
                            f"plugin.json declares no {override!r} override")

    # 4. The seam. Both halves of the install meet at one command name.
    if pyproject_field("name") and f'{CONSOLE_SCRIPT} = "blastradius.cli:main"' \
            not in PYPROJECT.read_text():
        problems.append(f"pyproject.toml does not declare the "
                        f"{CONSOLE_SCRIPT!r} console script")

    wiring = []
    hooks_file = plugin_root / "hooks" / "hooks.json"
    if hooks_file.exists():
        wiring.append(hooks_file)
    mcp_file = plugin_root / ".mcp.json"
    if mcp_file.exists():
        wiring.append(mcp_file)
    for path in wiring:
        if CONSOLE_SCRIPT not in path.read_text():
            problems.append(f"{path.relative_to(ROOT)} never invokes "
                            f"{CONSOLE_SCRIPT!r} — the plugin cannot reach the package")

    return problems


def main() -> int:
    # The release workflow compares the git tag against this. Parsing it out
    # of the success line would couple a release to prose.
    if "--print-version" in sys.argv:
        version = pyproject_field("version")
        if not version:
            print("could not read version from pyproject.toml", file=sys.stderr)
            return 1
        print(version)
        return 0

    problems = check()
    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok — version {pyproject_field('version')} across pyproject, "
          f"plugin and marketplace; plugin wired to `{CONSOLE_SCRIPT}`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
