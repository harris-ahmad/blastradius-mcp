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


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([-.a-zA-Z0-9]*)$")


def set_version(version: str) -> int:
    """Write one version into all three files that carry it.

    Editing three files by hand is the kind of thing that gets half done, and
    a half-done bump ships differently to each audience: pip users get the new
    release while plugin users stay on the old one, because the marketplace
    entry's version is what gates a plugin update.
    """
    if not VERSION_RE.match(version):
        print(f"{version!r} is not a version like 1.2.3", file=sys.stderr)
        return 1

    marketplace = json.loads(MARKETPLACE.read_text())
    entry = marketplace["plugins"][0]
    plugin_manifest = (ROOT / entry["source"] / ".claude-plugin" / "plugin.json").resolve()
    manifest = json.loads(plugin_manifest.read_text())

    old = pyproject_field("version")
    if old == version:
        print(f"already at {version}")
        return 0

    # pyproject: the first version= under [project], not one in a dependency
    # pin further down the file.
    text = PYPROJECT.read_text()
    head, sep, tail = text.partition("[project]")
    tail, count = re.subn(r'^version\s*=\s*"[^"]+"', f'version = "{version}"',
                          tail, count=1, flags=re.MULTILINE)
    if not count:
        print("could not find a version to replace in pyproject.toml", file=sys.stderr)
        return 1
    PYPROJECT.write_text(head + sep + tail)

    # The JSON files are rewritten through json so a hand-edit elsewhere in
    # them cannot be clobbered by a regex that matched the wrong line.
    manifest["version"] = version
    plugin_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    entry["version"] = version
    MARKETPLACE.write_text(json.dumps(marketplace, indent=2) + "\n")

    print(f"{old} -> {version} in pyproject.toml, plugin.json, marketplace.json")
    print(f"\nnext:  git commit -am 'Release {version}'"
          f" && git tag v{version} && git push origin main v{version}")
    return 0


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
    if "--set-version" in sys.argv:
        index = sys.argv.index("--set-version")
        if index + 1 >= len(sys.argv):
            print("--set-version needs a version, e.g. 0.2.0", file=sys.stderr)
            return 1
        if set_version(sys.argv[index + 1]):
            return 1
        # Writing all three is only half the promise; prove they agree.
        return 0 if not check() else 1

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
