"""Wiring BlastRadius into a local Claude Code setup.

Editing settings.json by hand is the step most likely to half-work: a bare
`blastradius` that is not on Claude Code's PATH fails silently, and a silently
failing hook looks exactly like a hook with nothing to say. So this does the
merge, and `doctor` proves the result by actually executing the hooks.

Nothing here overwrites a settings file wholesale. Existing keys and other
people's hooks are preserved; only entries this tool owns are replaced.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

MARKER = "blastradius hook"          # identifies entries we own
SERVER_NAME = "blastradius"

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
)
TICK, CROSS, WARN = f"{GREEN}✓{OFF}", f"{RED}✗{OFF}", f"{YELLOW}!{OFF}"


def config_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))


def settings_path() -> Path:
    return config_dir() / "settings.json"


def binary_path() -> str:
    """Absolute path to this installation's entry point.

    Resolved from the running interpreter rather than PATH, so it stays correct
    inside a venv that Claude Code will not have activated.
    """
    candidate = Path(sys.executable).parent / "blastradius"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("blastradius")
    if found:
        return found
    return f"{sys.executable} -m blastradius.cli"


def hook_entries(binary: str) -> dict[str, list[dict]]:
    return {
        "PreToolUse": [{
            "matcher": "Read|Edit",
            "hooks": [{"type": "command", "command": f"{binary} hook inject", "timeout": 5}],
        }],
        "Stop": [{
            "hooks": [{"type": "command", "command": f"{binary} hook capture", "timeout": 10}],
        }],
    }


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{CROSS} {path} is not valid JSON ({exc}).\n"
            f"  Fix or move it before installing — refusing to overwrite it."
        )


def _strip_ours(settings: dict) -> int:
    """Remove hook entries this tool owns. Returns how many were removed."""
    removed = 0
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 0

    for event, groups in list(hooks.items()):
        if not isinstance(groups, list):
            continue
        surviving_groups = []
        for group in groups:
            if not isinstance(group, dict):
                surviving_groups.append(group)
                continue
            inner = group.get("hooks", [])
            kept = [
                h for h in inner
                if not (isinstance(h, dict) and MARKER in str(h.get("command", "")))
            ]
            removed += len(inner) - len(kept)
            if kept:
                surviving_groups.append({**group, "hooks": kept})
            elif not inner:
                surviving_groups.append(group)
        if surviving_groups:
            hooks[event] = surviving_groups
        else:
            del hooks[event]

    if not hooks:
        settings.pop("hooks", None)
    return removed


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = path.with_suffix(f".json.bak-{stamp}")
    shutil.copy2(path, target)
    return target


def install(dry_run: bool = False) -> int:
    path = settings_path()
    binary = binary_path()
    settings = _load(path)

    replaced = _strip_ours(settings)
    settings.setdefault("hooks", {})
    for event, groups in hook_entries(binary).items():
        settings["hooks"].setdefault(event, []).extend(groups)

    rendered = json.dumps(settings, indent=2) + "\n"

    if dry_run:
        print(f"{DIM}would write {path}{OFF}\n")
        print(rendered)
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup(path)
    path.write_text(rendered)

    print(f"{TICK} hooks {'updated' if replaced else 'added'} in {path}")
    print(f"  {DIM}using {binary}{OFF}")
    if backup:
        print(f"  {DIM}previous settings backed up to {backup.name}{OFF}")

    _register_mcp(binary)

    print(f"\n{BOLD}Restart Claude Code, then run:{OFF} blastradius doctor")
    return 0


def _register_mcp(binary: str) -> None:
    claude = shutil.which("claude")
    if not claude:
        print(f"{WARN} `claude` not on PATH — register the MCP server yourself:")
        print(f"    claude mcp add --scope user {SERVER_NAME} -- {binary} serve")
        return

    existing = subprocess.run([claude, "mcp", "list"], capture_output=True, text=True)
    if SERVER_NAME in existing.stdout:
        print(f"{TICK} MCP server already registered")
        return

    result = subprocess.run(
        [claude, "mcp", "add", "--scope", "user", SERVER_NAME, "--", binary, "serve"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"{TICK} MCP server registered")
    else:
        detail = (result.stderr or result.stdout).strip().splitlines()
        print(f"{WARN} could not register the MCP server automatically"
              + (f" ({detail[-1]})" if detail else ""))
        print(f"    run: claude mcp add --scope user {SERVER_NAME} -- {binary} serve")


def uninstall() -> int:
    path = settings_path()
    settings = _load(path)
    removed = _strip_ours(settings)

    if removed:
        _backup(path)
        path.write_text(json.dumps(settings, indent=2) + "\n")
        print(f"{TICK} removed {removed} hook(s) from {path}")
    else:
        print(f"{DIM}no BlastRadius hooks found in {path}{OFF}")

    claude = shutil.which("claude")
    if claude:
        result = subprocess.run([claude, "mcp", "remove", "--scope", "user", SERVER_NAME],
                                capture_output=True, text=True)
        print(f"{TICK} MCP server removed" if result.returncode == 0
              else f"{DIM}MCP server was not registered{OFF}")

    print(f"\n{DIM}The index at ~/.blastradius/ was left alone. "
          f"Delete it manually if you want a clean slate.{OFF}")
    return 0


def doctor() -> int:
    """Check the wiring, and prove it by running the hooks for real."""
    from .store import Store

    problems = 0
    binary = binary_path()
    print(f"{BOLD}binary{OFF}")
    if Path(binary.split()[0]).exists():
        print(f"  {TICK} {binary}")
    else:
        print(f"  {CROSS} not found: {binary}")
        problems += 1

    print(f"\n{BOLD}settings{OFF}")
    path = settings_path()
    settings = _load(path)
    found_events = []
    for event, groups in (settings.get("hooks") or {}).items():
        for group in groups if isinstance(groups, list) else []:
            for hook in (group.get("hooks") or []) if isinstance(group, dict) else []:
                if MARKER in str(hook.get("command", "")):
                    found_events.append(event)
    for wanted in ("PreToolUse", "Stop"):
        if wanted in found_events:
            print(f"  {TICK} {wanted} hook registered")
        else:
            print(f"  {CROSS} {wanted} hook missing — run: blastradius install")
            problems += 1

    print(f"\n{BOLD}hooks actually run{OFF}")
    for name in ("inject", "capture"):
        try:
            result = subprocess.run(
                [*binary.split(), "hook", name],
                input=json.dumps({"cwd": str(Path.cwd()), "tool_input": {}}),
                capture_output=True, text=True, timeout=15,
            )
            payload = json.loads(result.stdout)
            assert payload.get("continue") is True
            print(f"  {TICK} {name} returned valid hook JSON")
        except Exception as exc:
            print(f"  {CROSS} {name} failed: {type(exc).__name__}: {exc}")
            problems += 1

    print(f"\n{BOLD}mcp server{OFF}")
    claude = shutil.which("claude")
    if not claude:
        print(f"  {WARN} `claude` not on PATH — cannot check")
    else:
        listing = subprocess.run([claude, "mcp", "list"], capture_output=True, text=True)
        if SERVER_NAME in listing.stdout:
            print(f"  {TICK} registered")
        else:
            print(f"  {CROSS} not registered — run: blastradius install")
            problems += 1

    print(f"\n{BOLD}index{OFF}")
    stats = Store().stats()
    if stats["references"]:
        print(f"  {TICK} {stats['repositories']} repo(s), {stats['artifacts']} artifact(s), "
              f"{stats['references']} reference(s)")
    else:
        print(f"  {WARN} empty — nothing captured yet, so inject will stay silent")

    print()
    if problems:
        print(f"{RED}{problems} problem(s).{OFF}")
        return 1
    print(f"{GREEN}All wired up.{OFF}")
    return 0
