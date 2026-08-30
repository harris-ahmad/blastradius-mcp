"""Fill the index from repositories you already have on disk.

The hooks only learn about a repository once you open it in Claude Code, and
capture runs at Stop — after the reads. So a fresh install is correct and
completely silent: nothing is indexed, injection needs a *second* repository
before it has anything cross-repo to say, and the first useful moment is days
away. "Installed it, nothing happened" is a fair description of week one.

This walks a directory of repositories and runs one headless Claude session in
each, letting the same Stop hook do the capture. Extraction stays the model's
job — the thing that handles stage aliases, templated bases and heredocs that
a regex parser gets wrong — so a bootstrapped index is the same index the
hooks would have built, only sooner.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .config import load as load_config
from .repo import resolve_repository, unread_manifests
from .store import Store

TICK, CROSS, WARN = "\033[32m✓\033[0m", "\033[31m✗\033[0m", "\033[33m!\033[0m"
BOLD, DIM, OFF = "\033[1m", "\033[2m", "\033[0m"

# Reading is all this needs. Denying the write tools means a bootstrap can
# never modify a repository it was only meant to look at.
ALLOWED = ("Read,Glob,Grep,"
           "mcp__blastradius__record_dependencies,mcp__blastradius__blast_radius")
DENIED = "Write,Edit,NotebookEdit,Bash"

PROMPT = (
    "Inventory this repository's external dependencies: base images, Terraform "
    "modules, GitHub Actions, Helm charts and package manifests. Read the files "
    "that declare them and list what is pinned, with the version each is pinned "
    "to, exactly as written."
)

_SKIP_DIRS = {"node_modules", "vendor", ".terraform", "dist", "build",
              "__pycache__", ".venv", "target", ".cache", "Library"}


@dataclass
class Candidate:
    root: Path
    repository: str
    unseen: list[str]          # manifests the index has not recorded yet

    @property
    def indexed(self) -> bool:
        return not self.unseen


def find_repositories(root: Path, max_depth: int = 3) -> list[Path]:
    """Git repositories under `root`, not descending into one once found.

    A monorepo with vendored submodules would otherwise be walked as dozens of
    separate projects, and the vendored copies are not what anyone means by
    "my repositories".
    """
    found: list[Path] = []

    def walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        if (directory / ".git").exists():
            found.append(directory)
            return
        try:
            entries = sorted(p for p in directory.iterdir() if p.is_dir())
        except (PermissionError, OSError):
            return
        for entry in entries:
            if entry.name in _SKIP_DIRS or entry.name.startswith("."):
                continue
            walk(entry, depth + 1)

    walk(root, 0)
    return found


def survey(paths: list[Path]) -> list[Candidate]:
    """What each repository is, and what the index is still missing from it."""
    store = Store()
    config = load_config()

    known: dict[str, set[str]] = {}
    for row in store.all_dependencies():
        known.setdefault(row["repository"], set()).add(row["file_path"])

    candidates = []
    for root in paths:
        repository = resolve_repository(root)
        if not repository or config.exclude.repository(repository):
            continue
        unseen = unread_manifests(root, repository, known.get(repository, set()),
                                  store.last_scanned(repository),
                                  exclude=config.exclude.path)
        candidates.append(Candidate(root=root, repository=repository, unseen=unseen))
    return candidates


def _references() -> int:
    return int(Store().stats().get("references", 0))


def index(directory: str, dry_run: bool = False, limit: int | None = None,
          timeout: int = 300, force: bool = False) -> int:
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        print(f"{CROSS} not a directory: {root}")
        return 1

    claude = shutil.which("claude")
    if not claude and not dry_run:
        print(f"{CROSS} `claude` is not on PATH")
        print(f"  {DIM}bootstrapping runs a headless Claude session per repository,")
        print(f"  so it needs the Claude Code CLI installed.{OFF}")
        return 1

    repositories = find_repositories(root)
    if not repositories:
        print(f"{CROSS} no git repositories under {root}")
        return 1

    candidates = survey(repositories)
    pending = candidates if force else [c for c in candidates if not c.indexed]
    already = len(candidates) - len(pending)
    if limit:
        pending = pending[:limit]

    print(f"{BOLD}{len(candidates)} repositor{'y' if len(candidates) == 1 else 'ies'} "
          f"under {root}{OFF}")
    if already:
        print(f"  {DIM}{already} already indexed{OFF}")
    if not pending:
        print(f"\n{TICK} nothing to do — run `blastradius stats` to see the index")
        return 0

    for candidate in pending:
        count = len(candidate.unseen)
        print(f"  {candidate.repository:<40} {count} manifest(s) to read")

    if dry_run:
        print(f"\n{DIM}--dry-run: no sessions were started{OFF}")
        return 0

    print(f"\n{BOLD}Indexing {len(pending)}…{OFF} "
          f"{DIM}one headless session each, reading only{OFF}\n")

    started = _references()
    failures = 0
    for position, candidate in enumerate(pending, start=1):
        prefix = f"[{position}/{len(pending)}] {candidate.repository}"
        print(f"{prefix} … ", end="", flush=True)
        before = _references()
        began = time.monotonic()
        try:
            result = subprocess.run(
                [claude, "-p", PROMPT,
                 "--allowedTools", ALLOWED,
                 "--disallowedTools", DENIED,
                 "--permission-mode", "dontAsk"],
                cwd=candidate.root, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"{CROSS} timed out after {timeout}s")
            failures += 1
            continue
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"{CROSS} {exc}")
            failures += 1
            continue

        elapsed = time.monotonic() - began
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            print(f"{CROSS} session failed"
                  + (f" — {detail[-1][:80]}" if detail else ""))
            failures += 1
            continue

        gained = _references() - before
        if gained > 0:
            print(f"{TICK} {gained} reference(s)  {DIM}{elapsed:.0f}s{OFF}")
        else:
            # The session ran but the hook asked for nothing, or the model
            # declined. Not fatal, and worth distinguishing from a crash.
            print(f"{WARN} nothing recorded  {DIM}{elapsed:.0f}s{OFF}")

    total = _references() - started
    print(f"\n{BOLD}{total} reference(s) recorded{OFF}")
    if failures:
        print(f"{WARN} {failures} session(s) failed")

    repositories_indexed = len({c.repository for c in survey(repositories)
                                if c.indexed})
    if repositories_indexed < 2:
        print(f"\n{WARN} cross-repo impact needs two indexed repositories before "
              f"it has anything to say")
    else:
        print(f"\nNext:  blastradius check      {DIM}# match the index against OSV{OFF}")
        print(f"       blastradius hygiene    {DIM}# what is pinned worst{OFF}")

    return 1 if failures and total == 0 else 0
