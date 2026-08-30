#!/usr/bin/env python3
"""Check that the fixture corpus and its ground truth still describe each other.

    python3 fixtures/check-corpus.py [corpus-dir]

`make-fixtures.sh` and `expected.json` are two files that have to agree, and
nothing forces them to. Adding a repo to the generator without ground truth
makes the grader silently ignore it; renaming one makes every expectation for
it read as a recall failure. Both are invisible until a scoring run looks
wrong for reasons that have nothing to do with extraction.

This does not run Claude and does not score anything. It only checks the two
files line up, which is the part CI can settle on its own.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from blastradius.store import ARTIFACT_TYPES, canonical_identifier  # noqa: E402

HERE = Path(__file__).resolve().parent
EXPECTED = HERE / "expected.json"
MAKE = HERE / "make-fixtures.sh"

# Repos are written as bare directory names by the generator and as
# `owner/name` by the ground truth, because that is what the model reports.
OWNER = "acme"


def build_corpus() -> tuple[Path, tempfile.TemporaryDirectory]:
    """Generate a throwaway corpus. Returns the dir and its owning handle,
    which the caller must keep alive."""
    handle = tempfile.TemporaryDirectory(prefix="br-corpus-")
    target = Path(handle.name) / "corpus"
    subprocess.run([str(MAKE), str(target)], check=True,
                   stdout=subprocess.DEVNULL)
    return target, handle


def check_shape(expected: dict) -> list[str]:
    """Every expectation is a well-formed one."""
    problems = []
    for repo, spec in expected.items():
        if repo.startswith("_"):
            continue
        for bucket in ("required", "optional"):
            for want in spec.get(bucket, []):
                where = f"{repo}/{bucket}"
                if want.get("type") not in ARTIFACT_TYPES:
                    problems.append(
                        f"{where}: unknown type {want.get('type')!r} "
                        f"(expected one of {', '.join(ARTIFACT_TYPES)})")
                identifiers = want.get("identifier")
                if not identifiers:
                    problems.append(f"{where}: entry has no identifier")
                    continue
                for ident in (identifiers if isinstance(identifiers, list)
                              else [identifiers]):
                    # An expectation the store can never produce is dead: it
                    # can only ever be scored as missing.
                    canonical = canonical_identifier(want.get("type", ""), ident)
                    if canonical != ident:
                        problems.append(
                            f"{where}: {ident!r} is stored as {canonical!r}, "
                            f"so this expectation can never match")
            if not isinstance(spec.get("forbidden", []), list):
                problems.append(f"{repo}: forbidden must be a list")
    return problems


def check_repos(expected: dict, corpus: Path) -> list[str]:
    """The generated repos and the described repos are the same set."""
    generated = {f"{OWNER}/{p.name}" for p in sorted(corpus.iterdir()) if p.is_dir()}
    described = {k for k in expected if not k.startswith("_")}

    problems = []
    for repo in sorted(described - generated):
        problems.append(f"{repo}: has ground truth but make-fixtures.sh does "
                        f"not generate it")
    for repo in sorted(generated - described):
        problems.append(f"{repo}: generated but has no entry in expected.json, "
                        f"so the grader ignores it entirely")
    return problems


def main() -> int:
    expected = json.loads(EXPECTED.read_text())

    if len(sys.argv) > 1:
        corpus, handle = Path(sys.argv[1]), None
    else:
        corpus, handle = build_corpus()

    try:
        problems = check_shape(expected) + check_repos(expected, corpus)
    finally:
        if handle is not None:
            handle.cleanup()

    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1

    repos = [k for k in expected if not k.startswith("_")]
    wants = sum(len(expected[r]["required"]) for r in repos)
    traps = sum(len(expected[r].get("forbidden", [])) for r in repos)
    print(f"ok — {len(repos)} repos, {wants} required artifacts, {traps} traps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
