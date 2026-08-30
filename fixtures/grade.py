#!/usr/bin/env python3
"""Score what capture actually extracted against the fixture ground truth.

    python3 fixtures/grade.py [--db PATH] [--verbose]

Three numbers that matter, per repo and overall:

  recall     of the artifacts that are really there, how many were found
  traps      stage aliases, local paths and heredoc text wrongly recorded
  specs      of the ones found, how many kept the version string intact

`specs` is the one to watch. A model that quietly normalises `^18.2.0` to
`18.2.0` scores full recall while destroying the signal the whole tool is for.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from blastradius.store import Store  # noqa: E402

EXPECTED = Path(__file__).resolve().parent / "expected.json"

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
)


def as_list(value):
    if value is None:
        return [None]
    return value if isinstance(value, list) else [value]


def normalise(spec):
    """Compare version specs ignoring only whitespace — never operators."""
    return None if spec is None else "".join(str(spec).split())


def find_match(want, actual_rows, claimed):
    """An unclaimed row matching this expectation on type + identifier.

    Rows are consumed as they match. Without that, two expectations that share
    an acceptable identifier — a Terraform submodule and its parent, say — both
    match the same row and one is scored against the other's version.
    """
    identifiers = {i.lower() for i in as_list(want["identifier"])}
    for index, row in enumerate(actual_rows):
        if index in claimed or row["type"] != want["type"]:
            continue
        if row["identifier"].lower() in identifiers:
            claimed.add(index)
            return row
    return None


def grade(db_path: str | None, verbose: bool) -> int:
    expected = json.loads(EXPECTED.read_text())
    store = Store(db_path) if db_path else Store()

    rows_by_repo: dict[str, list[dict]] = {}
    for row in store.all_dependencies():
        rows_by_repo.setdefault(row["repository"], []).append(row)

    if not rows_by_repo:
        print(f"{RED}The index is empty.{OFF} Run capture over the fixture repos first.")
        return 1

    totals = {"required": 0, "found": 0, "spec_ok": 0, "traps": 0, "unindexed": 0}
    problems: list[str] = []

    for repo, spec in expected.items():
        if repo.startswith("_"):
            continue
        actual = rows_by_repo.get(repo)
        if actual is None:
            totals["unindexed"] += 1
            totals["required"] += len(spec["required"])
            print(f"{DIM}{repo:<24} not indexed{OFF}")
            continue

        found = spec_ok = 0
        claimed: set[int] = set()
        for want in spec["required"]:
            totals["required"] += 1
            match = find_match(want, actual, claimed)
            if match is None:
                problems.append(f"{repo}: missing {want['type']} {as_list(want['identifier'])[0]}")
                continue
            found += 1
            acceptable = {normalise(v) for v in as_list(want["version_spec"])}
            if normalise(match["version_spec"]) in acceptable:
                spec_ok += 1
            else:
                problems.append(
                    f"{repo}: {match['identifier']} spec is "
                    f"{match['version_spec']!r}, expected {as_list(want['version_spec'])[0]!r}"
                )

        forbidden = {f.lower() for f in spec["forbidden"]}
        traps = [r for r in actual if r["identifier"].lower() in forbidden]
        for trap in traps:
            problems.append(
                f"{repo}: FALSE POSITIVE {trap['identifier']!r} "
                f"({trap['file_path']}:{trap['line_number']})"
            )

        totals["found"] += found
        totals["spec_ok"] += spec_ok
        totals["traps"] += len(traps)

        need = len(spec["required"])
        colour = GREEN if found == need and not traps else (RED if traps else YELLOW)
        print(f"{colour}{repo:<24}{OFF} "
              f"recall {found}/{need}   specs {spec_ok}/{max(found,1)}   "
              f"traps {len(traps)}")

    print()
    need = totals["required"]
    pct = (100 * totals["found"] / need) if need else 0
    spec_pct = (100 * totals["spec_ok"] / totals["found"]) if totals["found"] else 0
    print(f"{BOLD}recall{OFF}  {totals['found']}/{need}  ({pct:.0f}%)")
    print(f"{BOLD}specs{OFF}   {totals['spec_ok']}/{totals['found']}  ({spec_pct:.0f}% kept intact)")
    print(f"{BOLD}traps{OFF}   {totals['traps']} false positive(s)")
    if totals["unindexed"]:
        print(f"{DIM}{totals['unindexed']} repo(s) not indexed yet{OFF}")

    if problems and (verbose or len(problems) <= 25):
        print()
        for line in problems:
            marker = RED if "FALSE POSITIVE" in line else YELLOW
            print(f"  {marker}·{OFF} {line}")
    elif problems:
        print(f"\n{DIM}{len(problems)} problems — rerun with --verbose{OFF}")

    return 0 if (totals["traps"] == 0 and totals["found"] == need) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=None, help="Index path (default: ~/.blastradius/index.db)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    sys.exit(grade(args.db, args.verbose))
