"""Self-test for the fixture grader.

The grader is what certifies extraction quality, so a bug in it is worse than
a bug in extraction: it reports a number nobody can check. It has already had
two — an expectation that could match the same row twice, and a matcher that
did not consume rows — and both showed up as a score that looked fine.

These build an index that is perfect by construction, then damage it in the
two ways that must be caught.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

from grade import grade  # noqa: E402

from blastradius.store import Dependency, Store  # noqa: E402

EXPECTED = json.loads((FIXTURES / "expected.json").read_text())
REPOS = {k: v for k, v in EXPECTED.items() if not k.startswith("_")}


def plain(text: str) -> str:
    """Assertions read the report, not its colour codes."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def first(value):
    """Expectations accept a list when more than one form is fair."""
    return value[0] if isinstance(value, list) else value


def perfect_index(db_path: Path, skip: tuple[str, str] | None = None,
                  plant_trap: str | None = None,
                  strip_spec: tuple[str, str] | None = None) -> Store:
    """An index containing exactly what the ground truth requires.

    `skip` drops one (repo, identifier) so recall must fall; `plant_trap`
    records one forbidden identifier so the trap count must rise;
    `strip_spec` drops the range operator from one pin so specs must fall
    while recall and traps stay perfect.
    """
    store = Store(db_path)
    for repo, spec in REPOS.items():
        deps = []
        for line, want in enumerate(spec["required"], start=1):
            identifier = first(want["identifier"])
            if skip == (repo, identifier):
                continue
            version = first(want["version_spec"])
            if strip_spec == (repo, identifier):
                version = (version or "").lstrip("^~>= ") or None
            deps.append(Dependency(
                type=want["type"],
                identifier=identifier,
                version_spec=version,
                file_path="synthetic",
                line_number=line,
            ))
        if plant_trap and repo == "acme/payments":
            deps.append(Dependency(type="docker_image", identifier=plant_trap,
                                   version_spec=None, file_path="Dockerfile",
                                   line_number=99))
        store.record(repo, deps)
    return store


def test_a_perfect_index_scores_clean(tmp_path, capsys):
    db = tmp_path / "index.db"
    perfect_index(db)

    assert grade(str(db), verbose=False) == 0

    out = plain(capsys.readouterr().out)
    assert "traps   0 false positive(s)" in out
    assert "(100%)" in out


def test_a_missing_artifact_fails_recall(tmp_path, capsys):
    db = tmp_path / "index.db"
    perfect_index(db, skip=("acme/payments", "golang"))

    assert grade(str(db), verbose=False) == 1
    assert "missing docker_image golang" in plain(capsys.readouterr().out)


def test_a_forbidden_identifier_fails_as_a_trap(tmp_path, capsys):
    db = tmp_path / "index.db"
    # "builder" is a Dockerfile stage alias in the payments fixture, not an
    # image. Recording it is the canonical false positive.
    perfect_index(db, plant_trap="builder")

    assert grade(str(db), verbose=False) == 1
    out = plain(capsys.readouterr().out)
    assert "FALSE POSITIVE" in out
    assert "traps   1 false positive(s)" in out


def test_one_stripped_operator_is_enough_to_fail(tmp_path, capsys):
    """The realistic regression is one pin, not the whole corpus."""
    db = tmp_path / "index.db"
    perfect_index(db, strip_spec=("acme/checkout", "express"))

    assert grade(str(db), verbose=False) == 1

    out = plain(capsys.readouterr().out)
    assert "recall  39/39" in out
    assert "specs   38/39" in out
    assert "express spec is '4.19.2', expected '^4.19.2'" in out


def test_an_empty_index_is_reported_rather_than_scored(tmp_path, capsys):
    db = tmp_path / "index.db"
    Store(db)

    assert grade(str(db), verbose=False) == 1
    assert "index is empty" in plain(capsys.readouterr().out)


def test_a_stripped_range_operator_fails(tmp_path, capsys):
    """The failure the grader exists for: full recall, destroyed signal.

    Recall is a perfect 39/39 here and no trap is tripped. Only the specs
    number moves, so it has to gate the exit code or this passes silently.
    """
    db = tmp_path / "index.db"
    store = Store(db)
    for repo, spec in REPOS.items():
        store.record(repo, [
            Dependency(type=want["type"], identifier=first(want["identifier"]),
                       # Drop every range operator, the way a helpful model does.
                       version_spec=(first(want["version_spec"]) or "").lstrip("^~>= ")
                                    or None,
                       file_path="synthetic", line_number=line)
            for line, want in enumerate(spec["required"], start=1)
        ])

    assert grade(str(db), verbose=False) == 1

    out = plain(capsys.readouterr().out)
    assert "recall  39/39" in out           # recall alone would have passed it
    assert "traps   0 false positive(s)" in out
    assert "(74% kept intact)" in out
    assert "express spec is '4.19.2', expected '^4.19.2'" in out


@pytest.mark.parametrize("repo", sorted(REPOS))
def test_every_repo_has_required_artifacts_and_traps(repo):
    """A repo with no traps is not exercising the extraction cases that are
    hard, which is the entire point of the corpus."""
    assert REPOS[repo]["required"], f"{repo} requires nothing"
    assert "forbidden" in REPOS[repo], f"{repo} declares no traps"
