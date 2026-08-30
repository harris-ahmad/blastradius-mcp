"""The cold-start path: filling an index from repos already on disk.

Nothing here spawns a Claude session. What is worth testing is the decision
made *before* one is spawned — which repositories exist, and which of their
manifests are actually still unread — because a wrong answer there is what
turns a bootstrap into a paid session that records nothing.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from blastradius import bootstrap
from blastradius.repo import unread_manifests
from blastradius.store import Dependency, Store


def git_repo(path: Path, remote: str | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(path), "init", "-q"], check=True)
    if remote:
        subprocess.run(["git", "-C", str(path), "remote", "add", "origin", remote],
                       check=True)
    return path


@pytest.fixture
def db(tmp_path, monkeypatch):
    """An index of our own.

    `Store()` resolves its path from a default argument bound at import, so
    setting BLASTRADIUS_DB here would be ignored and every one of these tests
    would read and write the developer's real index.
    """
    path = tmp_path / "index.db"
    monkeypatch.setattr(bootstrap, "Store", lambda: Store(path))
    return path


@pytest.fixture
def workspace(tmp_path, db):
    root = tmp_path / "code"
    root.mkdir()
    return root


class TestFindingRepositories:
    def test_finds_repos_one_level_down(self, workspace):
        git_repo(workspace / "api")
        git_repo(workspace / "web")
        (workspace / "not-a-repo").mkdir()

        found = {p.name for p in bootstrap.find_repositories(workspace)}
        assert found == {"api", "web"}

    def test_does_not_descend_into_a_repo(self, workspace):
        """A repo with a vendored checkout inside it is one project, not two."""
        outer = git_repo(workspace / "monorepo")
        git_repo(outer / "third_party" / "lib")

        found = [p.name for p in bootstrap.find_repositories(workspace)]
        assert found == ["monorepo"]

    def test_skips_dependency_trees_and_dotfiles(self, workspace):
        git_repo(workspace / "node_modules" / "pkg")
        git_repo(workspace / ".cache" / "thing")
        git_repo(workspace / "real")

        found = [p.name for p in bootstrap.find_repositories(workspace)]
        assert found == ["real"]

    def test_depth_is_bounded(self, workspace):
        git_repo(workspace / "a" / "b" / "c" / "d" / "deep")
        assert bootstrap.find_repositories(workspace, max_depth=2) == []


class TestSurvey:
    def test_an_untouched_repo_has_everything_to_read(self, workspace):
        repo = git_repo(workspace / "api", "git@github.com:acme/api.git")
        (repo / "Dockerfile").write_text("FROM alpine:3.19\n")

        candidate = bootstrap.survey([repo])[0]
        assert candidate.repository == "acme/api"
        assert candidate.unseen == ["Dockerfile"]
        assert not candidate.indexed

    def test_a_recorded_manifest_is_not_offered_again(self, workspace, db):
        repo = git_repo(workspace / "api", "git@github.com:acme/api.git")
        (repo / "Dockerfile").write_text("FROM alpine:3.19\n")
        Store(db).record("acme/api", [Dependency(
            type="docker_image", identifier="alpine", version_spec="3.19",
            file_path="Dockerfile", line_number=1)])

        assert bootstrap.survey([repo])[0].indexed


class TestUnreadManifests:
    """The rule the hook and the bootstrap both depend on."""

    @pytest.fixture(autouse=True)
    def _isolate(self, db):
        self.db = db

    def _repo(self, tmp_path, body="FROM alpine:3.19\n"):
        root = tmp_path / "repo"
        root.mkdir()
        (root / "Dockerfile").write_text(body)
        return root

    def test_never_scanned_means_everything_is_unread(self, tmp_path):
        root = self._repo(tmp_path)
        assert unread_manifests(root, "acme/api", set(), None) == ["Dockerfile"]

    def test_a_manifest_that_yielded_rows_is_not_unread(self, tmp_path):
        root = self._repo(tmp_path)
        assert unread_manifests(root, "acme/api", {"Dockerfile"}, None) == []

    def test_a_manifest_that_yields_nothing_is_read_once_not_forever(self, tmp_path):
        """A local Terraform module holding one variable produces no rows
        however carefully it is read. Before the scan stamp it was offered
        again at every Stop, and cost a session on every bootstrap."""
        root = tmp_path / "repo"
        root.mkdir()
        (root / "main.tf").write_text('variable "env" { default = "prod" }\n')

        assert unread_manifests(root, "acme/infra", set(), None) == ["main.tf"]

        Store(self.db).record("acme/infra", [])          # scanned, found nothing
        scanned = Store(self.db).last_scanned("acme/infra")
        assert unread_manifests(root, "acme/infra", set(), scanned) == []

    def test_a_manifest_added_after_the_scan_is_unread(self, tmp_path):
        root = self._repo(tmp_path)
        Store(self.db).record("acme/api", [])
        scanned = Store(self.db).last_scanned("acme/api")
        assert unread_manifests(root, "acme/api", {"Dockerfile"}, scanned) == []

        (root / "Chart.yaml").write_text("name: api\n")
        assert unread_manifests(root, "acme/api", {"Dockerfile"}, scanned) == ["Chart.yaml"]

    def test_a_manifest_changed_after_the_scan_is_unread_again(self, tmp_path):
        import os, time
        root = tmp_path / "repo"
        root.mkdir()
        (root / "main.tf").write_text('variable "env" {}\n')
        Store(self.db).record("acme/infra", [])
        scanned = Store(self.db).last_scanned("acme/infra")
        assert unread_manifests(root, "acme/infra", set(), scanned) == []

        # Edited a second later; the stamp is what it is compared against.
        os.utime(root / "main.tf", (time.time() + 5, time.time() + 5))
        assert unread_manifests(root, "acme/infra", set(), scanned) == ["main.tf"]

    def test_an_unparseable_stamp_falls_back_to_offering_the_file(self, tmp_path):
        root = self._repo(tmp_path)
        assert unread_manifests(root, "acme/api", set(), "not-a-timestamp") == ["Dockerfile"]

    def test_exclusions_are_honoured(self, tmp_path):
        root = self._repo(tmp_path)
        assert unread_manifests(root, "acme/api", set(), None,
                                exclude=lambda p: p == "Dockerfile") == []


class TestIndexGuards:
    def test_a_path_that_is_not_a_directory_fails(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("x")
        assert bootstrap.index(str(target)) == 1

    def test_a_directory_with_no_repositories_fails(self, workspace):
        assert bootstrap.index(str(workspace)) == 1

    def test_dry_run_starts_no_sessions(self, workspace, monkeypatch, capsys):
        repo = git_repo(workspace / "api", "git@github.com:acme/api.git")
        (repo / "Dockerfile").write_text("FROM alpine:3.19\n")

        # `git` still has to run — resolving the repo name needs it. Only a
        # Claude session is forbidden here.
        real_run = bootstrap.subprocess.run

        def guard(command, *a, **k):
            if "claude" in str(command[0]):
                raise AssertionError("--dry-run must not spawn a session")
            return real_run(command, *a, **k)
        monkeypatch.setattr(bootstrap.subprocess, "run", guard)

        assert bootstrap.index(str(workspace), dry_run=True) == 0
        assert "no sessions were started" in capsys.readouterr().out

    def test_a_missing_claude_cli_is_named_not_crashed(self, workspace, monkeypatch, capsys):
        git_repo(workspace / "api", "git@github.com:acme/api.git")
        monkeypatch.setattr(bootstrap.shutil, "which", lambda _: None)

        assert bootstrap.index(str(workspace)) == 1
        assert "not on PATH" in capsys.readouterr().out
