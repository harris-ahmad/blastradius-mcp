import json
import subprocess

import pytest

from blastradius import hooks
from blastradius.store import Dependency, Store


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A real git repo with a real remote, plus an index pointed at tmp."""
    root = tmp_path / "api"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("uses: actions/checkout@v4\n")
    (root / "Dockerfile").write_text("FROM alpine:3.19\n")
    for cmd in (["init", "-q", "-b", "main"],
                ["remote", "add", "origin", "git@github.com:org/api.git"]):
        subprocess.run(["git", "-C", str(root), *cmd], check=True, capture_output=True)

    db = tmp_path / "index.db"
    monkeypatch.setenv("BLASTRADIUS_DB", str(db))
    monkeypatch.setattr(hooks, "Store", lambda: Store(db))
    return root, db


def dep(type_, ident, spec, path, line=1):
    return Dependency(type=type_, identifier=ident, version_spec=spec,
                      file_path=path, line_number=line)


class TestInject:
    def test_ignores_non_manifest_files(self, repo):
        root, _ = repo
        out = hooks.inject({"cwd": str(root), "tool_input": {"file_path": str(root / "README.md")}})
        assert "hookSpecificOutput" not in out

    def test_stays_quiet_when_nothing_else_consumes_it(self, repo):
        root, db = repo
        Store(db).record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile")])
        out = hooks.inject({"cwd": str(root), "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "hookSpecificOutput" not in out

    def test_pushes_cross_repo_impact_unprompted(self, repo):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        store.record("org/web", [dep("docker_image", "alpine", "latest", "Dockerfile", 1)])
        store.record("org/jobs", [dep("docker_image", "alpine", "3.19", "build/Dockerfile", 4)])

        out = hooks.inject({
            "cwd": str(root),
            "tool_input": {"file_path": str(root / "Dockerfile")},
        })

        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert "alpine" in ctx
        assert "2 other repo(s)" in ctx
        assert "org/web" in ctx and "org/jobs" in ctx
        # Worst pinning surfaces first — org/web floats on `latest`.
        assert ctx.index("org/web") < ctx.index("org/jobs")
        assert "unpinned" in ctx

    def test_surfaces_open_cves(self, repo):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("github_action", "actions/checkout", "v4",
                                     ".github/workflows/ci.yml", 1)])
        store.record("org/web", [dep("github_action", "actions/checkout", "v4",
                                     ".github/workflows/ci.yml", 1)])
        artifact_id = store.monitorable_artifacts()[0]["id"]
        store.add_alert(artifact_id, {"id": "GHSA-xxxx", "cve_id": "CVE-2026-1",
                                      "severity": "high", "summary": "bad"})

        out = hooks.inject({
            "cwd": str(root),
            "tool_input": {"file_path": str(root / ".github/workflows/ci.yml")},
        })
        assert "CVE-2026-1" in out["hookSpecificOutput"]["additionalContext"]


class TestCapture:
    def test_flags_manifests_missing_from_the_index(self, repo):
        root, _ = repo
        out = hooks.capture({"cwd": str(root)})
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "Dockerfile" in ctx
        assert ".github/workflows/ci.yml" in ctx
        assert "record_dependencies" in ctx

    def test_quiet_once_everything_is_indexed(self, repo):
        root, db = repo
        Store(db).record("org/api", [
            dep("docker_image", "alpine", "3.19", "Dockerfile"),
            dep("github_action", "actions/checkout", "v4", ".github/workflows/ci.yml"),
        ])
        assert "hookSpecificOutput" not in hooks.capture({"cwd": str(root)})


class TestRobustness:
    def test_a_broken_payload_never_breaks_the_session(self, repo, capsys):
        hooks.run("inject")  # empty stdin
        assert json.loads(capsys.readouterr().out)["continue"] is True

    def test_unknown_hook_name_passes_through(self, capsys):
        hooks.run("nope")
        assert json.loads(capsys.readouterr().out)["continue"] is True
