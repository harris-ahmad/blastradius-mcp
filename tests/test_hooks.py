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


class TestDebugNarration:
    """Both hooks pass through silently by design, so 'quiet' must be explainable."""

    def _run(self, monkeypatch, capsys, payload, db):
        monkeypatch.setattr(hooks, "DEBUG", True)
        hooks.inject(payload)
        return capsys.readouterr().err

    def test_names_an_empty_index(self, repo, monkeypatch, capsys, tmp_path):
        root, _ = repo
        empty = tmp_path / "empty.db"
        monkeypatch.setattr(hooks, "Store", lambda: Store(empty))
        err = self._run(monkeypatch, capsys,
                        {"cwd": str(root), "tool_input": {"file_path": str(root / "Dockerfile")}}, empty)
        assert "index is EMPTY" in err

    def test_lists_known_files_when_this_one_is_unindexed(self, repo, monkeypatch, capsys):
        root, db = repo
        Store(db).record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile")])
        err = self._run(monkeypatch, capsys,
                        {"cwd": str(root),
                         "tool_input": {"file_path": str(root / ".github/workflows/ci.yml")}}, db)
        assert "no artifacts recorded for this file" in err
        assert "Dockerfile" in err

    def test_explains_correct_silence_when_sole_consumer(self, repo, monkeypatch, capsys):
        root, db = repo
        Store(db).record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile")])
        err = self._run(monkeypatch, capsys,
                        {"cwd": str(root), "tool_input": {"file_path": str(root / "Dockerfile")}}, db)
        assert "no OTHER repo consumes them" in err

    def test_rejects_non_manifests_by_name(self, repo, monkeypatch, capsys):
        root, db = repo
        err = self._run(monkeypatch, capsys,
                        {"cwd": str(root), "tool_input": {"file_path": str(root / "README.md")}}, db)
        assert "not a manifest file" in err

    def test_silent_when_debug_is_off(self, repo, capsys):
        root, _ = repo
        hooks.inject({"cwd": str(root), "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert capsys.readouterr().err == ""


class TestConfigGovernsInjection:
    def _with_config(self, monkeypatch, **inject):
        from blastradius.config import Config, ExcludeConfig, InjectConfig
        exclude = inject.pop("exclude", ExcludeConfig())
        monkeypatch.setattr(hooks, "load_config",
                            lambda: Config(inject=InjectConfig(**inject), exclude=exclude))

    def _shared(self, db):
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        store.record("org/web", [dep("docker_image", "alpine", "latest", "Dockerfile", 1)])

    def test_injection_can_be_disabled(self, repo, monkeypatch):
        root, db = repo
        self._shared(db)
        self._with_config(monkeypatch, enabled=False)
        out = hooks.inject({"cwd": str(root),
                            "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "hookSpecificOutput" not in out

    def test_types_can_be_narrowed(self, repo, monkeypatch):
        root, db = repo
        self._shared(db)
        self._with_config(monkeypatch, types=("terraform_module",))
        out = hooks.inject({"cwd": str(root),
                            "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "hookSpecificOutput" not in out

    def test_an_excluded_repository_is_silent(self, repo, monkeypatch):
        from blastradius.config import ExcludeConfig
        root, db = repo
        self._shared(db)
        self._with_config(monkeypatch, exclude=ExcludeConfig(repositories=("org/api",)))
        out = hooks.inject({"cwd": str(root),
                            "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "hookSpecificOutput" not in out

    def test_an_excluded_artifact_is_silent(self, repo, monkeypatch):
        from blastradius.config import ExcludeConfig
        root, db = repo
        self._shared(db)
        self._with_config(monkeypatch, exclude=ExcludeConfig(artifacts=("alp*",)))
        out = hooks.inject({"cwd": str(root),
                            "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "hookSpecificOutput" not in out

    def test_consumer_limit_is_respected(self, repo, monkeypatch):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        for i in range(5):
            store.record(f"org/other{i}", [dep("docker_image", "alpine", "latest", "Dockerfile", 1)])
        self._with_config(monkeypatch, max_consumers=2)
        out = hooks.inject({"cwd": str(root),
                            "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "…and 3 more" in out["hookSpecificOutput"]["additionalContext"]

    def test_capture_skips_excluded_repositories(self, repo, monkeypatch):
        from blastradius.config import ExcludeConfig
        root, _ = repo
        self._with_config(monkeypatch, exclude=ExcludeConfig(repositories=("org/api",)))
        assert "hookSpecificOutput" not in hooks.capture({"cwd": str(root)})


class TestRelevanceRanking:
    """Injected context is capped, so what gets cut matters more than what fits."""

    def test_an_advisory_outranks_breadth_of_use(self):
        cve_only = {"worst_severity": "critical", "other_consumers": 0, "version_spread": 1}
        popular = {"worst_severity": None, "other_consumers": 5, "version_spread": 2}
        assert hooks._relevance(cve_only) > hooks._relevance(popular)

    def test_more_consumers_outranks_fewer(self):
        assert hooks._relevance({"other_consumers": 5}) > hooks._relevance({"other_consumers": 1})

    def test_drift_counts_against_an_artifact(self):
        drifting = {"other_consumers": 2, "version_spread": 3}
        aligned = {"other_consumers": 2, "version_spread": 1}
        assert hooks._relevance(drifting) > hooks._relevance(aligned)

    def test_severity_ordering(self):
        scores = [hooks._relevance({"worst_severity": s})
                  for s in ("critical", "high", "medium", "low")]
        assert scores == sorted(scores, reverse=True)

    def test_an_unremarkable_artifact_scores_zero(self):
        assert hooks._relevance({"other_consumers": 0, "version_spread": 1}) == 0

    def test_the_important_ones_survive_the_cap(self, repo, monkeypatch):
        """Ten dependencies, room for two: the CVE and the drifting one."""
        from blastradius.config import Config, InjectConfig
        root, db = repo
        store = Store(db)
        boring = [dep("npm_package", n, "1.0.0", "package.json", i + 1)
                  for i, n in enumerate("abcdefgh")]
        store.record("org/api", [
            *boring,
            dep("npm_package", "lodash", "^4.17.20", "package.json", 9),
            dep("npm_package", "vite", "^5.2.0", "package.json", 10),
        ])
        store.record("org/web", [dep("npm_package", "lodash", "latest", "package.json", 1)])
        store.record("org/ops", [dep("npm_package", "vite", "^5.0.0", "package.json", 1)])
        vite_id = next(a["id"] for a in store.monitorable_artifacts()
                       if a["identifier"] == "vite")
        store.add_alert(vite_id, {"id": "X", "severity": "critical", "summary": "RCE"}, ["^5.2.0"])

        monkeypatch.setattr(hooks, "load_config",
                            lambda: Config(inject=InjectConfig(max_artifacts=2)))
        (root / "package.json").write_text("{}")
        out = hooks.inject({"cwd": str(root),
                            "tool_input": {"file_path": str(root / "package.json")}})

        context = out["hookSpecificOutput"]["additionalContext"]
        assert "vite" in context and "lodash" in context
        assert context.index("vite") < context.index("lodash")   # CVE ranks first
        for name in "abcdefgh":
            assert f"`{name}`" not in context


class TestSessionDeduplication:
    """Agents re-read manifests constantly. The second injection tells them
    nothing the first did not, and costs the same context."""

    def _shared(self, db):
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        store.record("org/web", [dep("docker_image", "alpine", "latest", "Dockerfile", 1)])

    def _read(self, root, session="s1"):
        return hooks.inject({"session_id": session, "cwd": str(root),
                             "tool_input": {"file_path": str(root / "Dockerfile")}})

    def test_first_read_injects(self, repo):
        root, db = repo
        self._shared(db)
        assert "hookSpecificOutput" in self._read(root)

    def test_second_read_in_the_same_session_is_silent(self, repo):
        root, db = repo
        self._shared(db)
        self._read(root)
        assert "hookSpecificOutput" not in self._read(root)

    def test_a_new_session_injects_again(self, repo):
        root, db = repo
        self._shared(db)
        self._read(root, "s1")
        assert "hookSpecificOutput" in self._read(root, "s2")

    def test_a_different_file_still_injects(self, repo):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1),
                                 dep("github_action", "actions/checkout", "v4",
                                     ".github/workflows/ci.yml", 1)])
        store.record("org/web", [dep("docker_image", "alpine", "latest", "Dockerfile", 1),
                                 dep("github_action", "actions/checkout", "main",
                                     ".github/workflows/ci.yml", 1)])
        self._read(root)
        out = hooks.inject({"session_id": "s1", "cwd": str(root),
                            "tool_input": {"file_path": str(root / ".github/workflows/ci.yml")}})
        assert "hookSpecificOutput" in out

    def test_without_a_session_id_it_cannot_dedupe(self, repo):
        """No session means no way to know it is a repeat — inject rather than
        silently withhold."""
        root, db = repo
        self._shared(db)
        first = hooks.inject({"cwd": str(root),
                              "tool_input": {"file_path": str(root / "Dockerfile")}})
        second = hooks.inject({"cwd": str(root),
                               "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert "hookSpecificOutput" in first
        assert "hookSpecificOutput" in second


class TestInjectionAccounting:
    def test_what_was_sent_is_recorded(self, repo):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        store.record("org/web", [dep("docker_image", "alpine", "latest", "Dockerfile", 1)])
        out = hooks.inject({"session_id": "s1", "cwd": str(root),
                            "tool_input": {"file_path": str(root / "Dockerfile")}})

        stats = store.injection_stats()
        assert stats["sent"] == 1
        assert stats["sessions"] == 1
        # The recorded size must match what actually went to the model.
        assert stats["characters"] == len(out["hookSpecificOutput"]["additionalContext"])

    def test_suppressed_repeats_are_counted_separately(self, repo):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        store.record("org/web", [dep("docker_image", "alpine", "latest", "Dockerfile", 1)])
        for _ in range(4):
            hooks.inject({"session_id": "s1", "cwd": str(root),
                          "tool_input": {"file_path": str(root / "Dockerfile")}})
        stats = store.injection_stats()
        assert stats["sent"] == 1
        assert stats["suppressed"] == 3

    def test_a_quiet_hook_costs_nothing_and_records_nothing(self, repo):
        root, db = repo
        store = Store(db)
        store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        hooks.inject({"session_id": "s1", "cwd": str(root),
                      "tool_input": {"file_path": str(root / "Dockerfile")}})
        assert store.injection_stats()["sent"] == 0
