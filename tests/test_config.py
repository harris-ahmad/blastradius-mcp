"""Config governs what reaches the model and what reaches disk. A broken config
must never break a hook."""
import json

import pytest

from blastradius import config as cfg


def write(tmp_path, payload):
    path = tmp_path / "config.json"
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
    return path


class TestDefaults:
    def test_absent_file_behaves_as_before(self, tmp_path):
        c = cfg.load(tmp_path / "nope.json")
        assert c.inject.enabled is True
        assert c.inject.max_artifacts == 8
        assert c.inject.types == cfg.ALL_TYPES
        assert c.exclude.repositories == ()

    @pytest.mark.parametrize("broken", ["{ not json", "[]", '"a string"', ""])
    def test_malformed_config_falls_back_silently(self, tmp_path, broken):
        assert cfg.load(write(tmp_path, broken)).inject.enabled is True

    def test_partial_config_keeps_other_defaults(self, tmp_path):
        c = cfg.load(write(tmp_path, {"inject": {"max_artifacts": 3}}))
        assert c.inject.max_artifacts == 3
        assert c.inject.max_consumers == 5
        assert c.inject.enabled is True


class TestInjectControl:
    def test_can_be_turned_off_entirely(self, tmp_path):
        assert cfg.load(write(tmp_path, {"inject": {"enabled": False}})).inject.enabled is False

    def test_limits_which_types_are_surfaced(self, tmp_path):
        c = cfg.load(write(tmp_path, {"inject": {"types": ["terraform_module", "github_action"]}}))
        assert c.inject.types == ("terraform_module", "github_action")

    def test_unknown_types_are_dropped_not_trusted(self, tmp_path):
        c = cfg.load(write(tmp_path, {"inject": {"types": ["terraform_module", "nonsense"]}}))
        assert c.inject.types == ("terraform_module",)

    def test_an_empty_type_list_means_everything_not_nothing(self, tmp_path):
        assert cfg.load(write(tmp_path, {"inject": {"types": []}})).inject.types == cfg.ALL_TYPES

    def test_zero_limits_are_clamped_to_something_usable(self, tmp_path):
        c = cfg.load(write(tmp_path, {"inject": {"max_artifacts": 0, "max_consumers": 0}}))
        assert c.inject.max_artifacts == 1
        assert c.inject.max_consumers == 1


class TestExclusions:
    def test_repository_globs(self, tmp_path):
        c = cfg.load(write(tmp_path, {"exclude": {"repositories": ["acme/internal-*"]}}))
        assert c.exclude.repository("acme/internal-billing") is True
        assert c.exclude.repository("acme/web") is False

    def test_path_globs(self, tmp_path):
        c = cfg.load(write(tmp_path, {"exclude": {"paths": ["vendor/**", "examples/**"]}}))
        assert c.exclude.path("vendor/lib/Dockerfile") is True
        assert c.exclude.path("Dockerfile") is False

    def test_artifact_globs_cover_internal_registries(self, tmp_path):
        c = cfg.load(write(tmp_path, {"exclude": {"artifacts": ["registry.internal.*"]}}))
        assert c.exclude.artifact("registry.internal.acme.io:5000/base") is True
        assert c.exclude.artifact("alpine") is False

    def test_a_bare_string_is_accepted_as_one_pattern(self, tmp_path):
        c = cfg.load(write(tmp_path, {"exclude": {"repositories": "acme/secret"}}))
        assert c.exclude.repository("acme/secret") is True


class TestSeverityThreshold:
    def test_ordering(self, tmp_path):
        c = cfg.load(tmp_path / "none.json")
        assert c.severity_at_least("critical", "high") is True
        assert c.severity_at_least("low", "high") is False
        assert c.severity_at_least("high", "high") is True

    def test_unknown_severity_sorts_lowest(self, tmp_path):
        c = cfg.load(tmp_path / "none.json")
        assert c.severity_at_least("unknown", "low") is False


def test_the_example_config_is_valid(tmp_path):
    """`config --init` must write something the loader accepts."""
    loaded = cfg.load(write(tmp_path, cfg.EXAMPLE))
    assert loaded.inject.enabled is True
    assert loaded.exclude.repositories == ("acme/internal-*",)
