"""Regression tests for the two classification bugs in the original BlastRadius."""
import pytest

from blastradius.scoring import classify_pinning, worst_quality


class TestNpmRangesAreNotExact:
    """The original stripped `^~><=` before classifying, so every caret range
    was reported as an exact pin. 128 of 129 npm packages read 'exact'."""

    @pytest.mark.parametrize("spec", [
        "^18.2.0", "~1.2.3", ">=1.0.0", "<2.0.0", ">=1.0.0 <2.0.0",
        "1.x", "1.2.x", "*", "^0.8.0", "~> 3.0", "1 || 2", "1.0.0 - 2.0.0",
    ])
    def test_ranges_are_never_exact(self, spec):
        assert classify_pinning(spec, "npm_package") != "exact"

    @pytest.mark.parametrize("spec", ["18.2.0", "3.864.0", "0.213.0", "1.9.0"])
    def test_bare_versions_are_exact(self, spec):
        assert classify_pinning(spec, "npm_package") == "exact"

    def test_caret_is_partial_not_exact(self):
        assert classify_pinning("^18.2.0", "npm_package") == "partial"

    def test_star_is_unpinned(self):
        assert classify_pinning("*", "npm_package") == "unpinned"


class TestTerraform:
    def test_equals_pins_a_point(self):
        assert classify_pinning("= 5.0.0", "terraform_module") == "exact"

    def test_pessimistic_constraint_is_partial(self):
        assert classify_pinning("~> 5.0", "terraform_module") == "partial"

    def test_gte_is_partial(self):
        assert classify_pinning(">= 5.0.0", "terraform_module") == "partial"

    def test_missing_version_is_unknown_not_a_guess(self):
        assert classify_pinning(None, "terraform_module") == "unknown"


class TestDocker:
    def test_digest_is_sha(self):
        assert classify_pinning("sha256:" + "a" * 64, "docker_image") == "sha"

    def test_latest_is_unpinned(self):
        assert classify_pinning("latest", "docker_image") == "unpinned"

    def test_no_tag_means_implicit_latest(self):
        assert classify_pinning(None, "docker_image") == "unpinned"

    def test_dated_tag_is_a_point(self):
        assert classify_pinning("bookworm-20260112", "docker_image") == "partial"

    def test_full_semver_tag_is_exact(self):
        assert classify_pinning("3.22.2", "docker_image") == "exact"


class TestGitHubActions:
    def test_commit_sha_is_sha(self):
        assert classify_pinning("a" * 40, "github_action") == "sha"

    def test_major_tag_moves(self):
        assert classify_pinning("v4", "github_action") == "partial"

    def test_full_tag_is_exact(self):
        assert classify_pinning("v4.1.0", "github_action") == "exact"

    def test_branch_ref_is_unpinned(self):
        assert classify_pinning("main", "github_action") == "unpinned"


def test_worst_quality_picks_the_riskiest():
    assert worst_quality(["sha", "exact", "unpinned"]) == "unpinned"
    assert worst_quality(["sha", "exact"]) == "exact"
    assert worst_quality([]) == "unknown"
