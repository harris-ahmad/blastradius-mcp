"""Version logic decides whether a security alert is shown. Uncertainty must
always fail toward showing it."""
import pytest

from blastradius.semver import (
    AFFECTED, NOT_AFFECTED, UNKNOWN,
    compare, floor_of, parse, spec_is_affected, version_is_affected,
)

# The real lodash ReDoS advisory: everything below 4.17.21.
LODASH = [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]


class TestParsing:
    @pytest.mark.parametrize("raw,expected", [
        ("1.2.3", (1, 2, 3, "")), ("v4", (4, 0, 0, "")), ("1.2", (1, 2, 0, "")),
        ("18.3.1", (18, 3, 1, "")), ("1.0.0-beta.1", (1, 0, 0, "beta.1")),
    ])
    def test_parses(self, raw, expected):
        assert parse(raw) == expected

    @pytest.mark.parametrize("raw", ["latest", "main", "", None, "bookworm-slim", "sha256:abc"])
    def test_rejects_non_versions(self, raw):
        assert parse(raw) is None


class TestCompare:
    @pytest.mark.parametrize("a,b,expected", [
        ("1.0.0", "1.0.1", -1), ("2.0.0", "1.9.9", 1), ("1.2.3", "1.2.3", 0),
        ("v4", "4.0.0", 0), ("1.10.0", "1.9.0", 1),          # not string order
        ("1.0.0-beta", "1.0.0", -1),                          # prerelease sorts below
    ])
    def test_ordering(self, a, b, expected):
        assert compare(a, b) == expected

    def test_incomparable_is_none(self):
        assert compare("latest", "1.0.0") is None


class TestFloor:
    @pytest.mark.parametrize("spec,expected", [
        ("^4.17.20", "4.17.20"), ("~1.2.3", "1.2.3"), (">=1.0.0", "1.0.0"),
        ("~> 5.0", "5.0"), ("4.17.21", "4.17.21"), (">=1.3.0 <2.0.0", "1.3.0"),
        ("1.x", "1"), ("v4", "v4"),
    ])
    def test_lowest_permitted_version(self, spec, expected):
        assert floor_of(spec) == expected

    @pytest.mark.parametrize("spec", ["latest", "*", "main", None, "", "workspace:*"])
    def test_no_usable_floor(self, spec):
        assert floor_of(spec) is None


class TestApplicability:
    """Against the real published lodash advisory."""

    def test_the_fixed_version_is_clear(self):
        assert spec_is_affected("4.17.21", LODASH) == NOT_AFFECTED

    def test_a_version_below_the_fix_is_affected(self):
        assert spec_is_affected("4.17.20", LODASH) == AFFECTED

    def test_a_caret_range_that_could_resolve_low_is_affected(self):
        # ^4.17.20 may still be sitting on 4.17.20
        assert spec_is_affected("^4.17.20", LODASH) == AFFECTED

    def test_a_caret_range_whose_floor_is_fixed_is_clear(self):
        assert spec_is_affected("^4.17.21", LODASH) == NOT_AFFECTED

    @pytest.mark.parametrize("spec", ["latest", "*", "main", None])
    def test_unpinnable_specs_are_unknown_not_clear(self, spec):
        assert spec_is_affected(spec, LODASH) == UNKNOWN

    def test_no_range_data_is_unknown_not_clear(self):
        assert spec_is_affected("1.0.0", [{}]) == UNKNOWN

    def test_git_only_ranges_say_nothing_about_a_semver_pin(self):
        git_only = [{"ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}]}]
        assert spec_is_affected("1.0.0", git_only) == UNKNOWN

    def test_explicit_version_list(self):
        listed = [{"versions": ["1.0.0", "1.0.1"]}]
        assert version_is_affected("1.0.0", listed) is True
        assert version_is_affected("1.0.2", listed) is False

    def test_last_affected_bound(self):
        advisory = [{"ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0.0"}, {"last_affected": "1.5.0"}]}]}]
        assert version_is_affected("1.5.0", advisory) is True
        assert version_is_affected("1.5.1", advisory) is False

    def test_introduced_after_a_fix_reopens_the_range(self):
        advisory = [{"ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0.0"}, {"fixed": "1.2.0"},
            {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]}]
        assert version_is_affected("1.1.0", advisory) is True
        assert version_is_affected("1.5.0", advisory) is False   # in the safe gap
        assert version_is_affected("2.0.5", advisory) is True
        assert version_is_affected("2.1.0", advisory) is False
