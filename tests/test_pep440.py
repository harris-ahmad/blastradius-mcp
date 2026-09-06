"""Python version comparison and spec floors.

Python is not semver. Releases have any number of segments, carry epochs, and
order their suffixes dev < pre < release < post. Judging a Python pin with
npm's rules mis-evaluates every advisory boundary that lands on one of those.

The OSV payloads here are shaped like real PyPI advisories — ECOSYSTEM ranges
with introduced/fixed events — but they are written by hand. api.osv.dev was
not reachable from the environment these were written in, so the live
behaviour of the query path is covered by test_monitor, not here.
"""
import pytest

from blastradius.pep440 import (AFFECTED, NOT_AFFECTED, UNKNOWN, compare,
                                floor_of, parse, spec_is_affected,
                                version_is_affected)


class TestOrdering:
    @pytest.mark.parametrize("a,b,expected", [
        ("1.0", "1.0.0", 0),            # trailing zeros are not significant
        ("1.2", "1.10", -1),            # numeric, not lexical
        ("1.2.3.4", "1.2.3", 1),        # four segments are legal
        ("1.0a1", "1.0", -1),           # pre-release below its release
        ("1.0", "1.0.post1", -1),       # post above its release
        ("1.0.dev1", "1.0a1", -1),      # dev below pre
        ("1.0a1.dev1", "1.0a1", -1),    # dev of a pre below that pre
        ("1.0b2", "1.0rc1", -1),        # beta before rc
        ("2!1.0", "1.99", 1),           # epoch outranks everything
        ("1.0", "1.0+ubuntu1", 0),      # local segment does not change order
    ])
    def test_compare(self, a, b, expected):
        assert compare(a, b) == expected
        assert compare(b, a) == -expected

    @pytest.mark.parametrize("bad", ["", None, "latest", "main", "not-a-version"])
    def test_unparseable_is_none_not_a_guess(self, bad):
        assert parse(bad) is None
        assert compare(bad or "x", "1.0") is None


class TestFloors:
    @pytest.mark.parametrize("spec,expected", [
        ("==1.2.3", "1.2.3"),
        (">=1.0,<2.0", "1.0"),
        (">= 1.0, < 2.0", "1.0"),
        ("~=1.4.2", "1.4.2"),
        ("^1.2.3", "1.2.3"),                  # Poetry
        ("~1.2.3", "1.2.3"),                  # Poetry
        ("==1.4.*", "1.4"),
        ("1.2.3", "1.2.3"),
        ("requests[security]>=2.0", "2.0"),   # extras stripped
        ('>=2.0 ; python_version < "3.9"', "2.0"),   # marker stripped
        (">=2.0  # pinned by ops", "2.0"),    # comment stripped
    ])
    def test_floor(self, spec, expected):
        assert floor_of(spec) == expected

    @pytest.mark.parametrize("spec", ["*", "", None, "!=1.2.3", "<2.0", "<=2.0"])
    def test_specs_with_no_lower_bound(self, spec):
        """No floor means no verdict, and no verdict means affected."""
        assert floor_of(spec) is None

    def test_a_strict_greater_than_floors_at_the_excluded_version(self):
        """`>1.0` cannot resolve to 1.0, but treating 1.0 as the floor errs
        toward reporting, which is the direction this tool errs in."""
        assert floor_of(">1.0") == "1.0"


def advisory(introduced: str, fixed: str | None = None) -> list[dict]:
    """One PyPI-shaped affected entry."""
    events = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    return [{"package": {"ecosystem": "PyPI", "name": "django"},
             "ranges": [{"type": "ECOSYSTEM", "events": events}]}]


class TestVerdicts:
    def test_a_version_inside_the_range_is_affected(self):
        assert version_is_affected("4.2.0", advisory("4.0", "4.2.11")) is True

    def test_the_fix_itself_is_not_affected(self):
        assert version_is_affected("4.2.11", advisory("4.0", "4.2.11")) is False

    def test_a_range_whose_floor_is_already_fixed_is_clear(self):
        assert spec_is_affected(">=4.2.11", advisory("4.0", "4.2.11")) == NOT_AFFECTED

    def test_a_range_that_can_still_reach_the_hole_stands(self):
        assert spec_is_affected("^4.2.0", advisory("4.0", "4.2.11")) == AFFECTED

    def test_an_exact_pin_below_the_fix_is_affected(self):
        assert spec_is_affected("==4.2.0", advisory("4.0", "4.2.11")) == AFFECTED

    def test_an_unbounded_spec_is_unknown_not_clear(self):
        assert spec_is_affected("*", advisory("4.0", "4.2.11")) == UNKNOWN

    def test_a_prerelease_boundary_is_respected(self):
        """The case semver gets wrong: `1.0.dev1` is unparseable to semver and
        would drop out of the comparison entirely."""
        assert version_is_affected("1.0.dev1", advisory("1.0.dev0", "1.0")) is True
        assert version_is_affected("1.0", advisory("1.0.dev0", "1.0")) is False

    def test_a_git_only_range_says_nothing(self):
        git_only = [{"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]
        assert version_is_affected("4.2.0", git_only) is None
        assert spec_is_affected("==4.2.0", git_only) == UNKNOWN

    def test_no_range_data_is_unknown_rather_than_clear(self):
        assert version_is_affected("4.2.0", [{"package": {"name": "django"}}]) is None
