import pytest

from blastradius.cvss import base_score, severity_label


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_known_reference_vectors(vector, expected):
    assert base_score(vector) == expected


def test_cvss_30_vectors_also_parse():
    assert base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_scope_change_raises_the_score():
    unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")
    changed = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L")
    assert changed > unchanged


@pytest.mark.parametrize("bad", [
    "", None, "not a vector", "CVSS:2.0/AV:N/AC:L", "CVSS:3.1/AV:Z/AC:L/PR:N",
    "CVSS:3.1/AV:N",  # missing required metrics
])
def test_unparseable_returns_none(bad):
    assert base_score(bad) is None


@pytest.mark.parametrize("score,label", [
    (10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "none"),
])
def test_severity_labels(score, label):
    assert severity_label(score) == label
