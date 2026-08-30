import pytest

from blastradius.store import Dependency, Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "index.db")


def dep(type_, ident, spec, path="Dockerfile", line=1):
    return Dependency(type=type_, identifier=ident, version_spec=spec,
                      file_path=path, line_number=line)


def test_records_and_finds_consumers(store):
    store.record("org/api", [dep("github_action", "actions/checkout", "v4",
                                 ".github/workflows/ci.yml", 12)])
    store.record("org/web", [dep("github_action", "actions/checkout", "v4",
                                 ".github/workflows/ci.yml", 8)])

    consumers = store.consumers("actions/checkout")
    assert len(consumers) == 2
    assert {c["repository"] for c in consumers} == {"org/api", "org/web"}
    assert consumers[0]["file_path"] == ".github/workflows/ci.yml"
    assert consumers[0]["line_number"] in (8, 12)


def test_type_disambiguates_a_shared_name(store):
    """`node` is both a Docker image and an npm package. The original merged
    them into one blast radius with no error."""
    store.record("org/api", [dep("docker_image", "node", "20-alpine")])
    store.record("org/lib", [dep("npm_package", "node", "^20.0.0", "package.json")])

    assert len(store.consumers("node")) == 2
    assert len(store.consumers("node", artifact_type="docker_image")) == 1
    assert store.consumers("node", artifact_type="docker_image")[0]["repository"] == "org/api"
    assert store.consumers("node", artifact_type="npm_package")[0]["repository"] == "org/lib"


def test_raw_version_spec_survives_the_round_trip(store):
    """The caret has to still be there when it comes back out, or the pinning
    classifier is working from destroyed data."""
    store.record("org/web", [dep("npm_package", "react", "^18.2.0", "package.json")])
    assert store.consumers("react")[0]["version_spec"] == "^18.2.0"


def test_recording_twice_is_idempotent(store):
    d = dep("docker_image", "alpine", "3.19")
    store.record("org/api", [d])
    store.record("org/api", [d])
    assert store.stats()["references"] == 1


def test_rescan_updates_the_version_in_place(store):
    store.record("org/api", [dep("docker_image", "alpine", "3.19")])
    store.record("org/api", [dep("docker_image", "alpine", "3.20")])
    consumers = store.consumers("alpine")
    assert len(consumers) == 1
    assert consumers[0]["version_spec"] == "3.20"


def test_exclude_repository_filters_self(store):
    store.record("org/api", [dep("npm_package", "lodash", "^4.0.0", "package.json")])
    store.record("org/web", [dep("npm_package", "lodash", "^4.0.0", "package.json")])
    others = store.consumers("lodash", exclude_repository="org/api")
    assert [c["repository"] for c in others] == ["org/web"]


def test_artifacts_in_file_powers_the_injection_hook(store):
    store.record("org/api", [
        dep("docker_image", "golang", "1.22", "Dockerfile", 1),
        dep("docker_image", "alpine", "3.19", "Dockerfile", 9),
        dep("npm_package", "react", "^18.2.0", "package.json", 1),
    ])
    found = store.artifacts_in_file("org/api", "Dockerfile")
    assert [a["identifier"] for a in found] == ["golang", "alpine"]


def test_forget_repository_cascades(store):
    store.record("org/api", [dep("docker_image", "alpine", "3.19")])
    assert store.forget_repository("org/api") is True
    assert store.stats()["references"] == 0


def test_monitorable_artifacts_are_only_osv_supported_types(store):
    store.record("org/api", [
        dep("docker_image", "alpine", "3.19"),
        dep("npm_package", "react", "^18.2.0", "package.json"),
        dep("github_action", "actions/checkout", "v4", "ci.yml"),
    ])
    types = {a["type"] for a in store.monitorable_artifacts()}
    assert types == {"npm_package", "github_action"}


def test_all_dependencies_powers_the_repos_listing(store):
    store.record("org/api", [dep("docker_image", "alpine", "3.19", "Dockerfile")])
    store.record("org/web", [dep("npm_package", "react", "^18.2.0", "package.json")])
    repos = {row["repository"] for row in store.all_dependencies()}
    assert repos == {"org/api", "org/web"}


class TestVersionNormalisation:
    """'No version' arrives as null, '' or '   ' depending on the writer."""

    @pytest.mark.parametrize("raw", [None, "", "   ", "\t"])
    def test_absent_versions_all_become_none(self, store, raw):
        store.record("org/api", [dep("docker_image", "ubuntu", raw)])
        assert store.consumers("ubuntu")[0]["version_spec"] is None

    def test_a_real_spec_keeps_its_operator(self, store):
        store.record("org/api", [dep("npm_package", "react", "  ^18.2.0  ", "package.json")])
        assert store.consumers("react")[0]["version_spec"] == "^18.2.0"

    def test_identifier_whitespace_is_trimmed(self, store):
        store.record("org/api", [dep("docker_image", " alpine ", "3.19")])
        assert store.consumers("alpine")[0]["identifier"] == "alpine"


class TestListAlerts:
    def _seed(self, store):
        store.record("org/api", [
            dep("npm_package", "lodash", "^4.17.20", "package.json"),
            dep("npm_package", "vite", "^5.2.0", "package.json"),
        ])
        ids = {a["identifier"]: a["id"] for a in store.monitorable_artifacts()}
        store.add_alert(ids["lodash"], {"id": "GHSA-1", "cve_id": "CVE-1",
                                        "severity": "high", "summary": "s"}, ["^4.17.20"])
        store.add_alert(ids["vite"], {"id": "GHSA-2", "cve_id": "CVE-2",
                                      "severity": "medium", "summary": "s"}, ["^5.2.0"])
        return store

    def test_lists_every_open_alert(self, store):
        assert len(self._seed(store).list_alerts()) == 2

    def test_filters_by_severity(self, store):
        rows = self._seed(store).list_alerts(severity="high")
        assert [r["identifier"] for r in rows] == ["lodash"]

    def test_filters_by_artifact(self, store):
        rows = self._seed(store).list_alerts(identifier="vite")
        assert [r["cve_id"] for r in rows] == ["CVE-2"]

    def test_carries_the_specs_it_reaches(self, store):
        rows = self._seed(store).list_alerts(identifier="lodash")
        assert rows[0]["applies_to"] == "^4.17.20"

    def test_acknowledged_alerts_are_hidden(self, store):
        self._seed(store)
        with store._conn() as conn:
            conn.execute("UPDATE cve_alerts SET acknowledged_at = 'now' WHERE osv_id = 'GHSA-1'")
        assert [r["identifier"] for r in store.list_alerts()] == ["vite"]


class TestDuplicateAdvisoryRecords:
    """OSV often carries several records for one CVE — an original plus a later
    re-analysis — and they can disagree about whether a fix exists."""

    def test_both_records_are_stored_separately(self, store):
        store.record("org/api", [dep("npm_package", "lodash", "^4.17.20", "package.json")])
        artifact_id = store.monitorable_artifacts()[0]["id"]
        store.add_alert(artifact_id, {"id": "GHSA-a", "cve_id": "CVE-1",
                                      "severity": "high", "summary": "original"}, ["^4.17.20"])
        store.add_alert(artifact_id, {"id": "GHSA-b", "cve_id": "CVE-1",
                                      "severity": "high", "summary": "re-analysis"}, ["4.17.21"])
        rows = store.list_alerts()
        assert len(rows) == 2
        # The disagreement is the useful part and must survive storage.
        assert {r["applies_to"] for r in rows} == {"^4.17.20", "4.17.21"}
