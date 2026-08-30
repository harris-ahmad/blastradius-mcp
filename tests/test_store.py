import pytest

from blastradius.store import (Dependency, Store, canonical_identifier,
                              identifier_candidates)


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


class TestCanonicalIdentifier:
    """A reusable workflow is written as owner/repo/.github/workflows/x.yml, but
    the thing shared across repos — and the thing OSV knows about — is owner/repo."""

    @pytest.mark.parametrize("raw,expected", [
        ("acme/.github/.github/workflows/deploy.yml", "acme/.github"),
        ("octo/infra/.github/workflows/ci.yml", "octo/infra"),
        ("org/repo/subdir", "org/repo"),
        ("actions/checkout", "actions/checkout"),
        ("docker://alpine:3.18", "docker://alpine:3.18"),
    ])
    def test_actions_truncate_to_owner_repo(self, raw, expected):
        assert canonical_identifier("github_action", raw) == expected

    @pytest.mark.parametrize("type_,raw", [
        ("docker_image", "gcr.io/distroless/static-debian12"),
        ("terraform_module", "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"),
        ("npm_package", "@scope/pkg"),
        ("helm_chart", "bitnami/postgresql"),
    ])
    def test_other_types_are_left_alone(self, type_, raw):
        assert canonical_identifier(type_, raw) == raw

    def test_the_long_and_short_forms_land_on_one_artifact(self, store):
        """Before canonicalisation these were two artifacts, so a workflow shared
        by two repos looked like it had one consumer each."""
        store.record("acme/api", [dep("github_action", "acme/.github/.github/workflows/deploy.yml",
                                      "v1", ".github/workflows/release.yml", 4)])
        store.record("acme/web", [dep("github_action", "acme/.github",
                                      "v1", ".github/workflows/release.yml", 4)])

        consumers = store.consumers("acme/.github", artifact_type="github_action")
        assert {c["repository"] for c in consumers} == {"acme/api", "acme/web"}

    def test_a_lookup_by_the_long_form_finds_the_canonical_row(self, store):
        store.record("acme/api", [dep("github_action", "acme/.github",
                                      "v2", ".github/workflows/release.yml", 4)])

        found = store.consumers("acme/.github/.github/workflows/deploy.yml",
                                artifact_type="github_action")
        assert [c["repository"] for c in found] == ["acme/api"]

    def test_a_deep_docker_path_does_not_match_its_prefix(self, store):
        """Truncation is an Actions rule. Widening it to Docker would let a
        query for a distroless image match an unrelated shorter one."""
        store.record("acme/api", [dep("docker_image", "gcr.io/distroless", "latest")])

        found = store.consumers("gcr.io/distroless/static-debian12",
                                artifact_type="docker_image")
        assert found == []

    def test_candidates_offer_the_truncation_only_where_it_applies(self):
        long = "acme/.github/.github/workflows/deploy.yml"
        assert identifier_candidates(long, "github_action") == [long, "acme/.github"]
        assert identifier_candidates(long) == [long, "acme/.github"]
        assert identifier_candidates(long, "docker_image") == [long]
        assert identifier_candidates("actions/checkout", "github_action") == ["actions/checkout"]

    def test_a_bare_action_without_an_owner_is_untouched(self):
        assert canonical_identifier("github_action", "checkout") == "checkout"

    def test_empty_path_segments_do_not_shift_the_split(self):
        assert canonical_identifier("github_action", "acme//infra//x.yml") == "acme/infra"

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


class TestResolvedVersions:
    def test_backfill_pins_an_existing_index(self, store):
        store.record("org/api", [dep("npm_package", "vite", "^5.2.0", "package.json")])
        assert store.specs_for_artifact(1) == [("^5.2.0", None)]
        assert store.apply_resolved_versions("org/api", {"vite": "5.4.19"}) == 1
        assert store.specs_for_artifact(1) == [("^5.2.0", "5.4.19")]

    def test_backfill_does_not_leak_across_repositories(self, store):
        store.record("org/api", [dep("npm_package", "vite", "^5.2.0", "package.json")])
        store.record("org/web", [dep("npm_package", "vite", "^5.2.0", "package.json")])
        store.apply_resolved_versions("org/api", {"vite": "5.4.19"})
        rows = {r["repository"]: r["resolved_version"] for r in store.consumers("vite")}
        assert rows == {"org/api": "5.4.19", "org/web": None}

    def test_backfill_ignores_non_npm_artifacts(self, store):
        store.record("org/api", [dep("docker_image", "node", "20-alpine", "Dockerfile")])
        assert store.apply_resolved_versions("org/api", {"node": "20.11.0"}) == 0


class TestResolvedVersionReachesReaders:
    """The alert listing matches consumers against the same label the filter
    used. Comparing on the spec alone hides repos matched by their lockfile."""

    def test_consumers_expose_the_resolved_version(self, store):
        store.record("acme/web", [Dependency(
            "npm_package", "lodash", "^4.17.20", "package.json", 6,
            resolved_version="4.17.21")])
        row = store.consumers("lodash")[0]
        assert row["version_spec"] == "^4.17.20"
        assert row["resolved_version"] == "4.17.21"

    def test_a_repo_matched_by_its_lockfile_is_still_findable(self, store):
        """acme/web pins ^4.17.20 but installs 4.17.21, so an advisory that
        reaches 4.17.21 reaches web — even though its spec says otherwise."""
        store.record("acme/web", [Dependency(
            "npm_package", "lodash", "^4.17.20", "package.json", 6,
            resolved_version="4.17.21")])
        reaches = {"4.17.21"}
        exposed = {
            c["repository"] for c in store.consumers("lodash")
            if (c.get("resolved_version") or c["version_spec"]) in reaches
        }
        assert exposed == {"acme/web"}
