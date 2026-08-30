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
