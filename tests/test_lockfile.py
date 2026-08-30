"""Lockfiles are machine-generated and schema-stable — the one thing here that
should be parsed rather than extracted by a model."""
import json

import pytest

from blastradius.lockfile import npm_resolved_versions


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else json.dumps(content))


class TestPackageLockV3:
    def test_reads_install_paths(self, tmp_path):
        write(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/vite": {"version": "5.4.19"},
            "node_modules/lodash": {"version": "4.17.21"}}})
        assert npm_resolved_versions(tmp_path) == {"vite": "5.4.19", "lodash": "4.17.21"}

    def test_handles_scoped_names(self, tmp_path):
        write(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/@scope/thing": {"version": "2.1.0"}}})
        assert npm_resolved_versions(tmp_path)["@scope/thing"] == "2.1.0"

    def test_a_nested_copy_does_not_shadow_the_top_level(self, tmp_path):
        write(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/vite/node_modules/lodash": {"version": "4.17.5"}}})
        assert npm_resolved_versions(tmp_path)["lodash"] == "4.17.21"


class TestPackageLockV1:
    def test_reads_the_nested_tree(self, tmp_path):
        write(tmp_path, "package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "lodash": {"version": "4.17.21",
                       "dependencies": {"nested": {"version": "1.0.0"}}}}})
        resolved = npm_resolved_versions(tmp_path)
        assert resolved["lodash"] == "4.17.21"
        assert resolved["nested"] == "1.0.0"


class TestYarnLock:
    def test_reads_entries(self, tmp_path):
        write(tmp_path, "yarn.lock", '''# yarn lockfile v1
lodash@^4.17.20, lodash@^4.17.0:
  version "4.17.21"

"@scope/pkg@^1.0.0":
  version "1.2.3"
''')
        assert npm_resolved_versions(tmp_path) == {"lodash": "4.17.21", "@scope/pkg": "1.2.3"}


class TestRobustness:
    def test_no_lockfile_is_empty_not_an_error(self, tmp_path):
        assert npm_resolved_versions(tmp_path) == {}

    def test_malformed_json_is_ignored(self, tmp_path):
        write(tmp_path, "package-lock.json", "{ not json")
        assert npm_resolved_versions(tmp_path) == {}

    def test_vendored_lockfiles_are_skipped(self, tmp_path):
        write(tmp_path, "node_modules/dep/package-lock.json",
              {"lockfileVersion": 3, "packages": {"": {}, "node_modules/x": {"version": "9.9.9"}}})
        assert npm_resolved_versions(tmp_path) == {}

    def test_package_lock_wins_over_yarn_lock(self, tmp_path):
        write(tmp_path, "yarn.lock", 'lodash@^4.0.0:\n  version "4.0.0"\n')
        write(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {}, "node_modules/lodash": {"version": "4.17.21"}}})
        assert npm_resolved_versions(tmp_path)["lodash"] == "4.17.21"
