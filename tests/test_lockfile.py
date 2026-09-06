"""Lockfiles are machine-generated and schema-stable — the one thing here that
should be parsed rather than extracted by a model."""
import json

import pytest

from blastradius.lockfile import (normalise_python_name, npm_resolved_versions, python_resolved_versions)


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


class TestPythonResolvedVersions:
    """A pyproject range says what is permitted; a lock says what is installed.
    The difference is 43 advisories versus 9."""

    def test_poetry_lock_is_read(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "django"\nversion = "4.2.11"\n\n'
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n')
        assert python_resolved_versions(tmp_path) == {
            "django": "4.2.11", "requests": "2.31.0"}

    def test_uv_lock_is_read(self, tmp_path):
        (tmp_path / "uv.lock").write_text(
            '[[package]]\nname = "httpx"\nversion = "0.27.0"\n')
        assert python_resolved_versions(tmp_path) == {"httpx": "0.27.0"}

    def test_names_are_normalised_per_pep503(self, tmp_path):
        """Flask-Login, flask_login and FLASK.LOGIN are one project."""
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "Flask-Login"\nversion = "0.6.3"\n')
        assert python_resolved_versions(tmp_path) == {"flask-login": "0.6.3"}
        assert normalise_python_name("Flask_Login") == "flask-login"
        assert normalise_python_name("FLASK.LOGIN") == "flask-login"

    def test_only_exact_pins_count_as_resolved(self, tmp_path):
        """`django>=4.0` is a constraint. Recording it as a resolution would
        report a floor as though it were what is installed — the exact
        confusion this module exists to prevent."""
        (tmp_path / "requirements.txt").write_text(
            "django==4.2.1\n"
            "requests>=2.28\n"
            "urllib3~=2.2\n"
            "numpy==1.*\n")
        assert python_resolved_versions(tmp_path) == {"django": "4.2.1"}

    def test_directives_and_comments_are_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "# production deps\n"
            "-r base.txt\n"
            "--require-hashes\n"
            "-e ./local-pkg\n"
            "\n"
            "flask==3.0.0  # pinned by ops\n")
        assert python_resolved_versions(tmp_path) == {"flask": "3.0.0"}

    def test_extras_and_markers_do_not_break_the_name(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            'requests[security]==2.31.0 ; python_version >= "3.9"\n')
        assert python_resolved_versions(tmp_path) == {"requests": "2.31.0"}

    def test_a_lockfile_wins_over_a_pinned_requirement(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("django==4.1.0\n")
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "django"\nversion = "4.2.11"\n')
        assert python_resolved_versions(tmp_path)["django"] == "4.2.11"

    def test_vendored_trees_are_skipped(self, tmp_path):
        (tmp_path / ".venv" / "lib").mkdir(parents=True)
        (tmp_path / ".venv" / "lib" / "requirements.txt").write_text("evil==6.6.6\n")
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
        assert python_resolved_versions(tmp_path) == {"flask": "3.0.0"}

    def test_malformed_toml_yields_nothing_rather_than_raising(self, tmp_path):
        (tmp_path / "poetry.lock").write_text("[[package]\nname = broken")
        assert python_resolved_versions(tmp_path) == {}

    def test_no_python_files_is_empty(self, tmp_path):
        assert python_resolved_versions(tmp_path) == {}
