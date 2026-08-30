"""Pulling a manifest out of a shell command.

This is the risky half of the Bash matcher: it runs on every shell command an
agent issues, so a false positive costs context on something irrelevant and a
false negative puts the tool back to being silent exactly when it matters.
"""
import pytest

from blastradius.repo import is_manifest, manifest_in_command


class TestCommandsThatNameAManifest:
    @pytest.mark.parametrize("command,expected", [
        ("cat package.json",                       "package.json"),
        ("head -20 web/package.json",              "web/package.json"),
        ("jq .dependencies package.json",          "package.json"),
        ("grep -n react package.json",             "package.json"),
        ("less Dockerfile",                        "Dockerfile"),
        ("cat Dockerfile.prod",                    "Dockerfile.prod"),
        ("cat infra/main.tf",                      "infra/main.tf"),
        ("cat .github/workflows/ci.yml",           ".github/workflows/ci.yml"),
        ("cat charts/api/Chart.yaml",              "charts/api/Chart.yaml"),
        ("cat ./web/package.json | jq .name",      "./web/package.json"),
    ])
    def test_the_path_is_found(self, command, expected):
        assert manifest_in_command(command) == expected


class TestPackageManagers:
    """`npm install react@19` rewrites package.json and never names it. That
    is the moment the warning is worth having, so it has to be inferred."""

    @pytest.mark.parametrize("command", [
        "npm install react@19", "npm i react", "npm uninstall lodash",
        "yarn add lodash", "yarn remove vite", "pnpm add vite",
        "pnpm remove lodash", "npm upgrade",
    ])
    def test_a_dependency_change_implies_package_json(self, command):
        assert manifest_in_command(command) == "package.json"

    def test_a_plain_install_of_everything_still_counts(self):
        # `npm install` with no argument installs from package.json.
        assert manifest_in_command("npm install") == "package.json"


class TestCommandsThatMustStaySilent:
    @pytest.mark.parametrize("command", [
        "ls -la", "git status", "git log --oneline -5",
        "python3 -m pytest -q", "echo hello", "cd /tmp && pwd",
        "mkdir -p build", "curl -s https://example.com",
        "docker ps", "kubectl get pods", "make test",
    ])
    def test_no_manifest_is_reported(self, command):
        assert manifest_in_command(command) is None

    @pytest.mark.parametrize("command", ["", None])
    def test_an_empty_command_is_handled(self, command):
        assert manifest_in_command(command) is None

    def test_a_bare_flag_is_never_a_path(self):
        assert manifest_in_command("cat --help") is None


class TestWhatCountsAsAManifest:
    """manifest_in_command trusts is_manifest, so the boundary lives there."""

    @pytest.mark.parametrize("path,expected", [
        ("package.json", True), ("Dockerfile", True), ("Dockerfile.dev", True),
        ("main.tf", True), ("vars.tfvars", True), ("Chart.yaml", True),
        (".github/workflows/ci.yml", True),
        ("README.md", False), ("values.yaml", False), ("src/index.ts", False),
        ("deploy.yml", False),   # a yaml outside .github/workflows is not one
    ])
    def test_boundary(self, path, expected):
        assert is_manifest(path) is expected
