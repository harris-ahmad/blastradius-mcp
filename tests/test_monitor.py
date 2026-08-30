import httpx
import pytest

from blastradius import monitor
from blastradius.osv import ECOSYSTEMS, OsvClient, package_name, parse_vuln
from blastradius.store import Dependency, Store

# ── A fake OSV, so tests never touch the network ─────────────────────────────

VULNS = {
    "GHSA-critical": {
        "id": "GHSA-critical",
        "aliases": ["CVE-2026-0001"],
        "summary": "Remote code execution",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"type": "ADVISORY", "url": "https://example.test/1"}],
    },
    "GHSA-moderate": {
        "id": "GHSA-moderate",
        "aliases": ["CVE-2026-0002"],
        "summary": "Prototype pollution",
        "database_specific": {"severity": "MODERATE"},
        "references": [{"type": "WEB", "url": "https://example.test/2"}],
    },
}


def handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/querybatch"):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": i} for i in VULNS]}]})
    osv_id = request.url.path.rsplit("/", 1)[-1]
    if osv_id in VULNS:
        return httpx.Response(200, json=VULNS[osv_id])
    return httpx.Response(404, json={"error": "not found"})


@pytest.fixture
def client():
    return OsvClient(base_url="https://osv.test/v1",
                     client=httpx.Client(transport=httpx.MockTransport(handler)))


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "index.db")
    s.record("org/api", [Dependency("npm_package", "left-pad", "^1.3.0", "package.json", 1)])
    return s


# ── Severity resolution — the bug that made everything 'unknown' ─────────────

class TestParseVuln:
    def test_scores_a_cvss_vector(self):
        parsed = parse_vuln(VULNS["GHSA-critical"])
        assert parsed["severity"] == "critical"
        assert parsed["cvss_score"] == 9.8

    def test_maps_github_moderate_to_medium(self):
        assert parse_vuln(VULNS["GHSA-moderate"])["severity"] == "medium"

    def test_prefers_a_cve_alias_for_display(self):
        assert parse_vuln(VULNS["GHSA-critical"])["cve_id"] == "CVE-2026-0001"

    def test_falls_back_to_numeric_score(self):
        parsed = parse_vuln({
            "id": "X", "affected": [{"database_specific": {"cvss_score": 7.2}}],
        })
        assert parsed["severity"] == "high"

    def test_unscoreable_is_unknown_not_a_guess(self):
        assert parse_vuln({"id": "X"})["severity"] == "unknown"


class TestEcosystemCoverage:
    def test_only_claims_ecosystems_osv_actually_covers(self):
        assert set(ECOSYSTEMS) == {"github_action", "npm_package"}

    def test_action_version_suffix_is_stripped(self):
        assert package_name("actions/checkout@v4", "github_action") == "actions/checkout"

    def test_npm_name_passes_through(self):
        assert package_name("@scope/pkg", "npm_package") == "@scope/pkg"

    def test_unmonitorable_types_are_skipped_not_reported_clean(self, client, tmp_path):
        s = Store(tmp_path / "d.db")
        s.record("org/api", [Dependency("docker_image", "alpine", "3.19", "Dockerfile", 1)])
        assert client.discover(s.monitorable_artifacts()) == {}


# ── The cycle ────────────────────────────────────────────────────────────────

class TestCheck:
    def test_first_run_backfills_silently(self, store, client):
        alerts = monitor.check(store, client)
        assert alerts == []                       # nothing dumped on the user
        assert store.stats()["open_alerts"] == 2  # but it is all recorded

    def test_second_run_reports_only_what_is_new(self, store, client):
        monitor.check(store, client)
        assert monitor.check(store, client) == []

        VULNS["GHSA-new"] = {
            "id": "GHSA-new", "summary": "Fresh one",
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        }
        try:
            new = monitor.check(store, client)
            assert [a["id"] for a in new] == ["GHSA-new"]
            assert new[0]["severity"] == "high"
            assert new[0]["identifier"] == "left-pad"
        finally:
            del VULNS["GHSA-new"]

    def test_worst_severity_is_reported_first(self, store, client):
        alerts = monitor.check(store, client, first_run_is_silent=False)
        assert [a["severity"] for a in alerts] == ["critical", "medium"]

    def test_empty_index_does_no_network_calls(self, tmp_path):
        exploding = OsvClient(client=httpx.Client(
            transport=httpx.MockTransport(lambda r: pytest.fail("should not call OSV"))))
        assert monitor.check(Store(tmp_path / "e.db"), exploding) == []

    def test_a_network_failure_does_not_raise(self, store):
        def boom(request): raise httpx.ConnectError("offline")
        broken = OsvClient(client=httpx.Client(transport=httpx.MockTransport(boom)))
        assert monitor.check(store, broken) == []


class TestWatch:
    def test_loop_is_bounded_and_sleeps_between_cycles(self, store, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr(monitor, "check", lambda *a, **k: [])
        monitor.watch(interval_hours=6, store=store, sleeper=slept.append, iterations=3)
        assert slept == [21600.0, 21600.0]  # sleeps between, not after the last

    def test_one_bad_cycle_does_not_kill_the_daemon(self, store, monkeypatch):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            return []

        monkeypatch.setattr(monitor, "check", flaky)
        monitor.watch(store=store, sleeper=lambda _: None, iterations=3)
        assert calls["n"] == 3


class TestNotify:
    def test_formats_a_readable_report(self):
        alerts = [{"id": "GHSA-x", "cve_id": "CVE-2026-1", "severity": "critical",
                   "cvss_score": 9.8, "summary": "RCE", "url": "https://e.test",
                   "identifier": "left-pad", "type": "npm_package"}]
        text = monitor.format_alerts(alerts)
        assert "CRITICAL" in text and "9.8" in text
        assert "left-pad" in text and "CVE-2026-1" in text

    def test_slack_only_fires_above_the_threshold(self, capsys):
        posted: list[dict] = []
        alerts = [{"id": "a", "cve_id": None, "severity": "low", "cvss_score": 2.0,
                   "summary": "minor", "url": "", "identifier": "x", "type": "npm_package"}]
        import blastradius.monitor as m
        original = m.httpx.post
        m.httpx.post = lambda *a, **k: posted.append(k) or httpx.Response(200)
        try:
            m.notify(alerts, {"slack_webhook_url": "https://hook.test",
                              "notify_min_severity": "high"})
        finally:
            m.httpx.post = original
        assert posted == []            # below threshold: no webhook
        assert "x" in capsys.readouterr().out  # but still printed locally


class TestApplicabilityFiltering:
    """Only record advisories a pinned spec can actually resolve to."""

    LODASH_FIX = {
        "id": "GHSA-lodash", "summary": "ReDoS",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }

    def _client(self):
        def handler(request):
            if request.url.path.endswith("/querybatch"):
                return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-lodash"}]}]})
            return httpx.Response(200, json=self.LODASH_FIX)
        return OsvClient(base_url="https://osv.test/v1",
                         client=httpx.Client(transport=httpx.MockTransport(handler)))

    def _store_pinning(self, tmp_path, spec):
        s = Store(tmp_path / f"{abs(hash(spec))}.db")
        s.record("org/api", [Dependency("npm_package", "lodash", spec, "package.json", 1)])
        return s

    def test_a_fixed_pin_records_nothing(self, tmp_path):
        store = self._store_pinning(tmp_path, "4.17.21")
        monitor.check(store, self._client(), first_run_is_silent=False)
        assert store.stats()["open_alerts"] == 0

    def test_a_vulnerable_pin_is_recorded(self, tmp_path):
        store = self._store_pinning(tmp_path, "4.17.20")
        monitor.check(store, self._client(), first_run_is_silent=False)
        assert store.stats()["open_alerts"] == 1

    def test_a_caret_range_that_could_resolve_low_is_recorded(self, tmp_path):
        store = self._store_pinning(tmp_path, "^4.17.20")
        monitor.check(store, self._client(), first_run_is_silent=False)
        assert store.stats()["open_alerts"] == 1

    def test_a_caret_range_above_the_fix_records_nothing(self, tmp_path):
        store = self._store_pinning(tmp_path, "^4.17.21")
        monitor.check(store, self._client(), first_run_is_silent=False)
        assert store.stats()["open_alerts"] == 0

    def test_an_unpinnable_spec_is_kept_not_dropped(self, tmp_path):
        """Uncertainty must fail toward showing the alert."""
        store = self._store_pinning(tmp_path, "latest")
        monitor.check(store, self._client(), first_run_is_silent=False)
        assert store.stats()["open_alerts"] == 1

    def test_one_vulnerable_consumer_is_enough(self, tmp_path):
        store = Store(tmp_path / "multi.db")
        store.record("org/safe", [Dependency("npm_package", "lodash", "4.17.21", "package.json", 1)])
        store.record("org/old",  [Dependency("npm_package", "lodash", "4.17.20", "package.json", 1)])
        alerts = monitor.check(store, self._client(), first_run_is_silent=False)
        assert len(alerts) == 1
        assert alerts[0]["applies_to"] == ["4.17.20"]

    def test_applies_to_is_persisted_for_the_reader(self, tmp_path):
        store = self._store_pinning(tmp_path, "^4.17.20")
        monitor.check(store, self._client(), first_run_is_silent=False)
        assert store.alerts_for("lodash")[0]["applies_to"] == "^4.17.20"

    def test_the_report_names_the_affected_specs(self):
        text = monitor.format_alerts([{
            "id": "GHSA-x", "cve_id": "CVE-1", "severity": "high", "cvss_score": 7.5,
            "summary": "s", "url": "", "identifier": "lodash", "type": "npm_package",
            "applies_to": ["^4.17.20", "4.17.20"],
        }])
        assert "affects: ^4.17.20, 4.17.20" in text


class TestRefresh:
    """Already-recorded advisories are skipped as 'seen', so a changed filter
    never gets to judge them without an explicit re-evaluation."""

    def test_clear_alerts_empties_the_table(self, store, client):
        monitor.check(store, client, first_run_is_silent=False)
        assert store.stats()["open_alerts"] > 0
        assert store.clear_alerts() > 0
        assert store.stats()["open_alerts"] == 0

    def test_without_refresh_a_second_check_re_evaluates_nothing(self, store, client):
        monitor.check(store, client, first_run_is_silent=False)
        assert monitor.check(store, client, first_run_is_silent=False) == []

    def test_refresh_re_evaluates_everything(self, store, client):
        monitor.check(store, client, first_run_is_silent=False)
        again = monitor.check(store, client, first_run_is_silent=False, refresh=True)
        assert len(again) == 2

    def test_refresh_applies_the_current_filter(self, tmp_path):
        """An alert recorded before filtering existed should not survive a refresh
        once the pinned version turns out to be fixed."""
        store = Store(tmp_path / "r.db")
        store.record("org/api", [Dependency("npm_package", "lodash", "4.17.21", "package.json", 1)])
        artifact_id = store.monitorable_artifacts()[0]["id"]
        # Recorded the old way: no applicability check at all.
        store.add_alert(artifact_id, {"id": "GHSA-old", "severity": "high", "summary": "s"})
        assert store.stats()["open_alerts"] == 1

        fixed_in_that_version = {
            "id": "GHSA-old", "summary": "s", "database_specific": {"severity": "HIGH"},
            "affected": [{"ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
        }

        def handler(request):
            if request.url.path.endswith("/querybatch"):
                return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-old"}]}]})
            return httpx.Response(200, json=fixed_in_that_version)

        monitor.check(store, OsvClient(base_url="https://osv.test/v1",
                                       client=httpx.Client(transport=httpx.MockTransport(handler))),
                      first_run_is_silent=False, refresh=True)
        assert store.stats()["open_alerts"] == 0
