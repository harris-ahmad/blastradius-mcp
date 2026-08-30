"""The watcher only watches if it outlives the terminal that started it."""
import plistlib
import subprocess

import pytest

from blastradius import service


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(service.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(service, "LOG_PATH", tmp_path / ".blastradius" / "watch.log")
    monkeypatch.setattr(service, "_binary", lambda: "/opt/venv/bin/blastradius")
    monkeypatch.setattr(service, "_launchd_path",
                        lambda: tmp_path / "Library/LaunchAgents/dev.blastradius.watch.plist")
    monkeypatch.setattr(service, "_systemd_path",
                        lambda: tmp_path / ".config/systemd/user/blastradius.service")
    return tmp_path


def ran_ok(*_a, **_kw):
    return subprocess.CompletedProcess([], 0, "", "")


class TestGeneratedUnits:
    def test_launchd_plist_is_valid(self):
        parsed = plistlib.loads(
            service._launchd_plist("/opt/venv/bin/blastradius", 6.0).encode())
        assert parsed["Label"] == service.LABEL
        assert parsed["ProgramArguments"][:2] == ["/opt/venv/bin/blastradius", "watch"]
        assert parsed["KeepAlive"] is True     # restart if it dies
        assert parsed["RunAtLoad"] is True     # start at login

    def test_systemd_unit_restarts_and_enables(self):
        unit = service._systemd_unit("/opt/venv/bin/blastradius", 6.0)
        assert "ExecStart=/opt/venv/bin/blastradius watch --interval-hours 6.0" in unit
        assert "Restart=always" in unit
        assert "WantedBy=default.target" in unit

    def test_interval_reaches_both(self):
        assert "--interval-hours 12.0" in service._systemd_unit("/b", 12.0)
        assert "<string>12.0</string>" in service._launchd_plist("/b", 12.0)


class TestInstall:
    def test_writes_and_loads_on_macos(self, home, monkeypatch):
        monkeypatch.setattr(service, "_platform", lambda: "launchd")
        monkeypatch.setattr(service.subprocess, "run", ran_ok)
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        assert service.install(6.0) == 0
        assert service._launchd_path().exists()

    def test_writes_and_enables_on_linux(self, home, monkeypatch):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr(service.subprocess, "run", ran_ok)
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        assert service.install(6.0) == 0
        assert service._systemd_path().exists()

    def test_refuses_a_binary_that_does_not_run(self, home, monkeypatch, capsys):
        """Registering a service that crashes on every start is worse than none."""
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr("blastradius.install.verify_binary",
                            lambda _: (False, "ModuleNotFoundError"))
        assert service.install(6.0) == 1
        assert not service._systemd_path().exists()
        assert "Refusing to register" in capsys.readouterr().out

    def test_unsupported_platform_suggests_running_it_directly(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "unsupported")
        assert service.install(6.0) == 1
        assert "blastradius watch" in capsys.readouterr().out

    def test_reports_a_failed_start(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        monkeypatch.setattr(service.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess([], 1, "", "boom"))
        assert service.install(6.0) == 1
        assert "could not start it" in capsys.readouterr().out


class TestUninstall:
    def test_removes_the_unit(self, home, monkeypatch):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr(service.subprocess, "run", ran_ok)
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        service.install(6.0)
        assert service.uninstall() == 0
        assert not service._systemd_path().exists()

    def test_is_safe_when_nothing_is_installed(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        assert service.uninstall() == 0
        assert "no service installed" in capsys.readouterr().out


class TestStatus:
    def test_not_installed(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        assert service.status() == 1
        assert "not installed" in capsys.readouterr().out

    def test_installed_and_running(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr(service.subprocess, "run", ran_ok)
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        service.install(6.0)
        monkeypatch.setattr(service.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess([], 0, "active", ""))
        assert service.status() == 0
        assert "running" in capsys.readouterr().out

    def test_installed_but_stopped(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr(service.subprocess, "run", ran_ok)
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        service.install(6.0)
        monkeypatch.setattr(service.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess([], 3, "inactive", ""))
        assert service.status() == 1
        assert "not running" in capsys.readouterr().out


class TestStopAndStart:
    """`kill` does not work — both supervisors restart on failure — so pausing
    has to be a first-class command."""

    def _installed(self, monkeypatch):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        monkeypatch.setattr(service.subprocess, "run", ran_ok)
        monkeypatch.setattr("blastradius.install.verify_binary", lambda _: (True, ""))
        service.install(6.0)

    def test_stop_leaves_the_unit_in_place(self, home, monkeypatch, capsys):
        self._installed(monkeypatch)
        assert service.stop() == 0
        assert service._systemd_path().exists()          # paused, not removed
        assert "service start` resumes" in capsys.readouterr().out

    def test_start_after_stop(self, home, monkeypatch, capsys):
        self._installed(monkeypatch)
        service.stop()
        assert service.start() == 0
        assert "started" in capsys.readouterr().out

    def test_stop_is_safe_when_nothing_is_installed(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        assert service.stop() == 0
        assert "no service installed" in capsys.readouterr().out

    def test_start_refuses_when_nothing_is_installed(self, home, monkeypatch, capsys):
        monkeypatch.setattr(service, "_platform", lambda: "systemd")
        assert service.start() == 1
        assert "not installed" in capsys.readouterr().out

    def test_uninstall_removes_it_for_good(self, home, monkeypatch):
        self._installed(monkeypatch)
        assert service.uninstall() == 0
        assert not service._systemd_path().exists()
        assert service.status() == 1
