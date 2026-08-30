"""The installer edits a file the user owns. It must never clobber it."""
import json

import pytest

from blastradius import install as inst

_REAL_VERIFY = inst.verify_binary


@pytest.fixture
def claude_dir(tmp_path, monkeypatch):
    d = tmp_path / ".claude"
    d.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(d))
    monkeypatch.setattr(inst, "binary_path", lambda: "/opt/venv/bin/blastradius")
    monkeypatch.setattr(inst.shutil, "which", lambda _: None)   # no `claude` CLI
    # These tests exercise the settings merge with a stand-in path. The guard
    # that rejects a non-running binary is covered by TestBinaryVerification,
    # which uses real scripts.
    monkeypatch.setattr(inst, "verify_binary", lambda _: (True, ""))
    return d


def write(d, payload):
    (d / "settings.json").write_text(json.dumps(payload))


def read(d):
    return json.loads((d / "settings.json").read_text())


def ours(settings):
    found = []
    for event, groups in (settings.get("hooks") or {}).items():
        for group in groups:
            for hook in group.get("hooks", []):
                if inst.MARKER in hook.get("command", ""):
                    found.append(event)
    return found


class TestInstall:
    def test_creates_settings_when_absent(self, claude_dir):
        inst.install()
        assert sorted(ours(read(claude_dir))) == ["PreToolUse", "Stop"]

    def test_preserves_unrelated_keys(self, claude_dir):
        write(claude_dir, {"theme": "dark", "model": "opus", "env": {"FOO": "1"}})
        inst.install()
        settings = read(claude_dir)
        assert settings["theme"] == "dark"
        assert settings["model"] == "opus"
        assert settings["env"] == {"FOO": "1"}

    def test_preserves_other_peoples_hooks(self, claude_dir):
        write(claude_dir, {"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/bin/audit"}]}
        ]}})
        inst.install()
        commands = [
            h["command"]
            for g in read(claude_dir)["hooks"]["PreToolUse"] for h in g["hooks"]
        ]
        assert "/bin/audit" in commands
        assert any(inst.MARKER in c for c in commands)

    def test_running_twice_does_not_duplicate(self, claude_dir):
        inst.install()
        inst.install()
        inst.install()
        assert sorted(ours(read(claude_dir))) == ["PreToolUse", "Stop"]

    def test_reinstall_updates_a_stale_binary_path(self, claude_dir, monkeypatch):
        inst.install()
        monkeypatch.setattr(inst, "binary_path", lambda: "/new/path/blastradius")
        inst.install()
        commands = [
            h["command"]
            for groups in read(claude_dir)["hooks"].values()
            for g in groups for h in g["hooks"]
        ]
        assert all("/opt/venv" not in c for c in commands)
        assert any("/new/path" in c for c in commands)

    def test_backs_up_before_writing(self, claude_dir):
        write(claude_dir, {"theme": "dark"})
        inst.install()
        backups = list(claude_dir.glob("settings.json.bak-*"))
        assert len(backups) == 1
        assert json.loads(backups[0].read_text()) == {"theme": "dark"}

    def test_dry_run_writes_nothing(self, claude_dir):
        write(claude_dir, {"theme": "dark"})
        inst.install(dry_run=True)
        assert read(claude_dir) == {"theme": "dark"}

    def test_refuses_to_touch_malformed_json(self, claude_dir):
        (claude_dir / "settings.json").write_text("{ not json")
        with pytest.raises(SystemExit):
            inst.install()
        assert (claude_dir / "settings.json").read_text() == "{ not json"


class TestUninstall:
    def test_removes_only_our_hooks(self, claude_dir):
        write(claude_dir, {"theme": "dark", "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/bin/audit"}]}
        ]}})
        inst.install()
        inst.uninstall()

        settings = read(claude_dir)
        assert ours(settings) == []
        assert settings["theme"] == "dark"
        commands = [h["command"] for g in settings["hooks"]["PreToolUse"] for h in g["hooks"]]
        assert commands == ["/bin/audit"]

    def test_leaves_no_empty_scaffolding(self, claude_dir):
        inst.install()
        inst.uninstall()
        assert "hooks" not in read(claude_dir)

    def test_is_safe_to_run_when_not_installed(self, claude_dir):
        write(claude_dir, {"theme": "dark"})
        inst.uninstall()
        assert read(claude_dir) == {"theme": "dark"}

    def test_survives_a_shared_matcher_group(self, claude_dir):
        """Ours and someone else's in the same group — only ours should go."""
        write(claude_dir, {"hooks": {"PreToolUse": [{
            "matcher": "Read|Edit",
            "hooks": [
                {"type": "command", "command": "/bin/other"},
                {"type": "command", "command": "/opt/venv/bin/blastradius hook inject"},
            ],
        }]}})
        inst.uninstall()
        commands = [h["command"] for g in read(claude_dir)["hooks"]["PreToolUse"] for h in g["hooks"]]
        assert commands == ["/bin/other"]


class TestLink:
    """The console script runs fine unactivated — only PATH is missing."""

    @pytest.fixture
    def venv_bin(self, tmp_path, monkeypatch):
        real = tmp_path / "venv" / "bin" / "blastradius"
        real.parent.mkdir(parents=True)
        real.write_text("#!/usr/bin/env python3\n")
        real.chmod(0o755)
        monkeypatch.setattr(inst, "binary_path", lambda: str(real))
        return real

    def test_creates_the_symlink(self, venv_bin, tmp_path):
        target = tmp_path / "bin"
        assert inst.link(str(target)) == 0
        assert (target / "blastradius").resolve() == venv_bin.resolve()

    def test_creates_the_directory_if_absent(self, venv_bin, tmp_path):
        target = tmp_path / "nested" / "deep" / "bin"
        assert inst.link(str(target)) == 0
        assert (target / "blastradius").is_symlink()

    def test_is_idempotent(self, venv_bin, tmp_path):
        target = tmp_path / "bin"
        inst.link(str(target))
        assert inst.link(str(target)) == 0
        assert (target / "blastradius").resolve() == venv_bin.resolve()

    def test_replaces_a_stale_symlink(self, venv_bin, tmp_path):
        target = tmp_path / "bin"
        target.mkdir()
        (target / "blastradius").symlink_to(tmp_path / "gone")
        assert inst.link(str(target)) == 0
        assert (target / "blastradius").resolve() == venv_bin.resolve()

    def test_warns_when_the_directory_is_not_on_path(self, venv_bin, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        inst.link(str(tmp_path / "bin"))
        assert "not on your PATH" in capsys.readouterr().out

    def test_quiet_when_the_directory_is_on_path(self, venv_bin, tmp_path, capsys, monkeypatch):
        target = tmp_path / "bin"
        target.mkdir()
        monkeypatch.setenv("PATH", f"{target}:/usr/bin")
        inst.link(str(target))
        assert "not on your PATH" not in capsys.readouterr().out

    def test_refuses_when_there_is_no_console_script(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(inst, "binary_path", lambda: "/usr/bin/python -m blastradius.cli")
        assert inst.link(str(tmp_path / "bin")) == 1
        assert "no console script" in capsys.readouterr().out


class TestBinaryVerification:
    """A broken console script still exists on disk and still looks like a valid
    path. Writing it produces hooks that crash on every invocation."""

    def test_refuses_a_binary_that_does_not_run(self, claude_dir, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(inst, "verify_binary", _REAL_VERIFY)
        broken = tmp_path / "broken"
        broken.write_text("#!/usr/bin/env python3\nimport nonexistent_module_xyz\n")
        broken.chmod(0o755)
        monkeypatch.setattr(inst, "binary_path", lambda: str(broken))

        assert inst.install() == 1
        assert not (claude_dir / "settings.json").exists()
        assert "Refusing to write a command that does not run" in capsys.readouterr().out

    def test_leaves_existing_settings_untouched_when_refusing(self, claude_dir, tmp_path, monkeypatch):
        monkeypatch.setattr(inst, "verify_binary", _REAL_VERIFY)
        write(claude_dir, {"theme": "dark"})
        broken = tmp_path / "broken"
        broken.write_text("#!/usr/bin/env python3\nraise SystemExit(3)\n")
        broken.chmod(0o755)
        monkeypatch.setattr(inst, "binary_path", lambda: str(broken))

        assert inst.install() == 1
        assert read(claude_dir) == {"theme": "dark"}

    def test_reports_a_missing_binary(self, tmp_path):
        works, detail = inst.verify_binary(str(tmp_path / "nope"))
        assert works is False
        assert detail

    def test_accepts_a_working_binary(self, tmp_path):
        good = tmp_path / "good"
        good.write_text("#!/usr/bin/env python3\nprint('{}')\n")
        good.chmod(0o755)
        works, detail = inst.verify_binary(str(good))
        assert works is True
        assert detail == ""
