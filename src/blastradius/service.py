"""Running the watcher as a background service.

`blastradius watch` only watches while a terminal stays open, which is not
watching — the whole value of the daemon is noticing something while nobody is
looking. This registers it with the platform's own supervisor so it survives
logout, reboot and a crashed process.

launchd on macOS, systemd user units on Linux. Both are per-user: no sudo, no
system-wide daemon, and nothing outside the user's own home directory.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

LABEL = "dev.blastradius.watch"
LOG_PATH = Path.home() / ".blastradius" / "watch.log"

GREEN, RED, YELLOW, DIM, BOLD, OFF = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
)
TICK, CROSS, WARN = f"{GREEN}✓{OFF}", f"{RED}✗{OFF}", f"{YELLOW}!{OFF}"


def _binary() -> str:
    from .install import binary_path
    return binary_path()


def _platform() -> str:
    system = platform.system()
    if system == "Darwin":
        return "launchd"
    if system == "Linux" and shutil.which("systemctl"):
        return "systemd"
    return "unsupported"


def _launchd_plist(binary: str, interval_hours: float) -> str:
    program = "".join(
        f"        <string>{part}</string>\n" for part in
        [*binary.split(), "watch", "--interval-hours", str(interval_hours)]
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{program}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_PATH}</string>
</dict>
</plist>
"""


def _systemd_unit(binary: str, interval_hours: float) -> str:
    return f"""[Unit]
Description=BlastRadius dependency vulnerability watcher
After=network-online.target

[Service]
Type=simple
ExecStart={binary} watch --interval-hours {interval_hours}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
"""


def _launchd_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _systemd_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / "blastradius.service"


def install(interval_hours: float = 6.0) -> int:
    kind = _platform()
    if kind == "unsupported":
        print(f"{CROSS} No supported service manager found "
              f"({platform.system()}; Linux needs systemctl).")
        print(f"    Run it yourself instead:  blastradius watch --interval-hours {interval_hours}")
        return 1

    binary = _binary()
    from .install import verify_binary
    works, detail = verify_binary(binary)
    if not works:
        print(f"{CROSS} {binary} does not run: {detail}")
        print("    Refusing to register a service that would crash on every start.")
        return 1

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    if kind == "launchd":
        path = _launchd_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_launchd_plist(binary, interval_hours))
        subprocess.run(["launchctl", "unload", str(path)],
                       capture_output=True, text=True)   # ignore "not loaded"
        result = subprocess.run(["launchctl", "load", "-w", str(path)],
                                capture_output=True, text=True)
    else:
        path = _systemd_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_systemd_unit(binary, interval_hours))
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        result = subprocess.run(["systemctl", "--user", "enable", "--now", "blastradius.service"],
                                capture_output=True, text=True)

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        print(f"{CROSS} wrote {path} but could not start it")
        if detail:
            print(f"    {DIM}{detail}{OFF}")
        return 1

    print(f"{TICK} watching every {interval_hours}h, starting now")
    print(f"  {DIM}{path}{OFF}")
    print(f"  {DIM}logs: {LOG_PATH}{OFF}")
    return 0


def uninstall() -> int:
    kind = _platform()
    if kind == "launchd":
        path = _launchd_path()
        if path.exists():
            subprocess.run(["launchctl", "unload", "-w", str(path)], capture_output=True)
            path.unlink()
            print(f"{TICK} removed {path}")
        else:
            print(f"{DIM}no service installed{OFF}")
    elif kind == "systemd":
        path = _systemd_path()
        if path.exists():
            subprocess.run(["systemctl", "--user", "disable", "--now", "blastradius.service"],
                           capture_output=True)
            path.unlink()
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
            print(f"{TICK} removed {path}")
        else:
            print(f"{DIM}no service installed{OFF}")
    else:
        print(f"{DIM}nothing to remove on this platform{OFF}")
    return 0


def stop() -> int:
    """Halt the watcher without removing it.

    Killing the process directly does not work — both supervisors are told to
    restart it on failure, which is right for a watchdog and surprising if you
    reach for `kill` first.
    """
    kind = _platform()
    if kind == "launchd":
        path = _launchd_path()
        if not path.exists():
            print(f"{DIM}no service installed{OFF}")
            return 0
        # Without -w this is a pause: the plist stays, `start` brings it back.
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
    elif kind == "systemd":
        if not _systemd_path().exists():
            print(f"{DIM}no service installed{OFF}")
            return 0
        subprocess.run(["systemctl", "--user", "stop", "blastradius.service"],
                       capture_output=True)
    else:
        print(f"{DIM}nothing to stop on this platform{OFF}")
        return 0

    print(f"{TICK} stopped — still installed, `service start` resumes it")
    return 0


def start() -> int:
    kind = _platform()
    if kind == "launchd":
        path = _launchd_path()
        if not path.exists():
            print(f"{CROSS} not installed — run: blastradius service install")
            return 1
        result = subprocess.run(["launchctl", "load", "-w", str(path)],
                                capture_output=True, text=True)
    elif kind == "systemd":
        if not _systemd_path().exists():
            print(f"{CROSS} not installed — run: blastradius service install")
            return 1
        result = subprocess.run(["systemctl", "--user", "start", "blastradius.service"],
                                capture_output=True, text=True)
    else:
        print(f"{DIM}nothing to start on this platform{OFF}")
        return 1

    if result.returncode != 0:
        print(f"{CROSS} {(result.stderr or result.stdout).strip()}")
        return 1
    print(f"{TICK} started")
    return 0


def status() -> int:
    kind = _platform()
    if kind == "unsupported":
        print(f"{WARN} no supported service manager on {platform.system()}")
        return 1

    if kind == "launchd":
        path = _launchd_path()
        if not path.exists():
            print(f"{CROSS} not installed — run: blastradius service install")
            return 1
        result = subprocess.run(["launchctl", "list", LABEL], capture_output=True, text=True)
        running = result.returncode == 0
    else:
        path = _systemd_path()
        if not path.exists():
            print(f"{CROSS} not installed — run: blastradius service install")
            return 1
        result = subprocess.run(["systemctl", "--user", "is-active", "blastradius.service"],
                                capture_output=True, text=True)
        running = result.stdout.strip() == "active"

    print(f"{TICK if running else CROSS} {'running' if running else 'installed but not running'}")
    print(f"  {DIM}{path}{OFF}")
    if running:
        print(f"  {DIM}stop it with:  blastradius service stop"
              f"   (remove entirely: service uninstall){OFF}")
    if LOG_PATH.exists():
        size = LOG_PATH.stat().st_size
        print(f"  {DIM}logs: {LOG_PATH} ({size} bytes){OFF}")
        tail = LOG_PATH.read_text(errors="ignore").strip().splitlines()[-3:]
        for line in tail:
            print(f"    {DIM}{line[:100]}{OFF}")
    else:
        print(f"  {DIM}no log output yet{OFF}")
    return 0 if running else 1
