"""OS-native scheduler integration — install/remove periodic scans.

macOS: launchd plist
Linux: systemd timer + service
Windows: Task Scheduler (future)
"""

import platform
import subprocess
import sys
from pathlib import Path


_LABEL = "ai.humanbound.hb-scan"
_PLIST_DIR = Path.home() / "Library" / "LaunchAgents"
_PLIST_PATH = _PLIST_DIR / f"{_LABEL}.plist"
_SYSTEMD_DIR = Path.home() / ".config" / "systemd" / "user"
_SERVICE_PATH = _SYSTEMD_DIR / "hb-scan.service"
_TIMER_PATH = _SYSTEMD_DIR / "hb-scan.timer"


def _find_hb_scan_path() -> str:
    """Find the hb-scan executable path."""
    import shutil
    path = shutil.which("hb-scan")
    if path:
        return path
    # Fallback: python -m hb_scan.cli
    return f"{sys.executable} -m hb_scan.cli"


def install(interval: str = "daily") -> str:
    """Install periodic scan schedule. Returns status message."""
    system = platform.system()
    if system == "Darwin":
        return _install_launchd(interval)
    elif system == "Linux":
        return _install_systemd(interval)
    else:
        return f"Scheduling not yet supported on {system}. Use cron instead:\n  crontab -e\n  0 9 * * * {_find_hb_scan_path()} --since 24h --no-telemetry"


def uninstall() -> str:
    """Remove periodic scan schedule. Returns status message."""
    system = platform.system()
    if system == "Darwin":
        return _uninstall_launchd()
    elif system == "Linux":
        return _uninstall_systemd()
    else:
        return "Remove the hb-scan entry from your crontab: crontab -e"


def is_installed() -> bool:
    """Check if a schedule is currently installed."""
    system = platform.system()
    if system == "Darwin":
        return _PLIST_PATH.exists()
    elif system == "Linux":
        return _TIMER_PATH.exists()
    return False


def _interval_seconds(interval: str) -> int:
    """Convert interval string to seconds."""
    intervals = {
        "hourly": 3600,
        "4h": 14400,
        "8h": 28800,
        "12h": 43200,
        "daily": 86400,
        "weekly": 604800,
    }
    return intervals.get(interval, 86400)


# ── macOS (launchd) ──

def _install_launchd(interval: str) -> str:
    hb_scan = _find_hb_scan_path()
    secs = _interval_seconds(interval)

    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{hb_scan}</string>
        <string>--since</string>
        <string>24h</string>
        <string>--no-telemetry</string>
    </array>
    <key>StartInterval</key>
    <integer>{secs}</integer>
    <key>StandardOutPath</key>
    <string>{Path.home() / ".hb-scan" / "scheduler.log"}</string>
    <key>StandardErrorPath</key>
    <string>{Path.home() / ".hb-scan" / "scheduler.log"}</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""

    _PLIST_DIR.mkdir(parents=True, exist_ok=True)
    (Path.home() / ".hb-scan").mkdir(parents=True, exist_ok=True)
    _PLIST_PATH.write_text(plist)

    try:
        subprocess.run(["launchctl", "unload", str(_PLIST_PATH)],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    try:
        subprocess.run(["launchctl", "load", str(_PLIST_PATH)],
                       capture_output=True, check=True, timeout=5)
    except subprocess.CalledProcessError as e:
        return f"Failed to load schedule: {e}"

    return f"Scheduled {interval} scan (every {secs // 3600}h) via launchd"


def _uninstall_launchd() -> str:
    if not _PLIST_PATH.exists():
        return "No schedule installed"

    try:
        subprocess.run(["launchctl", "unload", str(_PLIST_PATH)],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    _PLIST_PATH.unlink(missing_ok=True)
    return "Schedule removed"


# ── Linux (systemd) ──

def _install_systemd(interval: str) -> str:
    hb_scan = _find_hb_scan_path()

    service = f"""[Unit]
Description=hb-scan AI Hygiene Scanner

[Service]
Type=oneshot
ExecStart={hb_scan} --since 24h --no-telemetry
"""

    timer_interval = {
        "hourly": "OnCalendar=hourly",
        "4h": "OnUnitActiveSec=4h",
        "8h": "OnUnitActiveSec=8h",
        "12h": "OnUnitActiveSec=12h",
        "daily": "OnCalendar=daily",
        "weekly": "OnCalendar=weekly",
    }.get(interval, "OnCalendar=daily")

    timer = f"""[Unit]
Description=hb-scan periodic AI hygiene scan

[Timer]
{timer_interval}
Persistent=true

[Install]
WantedBy=timers.target
"""

    _SYSTEMD_DIR.mkdir(parents=True, exist_ok=True)
    _SERVICE_PATH.write_text(service)
    _TIMER_PATH.write_text(timer)

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"],
                       capture_output=True, timeout=5)
        subprocess.run(["systemctl", "--user", "enable", "--now", "hb-scan.timer"],
                       capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return f"Failed to enable timer: {e}"

    return f"Scheduled {interval} scan via systemd timer"


def _uninstall_systemd() -> str:
    if not _TIMER_PATH.exists():
        return "No schedule installed"

    try:
        subprocess.run(["systemctl", "--user", "disable", "--now", "hb-scan.timer"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    _SERVICE_PATH.unlink(missing_ok=True)
    _TIMER_PATH.unlink(missing_ok=True)

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    return "Schedule removed"
