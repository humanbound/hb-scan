"""Anonymous telemetry — opt-out via --no-telemetry or HB_SCAN_NO_TELEMETRY=1.

Sends only aggregate counts on each scan. No conversation content, file paths,
or secrets. Install ID is a random UUID with no link to the user's identity.
"""

import json
import os
import platform
import uuid
from pathlib import Path
from typing import Dict


_CONFIG_DIR = Path.home() / ".hb-scan"
_INSTALL_ID_FILE = _CONFIG_DIR / "install-id"


def is_enabled() -> bool:
    """Check if telemetry is enabled (opt-out)."""
    return os.environ.get("HB_SCAN_NO_TELEMETRY", "").lower() not in ("1", "true", "yes")


def get_install_id() -> str:
    """Get or create a random install ID."""
    try:
        if _INSTALL_ID_FILE.exists():
            return _INSTALL_ID_FILE.read_text().strip()

        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        install_id = str(uuid.uuid4())
        _INSTALL_ID_FILE.write_text(install_id)
        return install_id
    except OSError:
        return "unknown"


def send_ping(
    scan_results: Dict,
    enabled: bool = True,
) -> bool:
    """Send anonymous telemetry ping. Returns True if sent.

    Payload:
        install_id: random UUID
        version: hb-scan version
        os: platform name
        tools_found: list of tool names
        session_count: total sessions scanned
        finding_count: total findings
        categories_triggered: list of finding categories
        score: posture score
    """
    if not enabled or not is_enabled():
        return False

    from hb_scan import __version__

    payload = {
        "install_id": get_install_id(),
        "version": __version__,
        "os": platform.system().lower(),
        "tools_found": scan_results.get("tools_found", []),
        "session_count": scan_results.get("session_count", 0),
        "finding_count": scan_results.get("finding_count", 0),
        "categories_triggered": scan_results.get("categories_triggered", []),
        "score": scan_results.get("score", 100),
    }

    try:
        import urllib.request

        req = urllib.request.Request(
            "https://telemetry.humanbound.ai/hb-scan/ping",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
        return True
    except Exception:
        return False  # Silently fail — telemetry must never block the scan
