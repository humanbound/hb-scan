"""Scan history — stores scores and reports for trend tracking.

Storage layout:
  ~/.hb-scan/
  ├── history.json        # [{date, score, grade, findings, hoi, active_creds, sessions}]
  └── reports/
      ├── 2026-03-16.html
      ├── 2026-03-17.html
      └── ...
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from hb_scan.insights import ScanInsights


_DATA_DIR = Path.home() / ".hb-scan"
_HISTORY_FILE = _DATA_DIR / "history.json"
_REPORTS_DIR = _DATA_DIR / "reports"


def _ensure_dirs():
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def save_scan(insights: ScanInsights, html_content: str) -> Path:
    """Save a scan result: append to history and write HTML report.

    Returns the path to the saved HTML report.
    """
    _ensure_dirs()

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H-%M")

    # Save HTML report
    report_name = f"{date_str}_{time_str}.html"
    report_path = _REPORTS_DIR / report_name
    report_path.write_text(html_content)

    # Append to history
    hoi = round(1.0 - insights.oversight.auto_pilot_rate, 2)
    entry = {
        "date": now.isoformat(),
        "date_short": now.strftime("%b %d"),
        "score": insights.score,
        "grade": insights.grade,
        "findings": len([f for f in insights.all_findings if not f.experimental]),
        "hoi": hoi,
        "active_creds": insights.credentials.active_count,
        "sessions": insights.sessions_scanned,
        "report": report_name,
    }

    history = load_history()
    history.append(entry)

    # Keep last 90 entries max
    if len(history) > 90:
        history = history[-90:]

    _HISTORY_FILE.write_text(json.dumps(history, indent=2))

    return report_path


def load_history() -> list:
    """Load scan history from disk."""
    if not _HISTORY_FILE.exists():
        return []
    try:
        return json.loads(_HISTORY_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def get_latest_report() -> Optional[Path]:
    """Get path to the most recent HTML report."""
    history = load_history()
    if not history:
        return None
    latest = history[-1]
    path = _REPORTS_DIR / latest["report"]
    return path if path.exists() else None


def get_trend(last_n: int = 5) -> Optional[str]:
    """Calculate score trend from last N scans."""
    history = load_history()
    if len(history) < 2:
        return None

    recent = history[-last_n:]
    scores = [e["score"] for e in recent]
    avg = sum(scores) / len(scores)

    if len(history) >= 2:
        diff = scores[-1] - scores[0]
        if diff > 5:
            return f"improving (+{diff} over {len(recent)} scans)"
        elif diff < -5:
            return f"declining ({diff} over {len(recent)} scans)"

    return f"stable ({round(avg)} avg over {len(recent)} scans)"
