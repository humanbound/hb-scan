"""Discoverer registry — auto-detect available AI tools."""

from typing import Dict, List, Optional

from .base import BaseDiscoverer
from .claude import ClaudeDiscoverer
from hb_scan.models.session import Session


# All known discoverers — add new tools here
_DISCOVERERS: List[BaseDiscoverer] = [
    ClaudeDiscoverer(),
]


def get_discoverers(tool_filter: Optional[str] = None) -> List[BaseDiscoverer]:
    """Get discoverers, optionally filtered by tool name."""
    if tool_filter:
        return [d for d in _DISCOVERERS if d.name == tool_filter]
    return _DISCOVERERS


def discover_all(
    tool_filter: Optional[str] = None,
    since=None,
    project_filter: Optional[str] = None,
) -> Dict[str, List[Session]]:
    """Discover sessions across all installed AI tools.

    Returns:
        Dict mapping tool name to list of sessions.
    """
    results: Dict[str, List[Session]] = {}

    for discoverer in get_discoverers(tool_filter):
        if not discoverer.is_installed():
            continue
        sessions = discoverer.discover_sessions(
            since=since,
            project_filter=project_filter,
        )
        if sessions:
            results[discoverer.name] = sessions

    return results
