"""Base discoverer interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from hb_scan.models.session import Session


class BaseDiscoverer(ABC):
    """Abstract base for AI tool discoverers.

    Each AI tool (Claude Code, Cursor, Aider, etc.) gets its own discoverer
    that knows where to find session data and how to normalize it.
    """

    name: str = ""              # "claude-code"
    display_name: str = ""      # "Claude Code"

    @abstractmethod
    def get_default_paths(self) -> List[Path]:
        """Return platform-specific default data paths to check."""

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if this tool has data on disk."""

    @abstractmethod
    def discover_sessions(
        self,
        since: Optional[datetime] = None,
        project_filter: Optional[str] = None,
    ) -> List[Session]:
        """Find and normalize all sessions.

        Args:
            since: Only include sessions after this timestamp.
            project_filter: Only include sessions for this project path.

        Returns:
            List of normalized Session objects.
        """

    def session_count(self) -> int:
        """Quick count without full parsing."""
        return len(self.discover_sessions())
