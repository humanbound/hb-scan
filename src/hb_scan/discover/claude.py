"""Claude Code session discoverer."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import platform

from .base import BaseDiscoverer
from hb_scan.models.session import Session, Message, ToolCall


class ClaudeDiscoverer(BaseDiscoverer):
    """Discover and normalize Claude Code sessions.

    Claude Code stores conversations as JSONL files at:
        ~/.claude/projects/<encoded-project-path>/<session-uuid>.jsonl

    Each line is a JSON object with keys:
        type: "user" | "assistant" | "system"
        message.content: [{type: "text", text: "..."}, {type: "tool_use", ...}]
        sessionId, uuid, timestamp, cwd, gitBranch
    """

    name = "claude-code"
    display_name = "Claude Code"

    def get_default_paths(self) -> List[Path]:
        home = Path.home()
        system = platform.system()

        if system == "Darwin":
            return [home / ".claude"]
        elif system == "Linux":
            return [home / ".claude"]
        elif system == "Windows":
            return [
                home / ".claude",
                home / "AppData" / "Roaming" / "claude",
            ]
        return [home / ".claude"]

    def is_installed(self) -> bool:
        return any(p.exists() for p in self.get_default_paths())

    def _find_projects_dir(self) -> Optional[Path]:
        for base in self.get_default_paths():
            projects = base / "projects"
            if projects.is_dir():
                return projects
        return None

    def discover_sessions(
        self,
        since: Optional[datetime] = None,
        project_filter: Optional[str] = None,
    ) -> List[Session]:
        projects_dir = self._find_projects_dir()
        if not projects_dir:
            return []

        sessions = []

        for project_dir in projects_dir.iterdir():
            if not project_dir.is_dir():
                continue

            # Decode project path from directory name
            project_path = self._decode_project_path(project_dir.name)

            if project_filter and project_filter not in project_path:
                continue

            # Find all session JSONL files (direct children, not in subagents/)
            for jsonl_file in project_dir.glob("*.jsonl"):
                session = self._parse_session(jsonl_file, project_path, since)
                if session and session.messages:
                    sessions.append(session)

            # Also scan subagent files
            for subagent_dir in project_dir.glob("*/subagents"):
                if subagent_dir.is_dir():
                    for jsonl_file in subagent_dir.glob("*.jsonl"):
                        session = self._parse_session(jsonl_file, project_path, since)
                        if session and session.messages:
                            sessions.append(session)

        return sessions

    def _decode_project_path(self, encoded: str) -> str:
        """Decode project directory name back to filesystem path.

        Claude Code encodes paths by replacing / with - and prepending -.
        Example: -Applications-MAMP-htdocs-project → /Applications/MAMP/htdocs/project
        """
        if encoded.startswith("-"):
            return "/" + encoded[1:].replace("-", "/")
        return encoded

    def _parse_session(
        self, jsonl_path: Path, project_path: str, since: Optional[datetime]
    ) -> Optional[Session]:
        """Parse a JSONL file into a Session."""
        messages = []
        session_id = jsonl_path.stem  # UUID from filename
        cwd = ""
        first_ts = None
        last_ts = None

        try:
            with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    msg = self._parse_entry(entry)
                    if not msg:
                        continue

                    # Track timestamps
                    if msg.timestamp:
                        if first_ts is None or msg.timestamp < first_ts:
                            first_ts = msg.timestamp
                        if last_ts is None or msg.timestamp > last_ts:
                            last_ts = msg.timestamp

                    # Track cwd from first entry that has it
                    if not cwd and entry.get("cwd"):
                        cwd = entry["cwd"]

                    messages.append(msg)
        except (OSError, PermissionError):
            return None

        # Filter by time
        if since and last_ts and last_ts < since:
            return None

        if not messages:
            return None

        return Session(
            id=session_id,
            tool=self.name,
            project_path=project_path,
            cwd=cwd,
            messages=messages,
            started_at=first_ts,
            ended_at=last_ts,
        )

    def _parse_entry(self, entry: dict) -> Optional[Message]:
        """Parse a single JSONL entry into a Message."""
        msg_type = entry.get("type")
        if msg_type not in ("user", "assistant", "system"):
            return None

        timestamp = self._parse_timestamp(entry.get("timestamp"))
        text_parts = []
        tool_calls = []

        message = entry.get("message", {})
        content = message.get("content", [])

        # Content can be a string or list of blocks
        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue

                block_type = block.get("type", "")

                if block_type == "text":
                    text_parts.append(block.get("text", ""))

                elif block_type == "tool_use":
                    tool_calls.append(ToolCall(
                        name=block.get("name", ""),
                        input=block.get("input", {}),
                    ))

                elif block_type == "tool_result":
                    # Attach output to the most recent tool call if available
                    result_content = block.get("content", "")
                    if isinstance(result_content, list):
                        result_content = " ".join(
                            b.get("text", "") for b in result_content
                            if isinstance(b, dict) and b.get("type") == "text"
                        )
                    if tool_calls:
                        tool_calls[-1].output = str(result_content)[:10000]

        return Message(
            role=msg_type,
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            timestamp=timestamp,
        )

    @staticmethod
    def _parse_timestamp(ts) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            # Unix timestamp (milliseconds or seconds)
            if ts > 1e12:
                ts = ts / 1000
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None
