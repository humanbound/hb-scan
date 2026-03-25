"""Normalized session data model — tool-agnostic."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class ToolCall:
    """A single tool invocation within a message."""

    name: str           # "Bash", "Read", "Write", "Edit", etc.
    input: dict         # Tool-specific params (command, file_path, etc.)
    output: str = ""    # Tool result content


@dataclass
class Message:
    """A single message in a conversation."""

    role: str                               # "user" | "assistant" | "system"
    text: str = ""                          # Concatenated text content
    tool_calls: List[ToolCall] = field(default_factory=list)
    timestamp: Optional[datetime] = None


@dataclass
class Session:
    """A normalized AI tool session — the unit of scanning."""

    id: str                                     # Session UUID
    tool: str                                   # "claude-code", "chatgpt-desktop", etc.
    project_path: str = ""                      # Original project directory
    cwd: str = ""                               # Working directory (for scope detection)
    source_file: str = ""                       # Absolute path to the source data file (JSONL, etc.)
    messages: List[Message] = field(default_factory=list)
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

    @property
    def tool_execution_count(self) -> int:
        """Count of tool calls across all messages."""
        return sum(len(m.tool_calls) for m in self.messages)

    @property
    def user_message_count(self) -> int:
        """Count of substantive user messages (excludes empty/trivial)."""
        trivial = {"", "yes", "y", "ok", "go", "continue", "proceed", "do it", "go ahead"}
        return sum(
            1 for m in self.messages
            if m.role == "user" and m.text.strip().lower() not in trivial
        )
