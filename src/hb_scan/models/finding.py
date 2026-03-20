"""Finding data model."""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Finding:
    """A security finding from a rule match."""

    rule_id: str            # "aws-access-key-in-prompt"
    category: str           # "secret_exposure"
    severity: str           # "critical" | "high" | "medium" | "low" | "info"
    description: str        # Human-readable description from rule
    mitigation: str = ""    # Remediation steps from rule
    session_id: str = ""    # Which session
    tool: str = ""          # "claude-code"
    project_path: str = ""  # Which project
    timestamp: Optional[datetime] = None
    match_context: str = "" # Redacted snippet (for display)
    raw_match: str = ""     # Unredacted match (for enrichment only, never displayed)
    target: str = ""        # "user_prompt", "tool_input", etc.
    references: List[dict] = field(default_factory=list)
    experimental: bool = False
    evidence: List[dict] = field(default_factory=list)  # [{role, text, is_match}] conversation context
    source_file: str = ""       # absolute path to source data file for verification

    @property
    def id(self) -> str:
        """Deterministic ID from rule + session + match context."""
        raw = f"{self.rule_id}:{self.session_id}:{self.match_context}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def severity_points(self) -> int:
        """Penalty points for posture scoring."""
        if self.experimental:
            return 0
        return {
            "critical": 15,
            "high": 10,
            "medium": 5,
            "low": 2,
            "info": 0,
        }.get(self.severity, 0)


# --- Redaction utilities ---

_REDACT_PATTERNS = [
    # AWS keys: show prefix + last 4
    (re.compile(r"(AKIA)[A-Z0-9]{12}([A-Z0-9]{4})"), r"\1************\2"),
    # Generic long tokens: keep first 4 + last 4
    (re.compile(r"([A-Za-z0-9_-]{4})[A-Za-z0-9_-]{16,}([A-Za-z0-9_-]{4})"), r"\1****\2"),
    # Passwords after = or :
    (re.compile(r"((?:password|passwd|pwd|secret|token)\s*[=:]\s*['\"]?)[^\s'\"]+", re.IGNORECASE), r"\1*****"),
    # Home directory paths
    (re.compile(r"/Users/[^/]+/"), "~/"),
    (re.compile(r"/home/[^/]+/"), "~/"),
]


def redact(text: str) -> str:
    """Redact sensitive values from match context."""
    result = text
    for pattern, replacement in _REDACT_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
