"""Rule schema — YAML rule definition."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RuleMatch:
    """Match configuration for a rule."""

    target: str = "any"             # user_prompt, assistant_response, tool_input, tool_output, tool_name, any
    pattern: str = ""               # Regex pattern
    tool_filter: Optional[str] = None   # Only match in specific tool calls (e.g., "Bash")

    # Session heuristic (for DH-09)
    type: str = "regex"             # "regex" | "session_heuristic"
    condition: str = ""             # e.g. "tool_executions >= 50 AND user_messages <= 3"


@dataclass
class RuleExclude:
    """Exclusion pattern — matches that should NOT trigger the rule."""

    pattern: str = ""


@dataclass
class RuleReference:
    """Standards reference."""

    standard: str = ""
    url: str = ""


@dataclass
class Rule:
    """A single scanning rule loaded from YAML."""

    id: str
    version: int = 1
    category: str = ""              # DH-01 category name
    severity: str = "medium"        # critical, high, medium, low, info
    detection: str = "regex"        # regex, llm, hybrid
    experimental: bool = False
    description: str = ""
    mitigation: str = ""
    match: RuleMatch = field(default_factory=RuleMatch)
    exclude: List[RuleExclude] = field(default_factory=list)
    references: List[RuleReference] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Parse rule from YAML-loaded dict."""
        match_data = data.get("match", {})
        match = RuleMatch(
            target=match_data.get("target", "any"),
            pattern=match_data.get("pattern", ""),
            tool_filter=match_data.get("tool_filter"),
            type=match_data.get("type", "regex"),
            condition=match_data.get("condition", ""),
        )

        exclude = [
            RuleExclude(pattern=e.get("pattern", ""))
            for e in data.get("exclude", [])
        ]

        references = [
            RuleReference(
                standard=r.get("standard", ""),
                url=r.get("url", ""),
            )
            for r in data.get("references", [])
        ]

        return cls(
            id=data.get("id", ""),
            version=data.get("version", 1),
            category=data.get("category", ""),
            severity=data.get("severity", "medium"),
            detection=data.get("detection", "regex"),
            experimental=data.get("experimental", False),
            description=data.get("description", ""),
            mitigation=data.get("mitigation", ""),
            match=match,
            exclude=exclude,
            references=references,
        )

    def is_runnable_regex(self) -> bool:
        """Can this rule run in Tier 1.1 (regex only)?"""
        return self.detection in ("regex", "hybrid")
