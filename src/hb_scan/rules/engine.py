"""Rule engine — load YAML rules, match against sessions."""

import re
from pathlib import Path
from typing import List, Optional, Tuple

import yaml

from .schema import Rule
from hb_scan.models.session import Session, Message
from hb_scan.models.finding import Finding, redact

# Built-in rules directory
_BUILTIN_DIR = Path(__file__).parent / "builtin"


class RuleEngine:
    """Load and execute YAML security rules against sessions."""

    def __init__(self, rules_dirs: Optional[List[Path]] = None, include_llm: bool = False):
        """Initialize with rule directories.

        Args:
            rules_dirs: Additional rule directories to load (on top of built-in).
            include_llm: If False (default), skip rules with detection=llm.
        """
        self.include_llm = include_llm
        self.rules: List[Rule] = []
        self._compiled: dict = {}  # rule_id → compiled regex

        # Load built-in rules
        if _BUILTIN_DIR.is_dir():
            self._load_dir(_BUILTIN_DIR)

        # Load custom rules
        for d in (rules_dirs or []):
            if Path(d).is_dir():
                self._load_dir(Path(d))

    def _load_dir(self, directory: Path):
        """Load all YAML files from a directory."""
        for yml_file in sorted(directory.glob("*.yml")):
            self._load_file(yml_file)
        for yaml_file in sorted(directory.glob("*.yaml")):
            self._load_file(yaml_file)

    def _load_file(self, path: Path):
        """Load rules from a single YAML file (may contain multiple docs)."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:
            return

        for doc in docs:
            if not isinstance(doc, dict) or "id" not in doc:
                continue
            rule = Rule.from_dict(doc)

            # Compile regex if applicable
            if rule.match.pattern and rule.is_runnable_regex():
                try:
                    self._compiled[rule.id] = re.compile(rule.match.pattern, re.IGNORECASE)
                except re.error:
                    continue  # Skip rules with bad regex

            # Compile exclude patterns
            for i, exc in enumerate(rule.exclude):
                if exc.pattern:
                    try:
                        self._compiled[f"{rule.id}:exclude:{i}"] = re.compile(
                            exc.pattern, re.IGNORECASE
                        )
                    except re.error:
                        pass

            self.rules.append(rule)

    @property
    def active_rules(self) -> List[Rule]:
        """Rules that can run in current mode (regex-only or all)."""
        if self.include_llm:
            return self.rules
        return [r for r in self.rules if r.is_runnable_regex()]

    @property
    def skipped_llm_rules(self) -> List[Rule]:
        """Rules skipped because they require LLM."""
        if self.include_llm:
            return []
        return [r for r in self.rules if not r.is_runnable_regex()]

    def scan_session(self, session: Session) -> List[Finding]:
        """Scan a single session against all active rules."""
        findings: List[Finding] = []

        for rule in self.active_rules:
            if rule.match.type == "session_heuristic":
                finding = self._check_heuristic(rule, session)
                if finding:
                    findings.append(finding)
            else:
                matches = self._match_rule(rule, session)
                findings.extend(matches)

        return findings

    def scan_all(self, sessions: List[Session]) -> List[Finding]:
        """Scan all sessions and return deduplicated findings."""
        findings: List[Finding] = []
        seen_ids = set()

        for session in sessions:
            for finding in self.scan_session(session):
                if finding.id not in seen_ids:
                    seen_ids.add(finding.id)
                    findings.append(finding)

        return findings

    def _match_rule(self, rule: Rule, session: Session) -> List[Finding]:
        """Match a regex rule against a session."""
        compiled = self._compiled.get(rule.id)
        if not compiled:
            return []

        findings: List[Finding] = []
        targets = self._extract_targets(rule, session)

        for target_name, text in targets:
            match = compiled.search(text)
            if not match:
                continue

            context = self._extract_context(text, match.start(), match.end())

            # Check exclusions against context (not entire message)
            if self._is_excluded(rule, context):
                continue

            findings.append(Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                description=rule.description,
                mitigation=rule.mitigation,
                session_id=session.id,
                tool=session.tool,
                project_path=session.project_path,
                timestamp=session.started_at,
                match_context=redact(context),
                raw_match=match.group(),
                target=target_name,
                references=[{"standard": r.standard, "url": r.url} for r in rule.references],
                experimental=rule.experimental,
            ))

        return findings

    def _extract_targets(
        self, rule: Rule, session: Session
    ) -> List[Tuple[str, str]]:
        """Extract text to scan based on rule target."""
        targets: List[Tuple[str, str]] = []
        target = rule.match.target
        tool_filter = rule.match.tool_filter

        for msg in session.messages:
            if target in ("user_prompt", "any") and msg.role == "user":
                targets.append(("user_prompt", msg.text))

            if target in ("assistant_response", "any") and msg.role == "assistant":
                targets.append(("assistant_response", msg.text))

            if target in ("tool_input", "any"):
                for tc in msg.tool_calls:
                    if tool_filter and tc.name != tool_filter:
                        continue
                    # Serialize tool input for scanning
                    input_text = self._serialize_tool_input(tc)
                    targets.append(("tool_input", input_text))

            if target in ("tool_output", "any"):
                for tc in msg.tool_calls:
                    if tool_filter and tc.name != tool_filter:
                        continue
                    if tc.output:
                        targets.append(("tool_output", tc.output))

        return targets

    @staticmethod
    def _serialize_tool_input(tc) -> str:
        """Serialize tool call input to a scannable string."""
        if not tc.input:
            return ""
        if isinstance(tc.input, str):
            return tc.input
        # For dict inputs, extract key values
        parts = []
        for key, val in tc.input.items():
            parts.append(f"{key}: {val}" if isinstance(val, str) else f"{key}: {val}")
        return "\n".join(parts)

    def _is_excluded(self, rule: Rule, text: str) -> bool:
        """Check if the text matches any exclusion pattern."""
        for i in range(len(rule.exclude)):
            exc_compiled = self._compiled.get(f"{rule.id}:exclude:{i}")
            if exc_compiled and exc_compiled.search(text):
                return True
        return False

    @staticmethod
    def _extract_context(text: str, start: int, end: int, window: int = 80) -> str:
        """Extract context around a match, capped at window chars."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        context = text[ctx_start:ctx_end]
        if ctx_start > 0:
            context = "..." + context
        if ctx_end < len(text):
            context = context + "..."
        return context

    def _check_heuristic(self, rule: Rule, session: Session) -> Optional[Finding]:
        """Check session-level heuristic (DH-09)."""
        condition = rule.match.condition
        if not condition:
            return None

        # Parse simple conditions: "tool_executions >= 50 AND user_messages <= 3"
        tool_execs = session.tool_execution_count
        user_msgs = session.user_message_count

        try:
            # Replace variable names with values and evaluate
            expr = condition
            expr = expr.replace("tool_executions", str(tool_execs))
            expr = expr.replace("user_messages", str(user_msgs))
            expr = expr.replace("AND", "and")
            expr = expr.replace("OR", "or")

            # Safe eval — only allows numeric comparisons
            if not re.match(r'^[\d\s<>=!andor]+$', expr):
                return None

            if eval(expr):  # noqa: S307 — safe: only digits, operators, and/or
                return Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    mitigation=rule.mitigation,
                    session_id=session.id,
                    tool=session.tool,
                    project_path=session.project_path,
                    timestamp=session.started_at,
                    match_context=f"Session: {tool_execs} tool executions, {user_msgs} substantive user messages",
                    target="session_heuristic",
                    references=[{"standard": r.standard, "url": r.url} for r in rule.references],
                    experimental=rule.experimental,
                )
        except Exception:
            pass

        return None
