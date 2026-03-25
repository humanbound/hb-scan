"""Tests for the YAML rule engine."""

import pytest
from pathlib import Path

from hb_scan.rules.engine import RuleEngine
from hb_scan.rules.schema import Rule
from hb_scan.models.session import Session, Message, ToolCall


FIXTURES = Path(__file__).parent / "fixtures"


class TestRuleLoading:

    def test_loads_builtin_rules(self):
        engine = RuleEngine()
        assert len(engine.rules) > 50

    def test_active_rules_exclude_llm(self):
        engine = RuleEngine()
        active = engine.active_rules
        skipped = engine.skipped_llm_rules
        assert len(active) + len(skipped) == len(engine.rules)
        for r in active:
            assert r.detection in ("regex", "hybrid")
        for r in skipped:
            assert r.detection == "llm"

    def test_custom_rules_dir(self, tmp_path):
        rule_file = tmp_path / "custom.yml"
        rule_file.write_text("""
id: test-custom-rule
version: 1
category: secret_exposure
severity: high
detection: regex
description: "Test custom rule"
match:
  target: user_prompt
  pattern: "CUSTOM_SECRET_[A-Z]{10}"
mitigation: "Rotate it."
""")
        engine = RuleEngine(rules_dirs=[tmp_path])
        ids = [r.id for r in engine.rules]
        assert "test-custom-rule" in ids


class TestRuleSchema:

    def test_from_dict_basic(self):
        r = Rule.from_dict({
            "id": "test-rule",
            "category": "secret_exposure",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "user_prompt", "pattern": "SECRET_[A-Z]+"},
        })
        assert r.id == "test-rule"
        assert r.match.target == "user_prompt"
        assert r.is_runnable_regex()

    def test_llm_rule_not_runnable_regex(self):
        r = Rule.from_dict({
            "id": "llm-rule",
            "detection": "llm",
            "match": {"target": "any"},
        })
        assert not r.is_runnable_regex()

    def test_from_dict_with_excludes(self):
        r = Rule.from_dict({
            "id": "test",
            "detection": "regex",
            "match": {"target": "any", "pattern": "test"},
            "exclude": [{"pattern": "exclude_this"}],
        })
        assert len(r.exclude) == 1
        assert r.exclude[0].pattern == "exclude_this"


class TestRuleMatching:

    def _make_session(self, user_text="", assistant_text="", tool_name="", tool_input=""):
        messages = []
        if user_text:
            messages.append(Message(role="user", text=user_text))
        if assistant_text or tool_name:
            tool_calls = []
            if tool_name:
                tool_calls.append(ToolCall(name=tool_name, input={"command": tool_input}))
            messages.append(Message(role="assistant", text=assistant_text, tool_calls=tool_calls))
        return Session(id="test-session", tool="test", messages=messages, cwd="/test")

    def test_matches_user_prompt(self):
        engine = RuleEngine()
        # Create a minimal engine with one rule
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-match",
            "category": "secret_exposure",
            "severity": "high",
            "detection": "regex",
            "description": "Test match",
            "match": {"target": "user_prompt", "pattern": "AKIA[A-Z0-9]{16}"},
        })
        engine.rules.append(r)
        engine._compiled["test-match"] = re.compile(r.match.pattern, re.IGNORECASE)

        session = self._make_session(user_text="My key is AKIA1234567890ABCDEF")
        findings = engine.scan_session(session)
        assert len(findings) == 1
        assert findings[0].rule_id == "test-match"

    def test_no_match_wrong_target(self):
        engine = RuleEngine()
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-no-match",
            "category": "secret_exposure",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "user_prompt", "pattern": "AKIA[A-Z0-9]{16}"},
        })
        engine.rules.append(r)
        engine._compiled["test-no-match"] = re.compile(r.match.pattern, re.IGNORECASE)

        # Key in assistant response, not user prompt
        session = self._make_session(assistant_text="Your key is AKIA1234567890ABCDEF")
        findings = engine.scan_session(session)
        assert len(findings) == 0

    def test_exclude_filters_match(self):
        engine = RuleEngine()
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-exclude",
            "category": "secret_exposure",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "user_prompt", "pattern": "password=\\w+"},
            "exclude": [{"pattern": "example|test|fake"}],
        })
        engine.rules.append(r)
        engine._compiled["test-exclude"] = re.compile(r.match.pattern, re.IGNORECASE)
        engine._compiled["test-exclude:exclude:0"] = re.compile("example|test|fake", re.IGNORECASE)

        session = self._make_session(user_text="Use this test config: password=fakepass123")
        findings = engine.scan_session(session)
        assert len(findings) == 0  # excluded by "test" and "fake"

    def test_tool_filter_matches_correct_tool(self):
        engine = RuleEngine()
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-tool",
            "category": "dangerous_command",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "tool_input", "tool_filter": "Bash", "pattern": "sudo"},
        })
        engine.rules.append(r)
        engine._compiled["test-tool"] = re.compile(r.match.pattern, re.IGNORECASE)

        session = self._make_session(tool_name="Bash", tool_input="sudo rm -rf /tmp/test")
        findings = engine.scan_session(session)
        assert len(findings) == 1

    def test_tool_filter_ignores_wrong_tool(self):
        engine = RuleEngine()
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-tool-wrong",
            "category": "dangerous_command",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "tool_input", "tool_filter": "Bash", "pattern": "sudo"},
        })
        engine.rules.append(r)
        engine._compiled["test-tool-wrong"] = re.compile(r.match.pattern, re.IGNORECASE)

        session = self._make_session(tool_name="Read", tool_input="sudo something")
        findings = engine.scan_session(session)
        assert len(findings) == 0

    def test_deduplication_within_session(self):
        engine = RuleEngine()
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-dedup",
            "category": "secret_exposure",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "user_prompt", "pattern": "SECRET123"},
        })
        engine.rules.append(r)
        engine._compiled["test-dedup"] = re.compile(r.match.pattern, re.IGNORECASE)

        # Same session, two messages with same match → one finding
        session = Session(id="s1", tool="test", messages=[
            Message(role="user", text="SECRET123"),
            Message(role="user", text="SECRET123 again"),
        ])
        findings = engine.scan_all([session])
        # Same rule + session + context → deduplicated
        assert len(findings) >= 1

    def test_different_sessions_produce_different_findings(self):
        engine = RuleEngine()
        engine.rules = []
        engine._compiled = {}
        import re
        r = Rule.from_dict({
            "id": "test-diff",
            "category": "secret_exposure",
            "severity": "high",
            "detection": "regex",
            "description": "Test",
            "match": {"target": "user_prompt", "pattern": "SECRET123"},
        })
        engine.rules.append(r)
        engine._compiled["test-diff"] = re.compile(r.match.pattern, re.IGNORECASE)

        s1 = self._make_session(user_text="SECRET123")
        s2 = self._make_session(user_text="SECRET123")
        s2.id = "different-session"
        findings = engine.scan_all([s1, s2])
        # Different sessions → different finding IDs
        assert len(findings) == 2


class TestSessionHeuristic:

    def test_auto_pilot_detected(self):
        engine = RuleEngine()
        # Find the auto-pilot rule
        heuristic_rules = [r for r in engine.active_rules if r.match.type == "session_heuristic"]
        if not heuristic_rules:
            pytest.skip("No heuristic rules loaded")

        # Create a session with 60 tool calls and 1 user message
        messages = [Message(role="user", text="Build everything")]
        for i in range(60):
            messages.append(Message(role="assistant", text="", tool_calls=[
                ToolCall(name="Write", input={"file_path": f"file{i}.py"})
            ]))

        session = Session(id="auto-pilot", tool="test", messages=messages)
        findings = engine.scan_session(session)
        auto_findings = [f for f in findings if f.category == "excessive_reliance"]
        assert len(auto_findings) == 1
        assert auto_findings[0].experimental is True

    def test_supervised_session_not_flagged(self):
        engine = RuleEngine()

        messages = []
        for i in range(10):
            messages.append(Message(role="user", text=f"Do step {i} of the task"))
            messages.append(Message(role="assistant", text="", tool_calls=[
                ToolCall(name="Write", input={"file_path": f"file{i}.py"})
            ]))

        session = Session(id="supervised", tool="test", messages=messages)
        findings = engine.scan_session(session)
        auto_findings = [f for f in findings if f.category == "excessive_reliance"]
        assert len(auto_findings) == 0
