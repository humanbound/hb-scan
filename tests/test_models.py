"""Tests for data models: Session, Finding, PostureScore."""

import pytest
from datetime import datetime, timezone

from hb_scan.models.session import Session, Message, ToolCall
from hb_scan.models.finding import Finding, redact
from hb_scan.models.posture import calculate_posture, CATEGORY_WEIGHTS


# ── Session ──

class TestSession:

    def test_tool_execution_count(self):
        s = Session(id="s1", tool="test", messages=[
            Message(role="user", text="do something"),
            Message(role="assistant", text="ok", tool_calls=[
                ToolCall(name="Bash", input={"command": "ls"}),
                ToolCall(name="Write", input={"file_path": "x.py"}),
            ]),
            Message(role="assistant", text="done", tool_calls=[
                ToolCall(name="Read", input={"file_path": "y.py"}),
            ]),
        ])
        assert s.tool_execution_count == 3

    def test_tool_execution_count_empty(self):
        s = Session(id="s1", tool="test", messages=[
            Message(role="user", text="hello"),
        ])
        assert s.tool_execution_count == 0

    def test_user_message_count_excludes_trivial(self):
        s = Session(id="s1", tool="test", messages=[
            Message(role="user", text="Build me an API server"),
            Message(role="user", text="yes"),
            Message(role="user", text="ok"),
            Message(role="user", text="go ahead"),
            Message(role="user", text="Actually, change the port to 8080"),
        ])
        assert s.user_message_count == 2  # "Build me..." and "Actually, change..."

    def test_user_message_count_all_trivial(self):
        s = Session(id="s1", tool="test", messages=[
            Message(role="user", text="y"),
            Message(role="user", text="continue"),
            Message(role="user", text="proceed"),
        ])
        assert s.user_message_count == 0

    def test_user_message_count_excludes_assistant(self):
        s = Session(id="s1", tool="test", messages=[
            Message(role="user", text="Do this task"),
            Message(role="assistant", text="Sure, I'll do it"),
        ])
        assert s.user_message_count == 1


# ── Finding ──

class TestFinding:

    def test_id_is_deterministic(self):
        f1 = Finding(rule_id="r1", category="c", severity="high",
                     description="d", session_id="s1", match_context="ctx")
        f2 = Finding(rule_id="r1", category="c", severity="high",
                     description="d", session_id="s1", match_context="ctx")
        assert f1.id == f2.id

    def test_id_changes_with_context(self):
        f1 = Finding(rule_id="r1", category="c", severity="high",
                     description="d", session_id="s1", match_context="ctx1")
        f2 = Finding(rule_id="r1", category="c", severity="high",
                     description="d", session_id="s1", match_context="ctx2")
        assert f1.id != f2.id

    def test_severity_points(self):
        assert Finding(rule_id="r", category="c", severity="high", description="d").severity_points == 10
        assert Finding(rule_id="r", category="c", severity="medium", description="d").severity_points == 5
        assert Finding(rule_id="r", category="c", severity="low", description="d").severity_points == 2
        assert Finding(rule_id="r", category="c", severity="info", description="d").severity_points == 0

    def test_experimental_has_zero_points(self):
        f = Finding(rule_id="r", category="c", severity="high",
                    description="d", experimental=True)
        assert f.severity_points == 0


# ── Redaction ──

class TestRedaction:

    def test_redact_home_path_mac(self):
        assert "~/" in redact("/Users/john/secret.txt")

    def test_redact_home_path_linux(self):
        assert "~/" in redact("/home/john/secret.txt")

    def test_redact_password(self):
        result = redact("password=mysupersecretvalue")
        assert "mysupersecretvalue" not in result
        assert "*****" in result

    def test_redact_preserves_short_text(self):
        assert redact("hello world") == "hello world"


# ── Posture Scoring ──

class TestPostureScoring:

    def test_clean_scan_scores_100(self):
        p = calculate_posture([])
        assert p.score == 100
        assert p.grade == "A"

    def test_single_high_finding(self):
        f = Finding(rule_id="r", category="secret_exposure",
                    severity="high", description="d")
        p = calculate_posture([f])
        # secret_exposure weight = 20, high = 100% → penalty = 20
        assert p.score == 80
        assert p.grade == "B"

    def test_single_medium_finding(self):
        f = Finding(rule_id="r", category="dangerous_command",
                    severity="medium", description="d")
        p = calculate_posture([f])
        # dangerous_command weight = 10, medium = 50% → penalty = 5
        assert p.score == 95
        assert p.grade == "A"

    def test_multiple_same_category_no_stacking(self):
        """10 findings in same category should have same penalty as 1."""
        findings = [
            Finding(rule_id=f"r{i}", category="secret_exposure",
                    severity="high", description="d")
            for i in range(10)
        ]
        p = calculate_posture(findings)
        # Still just 20 points (control-based, not per-finding)
        assert p.score == 80

    def test_multiple_categories(self):
        findings = [
            Finding(rule_id="r1", category="secret_exposure", severity="high", description="d"),
            Finding(rule_id="r2", category="unsafe_code_acceptance", severity="high", description="d"),
            Finding(rule_id="r3", category="dangerous_command", severity="high", description="d"),
        ]
        p = calculate_posture(findings)
        # 20 + 12 + 10 = 42 penalty
        assert p.score == 58

    def test_info_severity_no_penalty(self):
        f = Finding(rule_id="r", category="excessive_reliance",
                    severity="info", description="d")
        p = calculate_posture([f])
        # excessive_reliance not in CATEGORY_WEIGHTS, and info = 0 multiplier
        assert p.score == 100

    def test_grade_thresholds(self):
        assert calculate_posture([]).grade == "A"  # 100

        f_high = Finding(rule_id="r", category="secret_exposure", severity="high", description="d")
        assert calculate_posture([f_high]).grade == "B"  # 80

        findings = [
            Finding(rule_id="r1", category="secret_exposure", severity="high", description="d"),
            Finding(rule_id="r2", category="sensitive_data_sharing", severity="high", description="d"),
        ]
        assert calculate_posture(findings).grade == "C"  # 65

    def test_category_weights_sum_to_100(self):
        assert sum(CATEGORY_WEIGHTS.values()) == 100
