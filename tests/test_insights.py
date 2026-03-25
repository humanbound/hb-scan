"""Tests for insight aggregation."""

import pytest

from hb_scan.insights import aggregate_findings, CredentialSummary
from hb_scan.models.finding import Finding


class TestCredentialAggregation:

    def test_deduplication(self):
        findings = [
            Finding(rule_id="jwt-token", category="secret_exposure", severity="high",
                    description="JWT found", match_context="eyJhbG...ABC", session_id="s1"),
            Finding(rule_id="jwt-token", category="secret_exposure", severity="high",
                    description="JWT found", match_context="eyJhbG...ABC", session_id="s2"),
        ]
        insights = aggregate_findings(findings, sessions_scanned=2)
        # Same match_context[:50] → deduplicated to 1 unique
        assert insights.credentials.total_unique == 1

    def test_different_creds_not_deduped(self):
        findings = [
            Finding(rule_id="jwt-token", category="secret_exposure", severity="high",
                    description="JWT found", match_context="eyJhbG...token1", session_id="s1"),
            Finding(rule_id="aws-access-key-id", category="secret_exposure", severity="high",
                    description="AWS key", match_context="AKIA1234567890ABCDEF", session_id="s1"),
        ]
        insights = aggregate_findings(findings, sessions_scanned=1)
        assert insights.credentials.total_unique == 2

    def test_type_mapping(self):
        findings = [
            Finding(rule_id="jwt-token", category="secret_exposure", severity="high",
                    description="d", match_context="jwt1"),
            Finding(rule_id="aws-access-key-id", category="secret_exposure", severity="high",
                    description="d", match_context="aws1"),
        ]
        insights = aggregate_findings(findings, sessions_scanned=1)
        assert "JWT Token" in insights.credentials.by_type
        assert "aws-access-key-id" in insights.credentials.by_type  # falls through to rule_id


class TestSectionMapping:

    def test_code_security_findings(self):
        f = Finding(rule_id="eval", category="unsafe_code_acceptance", severity="high",
                    description="eval found")
        insights = aggregate_findings([f], sessions_scanned=1)
        assert not insights.code_security.clean
        assert insights.code_security.finding_count == 1

    def test_command_findings(self):
        f = Finding(rule_id="sudo", category="dangerous_command", severity="high",
                    description="sudo used")
        insights = aggregate_findings([f], sessions_scanned=1)
        assert not insights.commands.clean

    def test_clean_scan(self):
        insights = aggregate_findings([], sessions_scanned=10)
        assert insights.sensitive_data.clean
        assert insights.code_security.clean
        assert insights.commands.clean
        assert insights.packages.clean
        assert insights.ip_leakage.clean
        assert insights.score == 100
        assert insights.grade == "A"


class TestOversightAggregation:

    def test_auto_pilot_rate(self):
        oversight_findings = [
            Finding(rule_id="auto-pilot", category="excessive_reliance", severity="info",
                    description="d", experimental=True)
            for _ in range(5)
        ]
        insights = aggregate_findings(oversight_findings, sessions_scanned=100)
        assert insights.oversight.auto_pilot_sessions == 5
        assert insights.oversight.auto_pilot_rate == 0.05

    def test_no_auto_pilot(self):
        insights = aggregate_findings([], sessions_scanned=50)
        assert insights.oversight.auto_pilot_sessions == 0
        assert insights.oversight.auto_pilot_rate == 0.0


class TestScoring:

    def test_control_based_no_stacking(self):
        """Multiple findings in one category should not stack penalties."""
        findings = [
            Finding(rule_id=f"r{i}", category="secret_exposure", severity="high", description="d")
            for i in range(20)
        ]
        insights = aggregate_findings(findings, sessions_scanned=1)
        # Control-based: secret_exposure weight = 20, regardless of count
        assert insights.score == 80

    def test_penalty_breakdown(self):
        findings = [
            Finding(rule_id="r1", category="secret_exposure", severity="high", description="d"),
            Finding(rule_id="r2", category="supply_chain_risk", severity="medium", description="d"),
        ]
        insights = aggregate_findings(findings, sessions_scanned=1)
        assert "secret_exposure" in insights.penalty_breakdown
        assert "supply_chain_risk" in insights.penalty_breakdown
