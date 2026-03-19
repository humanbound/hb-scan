"""Tests for compliance framework assessment."""

import pytest

from hb_scan.compliance import assess_compliance
from hb_scan.insights import aggregate_findings
from hb_scan.models.finding import Finding


class TestComplianceAssessment:

    def test_clean_scan_all_pass(self):
        insights = aggregate_findings([], sessions_scanned=10)
        frameworks = assess_compliance(insights)
        assert len(frameworks) > 0
        for fw in frameworks:
            for c in fw.controls:
                # Either pass or not_assessed (regulatory needs LLM)
                assert c.status in ("pass", "not_assessed")

    def test_secret_exposure_fails_relevant_controls(self):
        findings = [
            Finding(rule_id="r1", category="secret_exposure", severity="high", description="d"),
        ]
        insights = aggregate_findings(findings, sessions_scanned=1)
        frameworks = assess_compliance(insights)

        # OWASP LLM should have LLM02 as fail
        owasp = next(fw for fw in frameworks if fw.framework_id == "owasp_llm")
        lm02 = next(c for c in owasp.controls if c.control_id == "LLM02:2025")
        assert lm02.status == "fail"

    def test_alignment_score_calculation(self):
        insights = aggregate_findings([], sessions_scanned=10)
        frameworks = assess_compliance(insights)
        for fw in frameworks:
            # With no findings, all assessed controls should pass → high alignment
            assessed = [c for c in fw.controls if c.status != "not_assessed"]
            if assessed:
                assert fw.alignment_score >= 0.5  # at least some pass

    def test_partial_status_when_mixed(self):
        """A control mapped to both passing and not_assessed categories → partial."""
        findings = []
        insights = aggregate_findings(findings, sessions_scanned=1, rules_skipped_llm=5)
        frameworks = assess_compliance(insights)

        # Find a control that maps to both a clean category and regulatory
        for fw in frameworks:
            for c in fw.controls:
                if "regulatory_data_exposure" in c.mapped_categories and len(c.mapped_categories) > 1:
                    # This control should be partial (one category pass, one not_assessed)
                    assert c.status == "partial"
                    return

    def test_framework_counts(self):
        findings = [
            Finding(rule_id="r1", category="secret_exposure", severity="high", description="d"),
        ]
        insights = aggregate_findings(findings, sessions_scanned=1)
        frameworks = assess_compliance(insights)

        for fw in frameworks:
            total = fw.controls_passed + fw.controls_failed + fw.controls_partial + fw.controls_not_assessed
            assert total == fw.total_controls
