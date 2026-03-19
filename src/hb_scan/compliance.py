"""Compliance mapping — map scan results to international standards.

Maps DH threat classes to specific controls in international frameworks,
producing an audit-ready compliance assessment.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hb_scan.insights import ScanInsights


@dataclass
class ControlAssessment:
    """Assessment of a single compliance control."""

    control_id: str         # e.g. "LLM02:2025"
    control_name: str       # e.g. "Sensitive Information Disclosure"
    status: str             # "pass" | "fail" | "partial" | "not_assessed"
    mapped_categories: List[str] = field(default_factory=list)
    finding_count: int = 0
    notes: str = ""


@dataclass
class FrameworkAssessment:
    """Assessment against a single compliance framework."""

    framework_id: str       # e.g. "owasp_llm"
    framework_name: str     # e.g. "OWASP Top 10 for LLM Applications 2025"
    url: str = ""
    controls: List[ControlAssessment] = field(default_factory=list)
    controls_passed: int = 0
    controls_failed: int = 0
    controls_partial: int = 0
    controls_not_assessed: int = 0

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def alignment_score(self) -> float:
        """0.0-1.0 alignment score. Pass=1, Partial=0.5, Fail=0, Not assessed=excluded."""
        assessed = [c for c in self.controls if c.status != "not_assessed"]
        if not assessed:
            return 0.0
        total = sum(
            1.0 if c.status == "pass" else (0.5 if c.status == "partial" else 0.0)
            for c in assessed
        )
        return round(total / len(assessed), 2)


# --- Framework definitions ---
# Each framework maps controls to DH categories.
# Status is derived from scan results: if the DH category has findings → fail,
# if it was scanned and clean → pass, if it needs LLM → not_assessed.

_FRAMEWORKS = [
    {
        "id": "owasp_llm",
        "name": "OWASP Top 10 for LLM Applications 2025",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/",
        "controls": [
            {"id": "LLM02:2025", "name": "Sensitive Information Disclosure",
             "categories": ["secret_exposure", "sensitive_data_sharing"],
             "remediation": "Implement data classification and DLP controls for AI tool interactions. Apply strict input validation to detect and filter sensitive data."},
            {"id": "LLM03:2025", "name": "Supply Chain Vulnerabilities",
             "categories": ["supply_chain_risk"],
             "remediation": "Verify all AI-suggested packages on official registries. Use lockfiles and dependency scanning tools."},
            {"id": "LLM05:2025", "name": "Improper Output Handling",
             "categories": ["unsafe_code_acceptance"],
             "remediation": "Treat all AI-generated code as untrusted input. Run SAST tools before committing."},
            {"id": "LLM06:2025", "name": "Excessive Agency",
             "categories": ["dangerous_command", "scope_violation"],
             "remediation": "Restrict AI tool permissions to minimum necessary. Require human approval for high-impact actions."},
            {"id": "LLM09:2025", "name": "Misinformation (Overreliance)",
             "categories": ["excessive_reliance"],
             "remediation": "Mandate human review for AI outputs in critical decisions. Train staff on automation bias."},
        ],
    },
    {
        "id": "owasp_agentic",
        "name": "OWASP Top 10 for Agentic Applications 2026",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        "controls": [
            {"id": "ASI02", "name": "Tool Misuse and Exploitation",
             "categories": ["dangerous_command"],
             "remediation": "Implement strict tool permission scoping and sandboxed execution."},
            {"id": "ASI03", "name": "Identity and Privilege Abuse",
             "categories": ["scope_violation"],
             "remediation": "Give each AI session bounded identity with short-lived credentials. Isolate sessions."},
            {"id": "ASI05", "name": "Unexpected Code Execution",
             "categories": ["unsafe_code_acceptance", "dangerous_command"],
             "remediation": "Sandbox AI code generation. Review before execution."},
        ],
    },
    {
        "id": "nist",
        "name": "NIST AI Risk Management Framework & SP 800-218A",
        "url": "https://csrc.nist.gov/pubs/sp/800/218/a/final",
        "controls": [
            {"id": "AI 600-1 §2.4", "name": "Data Privacy — Memorisation Risks",
             "categories": ["secret_exposure", "sensitive_data_sharing", "regulatory_data_exposure"],
             "remediation": "Implement data minimisation for AI tool inputs. De-identify before processing."},
            {"id": "SP 800-218A PW.4", "name": "Secure Coding Practices",
             "categories": ["unsafe_code_acceptance"],
             "remediation": "Adhere to OWASP ASVS requirements for all AI-generated code."},
            {"id": "SP 800-218A PW.3", "name": "Supply Chain Integrity",
             "categories": ["supply_chain_risk"],
             "remediation": "Confirm integrity of all AI-suggested dependencies before use."},
            {"id": "AI RMF Measure 2.8", "name": "Human Oversight Statistics",
             "categories": ["excessive_reliance"],
             "remediation": "Maintain statistics about AI system override rates and reported errors."},
        ],
    },
    {
        "id": "iso42001",
        "name": "ISO/IEC 42001:2023 — AI Management System",
        "url": "https://www.iso.org/standard/42001",
        "controls": [
            {"id": "A.5", "name": "Assessing Impacts of AI Systems",
             "categories": ["excessive_reliance", "scope_violation"],
             "remediation": "Document intended use, foreseeable misuse, and role of human oversight."},
            {"id": "A.6", "name": "AI System Lifecycle — Responsible Development",
             "categories": ["unsafe_code_acceptance", "dangerous_command"],
             "remediation": "Apply security controls at each lifecycle stage of AI-assisted development."},
            {"id": "A.7", "name": "Data for AI Systems — Governance",
             "categories": ["sensitive_data_sharing", "regulatory_data_exposure"],
             "remediation": "Define data quality requirements. Record data provenance and lineage."},
            {"id": "A.8", "name": "Information and Transparency",
             "categories": ["secret_exposure", "ip_trade_secret_leakage"],
             "remediation": "Disclose AI system limitations and data handling risks to stakeholders."},
        ],
    },
    {
        "id": "iso27001",
        "name": "ISO/IEC 27001:2022 — Information Security",
        "url": "https://www.iso.org/standard/27001",
        "controls": [
            {"id": "A.5.14", "name": "Information Transfer",
             "categories": ["secret_exposure", "sensitive_data_sharing", "ip_trade_secret_leakage"],
             "remediation": "Establish rules and procedures for information transfer to AI tools."},
            {"id": "A.5.33", "name": "Protection of Records",
             "categories": ["sensitive_data_sharing", "regulatory_data_exposure"],
             "remediation": "Safeguard records against unauthorised release when using AI tools."},
            {"id": "A.8.28", "name": "Secure Coding",
             "categories": ["unsafe_code_acceptance"],
             "remediation": "Apply secure coding standards to all AI-generated code."},
        ],
    },
    {
        "id": "cis",
        "name": "CIS Controls v8.1",
        "url": "https://www.cisecurity.org/controls",
        "controls": [
            {"id": "Control 2", "name": "Inventory and Control of Software Assets",
             "categories": ["supply_chain_risk"],
             "remediation": "Track all AI-suggested dependencies. Maintain approved package lists."},
            {"id": "Control 3", "name": "Data Protection",
             "categories": ["secret_exposure", "sensitive_data_sharing", "ip_trade_secret_leakage"],
             "remediation": "Classify data and enforce DLP policies for AI tool interactions."},
            {"id": "Control 4", "name": "Secure Configuration",
             "categories": ["dangerous_command"],
             "remediation": "Harden AI tool configurations. Restrict command execution privileges."},
            {"id": "Control 6", "name": "Access Control Management",
             "categories": ["scope_violation"],
             "remediation": "Apply RBAC principles. AI tools should only access project-scoped resources."},
            {"id": "Control 16", "name": "Application Software Security",
             "categories": ["unsafe_code_acceptance"],
             "remediation": "Mandate code review for all AI-assisted development."},
        ],
    },
    {
        "id": "eu_ai_act",
        "name": "EU AI Act",
        "url": "https://artificialintelligenceact.eu/",
        "controls": [
            {"id": "Article 14", "name": "Human Oversight",
             "categories": ["excessive_reliance"],
             "remediation": "Enable effective human oversight. Users must remain aware of automation bias tendency."},
            {"id": "Article 15", "name": "Accuracy, Robustness, Cybersecurity",
             "categories": ["unsafe_code_acceptance", "supply_chain_risk"],
             "remediation": "Ensure AI outputs meet accuracy and security requirements."},
        ],
    },
    {
        "id": "mitre_atlas",
        "name": "MITRE ATLAS",
        "url": "https://atlas.mitre.org/",
        "controls": [
            {"id": "AML.T0051.002", "name": "LLM Data Leakage",
             "categories": ["secret_exposure", "sensitive_data_sharing"],
             "remediation": "Implement safeguards against unintentional data leakage through AI interactions."},
            {"id": "AML.T0024", "name": "Exfiltration via ML Inference API",
             "categories": ["sensitive_data_sharing", "ip_trade_secret_leakage"],
             "remediation": "Monitor and audit data shared with AI tool APIs."},
            {"id": "Agent Tool Invocation", "name": "Exfiltration via Agent Tool Invocation",
             "categories": ["dangerous_command", "scope_violation"],
             "remediation": "Validate all tool invocation parameters. Sandbox agent execution."},
        ],
    },
]

# DH categories that require LLM for assessment
_LLM_ONLY_CATEGORIES = {"regulatory_data_exposure"}


def assess_compliance(insights: ScanInsights) -> List[FrameworkAssessment]:
    """Assess scan results against international compliance frameworks."""

    # Build category status map from insights
    cat_status = {}
    for cat in [
        "secret_exposure", "sensitive_data_sharing", "unsafe_code_acceptance",
        "dangerous_command", "supply_chain_risk", "scope_violation",
        "ip_trade_secret_leakage", "regulatory_data_exposure", "excessive_reliance",
    ]:
        if cat in _LLM_ONLY_CATEGORIES and insights.rules_skipped_llm > 0:
            cat_status[cat] = "not_assessed"
        else:
            # Check if this category has findings
            has_findings = any(f.category == cat for f in insights.all_findings if f.severity != "info")
            cat_status[cat] = "fail" if has_findings else "pass"

    # Assess each framework
    assessments = []
    for fw_def in _FRAMEWORKS:
        controls = []
        for ctrl_def in fw_def["controls"]:
            categories = ctrl_def["categories"]
            statuses = [cat_status.get(c, "not_assessed") for c in categories]

            # Determine control status
            if all(s == "not_assessed" for s in statuses):
                status = "not_assessed"
            elif any(s == "fail" for s in statuses):
                status = "fail"
            elif any(s == "not_assessed" for s in statuses):
                status = "partial"
            else:
                status = "pass"

            finding_count = sum(
                1 for f in insights.all_findings
                if f.category in categories and f.severity != "info"
            )

            controls.append(ControlAssessment(
                control_id=ctrl_def["id"],
                control_name=ctrl_def["name"],
                status=status,
                mapped_categories=categories,
                finding_count=finding_count,
                notes=ctrl_def.get("remediation", ""),
            ))

        fw = FrameworkAssessment(
            framework_id=fw_def["id"],
            framework_name=fw_def["name"],
            url=fw_def.get("url", ""),
            controls=controls,
            controls_passed=sum(1 for c in controls if c.status == "pass"),
            controls_failed=sum(1 for c in controls if c.status == "fail"),
            controls_partial=sum(1 for c in controls if c.status == "partial"),
            controls_not_assessed=sum(1 for c in controls if c.status == "not_assessed"),
        )
        assessments.append(fw)

    return assessments
