"""Insight aggregation — transform raw findings into actionable summaries.

Raw findings are grouped, deduplicated, and enriched into section-level
insights that answer: "What should I know? What should I do?"
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import Counter

from hb_scan.models.finding import Finding


@dataclass
class CredentialInsight:
    """A unique credential found across sessions."""

    credential_type: str        # "api_key", "jwt", "password", "bearer", "private_key", etc.
    is_expired: bool = False
    is_test: bool = False       # appears to be a test/example credential
    sessions_count: int = 1     # how many sessions it appeared in
    first_seen: Optional[str] = None
    redacted_preview: str = ""  # e.g. "AKIA************CDEF"
    rule_id: str = ""
    evidence: List[dict] = field(default_factory=list)  # conversation context
    source_file: str = ""       # path to source data file


@dataclass
class CredentialSummary:
    """Aggregated credential exposure section."""

    total_unique: int = 0
    active_count: int = 0       # not expired, not test
    expired_count: int = 0
    test_count: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    credentials: List[CredentialInsight] = field(default_factory=list)
    action_needed: bool = False

    @property
    def status_text(self) -> str:
        if self.active_count == 0:
            return "No active credentials detected"
        return f"{self.active_count} credential(s) may still be active"


@dataclass
class SectionStatus:
    """Status for a check section (sensitive data, code, commands, packages)."""

    checked: bool = True
    clean: bool = True
    finding_count: int = 0
    details: List[str] = field(default_factory=list)  # human-readable detail lines
    findings: List[Finding] = field(default_factory=list)


@dataclass
class OversightSummary:
    """Oversight / auto-pilot analysis."""

    total_sessions: int = 0
    auto_pilot_sessions: int = 0
    auto_pilot_rate: float = 0.0

    @property
    def status_text(self) -> str:
        if self.auto_pilot_rate == 0:
            return "All sessions had active human oversight"
        pct = round(self.auto_pilot_rate * 100, 1)
        return f"{self.auto_pilot_sessions} of {self.total_sessions} sessions ({pct}%) ran with minimal oversight"


@dataclass
class ScanInsights:
    """Top-level aggregated insights from a scan."""

    # Usage overview
    tool_name: str = ""
    tool_display_name: str = ""
    sessions_scanned: int = 0
    scan_period: str = ""       # e.g. "Feb 17 — Mar 19, 2026"

    # Sections
    credentials: CredentialSummary = field(default_factory=CredentialSummary)
    sensitive_data: SectionStatus = field(default_factory=SectionStatus)
    code_security: SectionStatus = field(default_factory=SectionStatus)
    commands: SectionStatus = field(default_factory=SectionStatus)
    packages: SectionStatus = field(default_factory=SectionStatus)
    ip_leakage: SectionStatus = field(default_factory=SectionStatus)
    regulatory: SectionStatus = field(default_factory=SectionStatus)
    oversight: OversightSummary = field(default_factory=OversightSummary)

    # Scoring
    score: int = 100
    grade: str = "A"
    risk_level: str = "low"
    penalty_breakdown: Dict[str, int] = field(default_factory=dict)

    # Rule coverage
    rules_active: int = 0
    rules_total: int = 0
    rules_skipped_llm: int = 0

    # All findings (for detailed view)
    all_findings: List[Finding] = field(default_factory=list)


# --- Credential type mapping ---

_CREDENTIAL_TYPES = {
    "aws-access-key": "AWS Access Key",
    "github-token": "GitHub Token",
    "generic-api-key": "API Key",
    "private-key-block": "Private Key",
    "database-connection-string": "Database Credentials",
    "jwt-token": "JWT Token",
    "slack-token": "Slack Token",
    "stripe-key": "Stripe Key",
    "generic-password-assignment": "Password",
    "bearer-token": "Bearer Token",
    "openai-api-key": "OpenAI API Key",
    "anthropic-api-key": "Anthropic API Key",
}

_CATEGORY_TO_SECTION = {
    "secret_exposure": "credentials",
    "sensitive_data_sharing": "sensitive_data",
    "unsafe_code_acceptance": "code_security",
    "dangerous_command": "commands",
    "supply_chain_risk": "packages",
    "scope_violation": "sensitive_data",  # scope = sensitive data access
    "ip_trade_secret_leakage": "ip_leakage",
    "regulatory_data_exposure": "regulatory",
    "excessive_reliance": "oversight",
}


def aggregate_findings(
    findings: List[Finding],
    sessions_scanned: int = 0,
    tool_name: str = "",
    tool_display_name: str = "",
    scan_period: str = "",
    rules_active: int = 0,
    rules_total: int = 0,
    rules_skipped_llm: int = 0,
) -> ScanInsights:
    """Transform raw findings into aggregated insights."""

    insights = ScanInsights(
        tool_name=tool_name,
        tool_display_name=tool_display_name,
        sessions_scanned=sessions_scanned,
        scan_period=scan_period,
        rules_active=rules_active,
        rules_total=rules_total,
        rules_skipped_llm=rules_skipped_llm,
        all_findings=findings,
    )

    # Separate credentials from other findings
    credential_findings = []
    other_findings = []
    oversight_findings = []

    for f in findings:
        if f.category == "secret_exposure":
            credential_findings.append(f)
        elif f.category == "excessive_reliance":
            oversight_findings.append(f)
        else:
            other_findings.append(f)

    # Aggregate credentials
    insights.credentials = _aggregate_credentials(credential_findings)

    # Aggregate oversight
    insights.oversight = OversightSummary(
        total_sessions=sessions_scanned,
        auto_pilot_sessions=len(oversight_findings),
        auto_pilot_rate=len(oversight_findings) / max(sessions_scanned, 1),
    )

    # Aggregate other sections
    for f in other_findings:
        section = _CATEGORY_TO_SECTION.get(f.category, "sensitive_data")

        if section == "sensitive_data":
            insights.sensitive_data.clean = False
            insights.sensitive_data.finding_count += 1
            insights.sensitive_data.findings.append(f)
            _add_detail(insights.sensitive_data, f)
        elif section == "code_security":
            insights.code_security.clean = False
            insights.code_security.finding_count += 1
            insights.code_security.findings.append(f)
            _add_detail(insights.code_security, f)
        elif section == "commands":
            insights.commands.clean = False
            insights.commands.finding_count += 1
            insights.commands.findings.append(f)
            _add_detail(insights.commands, f)
        elif section == "packages":
            insights.packages.clean = False
            insights.packages.finding_count += 1
            insights.packages.findings.append(f)
            _add_detail(insights.packages, f)
        elif section == "ip_leakage":
            insights.ip_leakage.clean = False
            insights.ip_leakage.finding_count += 1
            insights.ip_leakage.findings.append(f)
            _add_detail(insights.ip_leakage, f)
        elif section == "regulatory":
            insights.regulatory.clean = False
            insights.regulatory.finding_count += 1
            insights.regulatory.findings.append(f)
            _add_detail(insights.regulatory, f)

    # Calculate score using control-based model
    from hb_scan.models.posture import calculate_posture

    posture = calculate_posture(
        findings,
        rules_active=rules_active,
        rules_total=rules_total,
        rules_skipped_llm=rules_skipped_llm,
    )
    insights.score = posture.score
    insights.grade = posture.grade
    insights.risk_level = posture.risk_level

    # Build penalty breakdown from category assessments
    insights.penalty_breakdown = {
        cat: round(a.penalty)
        for cat, a in posture.categories.items()
        if a.penalty > 0
    }

    return insights


def _aggregate_credentials(findings: List[Finding]) -> CredentialSummary:
    """Group credential findings by type and expiry status."""
    summary = CredentialSummary()

    # Deduplicate by redacted preview (same credential across sessions)
    seen = {}
    for f in findings:
        cred_type = _CREDENTIAL_TYPES.get(f.rule_id, f.rule_id)
        is_expired = "(expired)" in f.description
        key = f"{f.rule_id}:{f.match_context[:50]}"

        if key in seen:
            seen[key].sessions_count += 1
            continue

        cred = CredentialInsight(
            credential_type=cred_type,
            is_expired=is_expired,
            redacted_preview=f.match_context[:80] if f.match_context else "",
            rule_id=f.rule_id,
            first_seen=f.timestamp.strftime("%b %d") if f.timestamp else "",
            evidence=f.evidence if f.evidence else [],
            source_file=f.source_file,
        )
        seen[key] = cred

    credentials = list(seen.values())
    summary.credentials = credentials
    summary.total_unique = len(credentials)
    summary.expired_count = sum(1 for c in credentials if c.is_expired)
    summary.active_count = summary.total_unique - summary.expired_count
    summary.action_needed = summary.active_count > 0

    # Count by type
    for c in credentials:
        summary.by_type[c.credential_type] = summary.by_type.get(c.credential_type, 0) + 1

    return summary


def _add_detail(section: SectionStatus, finding: Finding):
    """Add a human-readable detail line, deduplicating by description."""
    desc = finding.description
    if desc not in section.details:
        section.details.append(desc)
