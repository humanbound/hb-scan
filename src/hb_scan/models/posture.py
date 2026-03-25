"""Posture scoring model — control-based assessment.

Scoring follows compliance framework principles (ISO 42001, CIS Controls):
each category is a control that is either passing or failing. The number
of individual violations within a control doesn't change the control's
status — one leaked API key and ten leaked API keys both mean the
credential hygiene control is failing.

Formula:
  score = 100 - sum(category_penalties)

  category_penalty = 0 if clean, otherwise:
    - high findings present:   full category weight
    - medium findings present: 50% of category weight
    - low/info findings only:  25% of category weight
"""

from dataclasses import dataclass, field
from typing import Dict, List

from .finding import Finding


# Category weights — how much each control area contributes to the score.
# Total = 100 so a device failing every control scores 0.
CATEGORY_WEIGHTS = {
    "secret_exposure":          20,  # Credential hygiene — highest impact
    "sensitive_data_sharing":   15,  # Data protection
    "ip_trade_secret_leakage":  15,  # IP protection
    "regulatory_data_exposure": 15,  # Regulatory compliance
    "unsafe_code_acceptance":   12,  # Code security
    "dangerous_command":        10,  # Command safety
    "supply_chain_risk":         8,  # Package integrity
    "scope_violation":           5,  # Access boundaries
    # excessive_reliance: 0 weight — informational only, never penalises
}

_SEVERITY_ORDER = {"high": 1.0, "medium": 0.5, "low": 0.25, "info": 0.0}


@dataclass
class CategoryAssessment:
    """Assessment result for a single control category."""

    category: str
    weight: int                 # max penalty points
    status: str = "pass"        # "pass" | "fail"
    worst_severity: str = ""    # highest severity finding in this category
    finding_count: int = 0
    penalty: float = 0.0       # actual penalty applied


@dataclass
class PostureScore:
    """AI hygiene posture score — control-based."""

    score: int = 100
    grade: str = "A"
    risk_level: str = "low"
    total_findings: int = 0
    total_penalty: int = 0
    categories: Dict[str, CategoryAssessment] = field(default_factory=dict)
    rules_active: int = 0
    rules_total: int = 0
    rules_skipped_llm: int = 0


def calculate_posture(findings: List[Finding], rules_active: int = 0,
                      rules_total: int = 0, rules_skipped_llm: int = 0) -> PostureScore:
    """Calculate posture score using control-based assessment.

    Each category is assessed independently:
    - Clean (no findings): 0 penalty
    - Has findings: penalty = weight * severity_multiplier
      - high:   100% of weight
      - medium:  50% of weight
      - low:     25% of weight
    """
    # Find worst severity per category
    worst_by_cat: Dict[str, str] = {}
    count_by_cat: Dict[str, int] = {}

    for f in findings:
        cat = f.category
        sev = f.severity
        count_by_cat[cat] = count_by_cat.get(cat, 0) + 1

        current_worst = worst_by_cat.get(cat, "")
        current_rank = _SEVERITY_ORDER.get(current_worst, 0.0)
        new_rank = _SEVERITY_ORDER.get(sev, 0.0)
        if new_rank > current_rank:
            worst_by_cat[cat] = sev

    # Assess each category
    categories = {}
    total_penalty = 0.0

    for cat, weight in CATEGORY_WEIGHTS.items():
        worst = worst_by_cat.get(cat, "")
        count = count_by_cat.get(cat, 0)
        multiplier = _SEVERITY_ORDER.get(worst, 0.0)
        penalty = weight * multiplier

        categories[cat] = CategoryAssessment(
            category=cat,
            weight=weight,
            status="fail" if count > 0 and multiplier > 0 else "pass",
            worst_severity=worst,
            finding_count=count,
            penalty=penalty,
        )
        total_penalty += penalty

    total_penalty_int = round(total_penalty)
    score = max(100 - total_penalty_int, 0)

    if score >= 90:
        grade, risk = "A", "low"
    elif score >= 75:
        grade, risk = "B", "medium"
    elif score >= 60:
        grade, risk = "C", "high"
    elif score >= 40:
        grade, risk = "D", "high"
    else:
        grade, risk = "F", "critical"

    return PostureScore(
        score=score,
        grade=grade,
        risk_level=risk,
        total_findings=len(findings),
        total_penalty=total_penalty_int,
        categories=categories,
        rules_active=rules_active,
        rules_total=rules_total,
        rules_skipped_llm=rules_skipped_llm,
    )
