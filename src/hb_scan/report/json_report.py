"""JSON report output."""

import json
from datetime import datetime
from typing import Dict, List

from hb_scan.models.finding import Finding
from hb_scan.models.posture import PostureScore


def generate_json(
    findings: List[Finding],
    posture: PostureScore,
    tools_found: Dict[str, int],
) -> str:
    """Generate JSON report string."""
    report = {
        "version": "1.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "tools_scanned": tools_found,
        "posture": {
            "score": posture.score,
            "grade": posture.grade,
            "risk_level": posture.risk_level,
            "total_findings": posture.total_findings,
            "total_penalty": posture.total_penalty,
            "categories": {
                cat: {
                    "status": a.status,
                    "weight": a.weight,
                    "worst_severity": a.worst_severity,
                    "finding_count": a.finding_count,
                    "penalty": round(a.penalty),
                }
                for cat, a in posture.categories.items()
            },
            "rules_active": posture.rules_active,
            "rules_total": posture.rules_total,
            "rules_skipped_llm": posture.rules_skipped_llm,
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "description": f.description,
                "mitigation": f.mitigation,
                "session_id": f.session_id,
                "tool": f.tool,
                "project_path": f.project_path,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                "match_context": f.match_context,
                "target": f.target,
                "references": f.references,
                "experimental": f.experimental,
            }
            for f in findings
        ],
    }
    return json.dumps(report, indent=2)
