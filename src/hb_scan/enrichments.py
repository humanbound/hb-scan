"""Post-processing enrichments for findings — expiry checks, filtering.

Key principle: only flag things the user didn't know about or couldn't control.
Expired JWTs shared intentionally during normal workflow are not findings.
"""

import base64
import json
import re
import time
from typing import List

from hb_scan.models.finding import Finding


def enrich_findings(findings: List[Finding]) -> List[Finding]:
    """Apply enrichments and filter out non-findings. Returns filtered list."""
    result = []
    for f in findings:
        if _is_expired_token(f):
            continue  # Drop expired tokens entirely — normal workflow, not a risk
        result.append(f)
    return result


def _is_expired_token(finding: Finding) -> bool:
    """Check if a JWT/bearer token finding is expired. If so, drop it."""
    if finding.rule_id not in ("jwt-token", "bearer-token"):
        return False

    source = finding.raw_match or finding.match_context
    jwt_match = re.search(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        source,
    )
    if not jwt_match:
        return False

    token = jwt_match.group()
    parts = token.split(".")
    if len(parts) < 2:
        return False

    try:
        payload_b64 = parts[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        exp = payload.get("exp")
        if exp and isinstance(exp, (int, float)):
            return exp < time.time()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        pass

    return False
