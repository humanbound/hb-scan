"""Tests for enrichment layer: JWT expiry, filtering."""

import base64
import json
import time
import pytest

from hb_scan.enrichments import enrich_findings
from hb_scan.models.finding import Finding


def _make_jwt(exp: int) -> str:
    """Create a minimal JWT with given exp timestamp."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp, "sub": "test"}).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


class TestJWTExpiry:

    def test_expired_jwt_filtered_out(self):
        expired_jwt = _make_jwt(int(time.time()) - 3600)  # expired 1h ago
        f = Finding(
            rule_id="jwt-token", category="secret_exposure", severity="high",
            description="JWT token found", raw_match=expired_jwt,
        )
        result = enrich_findings([f])
        assert len(result) == 0

    def test_valid_jwt_kept(self):
        valid_jwt = _make_jwt(int(time.time()) + 3600)  # expires in 1h
        f = Finding(
            rule_id="jwt-token", category="secret_exposure", severity="high",
            description="JWT token found", raw_match=valid_jwt,
        )
        result = enrich_findings([f])
        assert len(result) == 1

    def test_non_jwt_finding_untouched(self):
        f = Finding(
            rule_id="aws-access-key", category="secret_exposure", severity="high",
            description="AWS key found", raw_match="AKIA1234567890ABCDEF",
        )
        result = enrich_findings([f])
        assert len(result) == 1

    def test_bearer_token_expired_filtered(self):
        expired_jwt = _make_jwt(int(time.time()) - 7200)
        f = Finding(
            rule_id="bearer-token", category="secret_exposure", severity="high",
            description="Bearer token found", raw_match=f"Bearer {expired_jwt}",
        )
        result = enrich_findings([f])
        assert len(result) == 0

    def test_malformed_jwt_kept(self):
        f = Finding(
            rule_id="jwt-token", category="secret_exposure", severity="high",
            description="JWT found", raw_match="eyJnot.avalid.token",
        )
        result = enrich_findings([f])
        assert len(result) == 1  # can't decode → keep it

    def test_mixed_findings(self):
        expired_jwt = _make_jwt(int(time.time()) - 3600)
        valid_jwt = _make_jwt(int(time.time()) + 3600)
        findings = [
            Finding(rule_id="jwt-token", category="secret_exposure", severity="high",
                    description="d", raw_match=expired_jwt),
            Finding(rule_id="jwt-token", category="secret_exposure", severity="high",
                    description="d", raw_match=valid_jwt),
            Finding(rule_id="aws-access-key", category="secret_exposure", severity="high",
                    description="d", raw_match="AKIA1234567890ABCDEF"),
        ]
        result = enrich_findings(findings)
        assert len(result) == 2  # expired JWT removed, valid JWT + AWS kept
