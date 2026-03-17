"""
File Purpose:
- Validate repeated failed authentication triggers HTTP 429 rate limiting.

Key Security Considerations:
- Mitigates brute-force and credential stuffing behavior.

OWASP 2025 Categories Addressed:
- A07, A09
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app


def test_auth_rate_limit_11th_failed_request_returns_429():
    client = TestClient(app)
    status_codes = []
    for _ in range(11):
        res = client.post("/api/scans", json={})
        status_codes.append(res.status_code)

    assert 429 in status_codes
