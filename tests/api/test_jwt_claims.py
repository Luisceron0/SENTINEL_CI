"""
File Purpose:
- Verify JWT validation enforces expiration claims.

Key Security Considerations:
- Blocks long-lived or malformed bearer tokens missing exp.

OWASP 2025 Categories Addressed:
- A07, A08
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from jose import jwt

from api.main import app


def _build_token(payload: dict[str, object]) -> str:
    return jwt.encode(payload, "jwt", algorithm="HS256")


def test_jwt_without_exp_claim_returns_401() -> None:
    token = _build_token({"sub": str(uuid4())})
    client = TestClient(app)

    response = client.get(
        "/api/repositories",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Forwarded-For": "203.0.113.10",
        },
    )

    assert response.status_code == 401


def test_expired_jwt_returns_401() -> None:
    expired = datetime.now(UTC) - timedelta(minutes=5)
    token = _build_token({"sub": str(uuid4()), "exp": int(expired.timestamp())})
    client = TestClient(app)

    response = client.get(
        "/api/repositories",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Forwarded-For": "203.0.113.11",
        },
    )

    assert response.status_code == 401
