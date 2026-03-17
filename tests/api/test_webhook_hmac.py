"""
File Purpose:
- Verify tampered webhook payloads are rejected by HMAC verification.

Key Security Considerations:
- Ensures request integrity at GitHub webhook trust boundary.

OWASP 2025 Categories Addressed:
- A04, A08
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi.testclient import TestClient

from api.main import create_app


def test_tampered_webhook_payload_returns_401(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "anon")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("DEFECTDOJO_URL", "https://dojo.example.com")
    monkeypatch.setenv("DEFECTDOJO_API_KEY", "dojo")
    monkeypatch.setenv("SENTINEL_WEBHOOK_SECRET", "topsecret")
    monkeypatch.setenv("NEXT_PUBLIC_DASHBOARD_URL", "https://dash.example.com")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "jwt")

    client = TestClient(create_app())

    payload = b'{"action":"push"}'
    wrong_sig = "sha256=" + hmac.new(b"wrong", payload, hashlib.sha256).hexdigest()
    response = client.post(
        "/api/webhooks/github",
        content=payload,
        headers={"X-Hub-Signature-256": wrong_sig, "X-GitHub-Event": "push"},
    )
    assert response.status_code == 401
