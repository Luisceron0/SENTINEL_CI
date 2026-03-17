"""
File Purpose:
- Ensure unexpected server exceptions return sanitized error payloads.

Key Security Considerations:
- Prevents leaking stack traces and sensitive internals in API responses.

OWASP 2025 Categories Addressed:
- A10
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.testclient import TestClient

from api.main import create_app


def test_global_error_sanitization():
    app = create_app()
    router = APIRouter()

    @router.get("/boom")
    def boom():
        raise RuntimeError("sensitive internal details")

    app.include_router(router)
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/boom")
    assert response.status_code == 500
    assert response.json()["error"] == "internal_server_error"
    assert "sensitive" not in response.text
