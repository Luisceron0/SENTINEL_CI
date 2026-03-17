"""
File Purpose:
- Verify cross-user repository access is blocked with HTTP 403.

Key Security Considerations:
- Prevents tenant boundary violations through IDOR-like access patterns.

OWASP 2025 Categories Addressed:
- A01
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.db.supabase import InMemoryDatabase, get_db
from api.main import app
from api.middleware.auth import require_jwt_identity


def _override_jwt_identity(user_id):
    class _Identity:
        auth_type = "jwt"
        api_key_id = None

        def __init__(self, uid):
            self.user_id = uid

    return _Identity(user_id)


@pytest.fixture
def client_with_db():
    db = InMemoryDatabase()
    owner_id = uuid4()
    other_id = uuid4()
    repo = db.create_repository(owner_id, "owner/repo")

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_jwt_identity] = lambda: _override_jwt_identity(other_id)

    client = TestClient(app)
    yield client, repo["id"]

    app.dependency_overrides.clear()


def test_cross_user_access_returns_403(client_with_db):
    client, repo_id = client_with_db
    response = client.get(f"/api/repositories/{repo_id}/scans")
    assert response.status_code == 403
