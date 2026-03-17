"""
File Purpose:
- Configure shared test environment for Sentinel API security test suite.

Key Security Considerations:
- Provides non-secret deterministic environment values and forces in-memory DB backend.

OWASP 2025 Categories Addressed:
- A02, A06, A10
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

from api.main import app
from api.middleware.rate_limit import RateLimitMiddleware


def pytest_sessionstart(session) -> None:
    os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
    os.environ.setdefault("SUPABASE_ANON_KEY", "anon")
    os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "service")
    os.environ.setdefault("GITHUB_OAUTH_CLIENT_ID", "id")
    os.environ.setdefault("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    os.environ.setdefault("DEFECTDOJO_URL", "https://dojo.example.com")
    os.environ.setdefault("DEFECTDOJO_API_KEY", "dojo")
    os.environ.setdefault("SENTINEL_WEBHOOK_SECRET", "topsecret")
    os.environ.setdefault("NEXT_PUBLIC_DASHBOARD_URL", "https://dash.example.com")
    os.environ.setdefault("SENTINEL_JWT_SECRET", "jwt")
    os.environ.setdefault("SENTINEL_DB_BACKEND", "in-memory")


def _reset_rate_limit_state() -> None:
    if app.middleware_stack is None:
        app.middleware_stack = app.build_middleware_stack()

    current: Any = app.middleware_stack
    while current is not None:
        if isinstance(current, RateLimitMiddleware):
            current._events.clear()
            return
        current = getattr(current, "app", None)


@pytest.fixture(autouse=True)
def clear_rate_limit_state() -> Iterator[None]:
    _reset_rate_limit_state()
    yield
    _reset_rate_limit_state()
