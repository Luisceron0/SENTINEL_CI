"""
File Purpose:
- Ensure test runtime can import project modules from repository root.

Key Security Considerations:
- Prevents ambiguous import resolution during security test execution.

OWASP 2025 Categories Addressed:
- A06, A10
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_configure() -> None:
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
