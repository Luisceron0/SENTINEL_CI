"""
File Purpose:
- Load and validate runtime configuration for Sentinel API.

Key Security Considerations:
- Fails fast when required environment variables are missing.
- Prevents insecure startup states and accidental weak defaults.

OWASP 2025 Categories Addressed:
- A02, A07, A10
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str
    github_oauth_client_id: str
    github_oauth_client_secret: str
    defectdojo_url: str
    defectdojo_api_key: str
    sentinel_webhook_secret: str
    dashboard_url: str
    jwt_secret: str
    jwt_algorithm: str
    environment: str


_REQUIRED_VARS = {
    "SUPABASE_URL",
    "SUPABASE_ANON_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "GITHUB_OAUTH_CLIENT_ID",
    "GITHUB_OAUTH_CLIENT_SECRET",
    "DEFECTDOJO_URL",
    "DEFECTDOJO_API_KEY",
    "SENTINEL_WEBHOOK_SECRET",
    "NEXT_PUBLIC_DASHBOARD_URL",
    "SENTINEL_JWT_SECRET",
}


def load_settings() -> Settings:
    missing = sorted(name for name in _REQUIRED_VARS if not os.getenv(name))
    if missing:
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    return Settings(
        supabase_url=os.environ["SUPABASE_URL"],
        supabase_anon_key=os.environ["SUPABASE_ANON_KEY"],
        supabase_service_role_key=os.environ["SUPABASE_SERVICE_ROLE_KEY"],
        github_oauth_client_id=os.environ["GITHUB_OAUTH_CLIENT_ID"],
        github_oauth_client_secret=os.environ["GITHUB_OAUTH_CLIENT_SECRET"],
        defectdojo_url=os.environ["DEFECTDOJO_URL"],
        defectdojo_api_key=os.environ["DEFECTDOJO_API_KEY"],
        sentinel_webhook_secret=os.environ["SENTINEL_WEBHOOK_SECRET"],
        dashboard_url=os.environ["NEXT_PUBLIC_DASHBOARD_URL"],
        jwt_secret=os.environ["SENTINEL_JWT_SECRET"],
        jwt_algorithm=os.getenv("SENTINEL_JWT_ALGORITHM", "HS256"),
        environment=os.getenv("ENVIRONMENT", "development"),
    )
