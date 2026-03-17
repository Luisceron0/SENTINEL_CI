"""
File Purpose:
- Validate SSRF protections reject private address webhook targets.

Key Security Considerations:
- Prevents user-controlled webhooks from reaching internal/private infrastructure.

OWASP 2025 Categories Addressed:
- A01, A05
"""

from __future__ import annotations

import pytest

from api.utils.validators import validate_webhook_url


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/webhook",
        "https://10.0.0.5/callback",
        "https://192.168.1.50/hook",
        "https://169.254.1.1/hook",
        "https://[::1]/hook",
    ],
)
def test_private_ip_webhooks_rejected(url: str):
    with pytest.raises(ValueError):
        validate_webhook_url(url)
