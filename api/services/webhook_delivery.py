"""
File Purpose:
- Deliver outbound webhook alerts with HMAC signatures and retry logic.

Key Security Considerations:
- Enforces HTTPS-only targets and signs payloads with HMAC-SHA256.
- Uses bounded retry policy for reliability without silent failure.

OWASP 2025 Categories Addressed:
- A01, A04, A08, A10
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from api.utils.crypto import sign_hmac_sha256


async def deliver_webhook(url: str, secret: str, payload: dict[str, Any]) -> tuple[int, str]:
    if not url.startswith("https://"):
        raise ValueError("webhook delivery URL must use HTTPS")

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = sign_hmac_sha256(secret, body)

    delays = [0, 10, 30, 90]
    last_error = "delivery_failed"

    for delay in delays:
        if delay:
            await asyncio.sleep(delay)
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Sentinel-Signature": signature,
                    },
                )
                if 200 <= response.status_code < 300:
                    return response.status_code, "SENT"
                last_error = f"http_{response.status_code}"
        except httpx.HTTPError as exc:
            last_error = f"network_error:{exc.__class__.__name__}"

    return 0, last_error
