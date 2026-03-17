"""
File Purpose:
- Receive and verify GitHub webhook events.

Key Security Considerations:
- Verifies X-Hub-Signature-256 before any payload processing.
- Rejects tampered payloads with immediate HTTP 401.

OWASP 2025 Categories Addressed:
- A04, A08, A10
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from api.config import Settings, load_settings
from api.utils.crypto import verify_hmac_sha256

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    settings: Settings = Depends(load_settings),
) -> dict[str, str | None]:
    payload = await request.body()
    signature = x_hub_signature_256 or ""

    if not verify_hmac_sha256(settings.sentinel_webhook_secret, payload, signature):
        raise HTTPException(status_code=401, detail="invalid_signature")

    if x_github_event not in {"push", "pull_request"}:
        return {"status": "ignored", "event": x_github_event}

    return {"status": "accepted", "event": x_github_event}
