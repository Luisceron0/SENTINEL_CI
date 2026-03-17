"""
File Purpose:
- Manage repository webhook destinations and send signed alert payloads.

Key Security Considerations:
- Validates webhook targets against SSRF protections before persistence.
- Uses ownership checks to prevent cross-tenant configuration abuse.

OWASP 2025 Categories Addressed:
- A01, A04, A05, A08
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from api.db.supabase import DatabasePort, get_db
from api.middleware.auth import RequestIdentity, require_jwt_identity
from api.models.schemas import WebhookCreateIn, WebhookOut
from api.utils.validators import validate_webhook_url

router = APIRouter(prefix="/api/webhooks", tags=["alerts"])


@router.post("", response_model=WebhookOut, status_code=201)
def create_webhook(
    body: WebhookCreateIn,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> WebhookOut:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    if not db.repository_owned_by(owner_id, body.repository_id):
        raise HTTPException(status_code=403, detail="repository_access_denied")

    validated_url = validate_webhook_url(str(body.url))
    row = db.create_webhook(body.repository_id, validated_url, body.minimum_severity.value)
    return WebhookOut(**row)


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: UUID,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> None:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    deleted = db.delete_webhook(owner_id, webhook_id)
    if not deleted:
        raise HTTPException(status_code=403, detail="webhook_access_denied")
    return None
