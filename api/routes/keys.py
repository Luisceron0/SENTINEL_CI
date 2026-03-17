"""
File Purpose:
- Implement API key generation and revocation endpoints.

Key Security Considerations:
- Returns plaintext API key only at creation time and stores Argon2id hash only.

OWASP 2025 Categories Addressed:
- A04, A07, A08
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from api.db.supabase import DatabasePort, get_db
from api.middleware.auth import RequestIdentity, require_jwt_identity
from api.models.schemas import ApiKeyOut
from api.utils.crypto import generate_api_key, hash_api_key

router = APIRouter(prefix="/api/keys", tags=["keys"])


@router.post("", response_model=ApiKeyOut, status_code=201)
def create_api_key(
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> ApiKeyOut:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    plain = generate_api_key()
    row = db.create_api_key(owner_id, hash_api_key(plain))
    return ApiKeyOut(id=row["id"], prefix=row["prefix"], key=plain)


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(
    key_id: UUID,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> None:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    revoked = db.revoke_api_key(owner_id, key_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="api_key_not_found")
    return None
