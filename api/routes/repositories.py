"""
File Purpose:
- Implement repository management endpoints with ownership enforcement.

Key Security Considerations:
- Requires JWT identity and validates owner access for write/delete operations.

OWASP 2025 Categories Addressed:
- A01, A07, A10
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from api.db.supabase import DatabasePort, get_db
from api.middleware.auth import RequestIdentity, require_jwt_identity
from api.models.schemas import RepositoryCreateIn, RepositoryOut

router = APIRouter(prefix="/api/repositories", tags=["repositories"])


@router.get("", response_model=list[RepositoryOut])
def list_repositories(
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> list[RepositoryOut]:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    return [RepositoryOut(**row) for row in db.list_repositories(owner_id)]


@router.post("", response_model=RepositoryOut, status_code=201)
def create_repository(
    body: RepositoryCreateIn,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> RepositoryOut:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    return RepositoryOut(**db.create_repository(owner_id, body.full_name))


@router.delete("/{repository_id}", status_code=204)
def delete_repository(
    repository_id: UUID,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> None:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    deleted = db.delete_repository(owner_id, repository_id)
    if not deleted:
        raise HTTPException(status_code=403, detail="repository_access_denied")
    return None


@router.get("/{repository_id}/scans")
def list_repository_scans(
    repository_id: UUID,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> list[dict[str, object]]:
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    if not db.repository_owned_by(owner_id, repository_id):
        raise HTTPException(status_code=403, detail="repository_access_denied")
    return db.list_scans_by_repository(repository_id)
