"""
File Purpose:
- Authenticate requests via JWT or API key and attach identity context.

Key Security Considerations:
- Enforces strict API key format and centralized verify_api_key flow.
- Applies authentication before protected route execution.

OWASP 2025 Categories Addressed:
- A01, A07, A08
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request
from jose import JWTError, jwt

from api.config import Settings, load_settings
from api.db.supabase import DatabasePort, get_db
from api.utils.crypto import verify_api_key


@dataclass
class RequestIdentity:
    user_id: UUID | None
    api_key_id: UUID | None
    auth_type: str


def get_settings() -> Settings:
    return load_settings()


def _decode_jwt_token(token: str, settings: Settings) -> dict[str, Any]:
    try:
        claims = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return cast(dict[str, Any], claims)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="invalid_token") from exc


def require_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_sentinel_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> RequestIdentity:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", maxsplit=1)[1]
        claims = _decode_jwt_token(token, settings)
        user_sub = claims.get("sub")
        if not user_sub:
            raise HTTPException(status_code=401, detail="missing_sub_claim")
        identity = RequestIdentity(user_id=UUID(str(user_sub)), api_key_id=None, auth_type="jwt")
        request.state.identity = identity
        return identity

    if x_sentinel_key:
        db: DatabasePort = get_db()
        key_id = verify_api_key(x_sentinel_key, db.get_active_api_key_hashes())
        if not key_id:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        identity = RequestIdentity(user_id=None, api_key_id=key_id, auth_type="api_key")
        request.state.identity = identity
        return identity

    raise HTTPException(status_code=401, detail="missing_credentials")


def require_jwt_identity(identity: RequestIdentity = Depends(require_auth)) -> RequestIdentity:
    if identity.auth_type != "jwt" or identity.user_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    return identity
