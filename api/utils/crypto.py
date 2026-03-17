"""
File Purpose:
- Provide approved cryptographic primitives for API keys and webhook signatures.

Key Security Considerations:
- Uses Argon2id for API key hashing and HMAC-SHA256 for signatures.
- Implements verify_api_key() as the single source of truth for API key validation.

OWASP 2025 Categories Addressed:
- A04, A07, A08
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


_PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


def generate_api_key() -> str:
    return "sci_" + secrets.token_urlsafe(36)[:47]


def hash_api_key(plain_key: str) -> str:
    _validate_api_key_format(plain_key)
    return _PASSWORD_HASHER.hash(plain_key)


def verify_api_key(
    plain_key: str,
    stored_rows: Iterable[dict[str, object]],
) -> UUID | None:
    _validate_api_key_format(plain_key)

    for row in stored_rows:
        key_hash = str(row.get("key_hash", ""))
        try:
            if _PASSWORD_HASHER.verify(key_hash, plain_key):
                return UUID(str(row["id"]))
        except (VerifyMismatchError, ValueError, KeyError):
            continue
    return None


def verify_hmac_sha256(secret: str, payload: bytes, provided_signature: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, provided_signature)


def sign_hmac_sha256(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def hash_user_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_api_key_format(api_key: str) -> None:
    if not api_key.startswith("sci_") or len(api_key) != 51:
        raise ValueError("invalid API key format")
