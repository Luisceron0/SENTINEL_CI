"""
File Purpose:
- Verify API keys are persisted as hashes and never plaintext.

Key Security Considerations:
- Prevents key disclosure if database records are exposed.

OWASP 2025 Categories Addressed:
- A04, A07, A08
"""

from __future__ import annotations

from uuid import uuid4

from api.db.supabase import InMemoryDatabase
from api.utils.crypto import generate_api_key, hash_api_key


def test_api_key_not_stored_in_plaintext():
    db = InMemoryDatabase()
    user_id = uuid4()

    plain_key = generate_api_key()
    key_hash = hash_api_key(plain_key)
    row = db.create_api_key(user_id, key_hash)

    assert row["key_hash"] != plain_key
    assert row["key_hash"].startswith("$argon2id$")
