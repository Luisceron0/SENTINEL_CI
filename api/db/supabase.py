"""
File Purpose:
- Provide database abstractions for Supabase-backed Sentinel API operations.

Key Security Considerations:
- Centralizes ownership checks and avoids raw SQL construction.
- Supports deterministic idempotent finding writes.

OWASP 2025 Categories Addressed:
- A01, A05, A08, A10
"""

from __future__ import annotations

import hashlib
import importlib
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from api.config import load_settings

try:
    _supabase_module = importlib.import_module("supabase")
    create_client = getattr(_supabase_module, "create_client", None)
except ImportError:  # pragma: no cover
    create_client = None


@dataclass
class Identity:
    user_id: UUID | None
    api_key_id: UUID | None
    auth_type: str


class DatabasePort:
    def list_repositories(self, owner_id: UUID) -> list[dict[str, Any]]:
        raise NotImplementedError

    def create_repository(self, owner_id: UUID, full_name: str) -> dict[str, Any]:
        raise NotImplementedError

    def delete_repository(self, owner_id: UUID, repository_id: UUID) -> bool:
        raise NotImplementedError

    def repository_owned_by(self, owner_id: UUID, repository_id: UUID) -> bool:
        raise NotImplementedError

    def create_api_key(self, user_id: UUID, key_hash: str) -> dict[str, Any]:
        raise NotImplementedError

    def revoke_api_key(self, user_id: UUID, key_id: UUID) -> bool:
        raise NotImplementedError

    def get_active_api_key_hashes(self) -> Iterable[dict[str, Any]]:
        raise NotImplementedError

    def create_scan_with_findings(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def get_scan(self, scan_id: UUID) -> dict[str, Any] | None:
        raise NotImplementedError

    def list_scans_by_repository(self, repository_id: UUID) -> list[dict[str, Any]]:
        raise NotImplementedError

    def create_webhook(self, repository_id: UUID, url: str, minimum_severity: str) -> dict[str, Any]:
        raise NotImplementedError

    def delete_webhook(self, owner_id: UUID, webhook_id: UUID) -> bool:
        raise NotImplementedError


class SupabaseDatabase(DatabasePort):
    def __init__(self, client: Any):
        self.client = client

    def list_repositories(self, owner_id: UUID) -> list[dict[str, Any]]:
        resp = (
            self.client.table("repositories")
            .select("id,owner_id,full_name,default_branch,created_at")
            .eq("owner_id", str(owner_id))
            .execute()
        )
        return list(resp.data or [])

    def create_repository(self, owner_id: UUID, full_name: str) -> dict[str, Any]:
        payload = {
            "owner_id": str(owner_id),
            "full_name": full_name,
            "default_branch": "main",
        }
        resp = self.client.table("repositories").insert(payload).execute()
        return dict(resp.data[0])

    def delete_repository(self, owner_id: UUID, repository_id: UUID) -> bool:
        resp = (
            self.client.table("repositories")
            .delete()
            .eq("id", str(repository_id))
            .eq("owner_id", str(owner_id))
            .execute()
        )
        return bool(resp.data)

    def repository_owned_by(self, owner_id: UUID, repository_id: UUID) -> bool:
        resp = (
            self.client.table("repositories")
            .select("id")
            .eq("id", str(repository_id))
            .eq("owner_id", str(owner_id))
            .limit(1)
            .execute()
        )
        return bool(resp.data)

    def create_api_key(self, user_id: UUID, key_hash: str) -> dict[str, Any]:
        resp = (
            self.client.table("api_keys")
            .insert({"user_id": str(user_id), "key_hash": key_hash, "prefix": "sci_"})
            .execute()
        )
        return dict(resp.data[0])

    def revoke_api_key(self, user_id: UUID, key_id: UUID) -> bool:
        resp = (
            self.client.table("api_keys")
            .update({"revoked_at": datetime.now(UTC).isoformat()})
            .eq("id", str(key_id))
            .eq("user_id", str(user_id))
            .execute()
        )
        return bool(resp.data)

    def get_active_api_key_hashes(self) -> Iterable[dict[str, Any]]:
        resp = (
            self.client.table("api_keys")
            .select("id,key_hash")
            .is_("revoked_at", "null")
            .execute()
        )
        return list(resp.data or [])

    def create_scan_with_findings(self, payload: dict[str, Any]) -> dict[str, Any]:
        findings = payload["findings"]
        critical_count = sum(1 for item in findings if item["severity"] == "CRITICAL")

        scan_resp = (
            self.client.table("scans")
            .insert(
                {
                    "repository_id": str(payload["repository_id"]),
                    "commit_sha": payload["commit_sha"],
                    "branch": payload["branch"],
                    "trigger_event": payload["trigger_event"],
                    "status": "COMPLETED",
                    "scanner_versions": payload.get("scanner_versions", {}),
                    "findings_count": len(findings),
                    "critical_count": critical_count,
                }
            )
            .execute()
        )
        scan = dict(scan_resp.data[0])

        for finding in findings:
            row = {"scan_id": scan["id"], **finding}
            self.client.table("findings").upsert(
                row,
                on_conflict="idempotency_key",
                ignore_duplicates=True,
            ).execute()

        sbom_doc = payload["sbom_document"]
        sbom_hash = hashlib.sha256(str(sbom_doc).encode("utf-8")).hexdigest()
        self.client.table("sboms").upsert(
            {
                "scan_id": scan["id"],
                "format": "cyclonedx",
                "sha256": sbom_hash,
                "document": sbom_doc,
            },
            on_conflict="scan_id",
            ignore_duplicates=False,
        ).execute()

        return scan

    def get_scan(self, scan_id: UUID) -> dict[str, Any] | None:
        resp = self.client.table("scans").select("*").eq("id", str(scan_id)).limit(1).execute()
        if not resp.data:
            return None
        scan = dict(resp.data[0])

        findings_resp = self.client.table("findings").select("*").eq("scan_id", str(scan_id)).execute()
        sbom_resp = self.client.table("sboms").select("*").eq("scan_id", str(scan_id)).limit(1).execute()
        scan["findings"] = list(findings_resp.data or [])
        scan["sbom"] = (sbom_resp.data or [None])[0]
        return scan

    def list_scans_by_repository(self, repository_id: UUID) -> list[dict[str, Any]]:
        resp = (
            self.client.table("scans")
            .select("*")
            .eq("repository_id", str(repository_id))
            .order("created_at", desc=True)
            .execute()
        )
        return list(resp.data or [])

    def create_webhook(self, repository_id: UUID, url: str, minimum_severity: str) -> dict[str, Any]:
        resp = (
            self.client.table("webhooks")
            .insert(
                {
                    "repository_id": str(repository_id),
                    "url": url,
                    "minimum_severity": minimum_severity,
                    "active": True,
                }
            )
            .execute()
        )
        return dict(resp.data[0])

    def delete_webhook(self, owner_id: UUID, webhook_id: UUID) -> bool:
        hook_resp = self.client.table("webhooks").select("repository_id").eq("id", str(webhook_id)).limit(1).execute()
        if not hook_resp.data:
            return False
        repository_id = UUID(str(hook_resp.data[0]["repository_id"]))
        if not self.repository_owned_by(owner_id, repository_id):
            return False
        delete_resp = self.client.table("webhooks").delete().eq("id", str(webhook_id)).execute()
        return bool(delete_resp.data)


class InMemoryDatabase(DatabasePort):
    def __init__(self) -> None:
        self.repositories: dict[UUID, dict[str, Any]] = {}
        self.api_keys: dict[UUID, dict[str, Any]] = {}
        self.scans: dict[UUID, dict[str, Any]] = {}
        self.findings: dict[UUID, dict[str, Any]] = {}
        self.sboms: dict[UUID, dict[str, Any]] = {}
        self.webhooks: dict[UUID, dict[str, Any]] = {}
        self.idempotency_keys: set[str] = set()

    def list_repositories(self, owner_id: UUID) -> list[dict[str, Any]]:
        return [r for r in self.repositories.values() if r["owner_id"] == owner_id]

    def create_repository(self, owner_id: UUID, full_name: str) -> dict[str, Any]:
        for repo in self.repositories.values():
            if repo["owner_id"] == owner_id and repo["full_name"] == full_name:
                return repo
        repo_id = uuid4()
        record = {
            "id": repo_id,
            "owner_id": owner_id,
            "full_name": full_name,
            "default_branch": "main",
            "created_at": datetime.now(UTC),
        }
        self.repositories[repo_id] = record
        return record

    def delete_repository(self, owner_id: UUID, repository_id: UUID) -> bool:
        repo = self.repositories.get(repository_id)
        if not repo or repo["owner_id"] != owner_id:
            return False
        del self.repositories[repository_id]
        return True

    def repository_owned_by(self, owner_id: UUID, repository_id: UUID) -> bool:
        repo = self.repositories.get(repository_id)
        return bool(repo and repo["owner_id"] == owner_id)

    def create_api_key(self, user_id: UUID, key_hash: str) -> dict[str, Any]:
        key_id = uuid4()
        row = {
            "id": key_id,
            "user_id": user_id,
            "key_hash": key_hash,
            "prefix": "sci_",
            "revoked_at": None,
        }
        self.api_keys[key_id] = row
        return row

    def revoke_api_key(self, user_id: UUID, key_id: UUID) -> bool:
        row = self.api_keys.get(key_id)
        if not row or row["user_id"] != user_id:
            return False
        row["revoked_at"] = datetime.now(UTC)
        return True

    def get_active_api_key_hashes(self) -> Iterable[dict[str, Any]]:
        return [k for k in self.api_keys.values() if k["revoked_at"] is None]

    def create_scan_with_findings(self, payload: dict[str, Any]) -> dict[str, Any]:
        scan_id = uuid4()
        findings = payload["findings"]
        critical_count = sum(1 for item in findings if item["severity"] == "CRITICAL")

        self.scans[scan_id] = {
            "id": scan_id,
            "repository_id": UUID(str(payload["repository_id"])),
            "commit_sha": payload["commit_sha"],
            "branch": payload["branch"],
            "trigger_event": payload["trigger_event"],
            "status": "COMPLETED",
            "findings_count": len(findings),
            "critical_count": critical_count,
            "created_at": datetime.now(UTC),
        }

        for finding in findings:
            idem = finding["idempotency_key"]
            if idem in self.idempotency_keys:
                continue
            self.idempotency_keys.add(idem)
            finding_id = uuid4()
            self.findings[finding_id] = {
                "id": finding_id,
                "scan_id": scan_id,
                **finding,
            }

        sbom_doc = payload["sbom_document"]
        sbom_hash = hashlib.sha256(str(sbom_doc).encode("utf-8")).hexdigest()
        self.sboms[scan_id] = {
            "id": uuid4(),
            "scan_id": scan_id,
            "format": "cyclonedx",
            "sha256": sbom_hash,
            "document": sbom_doc,
        }

        return self.scans[scan_id]

    def get_scan(self, scan_id: UUID) -> dict[str, Any] | None:
        scan = self.scans.get(scan_id)
        if not scan:
            return None
        findings = [f for f in self.findings.values() if f["scan_id"] == scan_id]
        return {**scan, "findings": findings, "sbom": self.sboms.get(scan_id)}

    def list_scans_by_repository(self, repository_id: UUID) -> list[dict[str, Any]]:
        return [s for s in self.scans.values() if s["repository_id"] == repository_id]

    def create_webhook(self, repository_id: UUID, url: str, minimum_severity: str) -> dict[str, Any]:
        webhook_id = uuid4()
        row = {
            "id": webhook_id,
            "repository_id": repository_id,
            "url": url,
            "minimum_severity": minimum_severity,
            "active": True,
        }
        self.webhooks[webhook_id] = row
        return row

    def delete_webhook(self, owner_id: UUID, webhook_id: UUID) -> bool:
        webhook = self.webhooks.get(webhook_id)
        if not webhook:
            return False
        repo = self.repositories.get(webhook["repository_id"])
        if not repo or repo["owner_id"] != owner_id:
            return False
        del self.webhooks[webhook_id]
        return True


_db_singleton: DatabasePort | None = None


def get_db() -> DatabasePort:
    global _db_singleton
    if _db_singleton is None:
        if os.getenv("SENTINEL_DB_BACKEND", "supabase") == "in-memory":
            _db_singleton = InMemoryDatabase()
        else:
            if create_client is None:
                raise RuntimeError("supabase client package is required for database operations")
            settings = load_settings()
            client = create_client(settings.supabase_url, settings.supabase_service_role_key)
            _db_singleton = SupabaseDatabase(client)
    return _db_singleton
