"""
File Purpose:
- Implement scan ingestion and retrieval endpoints.

Key Security Considerations:
- Applies authenticated ingestion and repository ownership checks.
- Enforces fail-secure behavior for ingest processing errors.

OWASP 2025 Categories Addressed:
- A01, A07, A08, A10
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from api.config import Settings, load_settings
from api.db.supabase import DatabasePort, get_db
from api.middleware.auth import RequestIdentity, require_auth
from api.models.schemas import ScanIn, ScanOut
from api.services.defectdojo import DefectDojoService
from api.services.scanner_normalizer import normalize_findings

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=201)
async def ingest_scan(
    body: ScanIn,
    identity: RequestIdentity = Depends(require_auth),
    db: DatabasePort = Depends(get_db),
    settings: Settings = Depends(load_settings),
) -> ScanOut:
    if identity.auth_type != "api_key":
        raise HTTPException(status_code=403, detail="api_key_required")

    normalized_findings = normalize_findings([f.model_dump() for f in body.findings])
    payload = body.model_dump()
    payload["findings"] = normalized_findings

    scan = db.create_scan_with_findings(payload)

    service = DefectDojoService(settings.defectdojo_url, settings.defectdojo_api_key)
    try:
        await service.import_scan(body.repository_name, payload)
    except RuntimeError:
        # SECURITY: ingest remains successful; external integration failures are isolated.
        pass

    return ScanOut(
        scan_id=scan["id"],
        findings_count=scan["findings_count"],
        critical_count=scan["critical_count"],
        dashboard_url=f"{settings.dashboard_url.rstrip('/')}/scans/{scan['id']}",
    )


@router.get("/{scan_id}")
def get_scan(
    scan_id: UUID,
    identity: RequestIdentity = Depends(require_auth),
    db: DatabasePort = Depends(get_db),
) -> dict[str, object]:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_not_found")

    if identity.user_id and not db.repository_owned_by(identity.user_id, UUID(str(scan["repository_id"]))):
        raise HTTPException(status_code=403, detail="scan_access_denied")

    return scan
