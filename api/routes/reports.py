"""
File Purpose:
- Expose PDF and JSON report export endpoints for scan artifacts.

Key Security Considerations:
- Requires authenticated access and ownership checks before report generation.

OWASP 2025 Categories Addressed:
- A01, A05, A10
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response

from api.db.supabase import DatabasePort, get_db
from api.middleware.auth import RequestIdentity, require_jwt_identity
from api.services.report_generator import generate_json_report, generate_pdf_report

router = APIRouter(prefix="/api/scans", tags=["reports"])


@router.get("/{scan_id}/report.pdf")
def get_report_pdf(
    scan_id: UUID,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> Response:
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan_not_found")
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    if not db.repository_owned_by(owner_id, UUID(str(scan["repository_id"]))):
        raise HTTPException(status_code=403, detail="scan_access_denied")

    return Response(content=generate_pdf_report(scan), media_type="application/pdf")


@router.get("/{scan_id}/report.json")
def get_report_json(
    scan_id: UUID,
    identity: RequestIdentity = Depends(require_jwt_identity),
    db: DatabasePort = Depends(get_db),
) -> Response:
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan_not_found")
    owner_id = identity.user_id
    if owner_id is None:
        raise HTTPException(status_code=403, detail="jwt_required")
    if not db.repository_owned_by(owner_id, UUID(str(scan["repository_id"]))):
        raise HTTPException(status_code=403, detail="scan_access_denied")

    return Response(content=generate_json_report(scan), media_type="application/json")
