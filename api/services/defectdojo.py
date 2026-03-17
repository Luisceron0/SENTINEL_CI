"""
File Purpose:
- Push normalized findings to DefectDojo for deduplication and remediation tracking.

Key Security Considerations:
- Uses HTTPS outbound calls with sanitized error propagation.

OWASP 2025 Categories Addressed:
- A03, A08, A10
"""

from __future__ import annotations

from typing import Any

import httpx


class DefectDojoService:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    async def import_scan(self, repository_name: str, scan_payload: dict[str, Any]) -> None:
        if not self.base_url.startswith("https://"):
            raise ValueError("DefectDojo URL must be HTTPS")

        headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "repository_name": repository_name,
            "scan_type": "Sentinel CI Unified Scan",
            "payload": scan_payload,
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    f"{self.base_url}/api/v2/import-scan/",
                    headers=headers,
                    json=body,
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError("defectdojo_import_failed") from exc
