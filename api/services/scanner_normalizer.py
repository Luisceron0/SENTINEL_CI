"""
File Purpose:
- Normalize scanner outputs into Sentinel unified finding schema.

Key Security Considerations:
- Strict mapping avoids implicit trust in raw scanner payload structures.

OWASP 2025 Categories Addressed:
- A05, A10
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any


def normalize_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in raw_findings:
        scanner = str(item.get("scanner", "unknown")).lower()
        file_path = item.get("file_path")
        line_start = item.get("line_start")
        idem_source = f"{scanner}:{file_path}:{line_start}:{item.get('title','')}"
        idem = item.get("idempotency_key") or sha256(idem_source.encode("utf-8")).hexdigest()

        normalized.append(
            {
                "scanner": scanner,
                "severity": str(item.get("severity", "LOW")).upper(),
                "title": str(item.get("title", "Unnamed finding"))[:200],
                "description": str(item.get("description", ""))[:5000],
                "file_path": file_path,
                "line_start": line_start,
                "line_end": item.get("line_end"),
                "cve_id": item.get("cve_id"),
                "cwe_id": item.get("cwe_id"),
                "remediation": str(item.get("remediation", "Review scanner output and patch accordingly."))[:5000],
                "false_positive": bool(item.get("false_positive", False)),
                "status": str(item.get("status", "OPEN")).upper(),
                "idempotency_key": idem,
            }
        )
    return normalized
