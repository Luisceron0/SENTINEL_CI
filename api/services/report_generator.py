"""
File Purpose:
- Generate PDF and JSON reports for completed scans.

Key Security Considerations:
- Produces deterministic, escaped report content from validated scan records.

OWASP 2025 Categories Addressed:
- A05, A10
"""

from __future__ import annotations

import json
from html import escape
from typing import Any, cast

from weasyprint import HTML


def generate_json_report(scan: dict[str, Any]) -> bytes:
    return json.dumps(scan, separators=(",", ":"), default=str).encode("utf-8")


def generate_pdf_report(scan: dict[str, Any]) -> bytes:
    findings_rows = "".join(
        (
            "<tr>"
            f"<td>{escape(str(f.get('severity', '')))}</td>"
            f"<td>{escape(str(f.get('scanner', '')))}</td>"
            f"<td>{escape(str(f.get('title', '')))}</td>"
            "</tr>"
        )
        for f in scan.get("findings", [])
    )

    html = f"""
    <html>
      <head><meta charset='utf-8'><title>Sentinel Report</title></head>
      <body>
        <h1>Sentinel CI Scan Report</h1>
        <p>Scan ID: {escape(str(scan.get('id', '')))}</p>
        <p>Repository: {escape(str(scan.get('repository_id', '')))}</p>
        <p>Status: {escape(str(scan.get('status', '')))}</p>
        <table border='1' cellspacing='0' cellpadding='4'>
          <thead><tr><th>Severity</th><th>Scanner</th><th>Title</th></tr></thead>
          <tbody>{findings_rows}</tbody>
        </table>
      </body>
    </html>
    """
    return cast(bytes, HTML(string=html).write_pdf())
