"""
File Purpose:
- Aggregate scanner outputs, normalize findings, send scan payload to Sentinel API, and enforce gate.

Key Security Considerations:
- Treats scanner failures as fail-secure conditions.
- Applies deterministic severity gate and sanitized network error handling.

OWASP 2025 Categories Addressed:
- A03, A06, A08, A10
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

RESULTS_DIR = Path("results")

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def main() -> int:
    findings: list[dict[str, Any]] = []
    scanner_statuses = _collect_statuses()

    findings.extend(_parse_semgrep())
    findings.extend(_parse_trivy())
    findings.extend(_parse_gitleaks())
    findings.extend(_parse_checkov())
    findings.extend(_parse_zap())

    sbom_doc = _load_json(RESULTS_DIR / "trivy.sbom.json", default={"bomFormat": "CycloneDX", "components": []})

    repo_name = os.getenv("GITHUB_REPOSITORY", "unknown/unknown")
    repository_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinel:{repo_name}"))
    commit_sha = os.getenv("GITHUB_SHA", "unknown")
    branch = os.getenv("GITHUB_REF_NAME", "unknown")
    trigger_event = os.getenv("GITHUB_EVENT_NAME", "workflow_dispatch")

    payload = {
        "repository_id": repository_id,
        "repository_name": repo_name,
        "commit_sha": commit_sha,
        "branch": branch,
        "trigger_event": trigger_event,
        "scanner_versions": {},
        "findings": findings,
        "sbom_document": sbom_doc,
    }

    scan_id = str(uuid.uuid4())
    findings_count = len(findings)
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    dashboard_url = ""

    endpoint = os.getenv("SENTINEL_API_ENDPOINT", "").rstrip("/")
    api_key = os.getenv("SENTINEL_API_KEY", "")
    if endpoint and api_key and os.getenv("DRY_RUN", "0") != "1":
        response = _post_scan(endpoint, api_key, payload)
        scan_id = str(response.get("scan_id", scan_id))
        findings_count = int(response.get("findings_count", findings_count))
        critical_count = int(response.get("critical_count", critical_count))
        dashboard_url = str(response.get("dashboard_url", ""))

    _write_outputs(scan_id, findings_count, critical_count, dashboard_url)

    gate = os.getenv("FAIL_ON_SEVERITY", "HIGH").upper()
    gate_rank = SEVERITY_RANK.get(gate, SEVERITY_RANK["HIGH"])
    max_rank = max((SEVERITY_RANK.get(str(f.get("severity", "LOW")).upper(), 0) for f in findings), default=0)

    scanner_failures = [k for k, v in scanner_statuses.items() if v in {"FAILED", "TIMEOUT"}]
    if scanner_failures:
        print(f"Scanner failures detected: {', '.join(scanner_failures)}", file=sys.stderr)
        return 1

    if max_rank >= gate_rank:
        print(
            f"Findings meet/exceed fail-on-severity threshold ({gate}).",
            file=sys.stderr,
        )
        return 1

    return 0


def _collect_statuses() -> dict[str, str]:
    statuses: dict[str, str] = {}
    for status_path in RESULTS_DIR.glob("*_status.json"):
        data = _load_json(status_path, default={})
        scanner = str(data.get("scanner", status_path.stem.replace("_status", "")))
        status = str(data.get("status", "FAILED")).upper()
        statuses[scanner] = status
    return statuses


def _parse_semgrep() -> list[dict[str, Any]]:
    data = _load_json(RESULTS_DIR / "semgrep.json", default={})
    findings: list[dict[str, Any]] = []
    for item in data.get("results", []):
        severity = str(item.get("extra", {}).get("severity", "LOW")).upper()
        path = item.get("path")
        line = item.get("start", {}).get("line")
        findings.append(_finding("semgrep", severity, item.get("check_id", "Semgrep finding"), item.get("extra", {}).get("message", ""), path, line))
    return findings


def _parse_trivy() -> list[dict[str, Any]]:
    data = _load_json(RESULTS_DIR / "trivy.json", default={})
    findings: list[dict[str, Any]] = []
    for result in data.get("Results", []):
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = str(vuln.get("Severity", "LOW")).upper()
            findings.append(
                _finding(
                    "trivy",
                    severity,
                    vuln.get("VulnerabilityID", "Trivy vulnerability"),
                    vuln.get("Title", ""),
                    target,
                    None,
                    cve=vuln.get("VulnerabilityID"),
                )
            )
    return findings


def _parse_gitleaks() -> list[dict[str, Any]]:
    data = _load_json(RESULTS_DIR / "gitleaks.json", default=[])
    findings: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return findings
    for item in data:
        findings.append(
            _finding(
                "gitleaks",
                "HIGH",
                item.get("RuleID", "Gitleaks secret"),
                item.get("Description", "Potential secret exposure"),
                item.get("File"),
                item.get("StartLine"),
            )
        )
    return findings


def _parse_checkov() -> list[dict[str, Any]]:
    data = _load_json(RESULTS_DIR / "checkov.json", default={})
    failed = data.get("results", {}).get("failed_checks", [])
    findings: list[dict[str, Any]] = []
    for item in failed:
        severity = str(item.get("severity", "MEDIUM")).upper()
        findings.append(
            _finding(
                "checkov",
                severity,
                item.get("check_id", "Checkov finding"),
                item.get("check_name", ""),
                item.get("file_path"),
                item.get("file_line_range", [None])[0],
            )
        )
    return findings


def _parse_zap() -> list[dict[str, Any]]:
    data = _load_json(RESULTS_DIR / "zap.json", default={})
    findings: list[dict[str, Any]] = []
    for alert in data.get("site", [{}])[0].get("alerts", []):
        risk = str(alert.get("riskcode", "1"))
        severity = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}.get(risk, "LOW")
        findings.append(
            _finding(
                "zap",
                severity,
                alert.get("name", "ZAP alert"),
                alert.get("desc", ""),
                alert.get("url"),
                None,
                cwe=alert.get("cweid"),
            )
        )
    return findings


def _finding(
    scanner: str,
    severity: str,
    title: str,
    description: str,
    file_path: Any,
    line_start: Any,
    cve: Any = None,
    cwe: Any = None,
) -> dict[str, Any]:
    path_text = str(file_path) if file_path else None
    line_value = int(line_start) if isinstance(line_start, int | float) else None
    idem_src = f"{scanner}:{path_text}:{line_value}:{title}"
    return {
        "scanner": scanner,
        "severity": severity if severity in SEVERITY_RANK else "LOW",
        "title": str(title)[:200],
        "description": str(description)[:5000],
        "file_path": path_text,
        "line_start": line_value,
        "line_end": line_value,
        "cve_id": str(cve) if cve else None,
        "cwe_id": str(cwe) if cwe else None,
        "remediation": "Review scanner finding and apply least-risk remediation.",
        "false_positive": False,
        "status": "OPEN",
        "idempotency_key": hashlib.sha256(idem_src.encode("utf-8")).hexdigest(),
    }


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def _post_scan(endpoint: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("invalid_api_endpoint")

    req = urllib.request.Request(
        url=f"{endpoint}/scans",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-Key": api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        raise RuntimeError("scan_upload_failed") from exc


def _write_outputs(scan_id: str, findings_count: int, critical_count: int, dashboard_url: str) -> None:
    output_file = os.getenv("GITHUB_OUTPUT") or os.getenv("GITHUB_OUTPUT_PATH")
    if not output_file:
        return
    with open(output_file, "a", encoding="utf-8") as fh:
        fh.write(f"scan-id={scan_id}\n")
        fh.write(f"findings-count={findings_count}\n")
        fh.write(f"critical-count={critical_count}\n")
        fh.write(f"dashboard-url={dashboard_url}\n")


if __name__ == "__main__":
    raise SystemExit(main())
