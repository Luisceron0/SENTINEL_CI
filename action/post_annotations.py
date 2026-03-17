"""
File Purpose:
- Publish findings as GitHub check-run annotations for pull requests.

Key Security Considerations:
- Uses GitHub token from environment only and caps annotation volume.
- Avoids exposing sensitive payload internals in annotation text.

OWASP 2025 Categories Addressed:
- A02, A08, A10
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

MAX_ANNOTATIONS = 50


def main() -> int:
    token = os.getenv("GITHUB_TOKEN", "")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    sha = os.getenv("GITHUB_SHA", "")
    event_path = os.getenv("GITHUB_EVENT_PATH", "")

    if not token or not repo or not sha or not event_path:
        return 0

    findings = _load_findings()
    annotations = _to_annotations(findings)[:MAX_ANNOTATIONS]
    if not annotations:
        return 0

    payload = {
        "name": "Sentinel CI Findings",
        "head_sha": sha,
        "status": "completed",
        "conclusion": "neutral",
        "output": {
            "title": "Sentinel CI Security Findings",
            "summary": f"{len(findings)} findings detected.",
            "annotations": annotations,
        },
    }

    url = f"https://api.github.com/repos/{repo}/check-runs"
    req = urllib.request.Request(
        url=url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "sentinel-ci",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20):
            return 0
    except urllib.error.URLError:
        return 0


def _load_findings() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    aggregate_sources = [
        Path("results/semgrep.json"),
        Path("results/trivy.json"),
        Path("results/gitleaks.json"),
        Path("results/checkov.json"),
        Path("results/zap.json"),
    ]
    for path in aggregate_sources:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if path.name == "semgrep.json":
            for item in data.get("results", []):
                findings.append(
                    {
                        "path": item.get("path", ".github/workflows/sentinel-ci.yml"),
                        "line": item.get("start", {}).get("line", 1),
                        "title": item.get("check_id", "Semgrep finding"),
                        "message": item.get("extra", {}).get("message", "Security issue detected."),
                    }
                )
    return findings


def _to_annotations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    annotations: list[dict[str, Any]] = []
    for finding in findings:
        line = int(finding.get("line", 1) or 1)
        annotations.append(
            {
                "path": str(finding.get("path", ".github/workflows/sentinel-ci.yml")),
                "start_line": line,
                "end_line": line,
                "annotation_level": "warning",
                "message": str(finding.get("message", "Security issue detected."))[:300],
                "title": str(finding.get("title", "Sentinel finding"))[:80],
            }
        )
    return annotations


if __name__ == "__main__":
    raise SystemExit(main())
