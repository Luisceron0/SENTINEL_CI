#!/usr/bin/env bash
# File Purpose:
# - Run Semgrep SAST and emit normalized raw output artifact.
#
# Key Security Considerations:
# - Uses hard timeout to avoid indefinite scanner hangs.
# - Emits explicit failed status artifact if scanner crashes.
#
# OWASP 2025 Categories Addressed:
# - A03, A06, A10

set -euo pipefail
mkdir -p results

if ! command -v semgrep >/dev/null 2>&1; then
  python -m pip install --quiet "semgrep>=1,<2"
fi

status="COMPLETED"
if ! timeout 300 semgrep scan --config auto --json --output results/semgrep.json .; then
  status="FAILED"
  printf '{"scanner":"semgrep","status":"FAILED","findings":[]}' > results/semgrep.json
fi

printf '{"scanner":"semgrep","status":"%s"}\n' "$status" > results/semgrep_status.json
