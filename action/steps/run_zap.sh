#!/usr/bin/env bash
# File Purpose:
# - Run OWASP ZAP baseline scan against optional preview target.
#
# Key Security Considerations:
# - Skips safely when target is absent and marks scanner status explicitly.
# - Uses timeout to prevent indefinite pending state.
#
# OWASP 2025 Categories Addressed:
# - A03, A06, A10

set -euo pipefail
mkdir -p results

target="${DAST_TARGET:-}"
if [[ -z "$target" ]]; then
  printf '{"scanner":"zap","status":"SKIPPED","alerts":[]}' > results/zap.json
  printf '{"scanner":"zap","status":"SKIPPED"}\n' > results/zap_status.json
  exit 0
fi

status="COMPLETED"
if ! command -v zap-baseline.py >/dev/null 2>&1; then
  status="FAILED"
  printf '{"scanner":"zap","status":"FAILED","alerts":[]}' > results/zap.json
else
  if ! timeout 300 zap-baseline.py -t "$target" -J results/zap.json; then
    status="FAILED"
    printf '{"scanner":"zap","status":"FAILED","alerts":[]}' > results/zap.json
  fi
fi

printf '{"scanner":"zap","status":"%s"}\n' "$status" > results/zap_status.json
