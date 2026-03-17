#!/usr/bin/env bash
# File Purpose:
# - Run Checkov IaC scanner and output JSON report.
#
# Key Security Considerations:
# - Applies execution timeout and explicit failure status artifacts.
#
# OWASP 2025 Categories Addressed:
# - A03, A06, A10

set -euo pipefail
mkdir -p results

if ! command -v checkov >/dev/null 2>&1; then
  python -m pip install --quiet "checkov>=3,<4"
fi

status="COMPLETED"
if ! timeout 300 checkov -d . -o json > results/checkov.json; then
  status="FAILED"
  printf '{"results":{"failed_checks":[]}}' > results/checkov.json
fi

printf '{"scanner":"checkov","status":"%s"}\n' "$status" > results/checkov_status.json
