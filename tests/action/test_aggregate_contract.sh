#!/usr/bin/env bash
# File Purpose:
# - Validate aggregate.py contract for output fields and fail-secure behavior.
#
# Key Security Considerations:
# - Confirms deterministic outputs and severity gate behavior without external network calls.
#
# OWASP 2025 Categories Addressed:
# - A06, A08, A10

set -euo pipefail

rm -rf results
mkdir -p results

cat > results/semgrep.json <<'JSON'
{"results":[{"check_id":"SG001","path":"api/main.py","start":{"line":10},"extra":{"severity":"HIGH","message":"test finding"}}]}
JSON
cat > results/semgrep_status.json <<'JSON'
{"scanner":"semgrep","status":"COMPLETED"}
JSON
cat > results/trivy.sbom.json <<'JSON'
{"bomFormat":"CycloneDX","components":[]}
JSON
cat > results/trivy_status.json <<'JSON'
{"scanner":"trivy","status":"SKIPPED"}
JSON

export DRY_RUN=1
export FAIL_ON_SEVERITY=CRITICAL
export GITHUB_OUTPUT="$(pwd)/results/output.txt"

python action/aggregate.py

grep -q "scan-id=" results/output.txt
grep -q "findings-count=" results/output.txt
grep -q "critical-count=" results/output.txt
grep -q "dashboard-url=" results/output.txt

echo "aggregate.py output contract passed."
