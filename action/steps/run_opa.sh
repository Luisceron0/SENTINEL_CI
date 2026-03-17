#!/usr/bin/env bash
# File Purpose:
# - Run OPA policy evaluation over scanner result artifacts.
#
# Key Security Considerations:
# - Enforces policy-as-code gate and emits explicit status outputs.
#
# OWASP 2025 Categories Addressed:
# - A03, A06, A08

set -euo pipefail
mkdir -p results

policy_dir="${OPA_POLICY_DIR:-.sentinel/policies}"

if ! command -v opa >/dev/null 2>&1; then
  curl -fsSL -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
  chmod +x /usr/local/bin/opa
fi

status="COMPLETED"
if ! timeout 300 opa eval --format json --data "$policy_dir" --input results 'data.sentinel' > results/opa.json; then
  status="FAILED"
  printf '{"result":[]}' > results/opa.json
fi

printf '{"scanner":"opa","status":"%s"}\n' "$status" > results/opa_status.json
