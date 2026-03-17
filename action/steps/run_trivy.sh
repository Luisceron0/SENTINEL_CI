#!/usr/bin/env bash
# File Purpose:
# - Run Trivy for SCA and CycloneDX SBOM generation.
#
# Key Security Considerations:
# - Enforces timeout and fail-secure status artifact generation.
# - Produces SBOM used for integrity hash verification downstream.
#
# OWASP 2025 Categories Addressed:
# - A03, A08, A10

set -euo pipefail
mkdir -p results
mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

if ! command -v trivy >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$HOME/.local/bin"
fi

status="COMPLETED"
if ! timeout 300 trivy fs --scanners vuln --format json --output results/trivy.json .; then
  status="FAILED"
  printf '{"scanner":"trivy","status":"FAILED","results":[]}' > results/trivy.json
fi

if ! timeout 300 trivy fs --scanners vuln --format cyclonedx --output results/trivy.sbom.json .; then
  status="FAILED"
  printf '{"bomFormat":"CycloneDX","components":[]}' > results/trivy.sbom.json
fi

printf '{"scanner":"trivy","status":"%s"}\n' "$status" > results/trivy_status.json
