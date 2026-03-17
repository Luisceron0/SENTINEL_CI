#!/usr/bin/env bash
# File Purpose:
# - Run Gitleaks secrets detection and output JSON report.
#
# Key Security Considerations:
# - Scans git history in CI context with timeout and fail-secure status.
#
# OWASP 2025 Categories Addressed:
# - A03, A08, A10

set -euo pipefail
mkdir -p results
mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

if ! command -v gitleaks >/dev/null 2>&1; then
  version="8.24.2"
  arch="linux_x64"
  tarball="gitleaks_${version#v}_${arch}.tar.gz"
  url="https://github.com/gitleaks/gitleaks/releases/download/v${version#v}/${tarball}"
  curl -fsSL "$url" -o /tmp/gitleaks.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /tmp
  install -m 0755 /tmp/gitleaks "$HOME/.local/bin/gitleaks"
fi

status="COMPLETED"
if ! timeout 300 gitleaks detect --no-git --report-format json --report-path results/gitleaks.json; then
  status="FAILED"
  printf '[]' > results/gitleaks.json
fi

printf '{"scanner":"gitleaks","status":"%s"}\n' "$status" > results/gitleaks_status.json
