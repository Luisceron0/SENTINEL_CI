#!/usr/bin/env bash
# File Purpose:
# - Validate action scanner scripts are present and executable in CI.
#
# Key Security Considerations:
# - Prevents silent scanner step omission due to missing scripts.
#
# OWASP 2025 Categories Addressed:
# - A03, A06

set -euo pipefail

scripts=(
  action/steps/run_semgrep.sh
  action/steps/run_trivy.sh
  action/steps/run_gitleaks.sh
  action/steps/run_checkov.sh
  action/steps/run_zap.sh
  action/steps/run_opa.sh
)

for script in "${scripts[@]}"; do
  [[ -f "$script" ]] || { echo "Missing script: $script"; exit 1; }
  grep -q "#!/usr/bin/env bash" "$script" || { echo "Missing shebang: $script"; exit 1; }

done

echo "All action scripts exist with shebangs."
