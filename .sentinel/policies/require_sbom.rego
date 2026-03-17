# File Purpose:
# - Enforce policy that SBOM must be present in scan payload.
#
# Key Security Considerations:
# - Guarantees software composition visibility for supply-chain posture.
#
# OWASP 2025 Categories Addressed:
# - A03, A08

package sentinel

default allow = false

allow {
  input.sbom_document.bomFormat
}

deny[msg] {
  not allow
  msg := "SBOM document is required but missing."
}
