# File Purpose:
# - Enforce policy gate that blocks runs introducing new CRITICAL findings.
#
# Key Security Considerations:
# - Prevents silent acceptance of high-impact security regressions.
#
# OWASP 2025 Categories Addressed:
# - A03, A06, A08

package sentinel

default allow = true

deny[msg] {
  some finding in input.findings
  finding.severity == "CRITICAL"
  msg := sprintf("CRITICAL finding detected: %s", [finding.title])
}

allow {
  not deny[_]
}
