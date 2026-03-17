<!--
File Purpose:
- Define vulnerability disclosure process and summarize OWASP 2025 controls for Sentinel CI.

Key Security Considerations:
- Establishes responsible disclosure workflow and response SLAs.
- Maps implemented controls to OWASP categories and verification artifacts.

OWASP 2025 Categories Addressed:
- A01, A02, A03, A04, A05, A06, A07, A08, A09, A10
-->

# Security Policy

## Supported Versions
Sentinel CI is currently in MVP development. Security fixes are applied to the active main branch.

## Reporting a Vulnerability
Please do not create public issues for suspected vulnerabilities.

1. Send a report to the maintainers via private channel with reproduction steps.
2. Include impacted component, severity assessment, and proof of concept.
3. Provide a safe contact method for coordinated disclosure.

### Disclosure Process
- Acknowledgment target: within 72 hours.
- Initial triage target: within 7 days.
- Fix timeline: based on severity and exploitability.
- Public disclosure: after fix deployment and coordinated communication.

## Security Baseline (OWASP Top 10 2025)
| Category | Sentinel CI Mitigation Summary | Evidence Source |
|---|---|---|
| A01 Broken Access Control | API ownership checks plus mandatory Supabase RLS on all tables | API tests + SQL migrations |
| A02 Security Misconfiguration | Strict security headers, startup env validation, secrets via env/Vault | vercel.json, middleware, startup checks |
| A03 Software Supply Chain | Trivy scans, Dependabot, pinned action SHAs, SBOM generation | CI workflow and release artifacts |
| A04 Cryptographic Failures | Argon2id for API keys, HMAC-SHA256 for webhooks, weak crypto blocked | crypto utilities + Semgrep custom rule |
| A05 Injection | Pydantic strict validation, Supabase SDK-only DB access, Semgrep SQL rule | API schemas + static analysis |
| A06 Insecure Design | Threat model created before code, fail-secure defaults, least privilege | THREAT_MODEL.md + workflow permissions |
| A07 Authentication Failures | Supabase OAuth, strict session policy, API key validation and limits | auth middleware + tests |
| A08 Software/Data Integrity | Signature verification, pinned SHAs, SBOM hash persistence | ingestion checks + CI |
| A09 Security Logging/Alerting | Structured JSON logs, secret redaction, abuse detection alerts | logging middleware + tests |
| A10 Exceptional Conditions | Typed exception handling, sanitized client errors, global handler | FastAPI exception handling + tests |

## Secrets Handling Rules
- Never commit secrets to source control.
- Use environment variable references only.
- Store per-repository webhook secrets in Supabase Vault.
- Store API keys as Argon2id hashes only.

## Cryptography Rules
- Allowed: Argon2id and HMAC-SHA256.
- Disallowed: MD5, SHA1, custom cryptographic algorithms.

## Security Testing Commitments
- Static analysis and secret scanning run in CI.
- Security-focused API tests required for authentication, authorization, and webhook integrity.
- Merge gates block HIGH/CRITICAL findings per policy.
