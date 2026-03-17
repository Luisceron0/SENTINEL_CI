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

## OWASP 2025 Compliance Evidence
| Category | Implementation Evidence | Verification Evidence |
|---|---|---|
| A01 | Ownership checks in API routes + Supabase RLS policies on all tables | `tests/api/test_cross_user_access.py` returns 403 for cross-tenant access |
| A02 | CSP + frame/content/referrer headers in `vercel.json`, Astro middleware, and API middleware | Header configuration inspected in code and middleware execution paths |
| A03 | Dogfooding workflow runs Semgrep/Trivy/Gitleaks/Checkov/ZAP/OPA and Dependabot enabled | `.github/workflows/sentinel-ci.yml` and `.github/dependabot.yml` |
| A04 | Argon2id API key hashing + HMAC-SHA256 webhook signing/verification | `tests/api/test_api_key_hashing.py`, `tests/api/test_webhook_hmac.py` |
| A05 | Strict Pydantic models + SSRF validation + Semgrep custom rules | `api/models/schemas.py`, `api/utils/validators.py`, `.semgrep/` rules |
| A06 | Threat model created before app code and fail-secure scanner handling | `THREAT_MODEL.md`, action scanner scripts with timeout/failed status |
| A07 | JWT/API key auth controls, strict cookie policy, auth rate limit middleware | `api/middleware/auth.py`, `api/middleware/rate_limit.py` |
| A08 | Signed webhook payloads, pinned workflow SHAs, SBOM generation and release attachment flow | `api/services/webhook_delivery.py`, workflow pinning, `release-sbom` job |
| A09 | Structured JSON request logs with user hash and credential-stuffing warning event | `api/middleware/logging.py` |
| A10 | Global exception sanitizer + explicit typed try/except at trust boundaries | `api/main.py`, service-level exception handling |

## Current Validation Snapshot
1. `ruff check api/` passed.
2. `mypy api/` passed.
3. `pytest tests/api/` passed.
4. `bash tests/action/test_scripts_exist.sh` passed.
5. `bash tests/action/test_aggregate_contract.sh` passed.
