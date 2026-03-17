<!--
File Purpose:
- Define Sentinel CI threat model before any application code, per SRS A06 and project workflow.

Key Security Considerations:
- Enumerates trust boundaries, attack vectors, mitigations, and residual risk.
- Establishes fail-secure expectations and verification points for implementation phases.

OWASP 2025 Categories Addressed:
- A01, A02, A03, A04, A05, A06, A07, A08, A09, A10
-->

# Sentinel CI Threat Model

## Scope and Method
This document captures the MVP threat model for Sentinel CI using a practical risk table focused on likely attack vectors in CI-integrated systems.

## System Trust Boundaries
1. GitHub -> Sentinel API webhook boundary.
2. Dashboard/CI clients -> Sentinel API boundary.
3. Sentinel API -> Supabase boundary.
4. Sentinel API -> DefectDojo boundary.
5. Sentinel API -> User-configured webhook consumer boundary.

## Assets to Protect
- Repository scan data, findings, and SBOM artifacts.
- User identity/session state (GitHub OAuth via Supabase Auth).
- API keys and webhook secrets.
- Integrity of scan verdicts that can block merges.
- Audit logs and incident evidence.

## Threat Table
| Threat | Vector | Mitigation | Verification | Residual Risk |
|---|---|---|---|---|
| Forged GitHub webhook payload | Attacker sends fake events to ingestion endpoint | Verify X-Hub-Signature-256 HMAC before payload parsing; reject invalid with 401 | Automated tampered payload test | Low |
| Cross-tenant data exposure (IDOR) | User accesses another user's repository/scan IDs | Enforce ownership checks in API and Supabase RLS on all tables | Automated cross-user access tests return 403 | Very Low |
| API key theft/abuse | Leaked CI secret or intercepted key reuse | Argon2id hashes only in DB; one-time display; rotation/revocation; strict format and rate limits | Hashing tests and auth-failure rate-limit tests | Low |
| SSRF via webhook URL configuration | Malicious URL targets private/internal network | Central validate_webhook_url() rejects private, loopback, link-local, and non-HTTPS targets | SSRF prevention unit tests | Low |
| SQL/command injection in ingestion paths | Untrusted scanner payload fields | Pydantic v2 strict validation; Supabase SDK only; custom Semgrep no-string-sql rule | Semgrep CI + test fixtures | Very Low |
| Supply chain compromise | Malicious dependency/action update | Trivy on every PR, Dependabot, pinned GitHub Action SHAs, SBOM generation and hashing | CI policy checks + release SBOM evidence | Low |
| Weak crypto usage | Developer introduces MD5/SHA1 or custom crypto | Ban weak hashes via Semgrep rule; use argon2-cffi and Python hmac only | Semgrep custom rule detections | Very Low |
| XSS in dashboard finding display | Malicious finding content rendered in UI | Astro escaped rendering, strict CSP, no dangerouslySetInnerHTML | CSP validation + UI tests | Very Low |
| Credential stuffing against auth/key endpoints | Automated repeated unauthorized attempts | IP-based auth failure limits and warning event at 10+ 401 in 5 minutes | Security logging/rate-limit tests | Low |
| Scanner failure yields false pass | Scanner crash or timeout mis-marked as success | Fail-secure status handling: FAILED or TIMEOUT; never implicit pass | Pipeline tests with simulated failure/timeout | Very Low |
| Duplicate finding insertion (race/retry) | Retries re-submit same findings | Idempotency key + upsert conflict-ignore behavior | Ingestion idempotency tests | Very Low |
| Secret leakage in repo/logs | Keys/tokens in source or logs | Gitleaks in CI and pre-commit; log redaction policy forbids secrets/tokens | Gitleaks and log contract tests | Very Low |

## Security Design Principles
- Fail secure by default.
- Validate at every trust boundary.
- Defense in depth: API controls plus database RLS.
- Least privilege for CI permissions and service credentials.
- Deterministic auditability with structured logs and request correlation IDs.

## Review Cadence
- Update on every architecture change affecting trust boundaries.
- Review before each release candidate and at least once per quarter.
