# Sentinel CI — Software Requirements Specification (SRS)

**Version:** 1.0 — MVP  
**Status:** Draft  
**Author:** Luis Alejandro Cerón Muñoz  
**Date:** March 2026  
**Stack:** Python · TypeScript · Astro · Supabase · Vercel  
**Repository:** github.com/luisceron0/sentinel-ci  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [Functional Requirements](#3-functional-requirements)
4. [Non-Functional Requirements](#4-non-functional-requirements)
5. [Technology Stack](#5-technology-stack)
6. [Data Model](#6-data-model)
7. [API Specification](#7-api-specification)
8. [Security Architecture](#8-security-architecture)
9. [Observability](#9-observability)
10. [Deployment Architecture](#10-deployment-architecture)
11. [MVP Scope](#11-mvp-scope)
12. [Constraints and Assumptions](#12-constraints-and-assumptions)
13. [Acceptance Criteria](#13-acceptance-criteria)
14. [Glossary](#14-glossary)

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification (SRS) defines the functional and non-functional
requirements for Sentinel CI, an open-source DevSecOps pipeline toolkit. The document serves
as the authoritative reference for design, implementation, testing, and stakeholder
communication throughout the MVP development cycle.

### 1.2 Project Overview

Sentinel CI is a security automation toolkit that integrates into GitHub-based development
workflows to detect vulnerabilities, exposed secrets, insecure infrastructure code, and
outdated dependencies before they reach production. Results are surfaced through a web
dashboard and support webhook-based alerting.

The system addresses a gap in the 2025 market: most mid-level engineering portfolios declare
DevSecOps knowledge but provide no public evidence of security toolchain construction.
Sentinel CI is that evidence. The project is **open source** and uses itself to secure its
own codebase (dogfooding).

### 1.3 Scope

Sentinel CI covers the following capabilities within MVP scope:

- GitHub Action that orchestrates security scans on push and pull request events
- Scan engine integrating Semgrep (SAST), Trivy (SCA + SBOM), Gitleaks (secrets), Checkov
  (IaC), OWASP ZAP (DAST), and OPA (Policy as Code)
- Vulnerability aggregation and deduplication via DefectDojo integration
- Web dashboard (Astro + Island Architecture) authenticated via GitHub OAuth and API keys
- PDF and JSON report export per repository and per scan
- Webhook-based alerting to generic HTTP endpoints
- Deployment on Vercel (frontend + serverless functions) and Supabase (PostgreSQL + auth)

### 1.4 Definitions and Acronyms

| Term | Definition |
|------|-----------|
| SAST | Static Application Security Testing — analysis of source code without execution |
| SCA | Software Composition Analysis — vulnerability scanning of third-party dependencies |
| DAST | Dynamic Application Security Testing — analysis of a running application |
| IaC | Infrastructure as Code — declarative configuration files (Terraform, etc.) |
| SBOM | Software Bill of Materials — complete inventory of software components and licenses |
| OPA | Open Policy Agent — general-purpose policy engine using Rego language |
| MVP | Minimum Viable Product — first releasable scope of the system |
| RLS | Row-Level Security — PostgreSQL feature enforcing per-row access policies |
| OWASP | Open Web Application Security Project |
| CI | Continuous Integration |
| PAT | Personal Access Token — GitHub credential scoped to specific permissions |
| ASPM | Application Security Posture Management |

### 1.5 References

- OWASP Top 10 2025 — owasp.org/Top10
- Semgrep Documentation — semgrep.dev/docs
- Trivy Documentation — aquasecurity.github.io/trivy
- DefectDojo Documentation — defectdojo.com/docs
- Supabase Documentation — supabase.com/docs
- Astro Documentation — docs.astro.build
- Open Policy Agent — openpolicyagent.org/docs
- CycloneDX Specification — cyclonedx.org/specification

---

## 2. System Overview

### 2.1 Product Name and Identity

- **Name:** Sentinel CI
- **Tagline:** Security automation for developers who ship.

The name communicates the role of the system: a guardian that monitors every commit and
surfaces vulnerabilities before deployment. It is memorable, technically accurate, and
appropriate for the target market of developer-focused open-source tools.

### 2.2 System Context

Sentinel CI operates as an intermediary layer between the developer's GitHub repository and
the production environment. It is triggered by GitHub webhook events, executes a configurable
scan pipeline, and surfaces results through both the GitHub PR interface (annotations and
status checks) and an external web dashboard.

### 2.3 Architecture Overview

The system is structured across four layers:

1. **GitHub Action Layer** — YAML-defined composite action that orchestrates all scanners.
   Runs on GitHub-hosted or self-hosted runners. No Docker required.

2. **Scan Engine Layer** — Individual scanner binaries invoked by the Action. Each scanner
   is isolated, versioned, and independently configurable.

3. **Backend API Layer** — Python serverless functions (Vercel) that receive scan results,
   normalize them, interact with DefectDojo, and persist data to Supabase.

4. **Dashboard Layer** — Astro-based frontend with Island Architecture deployed to Vercel,
   authenticated via GitHub OAuth and Supabase Auth.

### 2.4 Target Users

| User Type | Description | Primary Interface | Authentication |
|-----------|-------------|-------------------|----------------|
| Individual Developer | Solo developer monitoring personal repos | Dashboard + GitHub | GitHub OAuth |
| Team Lead | Manages multiple repos for a small team | Dashboard | GitHub OAuth + API Key |
| Security Engineer | Reviews aggregated vulnerability data | Dashboard + PDF export | GitHub OAuth |
| CI System | Automated pipeline posting scan results | REST API | API Key |

---

## 3. Functional Requirements

### 3.1 Authentication and Authorization

#### FR-AUTH-01 — GitHub OAuth Login

The system shall authenticate users via GitHub OAuth 2.0. On successful authentication,
the system shall create or update a user record in Supabase with the GitHub user ID,
username, avatar URL, and email. The system shall issue a session cookie
(HttpOnly, Secure, SameSite=Strict) with a 24-hour expiration.

#### FR-AUTH-02 — API Key Management

Authenticated users shall be able to generate, rotate, and revoke API keys from the
dashboard. Each API key shall:

- Be prefixed with `sci_` for easy identification in logs
- Be stored as an Argon2id hash in Supabase
- Be shown in plaintext only once at generation and never again
- Be exactly 51 characters total (4-char prefix + 47-char random suffix)

#### FR-AUTH-03 — Role-Based Access Control

The system shall enforce three roles:

- **OWNER** — full access to a repository's scan data
- **VIEWER** — read-only access to shared reports
- **ADMIN** — reserved for the authenticated user who added a repository

Supabase RLS policies shall enforce these boundaries at the database layer, not only at
the API layer (defense in depth).

### 3.2 Repository Management

#### FR-REPO-01 — Repository Registration

An authenticated user shall be able to register a GitHub repository by providing its full
name (`owner/repo`). The system shall verify that the authenticated user has at least read
access to the repository via the GitHub API before registering it. A webhook secret shall
be generated and returned for the user to configure in GitHub.

#### FR-REPO-02 — Webhook Reception

The system shall expose a `POST /api/webhooks/github` endpoint that receives `push` and
`pull_request` events from GitHub. The endpoint shall:

- Verify the `X-Hub-Signature-256` HMAC before processing any payload
- Return HTTP 401 immediately for unverified requests with no further processing
- Process only `push` and `pull_request` event types; ignore all others silently

### 3.3 Scan Pipeline

#### FR-SCAN-01 — GitHub Action Orchestration

Sentinel CI shall provide a reusable GitHub Action (`uses: luisceron0/sentinel-ci@v1`)
that developers add to their workflow YAML. The Action shall accept the following inputs:

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-endpoint` | Yes | — | URL of the Sentinel CI backend |
| `api-key` | Yes | — | Sentinel CI API key (passed as secret) |
| `scanners` | No | `all` | Comma-separated list of scanners to enable |
| `dast-target` | No | — | URL for ZAP to scan (DAST skipped if not provided) |
| `fail-on-severity` | No | `HIGH` | Minimum severity to fail the pipeline |
| `opa-policy-dir` | No | `.sentinel/policies` | Directory containing Rego policies |

The Action shall produce the following outputs:

| Output | Description |
|--------|-------------|
| `scan-id` | UUID of the created scan in Sentinel CI |
| `findings-count` | Total number of findings |
| `critical-count` | Number of CRITICAL findings |
| `dashboard-url` | Direct link to the scan in the dashboard |

#### FR-SCAN-02 — Scanner Integration

The pipeline shall integrate the following scanners, each running as an independent step:

| Scanner | Category | Languages / Targets | Output Format |
|---------|----------|---------------------|---------------|
| Semgrep | SAST | Python, Java, TypeScript, Go | JSON (SARIF) |
| Trivy | SCA + SBOM | All languages + containers | JSON + CycloneDX |
| Gitleaks | Secrets | Git history + staged files | JSON |
| Checkov | IaC | Terraform, YAML, Dockerfile | JSON |
| OWASP ZAP | DAST | Running HTTP applications | JSON |
| OPA + Rego | Policy as Code | JSON/YAML policy targets | JSON |

#### FR-SCAN-03 — SBOM Generation

Trivy shall generate a CycloneDX-format SBOM for every scan. The SBOM shall be:

- Attached to the scan record in the database
- Available for download from the dashboard
- Include component name, version, license, and known CVEs
- Have its SHA256 hash stored alongside it for integrity verification

#### FR-SCAN-04 — Scan Result Ingestion

After all scanners complete, the Action shall `POST` the aggregated results to
`POST /api/scans`. The payload shall include:

- Repository name and ID
- Commit SHA and branch
- Triggered event type
- Array of normalized findings (one schema regardless of source scanner)
- Raw SBOM document

The API shall validate the API key, normalize findings to the unified schema, persist them
to Supabase, and forward findings to DefectDojo for deduplication and tracking.

#### FR-SCAN-05 — Pipeline Gate

The Action shall exit with a non-zero status code if any finding meets or exceeds the
configured `fail-on-severity` threshold. This causes the GitHub status check to fail and
blocks merging if branch protection rules are enabled. The specific findings that triggered
the failure shall be annotated on the PR diff via the GitHub Checks API.

### 3.4 Vulnerability Management

#### FR-VULN-01 — DefectDojo Integration

The backend shall forward all findings to a DefectDojo instance for deduplication,
false-positive tracking, and remediation workflow. Configuration:

- One **Product** per registered repository
- One **Engagement** per scan execution
- Sentinel CI dashboard links to the corresponding DefectDojo finding for each vulnerability

#### FR-VULN-02 — Finding Schema

Every finding persisted in Supabase shall conform to the following unified schema:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `scan_id` | UUID FK | Reference to scans table |
| `scanner` | TEXT | Source scanner: semgrep, trivy, gitleaks, checkov, zap, opa |
| `severity` | ENUM | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `title` | TEXT | Short description of the finding |
| `description` | TEXT | Full technical description |
| `file_path` | TEXT? | Affected file path (null for DAST/secrets) |
| `line_start` | INT? | Starting line number (null if not applicable) |
| `line_end` | INT? | Ending line number (null if not applicable) |
| `cve_id` | TEXT? | CVE identifier if applicable |
| `cwe_id` | TEXT? | CWE identifier if applicable |
| `remediation` | TEXT | Suggested fix from the scanner |
| `false_positive` | BOOL | Default false |
| `status` | ENUM | OPEN, IN_PROGRESS, RESOLVED, ACCEPTED |
| `idempotency_key` | TEXT UNIQUE | SHA256(scan_id + scanner + file_path + line_start) |
| `created_at` | TIMESTAMPTZ | Auto-generated |

### 3.5 Dashboard

#### FR-DASH-01 — Repository Overview

The dashboard homepage shall display all registered repositories with:

- Last scan date and duration
- Overall risk score: `(CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)`
- Trend sparkline (last 10 scans)
- Quick links to the latest report and scan detail

#### FR-DASH-02 — Scan Detail View

Each scan shall have a detail page showing:

- Scan metadata: trigger event, commit SHA, branch, duration, scanner versions
- Findings grouped by scanner
- Severity distribution chart (React island with Recharts)
- Filterable and sortable findings table (React island)
- SBOM download link (CycloneDX JSON)
- Link to DefectDojo engagement

#### FR-DASH-03 — Trend Analysis

The dashboard shall display a findings-over-time chart per repository showing the count of
CRITICAL and HIGH findings per scan over the last 30 scans. This enables users to verify
that their security posture is improving over time.

#### FR-DASH-04 — Report Export

Users shall be able to export any scan as:

- **PDF report** — executive summary, severity distribution, full findings table with
  remediation guidance, SBOM component summary, scan metadata
- **JSON report** — full raw findings array conforming to the finding schema

### 3.6 Alerting

#### FR-ALERT-01 — Webhook Notifications

Users shall be able to configure one or more generic webhook URLs per repository. On scan
completion, the system shall POST a JSON payload to each configured webhook containing:

- Repository name and ID
- Scan ID and dashboard URL
- Trigger event type
- Severity counts (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Timestamp

Every outbound webhook request shall include an `X-Sentinel-Signature` header containing
an HMAC-SHA256 signature of the payload body, computed using the user-configured webhook
secret. Consumers can verify payload integrity using this header.

#### FR-ALERT-02 — Alert Thresholds

Users shall be able to configure a minimum severity threshold per repository for webhook
alerts. Scans that produce no findings at or above the threshold shall not trigger webhook
notifications, preventing alert fatigue.

---

## 4. Non-Functional Requirements

### 4.1 Security — OWASP Top 10 2025 Compliance

Every OWASP 2025 category is addressed by a specific design decision. This section is the
primary DevSecOps artifact of the project.

| OWASP 2025 | Category | Mitigation in Sentinel CI | Verification Method |
|------------|----------|--------------------------|---------------------|
| **A01** | Broken Access Control | Supabase RLS enforces ownership at DB layer. API validates JWT + repo ownership before any read/write. SSRF prevented: webhook URLs validated against private IP blocklist before storage. | Automated test: cross-user repo access returns 403 |
| **A02** | Security Misconfiguration | All secrets in Vercel env vars + Supabase Vault. CSP, X-Frame-Options, X-Content-Type-Options, HSTS headers on all responses. Configuration validated on startup — process exits if required vars missing. | Trivy + Checkov scan own deployment in CI |
| **A03** | Software Supply Chain | Trivy SCA scans all dependencies on every PR. CycloneDX SBOM generated per build. Dependabot enabled. GitHub Action steps pinned to SHA, not floating tags. | SBOM attached to every GitHub Release |
| **A04** | Cryptographic Failures | TLS enforced on all endpoints (Vercel default). API keys stored as Argon2id hashes. Webhook secrets use HMAC-SHA256. No MD5/SHA1 (enforced by custom Semgrep rule). | CodeQL + Semgrep rule blocks weak hash usage |
| **A05** | Injection | All DB queries via Supabase SDK (parameterized). User input validated with Pydantic v2 (Python) and Zod (TypeScript). Custom Semgrep rule bans string interpolation in SQL contexts. Astro escapes output by default. | Semgrep scan on every PR |
| **A06** | Insecure Design | Threat model documented in THREAT_MODEL.md before first line of code. Fail-secure: scanner crash = FAILED scan status. GitHub Action token scoped to least privilege. | Threat model reviewed before each release |
| **A07** | Authentication Failures | GitHub OAuth via Supabase Auth. Sessions expire in 24h with HttpOnly/Secure/SameSite=Strict cookies. API key rate limit: 5 failed verifications per IP per minute. | Test: expired token returns 401; 6th failed auth returns 429 |
| **A08** | Software/Data Integrity | GitHub Action pinned by SHA. Webhook payloads verified with HMAC-SHA256 before any processing. SBOM SHA256 hash stored alongside document. | Gitleaks scans own repo in CI for exposed secrets |
| **A09** | Security Logging & Alerting | Structured JSON logs for every API request, auth event, scan event, and error. Alert fired on 10+ HTTP 401 responses from same IP in any 5-minute window. User IDs logged as SHA256 hashes. | Log pipeline tested with simulated attack traffic |
| **A10** | Mishandling of Exceptional Conditions | All exceptions caught at trust boundaries with typed except blocks. External errors sanitized before client response (no stack traces, paths, or internal details). Scanner timeouts set at 5 minutes — explicit TIMEOUT status if exceeded. Global FastAPI exception handler for all unhandled exceptions. | Test: inject scanner crash, verify neutral error response |

**Additional mitigations beyond OWASP 2025:**

- **Race Conditions** — Supabase upsert with `on_conflict=ignore` on `idempotency_key`
  column prevents duplicate findings on retry. Idempotency key: `SHA256(scan_id + scanner + file_path + line_start)`
- **File Upload Security** — No direct file uploads in MVP. SBOM and scan results are
  system-generated. If user-uploaded config files are added in future releases, magic bytes
  validation and metadata stripping are required before storage.
- **Prompt Injection** — Not applicable to MVP (no LLM features). If AI analysis is added,
  input sanitization and output validation must be implemented before merging.

### 4.2 Performance

| Metric | Target |
|--------|--------|
| Full scan pipeline completion | < 5 minutes for repos under 50,000 lines |
| Dashboard initial page load | < 2 seconds on 4G (Lighthouse score ≥ 90) |
| API response time p95 | < 500ms for all endpoints except scan ingestion |
| Scan ingestion endpoint | < 3 seconds for payloads under 5MB |

### 4.3 Scalability

Vercel serverless functions scale automatically to handle concurrent scan ingestion from
multiple repositories. Supabase connection pooling handles up to 100 concurrent database
connections. The architecture supports horizontal scaling without code changes.

### 4.4 Reliability

- Scan ingestion endpoint uptime: 99.9% (aligned with Vercel SLA)
- Failed scan POSTs retried by the GitHub Action with exponential backoff:
  3 retries at 10s, 30s, 90s intervals
- Dashboard degrades gracefully if DefectDojo is unavailable, displaying cached data with
  a staleness warning

### 4.5 Maintainability

Each scanner is encapsulated in an independent module. Adding a new scanner requires only:

1. Adding a new step in the Action YAML
2. Implementing a normalizer function in `scanner_normalizer.py`
3. Registering it in the scanner registry

No changes to the core pipeline or database schema are required.

---

## 5. Technology Stack

| Layer | Technology | Version | Rationale |
|-------|-----------|---------|-----------|
| GitHub Action | YAML composite action | GitHub Actions v4 | Native CI/CD, zero infrastructure, no Docker required |
| SAST | Semgrep | 1.x OSS | Multi-language (Python/Java/TS/Go), customizable rules, SARIF output |
| SCA + SBOM | Trivy | 0.5x | Unified SCA + SBOM (CycloneDX) in one tool |
| Secrets | Gitleaks | 8.x | Scans git history, low false-positive rate, OSS |
| IaC | Checkov | 3.x | Best Terraform coverage, integrates with Semgrep |
| DAST | OWASP ZAP | 2.14 | Industry standard, headless mode for CI |
| Policy as Code | OPA + Rego | 0.6x | Declarative, auditable, language-agnostic |
| Vuln Management | DefectDojo | 2.x | Open source ASPM, deduplication, remediation tracking |
| Backend API | Python + FastAPI | 3.12 / 0.11x | Matches CV stack, async, Pydantic v2 validation |
| Frontend | Astro + Island Architecture | 4.x | Static HTML + selective JS hydration, Lighthouse ≥ 90 |
| UI Styling | Tailwind CSS | 3.x | Utility-first, matches existing CV experience |
| Charts | Recharts (React island) | 2.x | Lightweight, composable, React-native |
| Database | Supabase (PostgreSQL) | 15.x + RLS | Managed Postgres, built-in auth, Vault, RLS |
| Auth | Supabase Auth + GitHub OAuth | OAuth 2.0 | Native GitHub OAuth, session management, no custom auth |
| Frontend Deploy | Vercel | Edge Network | Zero-config Astro deployment, automatic CDN |
| API Deploy | Vercel Serverless Functions | Python runtime | Serverless scale, co-located with frontend |
| IaC | Terraform | 1.7x | Provisions Supabase + Vercel config as code |
| CI/CD | GitHub Actions | native | Self-hosted pipeline using own toolkit (dogfooding) |
| PDF Generation | WeasyPrint | 60.x | Python-native, CSS-based PDF rendering |
| Linting (Python) | Ruff + mypy | latest | Fast, comprehensive, type-safe |
| Linting (TS/Astro) | ESLint + Prettier | latest | Standard toolchain |
| Pre-commit | pre-commit framework | latest | Enforces quality gates before every commit |

---

## 6. Data Model

### 6.1 Entity Overview

All tables reside in Supabase PostgreSQL. RLS is mandatory on every table. All tables
include `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` and
`created_at TIMESTAMPTZ DEFAULT now()` unless noted.

| Table | Primary Key | Description |
|-------|-------------|-------------|
| `users` | id (UUID) | Extends Supabase `auth.users`. Stores GitHub profile data. |
| `repositories` | id (UUID) | Registered GitHub repositories. FK to auth.users (owner). |
| `api_keys` | id (UUID) | Hashed API keys. FK to auth.users. |
| `scans` | id (UUID) | Individual scan executions. FK to repositories. |
| `findings` | id (UUID) | Individual vulnerability findings. FK to scans. |
| `sboms` | id (UUID) | CycloneDX SBOM documents. FK to scans (1:1). |
| `webhooks` | id (UUID) | Configured webhook endpoints. FK to repositories. |
| `alerts_log` | id (UUID) | Record of sent webhook alerts. FK to scans + webhooks. |

### 6.2 Key Relationships

```
auth.users (Supabase)
  └── public.users (1:1 extension)
        └── repositories (1:N)
              ├── scans (1:N)
              │     ├── findings (1:N)
              │     └── sboms (1:1)
              └── webhooks (1:N)
                    └── alerts_log (1:N)

auth.users
  └── api_keys (1:N)
```

### 6.3 RLS Policy Pattern

Applied to every table without exception:

```sql
-- Enable RLS
ALTER TABLE public.{table_name} ENABLE ROW LEVEL SECURITY;

-- Users can only access their own data
CREATE POLICY "owner_access" ON public.{table_name}
  FOR ALL
  USING (
    owner_id = auth.uid()  -- adjust FK column name per table
  );
```

### 6.4 Critical Column Constraints

```sql
-- api_keys
key_hash    TEXT NOT NULL,          -- Argon2id hash, never plaintext
prefix      CHAR(4) DEFAULT 'sci_', -- for log identification

-- scans
status      TEXT CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','TIMEOUT')),

-- findings
severity    TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
status      TEXT CHECK (status IN ('OPEN','IN_PROGRESS','RESOLVED','ACCEPTED')),
idempotency_key TEXT UNIQUE NOT NULL, -- prevents duplicate findings on retry

-- sboms
sha256      TEXT NOT NULL,          -- integrity verification
format      TEXT DEFAULT 'cyclonedx',

-- webhooks
url         TEXT NOT NULL,          -- HTTPS only, private IPs rejected at API layer
secret_id   UUID,                   -- Supabase Vault reference, not the secret itself

-- alerts_log
status      TEXT CHECK (status IN ('SENT','FAILED')),
response_code INT
```

---

## 7. API Specification

### 7.1 Authentication

All endpoints except `POST /api/webhooks/github` require one of:

- **Bearer token:** `Authorization: Bearer <supabase_jwt>` — for dashboard users
- **API key:** `X-Sentinel-Key: sci_<key>` — for CI systems

### 7.2 Rate Limits

| Scenario | Limit |
|----------|-------|
| Auth endpoint failures | 5 per IP per minute, then 429 |
| General API | 60 requests per IP per minute |
| Scan ingestion | 30 per minute per API key |
| Report generation | 10 per minute per user |
| Repository registration | 10 per minute per user |

### 7.3 Endpoints

| Method + Path | Auth | Description | Rate Limit |
|---------------|------|-------------|------------|
| `POST /api/webhooks/github` | HMAC signature | Receive GitHub webhook events | 100/min |
| `POST /api/scans` | API Key | Ingest scan results from GitHub Action | 30/min |
| `GET /api/scans/:id` | JWT or Key | Retrieve scan detail and findings | 60/min |
| `GET /api/repositories` | JWT | List registered repositories for auth user | 60/min |
| `POST /api/repositories` | JWT | Register a new repository | 10/min |
| `DELETE /api/repositories/:id` | JWT | Remove repository and all related data | 10/min |
| `GET /api/repositories/:id/scans` | JWT | Paginated scan history for a repository | 60/min |
| `GET /api/scans/:id/report.pdf` | JWT | Generate and download PDF report | 10/min |
| `GET /api/scans/:id/report.json` | JWT | Download JSON report | 30/min |
| `POST /api/webhooks` | JWT | Register a webhook endpoint for a repository | 10/min |
| `DELETE /api/webhooks/:id` | JWT | Remove a webhook endpoint | 10/min |
| `POST /api/keys` | JWT | Generate a new API key | 5/min |
| `DELETE /api/keys/:id` | JWT | Revoke an API key | 10/min |
| `GET /metrics` | Internal | Prometheus-compatible metrics | Internal only |

### 7.4 Standard Error Response

All errors return a consistent shape. Internal details are never exposed to the client:

```json
{
  "error": "error_code_snake_case",
  "message": "Human-readable description safe for client display",
  "request_id": "uuid-v4-for-log-correlation"
}
```

---

## 8. Security Architecture

### 8.1 Trust Boundaries

Sentinel CI defines four trust boundaries. Every boundary performs independent validation
and never relies solely on a previous boundary's checks.

**Boundary 1 — GitHub to Sentinel CI API**
All requests verified via HMAC-SHA256 signature (`X-Hub-Signature-256`) before any payload
processing. No trust extended to payload contents before signature verification.

**Boundary 2 — Client to Dashboard API**
All requests authenticated via Supabase JWT or hashed API key. Rate limiting applied at
Vercel Edge before reaching the serverless function. Ownership verified at API layer.

**Boundary 3 — API to Supabase**
All queries via Supabase SDK (parameterized). RLS enforced at database layer independently
of application logic. Service role key never exposed to the client or in logs.

**Boundary 4 — API to DefectDojo**
Requests authenticated via DefectDojo API token stored in Vercel environment secrets.
All communication over HTTPS. Errors from DefectDojo sanitized before surfacing to client.

### 8.2 Secrets Management

| Secret | Storage Location | Rotation Policy |
|--------|-----------------|-----------------|
| GitHub OAuth Client Secret | Vercel Environment Variables | On suspected compromise |
| Supabase Service Role Key | Vercel Environment Variables | Quarterly |
| DefectDojo API Token | Vercel Environment Variables | Quarterly |
| Per-repo Webhook Secrets | Supabase Vault (encrypted at rest) | On user request |
| User API Keys | Supabase DB as Argon2id hash | On user request |
| GitHub Action API Key | GitHub Encrypted Secrets | On rotation from dashboard |

Rules enforced:
- No secrets in source code, comments, or git history (enforced by Gitleaks in CI)
- All secrets referenced as environment variables only
- `.env.example` contains placeholder values and documents where each real value comes from
- Startup validation: process exits with clear error if any required env var is missing

### 8.3 Threat Model Summary

Full threat model maintained in `THREAT_MODEL.md`. Key threats:

| Threat | Vector | Mitigation | Residual Risk |
|--------|--------|-----------|---------------|
| Forged webhook payload | External attacker | HMAC-SHA256 verification before processing | Low |
| Stolen API key | Credential theft | Keys are Argon2id hashed; instant revocation available | Low |
| Cross-user data access | IDOR | Supabase RLS + API ownership check (defense in depth) | Very Low |
| Supply chain compromise | Malicious dependency | Trivy SCA + SBOM + Dependabot on every PR | Low |
| SSRF via webhook URL | Malicious user input | IP range validation rejects private ranges | Low |
| Secrets in scan results | Accidental exposure | Gitleaks scans own repo in CI pipeline | Very Low |
| Scan result injection | Malformed scanner output | Pydantic schema validation on every ingestion | Very Low |
| Dashboard XSS | Malicious finding content | Astro escapes by default; strict CSP header | Very Low |
| Credential stuffing | Automated auth attacks | Rate limit: 5 failures/IP/min → 429 + alert | Low |
| Scanner crash → false pass | Infrastructure failure | Fail-secure: crash = FAILED status, not PASSED | Very Low |

### 8.4 Custom Semgrep Rules

Two custom rules are maintained in `.semgrep/`:

**`no-weak-crypto.yaml`** — Blocks use of MD5 and SHA1 in any context. Applies to Python
and TypeScript. Fails the pipeline if triggered.

**`no-string-sql.yaml`** — Blocks string interpolation or concatenation in any function
call whose name contains `query`, `execute`, or `sql`. Applies to Python. Fails the
pipeline if triggered.

---

## 9. Observability

### 9.1 Structured Logging

All API requests produce a structured JSON log entry with the following fields:

```json
{
  "timestamp": "ISO 8601",
  "request_id": "UUID v4",
  "event_type": "api_request | auth_event | scan_event | alert_event | error",
  "method": "GET | POST | DELETE",
  "path": "/api/scans",
  "status_code": 200,
  "duration_ms": 142,
  "user_id": "SHA256 hash of actual user ID",
  "repository_id": "UUID or null",
  "ip_address": "last octet zeroed: 192.168.1.0",
  "scanner": "semgrep | trivy | null",
  "error_code": "null or snake_case code"
}
```

**Never logged:** API keys (even partial), JWT tokens, webhook secrets, raw passwords,
stack traces, internal file paths.

### 9.2 Metrics (Prometheus-Compatible)

| Metric Name | Type | Labels |
|-------------|------|--------|
| `sentinel_scans_total` | Counter | repository_id, status |
| `sentinel_findings_total` | Counter | severity, scanner |
| `sentinel_scan_duration_seconds` | Histogram | scanner |
| `sentinel_api_request_duration_seconds` | Histogram | path, method |
| `sentinel_api_errors_total` | Counter | status_code, path |
| `sentinel_webhook_deliveries_total` | Counter | status |
| `sentinel_auth_failures_total` | Counter | type (jwt/api_key) |

### 9.3 Alerting Rules

| Rule | Condition | Severity |
|------|-----------|----------|
| Potential credential stuffing | 10+ HTTP 401 from same IP in 5-minute window | WARNING |
| Pipeline reliability degradation | Scan ingestion error rate > 5% in 10-minute window | ERROR |
| Critical finding on main branch | CRITICAL finding detected in main/master branch scan | CRITICAL |
| Scan stuck in PENDING | Scan in PENDING status for > 10 minutes | WARNING |

---

## 10. Deployment Architecture

### 10.1 Infrastructure

| Component | Platform / Service | Notes |
|-----------|-------------------|-------|
| Frontend | Vercel (Astro static) | Auto-deployed on merge to main |
| Backend API | Vercel Serverless Functions (Python) | Co-located with frontend |
| Database | Supabase (PostgreSQL 15) | Managed, connection pooling enabled |
| Auth | Supabase Auth | GitHub OAuth provider configured |
| Secrets Storage | Supabase Vault + Vercel Env Vars | Vault for per-repo secrets |
| Vuln Management | DefectDojo (Railway) | Self-hosted on Railway free tier |
| CDN | Vercel Edge Network | Automatic, global |
| IaC | Terraform | Provisions Supabase project + Vercel project |

### 10.2 Environment Configuration

Required environment variables (all documented in `.env.example`):

```bash
# Supabase
SUPABASE_URL=                    # Project URL from Supabase dashboard
SUPABASE_ANON_KEY=               # Public anon key (safe for client)
SUPABASE_SERVICE_ROLE_KEY=       # Private service key (server only, never client)

# GitHub OAuth (configured in Supabase Auth)
GITHUB_OAUTH_CLIENT_ID=          # From GitHub OAuth App settings
GITHUB_OAUTH_CLIENT_SECRET=      # From GitHub OAuth App settings (Vercel env var only)

# DefectDojo
DEFECTDOJO_URL=                  # DefectDojo instance URL
DEFECTDOJO_API_KEY=              # DefectDojo API token

# Sentinel CI internal
SENTINEL_WEBHOOK_SECRET=         # Default HMAC secret for GitHub webhooks
NEXT_PUBLIC_DASHBOARD_URL=       # Public URL of the deployed dashboard
```

### 10.3 CI/CD Pipeline — Dogfooding

Sentinel CI uses its own GitHub Action to secure itself. The pipeline on every PR:

```
1. Semgrep    → scans Python (FastAPI) and TypeScript (Astro)
2. Trivy      → scans Python + Node.js dependencies, generates SBOM
3. Gitleaks   → scans git history for exposed secrets
4. Checkov    → scans Terraform configuration
5. OWASP ZAP  → runs against the Vercel preview deployment URL
6. OPA        → evaluates that no new HIGH findings are introduced without documented exception
7. Results    → posted to Sentinel CI dashboard (the project monitors itself)
8. Gate       → PR blocked if any scanner exits non-zero
```

This dogfooding architecture is a key portfolio signal: the tool is trusted enough to gate
its own releases.

---

## 11. MVP Scope

### 11.1 In Scope for MVP

- GitHub OAuth authentication and API key management (generate, rotate, revoke)
- Repository registration with HMAC webhook verification
- GitHub Action with all six scanners (Semgrep, Trivy, Gitleaks, Checkov, ZAP, OPA)
- Scan result ingestion API with full Pydantic validation
- DefectDojo integration for deduplication and tracking
- Astro dashboard: repository overview, scan detail, trend chart, settings
- PDF and JSON report export
- Generic webhook alerting with HMAC signature
- SBOM generation (CycloneDX via Trivy) and download
- Prometheus-compatible metrics endpoint
- Terraform IaC for Supabase + Vercel provisioning
- Full OWASP 2025 Top 10 mitigations documented, implemented, and tested
- Dogfooding: Sentinel CI secures its own codebase

### 11.2 Out of Scope for MVP — Future Releases

- GitLab or Bitbucket integration (GitHub only in MVP)
- AI-powered remediation suggestions (planned for v2)
- Slack or Teams notifications (generic webhooks only in MVP)
- Multi-organization support (single GitHub account in MVP)
- Self-hosted deployment guide (Vercel + Supabase only in MVP)
- SARIF upload from external scanners not in the Action
- Mobile-optimized dashboard (desktop-first in MVP)

---

## 12. Constraints and Assumptions

### 12.1 Technical Constraints

- **No Docker on local development.** All scanner execution happens on GitHub-hosted runners.
  Local development uses mock scanner outputs for testing.
- **Vercel free tier limits:** 100GB bandwidth/month, 12 serverless function invocations/second.
  MVP traffic is expected well below these limits for up to 50 repositories.
- **Supabase free tier:** 500MB database, 2GB bandwidth. Scan results are JSON-compressed.
  Expected to stay within limits for up to 50 active repositories with daily scans.
- **OWASP ZAP DAST** requires a running target URL. For repositories without a deployed
  preview URL, the DAST step is skipped with a documented `SKIPPED` status in the scan record.

### 12.2 Assumptions

- Users have GitHub accounts and can configure webhooks on their repositories
- Target repositories use GitHub Actions (not GitLab CI or CircleCI)
- DefectDojo is deployed and accessible from Vercel egress IPs before onboarding first user
- Webhook consumer endpoints are HTTPS only; HTTP webhook targets are rejected at the API layer
- The deploying developer has Vercel and Supabase accounts and can run Terraform locally

---

## 13. Acceptance Criteria

The MVP is considered complete when all of the following criteria pass:

| ID | Criterion | Verification Method |
|----|-----------|---------------------|
| AC-01 | A developer can add `sentinel-ci` to a GitHub repo and see findings in the dashboard within 10 minutes of the first push | Manual timed walkthrough |
| AC-02 | Pipeline blocks PR merge when a known-vulnerable dependency is introduced | Automated test with intentionally vulnerable `requirements.txt` |
| AC-03 | Cross-user data access returns HTTP 403 for all repository, scan, and finding endpoints | Automated security test suite (`test_cross_user_access.py`) |
| AC-04 | All API keys are stored as Argon2id hashes — no plaintext in database | Database inspection test (`test_api_key_hashing.py`) |
| AC-05 | HMAC signature verification rejects tampered webhook payloads with HTTP 401 | Automated test with modified payload (`test_webhook_hmac.py`) |
| AC-06 | PDF report is generated and downloadable for any completed scan | Automated API test + manual visual inspection |
| AC-07 | CycloneDX SBOM is attached to every completed scan record | Automated API assertion on scan ingestion |
| AC-08 | Sentinel CI pipeline passes its own security scan (dogfooding) | CI green on main branch — observable in GitHub Actions |
| AC-09 | Prometheus metrics endpoint returns scan and API metrics | Automated assertion on `/metrics` response shape |
| AC-10 | OWASP Top 10 2025 mitigations are documented in `SECURITY.md` with test evidence for each | Manual review by reviewer against this SRS |

---

## 14. Glossary

| Term | Definition |
|------|-----------|
| **Dogfooding** | Using a product to build or test itself. Sentinel CI secures its own codebase with its own pipeline. |
| **Island Architecture** | Frontend pattern where the page is static HTML except for isolated interactive "islands" that hydrate independently with JavaScript. |
| **HMAC** | Hash-based Message Authentication Code. Used to verify that a webhook payload was sent by the expected sender and was not tampered with in transit. |
| **Argon2id** | Memory-hard password hashing algorithm recommended by OWASP for credential storage. Resistant to GPU and side-channel attacks. |
| **CycloneDX** | Open standard for Software Bill of Materials (SBOM). Supported natively by Trivy. |
| **RLS** | Row-Level Security. PostgreSQL feature that enforces per-row access policies at the database engine level, independent of application logic. |
| **Composite Action** | GitHub Actions type that allows reuse of multi-step logic across repositories without requiring a Docker container or separate runner. |
| **Fail-secure** | Design principle where a system denies access or blocks the operation when it encounters an error, rather than allowing it to proceed. |
| **Trust Boundary** | A point in the system where data crosses from one trust level to another and must be independently validated regardless of prior validation. |
| **Idempotency Key** | A unique identifier attached to a request so that retrying it produces the same result without duplicating data in the database. |
| **DefectDojo** | Open-source Application Security Posture Management (ASPM) platform that aggregates findings from multiple scanners and tracks remediation. |
| **Rego** | The policy language used by Open Policy Agent. Declarative, auditable, and language-agnostic. |
