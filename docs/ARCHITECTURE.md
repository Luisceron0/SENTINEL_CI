<!--
File Purpose:
- Document final Sentinel CI architecture, data flow, and trust boundaries.

Key Security Considerations:
- Captures enforcement points for authn/authz, signature validation, and RLS.

OWASP 2025 Categories Addressed:
- A01, A02, A06, A08, A10
-->

# Sentinel CI Architecture

## System Layers
1. GitHub Action Orchestration Layer.
2. Scan Engine Layer (Semgrep, Trivy, Gitleaks, Checkov, ZAP, OPA).
3. Backend API Layer (FastAPI on Vercel serverless).
4. Data/Auth Layer (Supabase PostgreSQL + Auth + RLS + Vault).
5. Dashboard Layer (Astro SSR + React islands).

## Runtime Data Flow
```text
GitHub Events
  -> Sentinel Composite Action
  -> Scanner Outputs in results/*.json
  -> action/aggregate.py normalization + gate
  -> POST /api/scans (API key auth)
  -> FastAPI validation + ownership checks
  -> Supabase writes (RLS constrained)
  -> DefectDojo import
  -> Dashboard SSR/API consumption
  -> Signed outbound webhook alerts
```

## Trust Boundaries
1. GitHub -> API: HMAC verification before processing.
2. User/CI -> API: JWT/API-key auth + rate limit.
3. API -> DB: Supabase SDK only + RLS policy enforcement.
4. API -> DefectDojo/Webhooks: HTTPS only, typed error sanitization.

## Security Controls by Layer
- Action: fail-secure on scanner failure/timeout; severity gate blocks merge.
- API: strict Pydantic validation, global exception sanitizer, structured logs.
- DB: owner-access RLS policies on all tables.
- Dashboard: CSP + anti-clickjacking headers + auth middleware.

## Deployment Topology
- Frontend/API: Vercel.
- Database/Auth/Vault: Supabase.
- CI/CD: GitHub Actions dogfooding pipeline.
- IaC: Terraform for platform provisioning references.
