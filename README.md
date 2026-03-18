<!--
File Purpose:
- Provide project overview, quick-start guidance, architecture, and contributor entry points.

Key Security Considerations:
- Emphasizes secure setup, secret handling, and dogfooding expectations.
- Points contributors to threat model and security policy before code changes.

OWASP 2025 Categories Addressed:
- A02, A03, A06, A08, A09
-->

# Sentinel CI

Security automation for developers who ship.

[![CI](https://img.shields.io/badge/ci-pending-lightgrey)](#)
[![Security](https://img.shields.io/badge/security-owasp%202025-blue)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](#)

## Overview
Sentinel CI is an open-source DevSecOps toolkit for GitHub workflows. It orchestrates multi-scanner security checks, blocks risky merges by severity policy, and surfaces findings in a dashboard with reporting and alerting.

## Core Capabilities
- Reusable GitHub composite action for security scanning.
- Unified finding ingestion API with strict validation.
- Supabase-backed data model with mandatory Row-Level Security.
- Dashboard for repository posture, trends, and scan details.
- DefectDojo integration for vulnerability lifecycle management.
- Dogfooding pipeline where Sentinel CI secures itself.

## Architecture (ASCII)
```text
+-----------------------+        +----------------------------+
| GitHub Repository     |        | Sentinel CI Dashboard      |
| (push / pull_request) |        | Astro + React Islands      |
+-----------+-----------+        +-------------+--------------+
            |                                  ^
            v                                  |
+-----------+----------------------------------+--------------+
|          Sentinel CI GitHub Composite Action                |
|  Semgrep | Trivy(+SBOM) | Gitleaks | Checkov | ZAP | OPA    |
+-----------+----------------------------------+--------------+
            | POST /api/scans (signed, validated)
            v
+-----------+----------------------------------+--------------+
|                  Sentinel API (FastAPI)                     |
| AuthN/AuthZ | Validation | Normalization | Alerts | Reports |
+-----------+----------------------------------+--------------+
            |
            v
+-----------+---------------------+     +---------------------+
| Supabase PostgreSQL + RLS + Auth|     | DefectDojo          |
| Vault for webhook secrets       |<--->| Product/Engagement  |
+---------------------------------+     +---------------------+
```

## Quick Start
1. Read THREAT_MODEL.md and SECURITY.md.
2. Configure required environment variables in local shell and deployment platform.
3. Add Sentinel CI action to your repository workflow.
4. Connect Supabase, Vercel, and DefectDojo according to setup docs.

## Deployment

### Dashboard (Vercel)
The Astro dashboard is configured for serverless deployment on Vercel with security headers and middleware.

**Prerequisites:**
- Supabase project with authentication configured
- Environment variables set in Vercel project settings

**Environment Variables (Dashboard):**
```
PUBLIC_SENTINEL_API_ENDPOINT=https://api.yourdomain.com
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
```

**Deploy Steps:**
```bash
# Local build preview
cd dashboard && npm install && npm run build

# Push to GitHub, connect to Vercel
# Vercel will auto-detect astro.config.mjs and build dashboard/
# Set environment variables in Vercel dashboard settings
```

**Build Output:** `dashboard/.vercel/output/static`

### API (FastAPI)
Deployed separately as backend service (to cloud platform of choice: Render, Railway, AWS, etc.)

**Environment Variables (API):**
```
SUPABASE_URL=...
SUPABASE_SERVICE_KEY=...
JWT_SECRET=...
VERCEL_URL=https://dashboard.vercel.app  # CORS origin
```

See [SETUP.md](docs/SETUP.md) for complete backend deployment guide.

## Project Status
**Phase 0 - Foundation:** Core dependencies updated via Dependabot integration.
**Phase 1 - Ready:** Dashboard frontend, API backend, Supabase migrations, GitHub Action.
Deployment to production pending environment provisioning.
