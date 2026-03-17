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
4. Connect Supabase, Vercel, and DefectDojo according to setup docs (added in later phases).

## Project Status
This repository currently contains Phase 0 foundation artifacts. Implementation of API, action internals, database migrations, and dashboard follows phased delivery.
