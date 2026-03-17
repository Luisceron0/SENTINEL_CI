<!--
File Purpose:
- Provide end-to-end setup instructions for GitHub OAuth, Supabase, Vercel, and DefectDojo integration.

Key Security Considerations:
- Ensures secret values are provisioned through env managers only.

OWASP 2025 Categories Addressed:
- A02, A03, A07, A08
-->

# Setup Guide

## 1. Prerequisites
1. GitHub repository admin access.
2. Supabase project and organization.
3. Vercel account/project.
4. DefectDojo instance/API token.
5. Python 3.12 and Node.js installed.

## 2. Configure Environment Variables
Use [.env.example](../.env.example) as reference only.

Required values:
1. SUPABASE_URL
2. SUPABASE_ANON_KEY
3. SUPABASE_SERVICE_ROLE_KEY
4. GITHUB_OAUTH_CLIENT_ID
5. GITHUB_OAUTH_CLIENT_SECRET
6. DEFECTDOJO_URL
7. DEFECTDOJO_API_KEY
8. SENTINEL_WEBHOOK_SECRET
9. NEXT_PUBLIC_DASHBOARD_URL
10. SENTINEL_JWT_SECRET
11. SENTINEL_API_ENDPOINT

## 3. Supabase
1. Apply SQL migrations in order from supabase/migrations.
2. Confirm RLS is enabled on all tables.
3. Verify Vault helper functions exist.

## 4. GitHub OAuth
1. Create GitHub OAuth app.
2. Callback URL: https://<dashboard-domain>/auth/callback
3. Store client id/secret in deployment secrets.

## 5. Vercel
1. Link project with repository.
2. Add required environment variables in Vercel project settings.
3. Enable production deploys on main.

## 6. DefectDojo
1. Create product-per-repository model.
2. Generate API token.
3. Set DEFECTDOJO_URL and DEFECTDOJO_API_KEY.

## 7. Local Validation
1. ruff check api/
2. mypy api/
3. pytest tests/
4. bash tests/action/test_scripts_exist.sh
5. bash tests/action/test_aggregate_contract.sh
