-- File Purpose:
-- - Seed local development data for Sentinel CI schema validation and integration testing.
--
-- Key Security Considerations:
-- - Uses non-sensitive synthetic data only.
-- - Inserts are conditioned on existing auth users to avoid accidental privilege assumptions.
--
-- OWASP 2025 Categories Addressed:
-- - A01, A02, A08

WITH existing_user AS (
  SELECT id
  FROM auth.users
  ORDER BY created_at ASC
  LIMIT 1
),
inserted_profile AS (
  INSERT INTO public.users (id, github_user_id, github_username, avatar_url, email, display_name)
  SELECT
    id,
    1000001,
    'sentinel-dev-user',
    'https://avatars.githubusercontent.com/u/1000001',
    'dev-user@example.com',
    'Sentinel Dev User'
  FROM existing_user
  ON CONFLICT (id) DO NOTHING
  RETURNING id
),
selected_owner AS (
  SELECT id FROM inserted_profile
  UNION ALL
  SELECT id FROM existing_user
  LIMIT 1
),
inserted_repo AS (
  INSERT INTO public.repositories (owner_id, full_name, default_branch, active)
  SELECT id, 'example/sentinel-demo', 'main', TRUE
  FROM selected_owner
  ON CONFLICT (owner_id, full_name) DO UPDATE SET active = EXCLUDED.active
  RETURNING id
),
selected_repo AS (
  SELECT id FROM inserted_repo
  UNION ALL
  SELECT r.id
  FROM public.repositories r
  JOIN selected_owner o ON o.id = r.owner_id
  WHERE r.full_name = 'example/sentinel-demo'
  LIMIT 1
),
inserted_scan AS (
  INSERT INTO public.scans (
    repository_id,
    commit_sha,
    branch,
    trigger_event,
    status,
    scanner_versions,
    duration_ms,
    findings_count,
    critical_count
  )
  SELECT
    id,
    '1111111111111111111111111111111111111111',
    'main',
    'push',
    'COMPLETED',
    '{"semgrep":"1.62.0","trivy":"0.56.0"}'::jsonb,
    84231,
    1,
    0
  FROM selected_repo
  RETURNING id
),
selected_scan AS (
  SELECT id FROM inserted_scan
  LIMIT 1
)
INSERT INTO public.findings (
  scan_id,
  scanner,
  severity,
  title,
  description,
  file_path,
  line_start,
  line_end,
  cve_id,
  cwe_id,
  remediation,
  false_positive,
  status,
  idempotency_key
)
SELECT
  id,
  'semgrep',
  'MEDIUM',
  'Insecure subprocess invocation',
  'Potential command injection vector due to unsanitized subprocess input.',
  'api/routes/scans.py',
  42,
  42,
  NULL,
  'CWE-78',
  'Validate and sanitize untrusted input before command execution.',
  FALSE,
  'OPEN',
  encode(digest('seed-scan-semgrep-api/routes/scans.py-42', 'sha256'), 'hex')
FROM selected_scan
ON CONFLICT (idempotency_key) DO NOTHING;
