-- File Purpose:
-- - Create initial Sentinel CI schema with all required tables, enums, and constraints.
--
-- Key Security Considerations:
-- - Defines strict FK boundaries and enum constraints to prevent invalid security states.
-- - Keeps secret material out of plain columns by storing only secret references and hashes.
--
-- OWASP 2025 Categories Addressed:
-- - A01, A04, A05, A08, A10

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE public.scan_status AS ENUM (
  'PENDING',
  'RUNNING',
  'COMPLETED',
  'FAILED',
  'TIMEOUT'
);

CREATE TYPE public.finding_severity AS ENUM (
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
);

CREATE TYPE public.finding_status AS ENUM (
  'OPEN',
  'IN_PROGRESS',
  'RESOLVED',
  'ACCEPTED'
);

CREATE TYPE public.alert_status AS ENUM (
  'SENT',
  'FAILED'
);

CREATE TABLE public.users (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  github_user_id BIGINT UNIQUE,
  github_username TEXT NOT NULL,
  avatar_url TEXT,
  email TEXT,
  display_name TEXT
);

CREATE TABLE public.repositories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (owner_id, full_name)
);

CREATE TABLE public.api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL,
  prefix CHAR(4) NOT NULL DEFAULT 'sci_',
  key_label TEXT,
  revoked_at TIMESTAMPTZ,
  CHECK (prefix = 'sci_')
);

CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  repository_id UUID NOT NULL REFERENCES public.repositories(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  branch TEXT NOT NULL,
  trigger_event TEXT NOT NULL,
  status public.scan_status NOT NULL DEFAULT 'PENDING',
  scanner_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
  duration_ms INTEGER,
  findings_count INTEGER NOT NULL DEFAULT 0,
  critical_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE public.findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  severity public.finding_severity NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  cve_id TEXT,
  cwe_id TEXT,
  remediation TEXT NOT NULL,
  false_positive BOOLEAN NOT NULL DEFAULT FALSE,
  status public.finding_status NOT NULL DEFAULT 'OPEN',
  idempotency_key TEXT UNIQUE NOT NULL
);

CREATE TABLE public.sboms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  scan_id UUID UNIQUE NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  format TEXT NOT NULL DEFAULT 'cyclonedx',
  sha256 TEXT NOT NULL,
  document JSONB NOT NULL
);

CREATE TABLE public.webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  repository_id UUID NOT NULL REFERENCES public.repositories(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret_id UUID,
  minimum_severity public.finding_severity NOT NULL DEFAULT 'HIGH',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  CHECK (position('https://' in lower(url)) = 1)
);

CREATE TABLE public.alerts_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  webhook_id UUID NOT NULL REFERENCES public.webhooks(id) ON DELETE CASCADE,
  status public.alert_status NOT NULL,
  response_code INTEGER,
  response_time_ms INTEGER,
  error_message TEXT
);
