-- File Purpose:
-- - Provision Supabase Vault usage pattern for per-repository webhook secret storage.
--
-- Key Security Considerations:
-- - Stores webhook secrets in Vault and only keeps secret references in application tables.
-- - Restricts direct exposure of secret material to privileged database access only.
--
-- OWASP 2025 Categories Addressed:
-- - A02, A04, A08

CREATE SCHEMA IF NOT EXISTS vault;

-- SECURITY: Supabase Vault extension ownership is managed by the platform.
-- SECURITY: We define helper functions that return only a secret reference UUID.

CREATE OR REPLACE FUNCTION public.create_webhook_secret(secret_plaintext TEXT)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  secret_ref UUID;
BEGIN
  IF secret_plaintext IS NULL OR length(secret_plaintext) < 16 THEN
    RAISE EXCEPTION 'webhook secret must be at least 16 characters';
  END IF;

  SELECT vault.create_secret(secret_plaintext, 'sentinel webhook secret') INTO secret_ref;
  RETURN secret_ref;
END;
$$;

REVOKE ALL ON FUNCTION public.create_webhook_secret(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_webhook_secret(TEXT) TO authenticated;

CREATE OR REPLACE FUNCTION public.read_webhook_secret(secret_ref UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  secret_plaintext TEXT;
BEGIN
  SELECT decrypted_secret
  INTO secret_plaintext
  FROM vault.decrypted_secrets
  WHERE id = secret_ref;

  RETURN secret_plaintext;
END;
$$;

REVOKE ALL ON FUNCTION public.read_webhook_secret(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.read_webhook_secret(UUID) TO service_role;
