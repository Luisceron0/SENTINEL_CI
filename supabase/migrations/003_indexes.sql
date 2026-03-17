-- File Purpose:
-- - Create indexes for foreign keys and idempotency to support performance and deduplication.
--
-- Key Security Considerations:
-- - Fast ownership-scoped lookups reduce pressure on auth-sensitive endpoints.
-- - Unique idempotency index prevents duplicate finding writes during retries.
--
-- OWASP 2025 Categories Addressed:
-- - A01, A08, A10

CREATE INDEX idx_repositories_owner_id ON public.repositories(owner_id);
CREATE INDEX idx_api_keys_user_id ON public.api_keys(user_id);
CREATE INDEX idx_scans_repository_id ON public.scans(repository_id);
CREATE INDEX idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX idx_findings_idempotency_key ON public.findings(idempotency_key);
CREATE INDEX idx_sboms_scan_id ON public.sboms(scan_id);
CREATE INDEX idx_webhooks_repository_id ON public.webhooks(repository_id);
CREATE INDEX idx_alerts_log_scan_id ON public.alerts_log(scan_id);
CREATE INDEX idx_alerts_log_webhook_id ON public.alerts_log(webhook_id);
