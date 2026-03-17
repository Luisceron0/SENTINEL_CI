-- File Purpose:
-- - Enable and enforce Row-Level Security policies for every Sentinel CI table.
--
-- Key Security Considerations:
-- - Applies defense-in-depth ownership controls in the database layer.
-- - Prevents cross-tenant data access even if API layer checks fail.
--
-- OWASP 2025 Categories Addressed:
-- - A01, A06, A08

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sboms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner_access" ON public.users
  FOR ALL
  USING (id = auth.uid())
  WITH CHECK (id = auth.uid());

CREATE POLICY "owner_access" ON public.repositories
  FOR ALL
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "owner_access" ON public.api_keys
  FOR ALL
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "owner_access" ON public.scans
  FOR ALL
  USING (
    EXISTS (
      SELECT 1
      FROM public.repositories r
      WHERE r.id = scans.repository_id
        AND r.owner_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM public.repositories r
      WHERE r.id = scans.repository_id
        AND r.owner_id = auth.uid()
    )
  );

CREATE POLICY "owner_access" ON public.findings
  FOR ALL
  USING (
    EXISTS (
      SELECT 1
      FROM public.scans s
      JOIN public.repositories r ON r.id = s.repository_id
      WHERE s.id = findings.scan_id
        AND r.owner_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM public.scans s
      JOIN public.repositories r ON r.id = s.repository_id
      WHERE s.id = findings.scan_id
        AND r.owner_id = auth.uid()
    )
  );

CREATE POLICY "owner_access" ON public.sboms
  FOR ALL
  USING (
    EXISTS (
      SELECT 1
      FROM public.scans s
      JOIN public.repositories r ON r.id = s.repository_id
      WHERE s.id = sboms.scan_id
        AND r.owner_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM public.scans s
      JOIN public.repositories r ON r.id = s.repository_id
      WHERE s.id = sboms.scan_id
        AND r.owner_id = auth.uid()
    )
  );

CREATE POLICY "owner_access" ON public.webhooks
  FOR ALL
  USING (
    EXISTS (
      SELECT 1
      FROM public.repositories r
      WHERE r.id = webhooks.repository_id
        AND r.owner_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM public.repositories r
      WHERE r.id = webhooks.repository_id
        AND r.owner_id = auth.uid()
    )
  );

CREATE POLICY "owner_access" ON public.alerts_log
  FOR ALL
  USING (
    EXISTS (
      SELECT 1
      FROM public.scans s
      JOIN public.repositories r ON r.id = s.repository_id
      WHERE s.id = alerts_log.scan_id
        AND r.owner_id = auth.uid()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM public.scans s
      JOIN public.repositories r ON r.id = s.repository_id
      WHERE s.id = alerts_log.scan_id
        AND r.owner_id = auth.uid()
    )
  );
