/*
File Purpose:
- Provide typed API client wrappers for Sentinel backend endpoints consumed by Astro pages and islands.

Key Security Considerations:
- Uses explicit endpoint allowlist and credentialed requests only to configured API origin.
- Sanitizes error surfaces and never logs sensitive tokens.

OWASP 2025 Categories Addressed:
- A01, A05, A10
*/

export type RepositorySummary = {
  id: string;
  full_name: string;
  default_branch: string;
  created_at: string;
};

export type Finding = {
  id?: string;
  scanner: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  file_path?: string | null;
  line_start?: number | null;
  status?: "OPEN" | "IN_PROGRESS" | "RESOLVED" | "ACCEPTED";
};

export type ScanDetail = {
  id: string;
  repository_id: string;
  status: string;
  findings_count: number;
  critical_count: number;
  findings: Finding[];
};

export type ApiKeyRecord = {
  id: string;
  prefix: string;
  key: string;
};

const API_BASE = import.meta.env.SENTINEL_API_ENDPOINT ?? import.meta.env.PUBLIC_SENTINEL_API_ENDPOINT ?? "";

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  if (!API_BASE) {
    throw new Error("missing_api_endpoint");
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error(`api_error_${response.status}`);
  }

  return (await response.json()) as T;
}

export function listRepositories(): Promise<RepositorySummary[]> {
  return apiRequest<RepositorySummary[]>("/repositories");
}

export function listRepositoryScans(repositoryId: string): Promise<ScanDetail[]> {
  return apiRequest<ScanDetail[]>(`/repositories/${repositoryId}/scans`);
}

export function getScan(scanId: string): Promise<ScanDetail> {
  return apiRequest<ScanDetail>(`/scans/${scanId}`);
}

export function createApiKey(): Promise<ApiKeyRecord> {
  return apiRequest<ApiKeyRecord>("/keys", { method: "POST" });
}

export function revokeApiKey(keyId: string): Promise<void> {
  return apiRequest<void>(`/keys/${keyId}`, { method: "DELETE" });
}

export async function createWebhook(repositoryId: string, url: string, minimumSeverity: string): Promise<void> {
  await apiRequest("/webhooks", {
    method: "POST",
    body: JSON.stringify({ repository_id: repositoryId, url, minimum_severity: minimumSeverity }),
  });
}
