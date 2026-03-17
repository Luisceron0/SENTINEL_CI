/*
File Purpose:
- Interactive sortable/filterable table for scan findings.

Key Security Considerations:
- Escaped text rendering only; no dangerouslySetInnerHTML usage.

OWASP 2025 Categories Addressed:
- A05
*/

import { useMemo, useState } from "react";

type Finding = {
  scanner: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  file_path?: string | null;
  line_start?: number | null;
  status?: string;
};

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState("ALL");

  const rows = useMemo(() => {
    const filtered = filter === "ALL" ? findings : findings.filter((f) => f.severity === filter);
    return filtered.slice().sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  }, [filter, findings]);

  return (
    <div>
      <div style={{ marginBottom: 10 }}>
        <label htmlFor="severityFilter">Severity:</label>
        <select id="severityFilter" value={filter} onChange={(e: any) => setFilter(e.target.value)}>
          <option value="ALL">All</option>
          {ORDER.map((sev) => (
            <option key={sev} value={sev}>{sev}</option>
          ))}
        </select>
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Scanner</th>
            <th>Title</th>
            <th>Location</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((finding: Finding, idx: number) => (
            <tr key={`${finding.scanner}-${finding.title}-${idx}`}>
              <td>{finding.severity}</td>
              <td>{finding.scanner}</td>
              <td>{finding.title}</td>
              <td>{finding.file_path ?? "-"}{finding.line_start ? `:${finding.line_start}` : ""}</td>
              <td>{finding.status ?? "OPEN"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
