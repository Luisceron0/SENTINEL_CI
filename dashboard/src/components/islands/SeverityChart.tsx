/*
File Purpose:
- Interactive severity distribution chart for scan findings.

Key Security Considerations:
- Consumes prevalidated structured data and avoids dynamic HTML injection.

OWASP 2025 Categories Addressed:
- A05
*/

import { Pie, PieChart, Cell, ResponsiveContainer, Tooltip } from "recharts";

type SeverityRow = {
  name: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  value: number;
};

const COLORS: Record<SeverityRow["name"], string> = {
  CRITICAL: "#FF4444",
  HIGH: "#FF8800",
  MEDIUM: "#FFCC00",
  LOW: "#44BB44",
  INFO: "#888888",
};

export default function SeverityChart({ data }: { data: SeverityRow[] }) {
  return (
    <div style={{ width: "100%", height: 280 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={95}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
