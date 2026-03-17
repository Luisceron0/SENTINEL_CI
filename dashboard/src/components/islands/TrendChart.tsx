/*
File Purpose:
- Interactive trend chart for CRITICAL/HIGH findings over time.

Key Security Considerations:
- Renders typed numeric data without unsafe client-side templating.

OWASP 2025 Categories Addressed:
- A05
*/

import { Line, LineChart, ResponsiveContainer, CartesianGrid, Tooltip, XAxis, YAxis } from "recharts";

type TrendPoint = {
  label: string;
  critical: number;
  high: number;
};

export default function TrendChart({ points }: { points: TrendPoint[] }) {
  return (
    <div style={{ width: "100%", height: 300 }}>
      <ResponsiveContainer>
        <LineChart data={points}>
          <CartesianGrid stroke="#30363D" strokeDasharray="4 4" />
          <XAxis dataKey="label" stroke="#8B949E" />
          <YAxis stroke="#8B949E" />
          <Tooltip />
          <Line type="monotone" dataKey="critical" stroke="#FF4444" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="high" stroke="#FF8800" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
