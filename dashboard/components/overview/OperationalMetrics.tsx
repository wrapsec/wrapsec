// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { formatRate, formatLatency } from "@/lib/utils"
import { AuditStatsResponse } from "@/lib/types"

export function OperationalMetrics({ stats }: { stats: AuditStatsResponse }) {
  const metrics = [
    { label: "Block rate",     value: formatRate(stats.block_rate),     color: "#dc2626" },
    { label: "Sanitize rate",  value: formatRate(stats.sanitize_rate),  color: "#d97706" },
    { label: "Allow rate",     value: formatRate(stats.allow_rate),     color: "#16a34a" },
    { label: "Avg latency",    value: formatLatency(stats.avg_latency_ms), color: "#670FEF" },
    { label: "P95 latency",    value: formatLatency(stats.p95_latency_ms), color: "#374151" },
  ]

  return (
    <div style={{
      background: "#fff", border: "1px solid #e5e7eb",
      borderRadius: "8px", padding: "18px 20px",
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>Operational metrics</h3>
        <span style={{ fontSize: "11px", color: "#9ca3af" }}>All time</span>
      </div>
      <div style={{ display: "flex", gap: "0" }}>
        {metrics.map((m, i) => (
          <div key={m.label} style={{
            flex: 1,
            padding: "0 16px",
            borderLeft: i > 0 ? "1px solid #f3f4f6" : "none",
          }}>
            <p style={{ fontSize: "10px", fontWeight: 600, color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.07em", margin: "0 0 6px 0" }}>
              {m.label}
            </p>
            <p style={{ fontSize: "18px", fontWeight: 700, color: m.color, margin: 0, lineHeight: 1 }}>
              {m.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}
