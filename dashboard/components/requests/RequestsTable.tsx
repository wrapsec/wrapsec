// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { AuditLogItem } from "@/lib/types"
import { timeAgo, formatLatency } from "@/lib/utils"

function ModeBadge({ label, active }: { label: string; active: boolean }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: "4px",
      fontSize: "11px", fontWeight: 500,
      border: active ? "1px solid rgba(103,15,239,0.20)" : "1px solid #e5e7eb",
      background: active ? "rgba(103,15,239,0.06)" : "#f9fafb",
      color: active ? "#670FEF" : "#6b7280",
    }}>
      {label}
    </span>
  )
}

const SEVERITY_STYLE: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: "#dc2626", bg: "rgba(220,38,38,0.08)",  border: "rgba(220,38,38,0.20)"  },
  HIGH:     { color: "#d97706", bg: "rgba(217,119,6,0.08)",  border: "rgba(217,119,6,0.20)"  },
  MEDIUM:   { color: "#2563eb", bg: "rgba(37,99,235,0.08)",  border: "rgba(37,99,235,0.20)"  },
  LOW:      { color: "#6b7280", bg: "rgba(107,114,128,0.08)", border: "rgba(107,114,128,0.20)" },
}

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span style={{ fontSize: "12px", color: "#d1d5db" }}>-</span>
  const s = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.LOW
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: "4px",
      fontSize: "11px", fontWeight: 600,
      background: s.bg, border: `1px solid ${s.border}`, color: s.color,
    }}>
      {severity}
    </span>
  )
}

const TH: React.CSSProperties = {
  textAlign: "left", padding: "10px 16px",
  fontSize: "10px", fontWeight: 700,
  color: "#9ca3af", textTransform: "uppercase",
  letterSpacing: "0.07em", whiteSpace: "nowrap",
  borderBottom: "1px solid #f3f4f6",
  background: "#fafafa",
}

const HEADERS = [
  "Trace ID", "Severity", "Decision", "Dept / App",
  "Threats", "Detection", "Execution", "Latency", "Time",
]

export function RequestsTable({ items, onSelect }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            {HEADERS.map(h => <th key={h} style={TH}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {items.length === 0 ? (
            <tr>
              <td colSpan={HEADERS.length} style={{ padding: "56px 16px", textAlign: "center" }}>
                <div style={{ fontSize: "20px", marginBottom: "8px" }}></div>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "#374151", marginBottom: "4px" }}>No requests found</div>
                <div style={{ fontSize: "12px", color: "#9ca3af" }}>Try adjusting your filters or expanding the time range</div>
              </td>
            </tr>
          ) : items.map((item, i) => (
            <tr
              key={item.trace_id}
              onClick={() => onSelect(item.trace_id)}
              style={{
                cursor: "pointer",
                borderBottom: i < items.length - 1 ? "1px solid #f9fafb" : "none",
              }}
              onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "rgba(103,15,239,0.03)"}
              onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
            >
              <td style={{ padding: "10px 16px", fontFamily: "monospace", fontSize: "12px", color: "#6b7280", whiteSpace: "nowrap" }}>
                {item.trace_id}
              </td>
              <td style={{ padding: "10px 16px" }}>
                <SeverityBadge severity={item.severity} />
              </td>
              <td style={{ padding: "10px 16px" }}>
                {item.output_decision && item.output_decision !== item.decision ? (
                  <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    <DecisionBadge decision={item.decision} size="sm" />
                    <span style={{ fontSize: "10px", color: "#9ca3af" }}>-></span>
                    <DecisionBadge decision={item.output_decision} size="sm" />
                  </div>
                ) : (
                  <DecisionBadge decision={item.decision} size="sm" />
                )}
              </td>
              <td style={{ padding: "10px 16px" }}>
                {(item.dept_name || item.app_name) ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: "1px" }}>
                    {item.dept_name && (
                      <span style={{ fontSize: "12px", color: "#374151", fontWeight: 500 }}>
                        {item.dept_name}
                      </span>
                    )}
                    {item.app_name && (
                      <span style={{ fontSize: "11px", color: "#9ca3af" }}>
                        {item.app_name}
                      </span>
                    )}
                  </div>
                ) : (
                  <span style={{ fontSize: "12px", color: "#d1d5db" }}>-</span>
                )}
              </td>
              <td style={{ padding: "10px 16px" }}>
                {item.threats.length === 0
                  ? <span style={{ fontSize: "12px", color: "#d1d5db" }}>-</span>
                  : <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
                      {item.threats.map(t => <ThreatBadge key={t} threat={t} />)}
                    </div>
                }
              </td>
              <td style={{ padding: "10px 16px" }}>
                <ModeBadge label={item.detection_mode === "full" ? "full" : "fast"} active={item.detection_mode === "full"} />
              </td>
              <td style={{ padding: "10px 16px" }}>
                <ModeBadge label={item.execution_mode === "proxy" ? "proxy" : "scan"} active={item.execution_mode === "proxy"} />
              </td>
              <td style={{ padding: "10px 16px", fontSize: "12px", color: "#6b7280", whiteSpace: "nowrap", fontVariantNumeric: "tabular-nums" }}>
                {formatLatency(item.latency_ms)}
              </td>
              <td style={{ padding: "10px 16px", fontSize: "12px", color: "#9ca3af", whiteSpace: "nowrap" }}>
                {timeAgo(item.timestamp)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
