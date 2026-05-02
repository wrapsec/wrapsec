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

const TH: React.CSSProperties = {
  textAlign: "left", padding: "10px 16px",
  fontSize: "10px", fontWeight: 700,
  color: "#9ca3af", textTransform: "uppercase",
  letterSpacing: "0.07em", whiteSpace: "nowrap",
  borderBottom: "1px solid #f3f4f6",
  background: "#fafafa",
}

export function RequestsTable({ items, onSelect }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            {["Trace ID", "Decision", "Threats", "Detection", "Execution", "Latency", "Time"].map(h => (
              <th key={h} style={TH}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.length === 0 ? (
            <tr>
              <td colSpan={7} style={{ padding: "48px 16px", textAlign: "center", fontSize: "13px", color: "#9ca3af" }}>
                No requests found
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
                <DecisionBadge decision={item.decision} size="sm" />
              </td>
              <td style={{ padding: "10px 16px" }}>
                {item.threats.length === 0
                  ? <span style={{ fontSize: "12px", color: "#d1d5db" }}>—</span>
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
