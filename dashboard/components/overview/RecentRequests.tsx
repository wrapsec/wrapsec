import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { AuditLogItem } from "@/lib/types"
import { timeAgo, formatLatency, formatScore } from "@/lib/utils"

const SEVERITY_STYLE: Record<string, React.CSSProperties> = {
  CRITICAL: { color: "#dc2626", background: "#fef2f2", border: "1px solid #fecaca" },
  HIGH:     { color: "#d97706", background: "#fffbeb", border: "1px solid #fde68a" },
  MEDIUM:   { color: "#0369a1", background: "#eff6ff", border: "1px solid #bfdbfe" },
  LOW:      { color: "#059669", background: "#f0fdf4", border: "1px solid #bbf7d0" },
}

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span style={{ color: "#d1d5db", fontSize: "12px" }}>—</span>
  const s = SEVERITY_STYLE[severity] ?? { color: "#6b7280", background: "#f9fafb", border: "1px solid #e5e7eb" }
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: "4px",
      fontSize: "11px", fontWeight: 600, ...s,
    }}>
      {severity}
    </span>
  )
}

const TH: React.CSSProperties = {
  textAlign: "left", padding: "10px 16px",
  fontSize: "10px", fontWeight: 700, color: "#9ca3af",
  textTransform: "uppercase", letterSpacing: "0.07em",
  whiteSpace: "nowrap", borderBottom: "1px solid #f3f4f6",
  background: "#fafafa",
}

export function RecentRequests({ items, onSelect }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}) {
  return (
    <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: "8px", overflow: "hidden" }}>
      <div style={{
        padding: "14px 20px", borderBottom: "1px solid #f3f4f6",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>Recent requests</h3>
        <span style={{ fontSize: "11px", color: "#9ca3af" }}>Last 10 · live</span>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              {["Trace ID", "Decision", "Severity", "Score", "Threats", "Latency", "Time"].map(h => (
                <th key={h} style={TH}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: "40px", textAlign: "center", fontSize: "13px", color: "#9ca3af" }}>
                  No requests yet
                </td>
              </tr>
            ) : items.map((item, i) => (
              <tr
                key={item.trace_id}
                onClick={() => onSelect(item.trace_id)}
                style={{ cursor: "pointer", borderBottom: i < items.length - 1 ? "1px solid #f9fafb" : "none" }}
                onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "rgba(103,15,239,0.03)"}
                onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
              >
                <td style={{ padding: "10px 16px", fontFamily: "monospace", fontSize: "12px", color: "#6b7280" }}>
                  {item.trace_id}
                </td>
                <td style={{ padding: "10px 16px" }}>
                  <DecisionBadge decision={item.decision} size="sm" />
                </td>
                <td style={{ padding: "10px 16px" }}>
                  <SeverityBadge severity={(item as any).severity ?? null} />
                </td>
                <td style={{ padding: "10px 16px", fontSize: "12px", color: "#6b7280", fontVariantNumeric: "tabular-nums" }}>
                  {formatScore(item.risk_score)}
                </td>
                <td style={{ padding: "10px 16px" }}>
                  {item.threats.length === 0
                    ? <span style={{ fontSize: "12px", color: "#d1d5db" }}>—</span>
                    : <div style={{ display: "flex", gap: "3px", flexWrap: "wrap" }}>
                        {item.threats.slice(0, 2).map(t => <ThreatBadge key={t} threat={t} />)}
                      </div>
                  }
                </td>
                <td style={{ padding: "10px 16px", fontSize: "12px", color: "#6b7280", fontVariantNumeric: "tabular-nums" }}>
                  {formatLatency(item.latency_ms)}
                </td>
                <td style={{ padding: "10px 16px", fontSize: "12px", color: "#9ca3af" }}>
                  {timeAgo(item.timestamp)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
