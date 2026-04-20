import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { AuditLogItem } from "@/lib/types"
import { timeAgo, formatLatency } from "@/lib/utils"

interface RequestsTableProps {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}

function DetectionBadge({ mode }: { mode: string }) {
  const isFull = mode === "full"
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "2px 6px",
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 500,
      border: isFull ? "1px solid #fde68a" : "1px solid #e2e8f0",
      backgroundColor: isFull ? "#fffbeb" : "#f8fafc",
      color: isFull ? "#92400e" : "#475569",
    }}>
      {isFull ? "full" : "fast"}
    </span>
  )
}

function ExecutionBadge({ mode }: { mode: string }) {
  const isProxy = mode === "proxy"
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "2px 6px",
      borderRadius: "4px",
      fontSize: "11px",
      fontWeight: 500,
      border: isProxy ? "1px solid #ddd6fe" : "1px solid #e2e8f0",
      backgroundColor: isProxy ? "#f5f3ff" : "#f8fafc",
      color: isProxy ? "#6d28d9" : "#64748b",
    }}>
      {isProxy ? "proxy" : "scan"}
    </span>
  )
}

const HEADERS = ["Trace ID", "Decision", "Threats", "Detection", "Execution", "Latency", "Time"]

export function RequestsTable({ items, onSelect }: RequestsTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-100 bg-slate-50">
            {HEADERS.map((h) => (
              <th
                key={h}
                className="text-left px-5 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide whitespace-nowrap"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.length === 0 ? (
            <tr>
              <td colSpan={HEADERS.length} className="px-5 py-12 text-center text-sm text-slate-400">
                No requests found
              </td>
            </tr>
          ) : (
            items.map((item) => (
              <tr
                key={item.trace_id}
                className="border-b border-slate-50 hover:bg-slate-50 transition-colors cursor-pointer"
                onClick={() => onSelect(item.trace_id)}
              >
                <td className="px-5 py-3 font-mono text-xs text-slate-600 whitespace-nowrap">
                  {item.trace_id}
                </td>
                <td className="px-5 py-3">
                  <DecisionBadge decision={item.decision} size="sm" />
                </td>
                <td className="px-5 py-3">
                  <div className="flex flex-wrap gap-1">
                    {item.threats.length === 0 ? (
                      <span className="text-xs text-slate-400">--</span>
                    ) : (
                      item.threats.map((t) => <ThreatBadge key={t} threat={t} />)
                    )}
                  </div>
                </td>
                <td className="px-5 py-3">
                  <DetectionBadge mode={item.detection_mode} />
                </td>
                <td className="px-5 py-3">
                  <ExecutionBadge mode={item.execution_mode} />
                </td>
                <td className="px-5 py-3 text-xs text-slate-600 whitespace-nowrap">
                  {formatLatency(item.latency_ms)}
                </td>
                <td className="px-5 py-3 text-xs text-slate-400 whitespace-nowrap">
                  {timeAgo(item.timestamp)}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
