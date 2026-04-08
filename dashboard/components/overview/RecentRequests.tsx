import { Card, CardHeader } from "@/components/ui/Card"
import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { AuditLogItem } from "@/lib/types"
import { timeAgo, formatLatency, formatScore } from "@/lib/utils"

interface RecentRequestsProps {
  items: AuditLogItem[]
}

export function RecentRequests({ items }: RecentRequestsProps) {
  return (
    <Card padding={false}>
      <div className="px-5 py-4 border-b border-slate-100">
        <CardHeader title="Recent Requests" />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50">
              <th className="text-left px-5 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">Trace ID</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">Decision</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">Score</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">Threats</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">Latency</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">Time</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-5 py-8 text-center text-sm text-slate-400">
                  No requests yet
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <tr key={item.trace_id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3 font-mono text-xs text-slate-600">
                    {item.trace_id}
                  </td>
                  <td className="px-4 py-3">
                    <DecisionBadge decision={item.decision} size="sm" />
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600">
                    {formatScore(item.risk_score)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {item.threats.length === 0 ? (
                        <span className="text-xs text-slate-400">—</span>
                      ) : (
                        item.threats.slice(0, 2).map((t) => (
                          <ThreatBadge key={t} threat={t} />
                        ))
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600">
                    {formatLatency(item.latency_ms)}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {timeAgo(item.timestamp)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Card>
  )
}