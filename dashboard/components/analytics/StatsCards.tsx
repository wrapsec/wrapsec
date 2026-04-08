import { Card } from "@/components/ui/Card"
import { AuditStatsResponse } from "@/lib/types"
import { formatRate, formatLatency } from "@/lib/utils"

export function StatsCards({ stats }: { stats: AuditStatsResponse }) {
  const cards = [
    { label: "Total Requests",  value: stats.total_requests.toLocaleString() },
    { label: "Block Rate",      value: formatRate(stats.block_rate) },
    { label: "Sanitize Rate",   value: formatRate(stats.sanitize_rate) },
    { label: "Allow Rate",      value: formatRate(stats.allow_rate) },
    { label: "Avg Latency",     value: formatLatency(stats.avg_latency_ms) },
    { label: "P95 Latency",     value: formatLatency(stats.p95_latency_ms) },
  ]

  return (
    <div className="grid grid-cols-3 gap-4">
      {cards.map((c) => (
        <Card key={c.label}>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-1">
            {c.label}
          </p>
          <p className="text-2xl font-bold text-slate-900">{c.value}</p>
        </Card>
      ))}
    </div>
  )
}