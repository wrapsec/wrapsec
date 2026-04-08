import { Card, CardHeader } from "@/components/ui/Card"
import { ThreatCount } from "@/lib/types"
import { formatThreat } from "@/lib/utils"

interface TopThreatsProps {
  threats: ThreatCount[]
}

export function TopThreats({ threats }: TopThreatsProps) {
  const max = threats[0]?.count || 1

  return (
    <Card>
      <CardHeader title="Top Threats" />
      {threats.length === 0 ? (
        <p className="text-sm text-slate-400">No threats detected</p>
      ) : (
        <div className="space-y-3">
          {threats.map((t) => (
            <div key={t.category}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-slate-700">
                  {formatThreat(t.category)}
                </span>
                <span className="text-xs text-slate-500">{t.count}</span>
              </div>
              <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-800 rounded-full"
                  style={{ width: `${(t.count / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}