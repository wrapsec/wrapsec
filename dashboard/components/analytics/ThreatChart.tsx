"use client"

import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell
} from "recharts"
import { Card, CardHeader } from "@/components/ui/Card"
import { ThreatCount } from "@/lib/types"
import { formatThreat } from "@/lib/utils"
import { CHART_COLORS } from "@/lib/constants"

export function ThreatChart({ threats }: { threats: ThreatCount[] }) {
  const data = threats.map((t) => ({
    name:  formatThreat(t.category),
    count: t.count,
  }))

  return (
    <Card>
      <CardHeader title="Threat Distribution" />
      {data.length === 0 ? (
        <p className="text-sm text-slate-400">No threats detected</p>
      ) : (
        <div className="h-52">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fontSize: 11 }}
                width={120}
              />
              <Tooltip
                contentStyle={{
                  fontSize:     12,
                  border:       "1px solid #e2e8f0",
                  borderRadius: 6,
                  boxShadow:    "none",
                }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {data.map((_, i) => (
                  <Cell key={i} fill="#1e40af" />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  )
}