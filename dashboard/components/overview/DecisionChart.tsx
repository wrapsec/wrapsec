// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts"
import { Card, CardHeader } from "@/components/ui/Card"
import { CHART_COLORS } from "@/lib/constants"
import { formatRate } from "@/lib/format"

interface DecisionChartProps {
  blockRate:    number
  sanitizeRate: number
  allowRate:    number
  total:        number
}

export function DecisionChart({
  blockRate,
  sanitizeRate,
  allowRate,
  total,
}: DecisionChartProps) {
  const t = useTranslations("pages.overview")
  const data = [
    { name: "BLOCK",    value: Math.round(blockRate * total),    color: CHART_COLORS.BLOCK },
    { name: "SANITIZE", value: Math.round(sanitizeRate * total), color: CHART_COLORS.SANITIZE },
    { name: "ALLOW",    value: Math.round(allowRate * total),    color: CHART_COLORS.ALLOW },
  ].filter((d) => d.value > 0)

  return (
    <Card>
      <CardHeader title={t("decision_distribution")} />
      <div className="flex items-center gap-6">
        <div className="h-36 w-36 flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={36}
                outerRadius={60}
                dataKey="value"
                strokeWidth={0}
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                formatter={(value: any, name: any) => [value, name]}
                contentStyle={{
                  fontSize:     12,
                  border:       "1px solid #e2e8f0",
                  borderRadius: 6,
                  boxShadow:    "none",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="flex flex-col gap-2.5">
          {[
            { label: "BLOCK",    rate: blockRate,    color: CHART_COLORS.BLOCK },
            { label: "SANITIZE", rate: sanitizeRate, color: CHART_COLORS.SANITIZE },
            { label: "ALLOW",    rate: allowRate,    color: CHART_COLORS.ALLOW },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-2">
              <span
                className="h-2.5 w-2.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-xs text-slate-600 w-16">{item.label}</span>
              <span className="text-xs font-semibold text-slate-900">
                {formatRate(item.rate)}
              </span>
            </div>
          ))}
        </div>
      </div>
    </Card>
  )
}