// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { KpiCard } from "@/components/ui/KpiCard"
import { AuditStatsResponse } from "@/lib/types"
import { formatNumber, formatCompact, formatRate, formatScore } from "@/lib/format"

// Posture-at-a-glance strip above the filtered event list. Unlike the global
// Overview page, this is scoped to the SAME filters as the table so its counts
// match the rows below, and it adds two per-filter aggregates the Overview does
// not: block rate and average risk. Severity is intentionally NOT shown here --
// it is a re-encoding of the decision axis and already lives on the Overview
// page (and per-row in the table), so repeating it as an aggregate bar next to
// the decision cards only reads as a second, competing breakdown.

function riskColor(score: number): string {
  return score >= 0.7 ? "#dc2626" : score >= 0.4 ? "#d97706" : "#16a34a"
}

// Compact count so large values never overflow the fixed-width card; the exact
// comma-grouped value is available on hover.
function Count({ n }: { n: number }) {
  return <span title={formatNumber(n)}>{formatCompact(n)}</span>
}

export function SecurityOverview({ stats, loading }: {
  stats?:   AuditStatsResponse
  loading?: boolean
}) {
  if (!stats) return loading ? <OverviewSkeleton /> : null
  const s = stats
  return (
    <div className="flex flex-col gap-2">
      <span className="text-[11px] text-slate-400">Scoped to current filters</span>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard label="Requests"     value={<Count n={s.total_requests} />} accent="#670FEF" />
        <KpiCard label="Allowed"      value={<Count n={s.allow_count} />}    valueColor="#16a34a" accent="#16a34a" sub={formatRate(s.allow_rate)} />
        <KpiCard label="Sanitized"    value={<Count n={s.sanitize_count} />} valueColor="#d97706" accent="#d97706" sub={formatRate(s.sanitize_rate)} />
        <KpiCard label="Blocked"      value={<Count n={s.block_count} />}    valueColor="#dc2626" accent="#dc2626" sub={formatRate(s.block_rate)} />
        <KpiCard label="Block Rate"   value={formatRate(s.block_rate)}       accent="#dc2626" />
        <KpiCard label="Average Risk" value={formatScore(s.avg_risk)}        valueColor={riskColor(s.avg_risk)} accent={riskColor(s.avg_risk)} />
      </div>
    </div>
  )
}

function OverviewSkeleton() {
  return (
    <div className="flex flex-col gap-2">
      <span className="text-[11px] text-slate-400">Scoped to current filters</span>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="h-[92px] rounded-lg animate-pulse"
            style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
          />
        ))}
      </div>
    </div>
  )
}
