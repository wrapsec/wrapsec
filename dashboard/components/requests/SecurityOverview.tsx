// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { KpiCard } from "@/components/ui/KpiCard"
import { AuditStatsResponse } from "@/lib/types"
import { formatNumber, formatRate, formatScore } from "@/lib/format"

// Posture-at-a-glance strip above a filtered event list. Scoped to the SAME
// filters as the table so the counts match the rows below. Kept generic
// (consumes AuditStatsResponse) so Requests / RAG / MCP / Agent surfaces reuse it.

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#d97706",
  MEDIUM:   "#2563eb",
  LOW:      "#64748b",
}
const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const

function riskColor(score: number): string {
  return score >= 0.7 ? "#dc2626" : score >= 0.4 ? "#d97706" : "#16a34a"
}

export function SecurityOverview({ stats, loading }: {
  stats?:   AuditStatsResponse
  loading?: boolean
}) {
  if (!stats) return loading ? <OverviewSkeleton /> : null
  const s = stats
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard label="Total"        value={formatNumber(s.total_requests)} />
        <KpiCard label="Allowed"      value={formatNumber(s.allow_count)}    valueColor="#16a34a" accent="#16a34a" sub={formatRate(s.allow_rate)} />
        <KpiCard label="Sanitized"    value={formatNumber(s.sanitize_count)} valueColor="#d97706" accent="#d97706" sub={formatRate(s.sanitize_rate)} />
        <KpiCard label="Blocked"      value={formatNumber(s.block_count)}    valueColor="#dc2626" accent="#dc2626" sub={formatRate(s.block_rate)} />
        <KpiCard label="Block Rate"   value={formatRate(s.block_rate)} />
        <KpiCard label="Average Risk" value={formatScore(s.avg_risk)}        valueColor={riskColor(s.avg_risk)} accent={riskColor(s.avg_risk)} />
      </div>
      <SeverityBar counts={s.severity_counts} />
    </div>
  )
}

function SeverityBar({ counts }: { counts: AuditStatsResponse["severity_counts"] }) {
  const sum = SEV_ORDER.reduce((a, k) => a + (counts[k] || 0), 0)
  return (
    <div
      className="px-5 py-4 rounded-lg"
      style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
    >
      <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-slate-400">
        Severity distribution
      </span>
      {sum === 0 ? (
        <p className="text-xs text-slate-400 mt-2">No matching requests</p>
      ) : (
        <>
          <div className="flex h-2 rounded-full overflow-hidden bg-slate-100 mt-2.5">
            {SEV_ORDER.map(k => counts[k] > 0 && (
              <div
                key={k}
                title={`${k}: ${counts[k]}`}
                style={{ width: `${(counts[k] / sum) * 100}%`, background: SEV_COLORS[k] }}
              />
            ))}
          </div>
          <div className="flex flex-wrap gap-x-5 gap-y-2 mt-3">
            {SEV_ORDER.map(k => (
              <div key={k} className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-sm" style={{ background: SEV_COLORS[k] }} />
                <span className="text-[11px] text-slate-500">{k[0] + k.slice(1).toLowerCase()}</span>
                <span className="text-[11px] font-semibold text-slate-700 tabular-nums">{counts[k] || 0}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function OverviewSkeleton() {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="h-[92px] rounded-lg animate-pulse"
            style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
          />
        ))}
      </div>
      <div
        className="h-[76px] rounded-lg animate-pulse"
        style={{ background: "var(--card-bg)", border: "1px solid var(--card-border)" }}
      />
    </div>
  )
}
