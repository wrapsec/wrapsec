"use client"

import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { StatsCards } from "@/components/analytics/StatsCards"
import { ThreatChart } from "@/components/analytics/ThreatChart"
import { LatencyStats } from "@/components/analytics/LatencyChart"
import { PageSpinner } from "@/components/ui/Spinner"
import { POLL_INTERVAL } from "@/lib/constants"
import { getAuditStats, getAttribution, getDepartments, getApplications, getAnalytics } from "@/lib/api"
import { useState } from "react"

export default function AnalyticsPage() {
  const { data: stats, isLoading: statsLoading } = useSWR(
    "analytics-stats",
    getAuditStats,
    { refreshInterval: POLL_INTERVAL }
  )

  const { data: attribution, isLoading: attrLoading } = useSWR(
    "analytics-attribution",
    getAttribution,
    { refreshInterval: POLL_INTERVAL }
  )

  const { data: depts }  = useSWR("departments-list", getDepartments)
  const { data: apps }   = useSWR("applications-list", getApplications)
  const [groupBy, setGroupBy] = useState<"hour" | "day" | "week" | "month">("day")
  const { data: analytics } = useSWR(
    ["analytics-trend", groupBy],
    () => getAnalytics({ group_by: groupBy }),
    { refreshInterval: POLL_INTERVAL }
  )
  const isLoading = statsLoading || attrLoading

  // Build lookup maps for names
  const deptNames: Record<string, string> = {}
  depts?.departments?.forEach((d: any) => { deptNames[d.id] = d.name })

  const appNames: Record<string, string> = {}
  apps?.applications?.forEach((a: any) => { appNames[a.id] = a.name })

  return (
    <Shell title="Analytics">
      {isLoading || !stats ? (
        <PageSpinner />
      ) : (
        <div className="space-y-5">
          <StatsCards stats={stats} />

          <div className="grid grid-cols-2 gap-4">
            <ThreatChart threats={stats.top_threats} />
            <LatencyStats stats={stats} />
          </div>

          {/* Confidence band distribution */}
          {attribution && attribution.by_confidence_band?.length > 0 && (
            <ConfidenceBandChart data={attribution.by_confidence_band} />
          )}

          {/* Trend chart */}
          {analytics && analytics.trend.length > 0 && (
            <TrendChart
              data={analytics.trend}
              groupBy={groupBy}
              onGroupByChange={setGroupBy}
            />
          )}

          {/* Attribution report */}
          {attribution && (
            <AttributionReport
              attribution={attribution}
              deptNames={deptNames}
              appNames={appNames}
            />
          )}
        </div>
      )}
    </Shell>
  )
}

// ── Confidence Band Chart ─────────────────────────────────────────────────

function ConfidenceBandChart({ data }: {
  data: { band: string; count: number }[]
}) {
  const total  = data.reduce((s, d) => s + d.count, 0)
  const colors: Record<string, string> = {
    HIGH:   "#10b981",
    MEDIUM: "#fbbf24",
    LOW:    "#f87171",
  }
  const labels: Record<string, string> = {
    HIGH:   "High confidence",
    MEDIUM: "Medium confidence",
    LOW:    "Low confidence — review recommended",
  }

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5">
      <h3 className="text-sm font-semibold text-slate-800 mb-1">Confidence Distribution</h3>
      <p className="text-xs text-slate-400 mb-4">
        Decision certainty across all requests. LOW confidence decisions warrant human review.
      </p>
      <div className="space-y-3">
        {["HIGH", "MEDIUM", "LOW"].map(band => {
          const row   = data.find(d => d.band === band)
          const count = row?.count ?? 0
          const pct   = total > 0 ? Math.round((count / total) * 100) : 0
          return (
            <div key={band}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-slate-600">{labels[band]}</span>
                <span className="text-xs font-mono text-slate-500">{count.toLocaleString()} ({pct}%)</span>
              </div>
              <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${pct}%`, backgroundColor: colors[band] }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Attribution Report ────────────────────────────────────────────────────

function AttributionReport({ attribution, deptNames, appNames }: {
  deptNames:   Record<string, string>
  appNames:    Record<string, string>
  attribution: {
    by_key:          { key_id: string; source: string; total: number; blocked: number; block_rate: number; avg_latency_ms: number }[]
    by_department:   { dept_id: string; total: number; blocked: number; block_rate: number }[]
    by_application:  { app_id: string; total: number; blocked: number; block_rate: number; avg_latency_ms: number }[]
    by_primary_reason: { primary_reason: string; count: number }[]
  }
}) {
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-slate-800">Attribution Report</h3>

      <div className="grid grid-cols-2 gap-4">
        {/* By API Key */}
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">By API Key</h4>
          {attribution.by_key.length === 0 ? (
            <p className="text-xs text-slate-400">No data</p>
          ) : (
            <div className="space-y-2">
              {attribution.by_key.slice(0, 8).map(row => (
                <div key={`${row.key_id}-${row.total}`} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-700 truncate">{row.source || row.key_id || "—"}</p>
                    <p className="text-xs text-slate-400">{row.total.toLocaleString()} requests</p>
                  </div>
                  <BlockRateBadge rate={row.block_rate} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* By Department */}
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">By Department</h4>
          {attribution.by_department.length === 0 ? (
            <p className="text-xs text-slate-400">No data</p>
          ) : (
            <div className="space-y-2">
              {attribution.by_department.slice(0, 8).map(row => (
                <div key={row.dept_id} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-700 truncate">{deptNames[row.dept_id] || row.dept_id || "No department"}</p>
                    <p className="text-xs text-slate-400">{row.total.toLocaleString()} requests</p>
                  </div>
                  <BlockRateBadge rate={row.block_rate} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* By Application */}
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">By Application</h4>
          {attribution.by_application.length === 0 ? (
            <p className="text-xs text-slate-400">No data</p>
          ) : (
            <div className="space-y-2">
              {attribution.by_application.slice(0, 8).map(row => (
                <div key={row.app_id} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-700 truncate">{appNames[row.app_id] || row.app_id || "No application"}</p>
                    <p className="text-xs text-slate-400">{row.total.toLocaleString()} requests</p>
                  </div>
                  <BlockRateBadge rate={row.block_rate} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* By Primary Reason */}
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">By Primary Reason</h4>
          {attribution.by_primary_reason.length === 0 ? (
            <p className="text-xs text-slate-400">No data</p>
          ) : (
            <div className="space-y-2">
              {attribution.by_primary_reason.map(row => (
                <div key={row.primary_reason} className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
                  <p className="text-xs font-medium text-slate-700 font-mono">{row.primary_reason}</p>
                  <span className="text-xs text-slate-500 font-mono">{row.count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function BlockRateBadge({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100)
  const color = pct >= 50 ? "text-red-600 bg-red-50" :
                pct >= 20 ? "text-amber-600 bg-amber-50" :
                            "text-emerald-600 bg-emerald-50"
  return (
    <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${color}`}>
      {pct}% blocked
    </span>
  )
}

// ── Trend Chart ───────────────────────────────────────────────────────────

function TrendChart({
  data,
  groupBy,
  onGroupByChange,
}: {
  data:            { period: string; total: number; blocked: number; sanitized: number; allowed: number; block_rate: number }[]
  groupBy:         "hour" | "day" | "week" | "month"
  onGroupByChange: (v: "hour" | "day" | "week" | "month") => void
}) {
  const CHART_H    = 160
  const maxTotal   = Math.max(...data.map(d => d.total), 1)
  const [hovered, setHovered] = useState<string | null>(null)

  const formatPeriod = (period: string) => {
    const d = new Date(period)
    if (groupBy === "hour")  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    if (groupBy === "month") return d.toLocaleDateString([], { month: "short", year: "numeric" })
    return d.toLocaleDateString([], { month: "short", day: "numeric" })
  }

  const hoveredData = data.find(d => d.period === hovered)

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-800">Request Trend</h3>
          <p className="text-xs text-slate-400 mt-0.5">Requests over time by decision</p>
        </div>
        <div className="flex items-center gap-1 bg-slate-100 rounded-lg p-1">
          {(["hour", "day", "week", "month"] as const).map(g => (
            <button
              key={g}
              onClick={() => onGroupByChange(g)}
              className={`text-xs px-2.5 py-1 rounded-md transition-colors ${
                groupBy === g
                  ? "bg-white text-slate-800 font-medium shadow-sm"
                  : "text-slate-500 hover:text-slate-700"
              }`}
            >
              {g.charAt(0).toUpperCase() + g.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Legend + live tooltip values */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-4">
          {[
            { label: "Blocked",   color: "#f87171" },
            { label: "Sanitized", color: "#fbbf24" },
            { label: "Allowed",   color: "#10b981" },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1.5">
              <div className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />
              <span className="text-xs text-slate-500">{label}</span>
            </div>
          ))}
        </div>
        {/* Live values on hover */}
        {hoveredData ? (
          <div className="flex items-center gap-3 text-xs">
            <span className="text-slate-400 font-medium">{formatPeriod(hoveredData.period)}</span>
            <span className="text-red-500 font-mono">{hoveredData.blocked} blocked</span>
            <span className="text-amber-500 font-mono">{hoveredData.sanitized} sanitized</span>
            <span className="text-emerald-500 font-mono">{hoveredData.allowed} allowed</span>
            <span className="text-slate-400 font-mono">{hoveredData.total} total</span>
            <span className="text-slate-400 font-mono">{Math.round(hoveredData.block_rate * 100)}% block rate</span>
          </div>
        ) : (
          <span className="text-xs text-slate-400">Hover a bar to see details</span>
        )}
      </div>

      {/* Bars */}
      <div className="flex items-end gap-1.5" style={{ height: `${CHART_H}px` }}>
        {data.map((d) => {
          const totalH    = Math.max(Math.round((d.total    / maxTotal) * CHART_H), 4)
          const blockH    = d.total > 0 ? Math.round((d.blocked   / d.total) * totalH) : 0
          const sanitizeH = d.total > 0 ? Math.round((d.sanitized / d.total) * totalH) : 0
          const allowH    = totalH - blockH - sanitizeH
          const isHovered = hovered === d.period

          return (
            <div
              key={d.period}
              className="flex-shrink-0 flex flex-col justify-end cursor-default transition-opacity duration-100"
              style={{
                width:   "32px",
                height:  `${CHART_H}px`,
                opacity: hovered && !isHovered ? 0.4 : 1,
              }}
              onMouseEnter={() => setHovered(d.period)}
              onMouseLeave={() => setHovered(null)}
            >
              <div
                className="flex flex-col w-full rounded-sm overflow-hidden transition-all duration-100"
                style={{
                  height:  `${totalH}px`,
                  outline: isHovered ? "2px solid #334155" : "none",
                  outlineOffset: "1px",
                }}
              >
                {blockH    > 0 && <div style={{ height: `${blockH}px`,    backgroundColor: "#f87171" }} />}
                {sanitizeH > 0 && <div style={{ height: `${sanitizeH}px`, backgroundColor: "#fbbf24" }} />}
                {allowH    > 0 && <div style={{ height: `${allowH}px`,    backgroundColor: "#10b981" }} />}
              </div>
            </div>
          )
        })}
      </div>

      {/* X-axis labels */}
      <div className="flex gap-1.5 mt-1.5">
        {data.map((d, i) => (
          <div key={d.period} className="flex-shrink-0 text-center" style={{ width: "32px" }}>
            {(i === 0 || i === data.length - 1 || i === Math.floor(data.length / 2)) && (
              <span className="text-slate-400" style={{ fontSize: "9px" }}>
                {formatPeriod(d.period)}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}