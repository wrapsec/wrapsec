// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { useState } from "react"
import { useTranslations } from "next-intl"
import { useTimeRange } from "@/hooks/useTimeRange"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { RangeTabs } from "@/components/ui/RangeTabs"
import { KpiCard } from "@/components/ui/KpiCard"
import { PageSpinner } from "@/components/ui/Spinner"
import { getAuditStats, getAttribution, getAnalytics, getDepartments, getApplications } from "@/lib/api"
import { AuditStatsResponse } from "@/lib/types"
import { useFormat } from "@/hooks/useFormat"


const CARD: React.CSSProperties = {
  background: "#fff",
  border: "1px solid #e5e7eb",
  borderRadius: "8px",
  padding: "20px",
}

const SECTION_LABEL: React.CSSProperties = {
  fontSize: "10px",
  fontWeight: 700,
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const,
  color: "#9ca3af",
  marginBottom: "12px",
  marginTop: 0,
}

const TH: React.CSSProperties = {
  textAlign: "left" as const,
  padding: "8px 12px",
  fontSize: "10px",
  fontWeight: 700,
  letterSpacing: "0.07em",
  textTransform: "uppercase" as const,
  color: "#9ca3af",
  borderBottom: "1px solid #f3f4f6",
  background: "#fafafa",
  whiteSpace: "nowrap" as const,
}

// ── Security KPIs ─────────────────────────────────────────────────────────

function SecuritySummary({ stats, attribution }: { stats: AuditStatsResponse; attribution: any }) {
  const fmt        = useFormat()
  const t          = useTranslations("pages.analytics.kpi")
  const byReason   = attribution?.by_primary_reason ?? []
  const piiCount   = byReason
    .filter((r: any) => r.primary_reason === "PII_GUARDRAIL_BLOCK" || r.primary_reason === "PII_GUARDRAIL_SANITIZE")
    .reduce((s: number, r: any) => s + r.count, 0)
  const exfilCount   = stats.top_threats?.find(t => t.category === "DATA_EXFILTRATION")?.count ?? 0
  const toxCount     = stats.top_threats?.find(t => t.category === "TOXICITY")?.count ?? 0
  const totalThreats = stats.top_threats?.reduce((s, t) => s + t.count, 0) ?? 0

  const KPIS = [
    { label: t("pii_attempts"),    value: fmt.number(piiCount),   sub: t("pii_attempts_sub"), accent: "#670FEF",
      icon: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" },
    { label: t("exfil_attempts"),  value: fmt.number(exfilCount), sub: t("exfil_attempts_sub", { code: "DATA_EXFILTRATION" }), accent: "#dc2626",
      icon: "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" },
    { label: t("toxicity_incidents"), value: fmt.number(toxCount),   sub: t("toxicity_incidents_sub"), accent: "#d97706",
      icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
    { label: t("total_detections"), value: fmt.number(totalThreats), sub: t("total_detections_sub", { count: stats.top_threats?.length ?? 0 }), accent: "#00B1FF",
      icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
  ]

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px" }}>
      {KPIS.map(k => (
        <KpiCard key={k.label} label={k.label} value={k.value} sub={k.sub} accent={k.accent} icon={k.icon} />
      ))}
    </div>
  )
}

// ── Trend Chart ───────────────────────────────────────────────────────────

function TrendChart({ data, groupBy, onGroupByChange }: {
  data: { period: string; total: number; blocked: number; sanitized: number; allowed: number; block_rate: number }[]
  groupBy: "hour" | "day" | "week" | "month"
  onGroupByChange: (v: "hour" | "day" | "week" | "month") => void
}) {
  const t        = useTranslations("pages.analytics.trend")
  const CHART_H  = 220
  const CHART_PAD_TOP = 16  // padding so tallest bar doesn't touch top edge
  const maxTotal = Math.max(...data.map(d => d.total), 1)
  const [hovered, setHovered] = useState<string | null>(null)
  const hoveredData = data.find(d => d.period === hovered)

  // Y-axis grid lines at 25%, 50%, 75%, 100%
  const gridLines = [0.25, 0.5, 0.75, 1.0]

  const fmt = (p: string) => {
    const d = new Date(p)
    if (groupBy === "hour")  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
    if (groupBy === "month") return d.toLocaleDateString([], { month: "short", year: "numeric" })
    return d.toLocaleDateString([], { month: "short", day: "numeric" })
  }

  // Show label every N bars depending on count
  const showLabel = (i: number, total: number) => {
    if (total <= 7)  return true
    if (total <= 14) return i % 2 === 0
    if (total <= 31) return i % 4 === 0 || i === total - 1
    if (total <= 72) return i % 6 === 0 || i === total - 1
    return i % 12 === 0 || i === total - 1
  }

  // Effective chart height for bars (leave padding at top)
  const effectiveH = CHART_H - CHART_PAD_TOP

  const legend: { k: "blocked" | "sanitized" | "allowed"; color: string }[] = [
    { k: "blocked",   color: "#f87171" },
    { k: "sanitized", color: "#fbbf24" },
    { k: "allowed",   color: "#10b981" },
  ]

  return (
    <div style={CARD}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "16px" }}>
        <div>
          <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: "0 0 2px 0" }}>{t("title")}</h3>
          <p style={{ fontSize: "12px", color: "#9ca3af", margin: 0 }}>{t("subtitle")}</p>
        </div>
        <div style={{ display: "flex", gap: "2px", background: "#f3f4f6", borderRadius: "7px", padding: "3px" }}>
          {(["hour", "day", "week", "month"] as const).map(g => (
            <button key={g} onClick={() => onGroupByChange(g)} style={{
              fontSize: "12px", fontWeight: groupBy === g ? 600 : 400,
              padding: "4px 10px", borderRadius: "5px", border: "none", cursor: "pointer",
              background: groupBy === g ? "#fff" : "transparent",
              color: groupBy === g ? "#111827" : "#6b7280",
              boxShadow: groupBy === g ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
            }}>{t(`group.${g}`)}</button>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <div style={{ display: "flex", gap: "16px" }}>
          {legend.map(({ k, color }) => (
            <div key={k} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
              <div style={{ width: 10, height: 10, borderRadius: "2px", background: color }} />
              <span style={{ fontSize: "12px", color: "#6b7280" }}>{t(k)}</span>
            </div>
          ))}
        </div>
        {hoveredData ? (
          <div style={{ display: "flex", gap: "12px", fontSize: "12px" }}>
            <span style={{ color: "#9ca3af", fontWeight: 500 }}>{fmt(hoveredData.period)}</span>
            <span style={{ color: "#ef4444", fontFamily: "monospace" }}>{t("hover_blocked",   { count: hoveredData.blocked })}</span>
            <span style={{ color: "#f59e0b", fontFamily: "monospace" }}>{t("hover_sanitized", { count: hoveredData.sanitized })}</span>
            <span style={{ color: "#10b981", fontFamily: "monospace" }}>{t("hover_allowed",   { count: hoveredData.allowed })}</span>
            <span style={{ color: "#9ca3af", fontFamily: "monospace" }}>{t("hover_total",     { count: hoveredData.total })}</span>
          </div>
        ) : (
          <span style={{ fontSize: "12px", color: "#9ca3af" }}>{t("hover_hint")}</span>
        )}
      </div>

      {/* Chart area with Y-axis */}
      <div style={{ display: "flex", gap: "8px" }}>
        {/* Y-axis labels */}
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between",
          height: `${CHART_H}px`, paddingTop: `${CHART_PAD_TOP}px`, paddingBottom: "2px", flexShrink: 0 }}>
          {[...gridLines].reverse().map(pct => (
            <span key={pct} style={{ fontSize: "9px", color: "#d1d5db", textAlign: "right", lineHeight: 1 }}>
              {Math.round(maxTotal * pct)}
            </span>
          ))}
        </div>

        {/* Bars + grid */}
        <div style={{ flex: 1, position: "relative" }}>
          {/* Grid lines */}
          <div style={{ position: "absolute", inset: 0, pointerEvents: "none" }}>
            {gridLines.map(pct => (
              <div key={pct} style={{
                position: "absolute", left: 0, right: 0,
                bottom: `${pct * 100}%`,
                borderTop: pct === 1.0 ? "1px solid #e5e7eb" : "1px dashed #f3f4f6",
              }} />
            ))}
          </div>

          {/* Bars */}
          <div style={{ display: "flex", alignItems: "flex-end", gap: "2px",
            height: `${CHART_H}px`, position: "relative", paddingTop: `${CHART_PAD_TOP}px` }}>
            {data.map(d => {
              const totalH    = Math.max(Math.round((d.total / maxTotal) * effectiveH), 2)
              const blockH    = d.total > 0 ? Math.round((d.blocked   / d.total) * totalH) : 0
              const sanitizeH = d.total > 0 ? Math.round((d.sanitized / d.total) * totalH) : 0
              const allowH    = totalH - blockH - sanitizeH
              const isHovered = hovered === d.period
              return (
                <div key={d.period}
                  style={{
                    flex: 1, maxWidth: "80px",  // cap width - prevents month single-bar filling screen
                    display: "flex", flexDirection: "column", justifyContent: "flex-end",
                    height: "100%", cursor: "pointer",
                    opacity: hovered && !isHovered ? 0.35 : 1, transition: "opacity 0.1s",
                  }}
                  onMouseEnter={() => setHovered(d.period)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <div style={{ display: "flex", flexDirection: "column", width: "100%", height: `${totalH}px`,
                    borderRadius: "3px 3px 0 0", overflow: "hidden",
                    outline: isHovered ? "2px solid #670FEF" : "none", outlineOffset: "1px" }}>
                    {blockH    > 0 && <div style={{ height: `${blockH}px`,    background: "#f87171" }} />}
                    {sanitizeH > 0 && <div style={{ height: `${sanitizeH}px`, background: "#fbbf24" }} />}
                    {allowH    > 0 && <div style={{ height: `${allowH}px`,    background: "#10b981" }} />}
                  </div>
                </div>
              )
            })}
          </div>

          {/* X-axis labels */}
          <div style={{ display: "flex", gap: "2px", marginTop: "6px" }}>
            {data.map((d, i) => (
              <div key={d.period} style={{ flex: 1, textAlign: "center", overflow: "hidden" }}>
                {showLabel(i, data.length) && (
                  <span style={{ fontSize: "9px", color: "#9ca3af", whiteSpace: "nowrap" }}>
                    {fmt(d.period)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Threat Intelligence ───────────────────────────────────────────────────

function ThreatIntelligence({ stats }: { stats: AuditStatsResponse }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.analytics")
  const total = stats.top_threats.reduce((s, t) => s + t.count, 0) || 1
  const THREAT_META: Record<string, { color: string; level: "critical" | "high" | "medium" | "low" }> = {
    PROMPT_INJECTION:  { color: "#dc2626", level: "critical" },
    JAILBREAK:         { color: "#7c3aed", level: "critical" },
    DATA_EXFILTRATION: { color: "#b91c1c", level: "critical" },
    MALICIOUS_INTENT:  { color: "#ea580c", level: "high"     },
    PII:               { color: "#9333ea", level: "high"     },
    TOXICITY:          { color: "#d97706", level: "medium"   },
  }
  const threatLabel = (category: string) =>
    t.has(`threats.category.${category}`) ? t(`threats.category.${category}`) : category
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>{t("threats.title")}</p>
      {(stats.top_threats?.length ?? 0) === 0 ? (
        <p style={{ fontSize: "13px", color: "#9ca3af" }}>{t("threats.empty")}</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr>{[t("threats.col_category"), t("threats.col_severity"), t("threats.col_count"), t("threats.col_share")].map(h => <th key={h} style={TH}>{h}</th>)}</tr></thead>
          <tbody>
            {(stats.top_threats ?? []).map((th, i) => {
              const meta  = THREAT_META[th.category] ?? { color: "#6b7280", level: "low" as const }
              const share = th.count / total
              return (
                <tr key={th.category} style={{ borderBottom: i < (stats.top_threats?.length ?? 0) - 1 ? "1px solid #f9fafb" : "none" }}>
                  <td style={{ padding: "9px 12px", fontSize: "12px", fontWeight: 500, color: "#374151" }}>
                    {threatLabel(th.category)}
                  </td>
                  <td style={{ padding: "9px 12px" }}>
                    <span style={{ fontSize: "11px", fontWeight: 600, padding: "2px 7px", borderRadius: "4px", color: meta.color, background: meta.color + "12" }}>
                      {t(`severity.${meta.level}`)}
                    </span>
                  </td>
                  <td style={{ padding: "9px 12px", fontFamily: "monospace", fontSize: "12px", color: "#374151" }}>{fmt.number(th.count)}</td>
                  <td style={{ padding: "9px 12px", minWidth: "140px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <div style={{ flex: 1, height: "5px", background: "#f3f4f6", borderRadius: "3px", overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${share * 100}%`, background: meta.color, borderRadius: "3px" }} />
                      </div>
                      <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#9ca3af", width: "36px", textAlign: "right" }}>
                        {(share * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ── Detection Layer Breakdown ─────────────────────────────────────────────

function DetectionBreakdown({ byReason }: { byReason: { primary_reason: string; count: number }[] }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.analytics.detection")
  const total = byReason.reduce((s, r) => s + r.count, 0) || 1
  const LAYERS: { k: string; reason: string; color: string }[] = [
    { k: "rule",          reason: "RULE_DETECTOR",            color: "#670FEF" },
    { k: "ml",            reason: "ML_DETECTOR",              color: "#CD00FF" },
    { k: "llm",           reason: "LLM_DETECTOR",             color: "#00B1FF" },
    { k: "pii_block",     reason: "PII_GUARDRAIL_BLOCK",      color: "#dc2626" },
    { k: "pii_sanitize",  reason: "PII_GUARDRAIL_SANITIZE",   color: "#f97316" },
    { k: "toxicity_block", reason: "TOXICITY_GUARDRAIL_BLOCK", color: "#d97706" },
  ]
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>{t("title")}</p>
      <p style={{ fontSize: "12px", color: "#9ca3af", marginTop: "-8px", marginBottom: "16px" }}>{t("subtitle")}</p>
      <div style={{ display: "flex", flexDirection: "column", gap: "11px" }}>
        {LAYERS.map(layer => {
          const count = byReason.find(r => r.primary_reason === layer.reason)?.count ?? 0
          const share = count / total
          return (
            <div key={layer.k}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: layer.color, flexShrink: 0 }} />
                  <span style={{ fontSize: "12px", fontWeight: 500, color: "#374151" }}>{t(`layer.${layer.k}`)}</span>
                  <span style={{ fontSize: "11px", color: "#9ca3af" }}>{t(`desc.${layer.k}`)}</span>
                </div>
                <div style={{ display: "flex", gap: "10px", flexShrink: 0 }}>
                  <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#6b7280" }}>{fmt.number(count)}</span>
                  <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#9ca3af", width: "38px", textAlign: "right" }}>
                    {(share * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
              <div style={{ height: "5px", background: "#f3f4f6", borderRadius: "3px", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${share * 100}%`, background: layer.color, borderRadius: "3px" }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Confidence Distribution ───────────────────────────────────────────────

function ConfidenceDistribution({ data }: { data: { band: string; count: number }[] }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.analytics.confidence")
  const total = data.reduce((s, d) => s + d.count, 0) || 1
  const BANDS: { band: string; k: "high" | "medium" | "low"; color: string }[] = [
    { band: "HIGH",   k: "high",   color: "#10b981" },
    { band: "MEDIUM", k: "medium", color: "#f59e0b" },
    { band: "LOW",    k: "low",    color: "#f87171" },
  ]
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>{t("title")}</p>
      <p style={{ fontSize: "12px", color: "#9ca3af", marginTop: "-8px", marginBottom: "16px" }}>
        {t("subtitle", { band: "LOW" })}
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        {BANDS.map(b => {
          const count = data.find(d => d.band === b.band)?.count ?? 0
          const share = count / total
          return (
            <div key={b.band}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "5px" }}>
                <div>
                  <span style={{ fontSize: "12px", fontWeight: 500, color: "#374151" }}>{t(b.k)}</span>
                  <span style={{ fontSize: "11px", color: "#9ca3af", marginLeft: "6px" }}>{t(`${b.k}_desc`)}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
                  <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#6b7280" }}>{fmt.number(count)}</span>
                  <span style={{ fontSize: "11px", fontWeight: 600, padding: "1px 6px", borderRadius: "4px", color: b.color, background: b.color + "15" }}>
                    {(share * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
              <div style={{ height: "6px", background: "#f3f4f6", borderRadius: "3px", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${share * 100}%`, background: b.color, borderRadius: "3px" }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Primary Reason Breakdown ──────────────────────────────────────────────

function PrimaryReasonBreakdown({ byReason }: { byReason: { primary_reason: string; count: number }[] }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.analytics.reason")
  const total = byReason.reduce((s, r) => s + r.count, 0) || 1
  const reasonLabel = (reason: string) =>
    t.has(`label.${reason}`) ? t(`label.${reason}`) : reason
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>{t("title")}</p>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr>{[t("col_reason"), t("col_count"), t("col_share")].map(h => <th key={h} style={TH}>{h}</th>)}</tr></thead>
        <tbody>
          {[...byReason].sort((a, b) => b.count - a.count).map((r, i, arr) => (
            <tr key={r.primary_reason} style={{ borderBottom: i < arr.length - 1 ? "1px solid #f9fafb" : "none" }}>
              <td style={{ padding: "9px 12px", fontSize: "12px", fontWeight: 500, color: "#374151" }}>
                {reasonLabel(r.primary_reason)}
              </td>
              <td style={{ padding: "9px 12px", fontFamily: "monospace", fontSize: "12px", color: "#6b7280" }}>
                {fmt.number(r.count)}
              </td>
              <td style={{ padding: "9px 12px", minWidth: "140px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <div style={{ flex: 1, height: "4px", background: "#f3f4f6", borderRadius: "2px", overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${(r.count / total) * 100}%`, background: "#670FEF", borderRadius: "2px" }} />
                  </div>
                  <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#9ca3af", width: "36px", textAlign: "right" }}>
                    {((r.count / total) * 100).toFixed(1)}%
                  </span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Attribution Table ─────────────────────────────────────────────────────

function AttributionTable({ title, rows, emptyText }: {
  title: string; emptyText: string
  rows: { name: string; sub: string; blockRate: number; total: number }[]
}) {
  const fmt = useFormat()
  const t   = useTranslations("pages.analytics.attribution")
  const maxTotal = Math.max(...rows.map(r => r.total), 1)
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>{title}</p>
      {rows.length === 0 ? (
        <p style={{ fontSize: "12px", color: "#9ca3af" }}>{emptyText}</p>
      ) : (
        <div>
          {rows.map((row, i) => {
            const bpct  = Math.round(row.blockRate * 100)
            const color = bpct >= 50 ? "#dc2626" : bpct >= 20 ? "#d97706" : "#059669"
            return (
              <div key={row.name + i} style={{
                display: "flex", alignItems: "center", gap: "12px",
                padding: "9px 0", borderBottom: i < rows.length - 1 ? "1px solid #f9fafb" : "none",
              }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: "12px", fontWeight: 500, color: "#111827", margin: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {row.name}
                  </p>
                  <p style={{ fontSize: "11px", color: "#9ca3af", margin: "1px 0 0 0" }}>{row.sub}</p>
                </div>
                <div style={{ width: "80px", flexShrink: 0 }}>
                  <div style={{ height: "4px", background: "#f3f4f6", borderRadius: "2px", overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${(row.total / maxTotal) * 100}%`, background: "#670FEF", borderRadius: "2px" }} />
                  </div>
                </div>
                <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#9ca3af", width: "52px", textAlign: "right", flexShrink: 0 }}>
                  {t("req", { count: fmt.number(row.total) })}
                </span>
                <span style={{ fontSize: "11px", fontWeight: 600, fontFamily: "monospace", padding: "2px 6px", borderRadius: "4px", flexShrink: 0, color, background: color + "12" }}>
                  {t("pct_blocked", { pct: bpct })}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  const fmt = useFormat()
  const t   = useTranslations("pages.analytics")
  const [groupBy,   setGroupBy]   = useState<"hour" | "day" | "week" | "month">("day")

  const {
    range: timeRange, setRange: setTimeRange, options: timeRangeOptions,
    from, to, customFrom, customTo, setCustomFrom, setCustomTo, customError,
  } = useTimeRange({
    defaultRange: "7d",
    options:      ["24h", "7d", "30d", "90d", "custom"],
  })

  const ANALYTICS_REFRESH = 5 * 60 * 1000 // 5 minutes - historical data doesn't need live polling

  const SWR_OPTS = {
    refreshInterval:   ANALYTICS_REFRESH,
    revalidateOnFocus: false,
    keepPreviousData:  false,
  }

  const { data: stats,       isLoading: statsLoading, error: statsError } = useSWR(["analytics-stats",       from, to], () => getAuditStats({ from, to }),                 SWR_OPTS)
  const { data: attribution, isLoading: attrLoading                     } = useSWR(["analytics-attribution", from, to], () => getAttribution({ from, to }),                SWR_OPTS)
  const { data: analytics }                            = useSWR(["analytics-trend", groupBy, from, to], () => getAnalytics({ group_by: groupBy, from, to }), SWR_OPTS)
  const { data: depts } = useSWR("departments-list",  getDepartments)
  const { data: apps  } = useSWR("applications-list", getApplications)

  const deptNames: Record<string, string> = {}
  depts?.departments?.forEach((d: any) => { deptNames[d.id] = d.name })

  const appNames: Record<string, string> = {}
  apps?.applications?.forEach((a: any) => { appNames[a.id] = a.name })

  if ((statsLoading || attrLoading) && !stats) {
    return <Shell title={t("title")}><PageSpinner /></Shell>
  }

  if (statsError && !stats) {
    return (
      <Shell title={t("title")}>
        <div className="max-w-2xl">
          <div className="bg-red-50 border border-red-200 rounded-xl p-5">
            <p className="text-sm font-semibold text-red-700 mb-1">{t("load_error")}</p>
            <p className="text-xs text-red-500">{statsError?.message ?? t("unexpected_error")}</p>
          </div>
        </div>
      </Shell>
    )
  }

  const byReason = attribution?.by_primary_reason ?? []

  return (
    <Shell title={t("title")}>
      <PageHeader
        description={t("description")}
        actions={
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "6px" }}>
            <RangeTabs
              options={timeRangeOptions}
              value={timeRange}
              onChange={setTimeRange}
              format={r => (r === "custom" ? t("custom") : r)}
            />

            {/* Custom date pickers - shown only when "custom" is active */}
            {timeRange === "custom" && (
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <input
                  type="date"
                  value={customFrom}
                  max={new Date().toISOString().slice(0, 10)}
                  onChange={(e) => setCustomFrom(e.target.value)}
                  style={{
                    fontSize: "12px", padding: "4px 8px", borderRadius: "5px",
                    border: "1px solid #e5e7eb", background: "#fff", color: "#374151",
                    outline: "none", cursor: "pointer",
                  }}
                />
                <span style={{ fontSize: "12px", color: "#9ca3af" }}>{t("date_to")}</span>
                <input
                  type="date"
                  value={customTo}
                  min={customFrom || undefined}
                  max={new Date().toISOString().slice(0, 10)}
                  onChange={(e) => setCustomTo(e.target.value)}
                  style={{
                    fontSize: "12px", padding: "4px 8px", borderRadius: "5px",
                    border: "1px solid #e5e7eb", background: "#fff", color: "#374151",
                    outline: "none", cursor: "pointer",
                  }}
                />
                {customError && (
                  <span style={{ fontSize: "11px", color: "#dc2626" }}>{customError}</span>
                )}
              </div>
            )}
          </div>
        }
      />
      <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>

        {stats && attribution && <SecuritySummary stats={stats} attribution={attribution} />}

        {(analytics?.trend?.length ?? 0) > 0 ? (
          <TrendChart data={analytics!.trend} groupBy={groupBy} onGroupByChange={setGroupBy} />
        ) : analytics !== undefined && (
          <div style={{ ...CARD, padding: "48px 24px", textAlign: "center" }}>
            <p style={{ fontSize: "13px", fontWeight: 600, color: "#374151", margin: "0 0 4px 0" }}>{t("trend.empty_title")}</p>
            <p style={{ fontSize: "12px", color: "#9ca3af", margin: 0 }}>
              {t("trend.empty_body")}
            </p>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          {stats && <ThreatIntelligence stats={stats} />}
          {byReason.length > 0 && <DetectionBreakdown byReason={byReason} />}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          {(attribution?.by_confidence_band?.length ?? 0) > 0 && (
            <ConfidenceDistribution data={attribution!.by_confidence_band} />
          )}
          {byReason.length > 0 && <PrimaryReasonBreakdown byReason={byReason} />}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          <AttributionTable
            title={t("attribution.dept_title")}
            emptyText={t("attribution.dept_empty")}
            rows={(attribution?.by_department ?? [])
              .filter((r: any) => !depts || !!deptNames[r.dept_id])
              .sort((a: any, b: any) => b.block_rate - a.block_rate)
              .slice(0, 8)
              .map((r: any) => ({
                name: deptNames[r.dept_id] || r.dept_id || t("attribution.no_department"),
                sub: t("attribution.requests_sub", { count: fmt.number(r.total) }),
                blockRate: r.block_rate, total: r.total,
              }))}
          />
          <AttributionTable
            title={t("attribution.app_title")}
            emptyText={t("attribution.app_empty")}
            rows={(attribution?.by_application ?? [])
              .filter((r: any) => !apps || !!appNames[r.app_id])
              .sort((a: any, b: any) => b.block_rate - a.block_rate)
              .slice(0, 8)
              .map((r: any) => ({
                name: appNames[r.app_id] || r.app_id || t("attribution.no_application"),
                sub: t("attribution.requests_latency_sub", { count: fmt.number(r.total), ms: r.avg_latency_ms?.toFixed(0) ?? "-" }),
                blockRate: r.block_rate, total: r.total,
              }))}
          />
        </div>

        {(attribution?.by_key?.length ?? 0) > 0 && (
          <AttributionTable
            title={t("attribution.key_title")}
            emptyText={t("attribution.key_empty")}
            rows={(attribution!.by_key as any[])
              .sort((a, b) => b.total - a.total)
              .slice(0, 10)
              .map(r => ({
                name: r.source || r.key_id || "-",
                sub: t("attribution.requests_latency_sub", { count: fmt.number(r.total), ms: r.avg_latency_ms?.toFixed(0) ?? "-" }),
                blockRate: r.block_rate, total: r.total,
              }))}
          />
        )}

      </div>
    </Shell>
  )
}
