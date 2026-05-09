// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { useState } from "react"
import { useTimeRange } from "@/hooks/useTimeRange"
import { Shell } from "@/components/layout/Shell"
import { PageSpinner } from "@/components/ui/Spinner"
import { POLL_INTERVAL, THREAT_LABELS } from "@/lib/constants"
import { getAuditStats, getAttribution, getAnalytics, getDepartments, getApplications } from "@/lib/api"
import { AuditStatsResponse } from "@/lib/types"

function num(n: number) { return n.toLocaleString() }

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
  const byReason   = attribution?.by_primary_reason ?? []
  const piiCount   = byReason
    .filter((r: any) => r.primary_reason === "PII_GUARDRAIL_BLOCK" || r.primary_reason === "PII_GUARDRAIL_SANITIZE")
    .reduce((s: number, r: any) => s + r.count, 0)
  const exfilCount   = stats.top_threats?.find(t => t.category === "DATA_EXFILTRATION")?.count ?? 0
  const toxCount     = stats.top_threats?.find(t => t.category === "TOXICITY")?.count ?? 0
  const totalThreats = stats.top_threats?.reduce((s, t) => s + t.count, 0) ?? 0

  const KPIS = [
    { label: "PII Exposure Attempts",      value: num(piiCount),   sub: "Guardrail blocks + sanitizations", accent: "#670FEF",
      icon: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" },
    { label: "Data Exfiltration Attempts", value: num(exfilCount), sub: "DATA_EXFILTRATION threat category", accent: "#dc2626",
      icon: "M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" },
    { label: "Toxicity Incidents",         value: num(toxCount),   sub: "Toxicity guardrail triggers",       accent: "#d97706",
      icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
    { label: "Total Threat Detections",    value: num(totalThreats), sub: `${stats.top_threats?.length ?? 0} unique threat types`, accent: "#00B1FF",
      icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" },
  ]

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px" }}>
      {KPIS.map(k => (
        <div key={k.label} style={{ ...CARD, borderTop: `3px solid ${k.accent}` }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "10px" }}>
            <p style={{ fontSize: "11px", fontWeight: 600, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.07em", margin: 0, lineHeight: 1.3 }}>
              {k.label}
            </p>
            <div style={{ width: 32, height: 32, borderRadius: "8px", background: k.accent + "12", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              <svg style={{ width: 16, height: 16 }} fill="none" stroke={k.accent} strokeWidth={1.75} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d={k.icon}/>
              </svg>
            </div>
          </div>
          <p style={{ fontSize: "26px", fontWeight: 700, color: "#111827", lineHeight: 1, margin: "0 0 5px 0" }}>{k.value}</p>
          <p style={{ fontSize: "11px", color: "#9ca3af", margin: 0 }}>{k.sub}</p>
        </div>
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

  return (
    <div style={CARD}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "16px" }}>
        <div>
          <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: "0 0 2px 0" }}>Request Trend</h3>
          <p style={{ fontSize: "12px", color: "#9ca3af", margin: 0 }}>Volume and decision distribution over time</p>
        </div>
        <div style={{ display: "flex", gap: "2px", background: "#f3f4f6", borderRadius: "7px", padding: "3px" }}>
          {(["hour", "day", "week", "month"] as const).map(g => (
            <button key={g} onClick={() => onGroupByChange(g)} style={{
              fontSize: "12px", fontWeight: groupBy === g ? 600 : 400,
              padding: "4px 10px", borderRadius: "5px", border: "none", cursor: "pointer",
              background: groupBy === g ? "#fff" : "transparent",
              color: groupBy === g ? "#111827" : "#6b7280",
              boxShadow: groupBy === g ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
            }}>{g.charAt(0).toUpperCase() + g.slice(1)}</button>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <div style={{ display: "flex", gap: "16px" }}>
          {[["Blocked", "#f87171"], ["Sanitized", "#fbbf24"], ["Allowed", "#10b981"]].map(([label, color]) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
              <div style={{ width: 10, height: 10, borderRadius: "2px", background: color }} />
              <span style={{ fontSize: "12px", color: "#6b7280" }}>{label}</span>
            </div>
          ))}
        </div>
        {hoveredData ? (
          <div style={{ display: "flex", gap: "12px", fontSize: "12px" }}>
            <span style={{ color: "#9ca3af", fontWeight: 500 }}>{fmt(hoveredData.period)}</span>
            <span style={{ color: "#ef4444", fontFamily: "monospace" }}>{hoveredData.blocked} blocked</span>
            <span style={{ color: "#f59e0b", fontFamily: "monospace" }}>{hoveredData.sanitized} sanitized</span>
            <span style={{ color: "#10b981", fontFamily: "monospace" }}>{hoveredData.allowed} allowed</span>
            <span style={{ color: "#9ca3af", fontFamily: "monospace" }}>{hoveredData.total} total</span>
          </div>
        ) : (
          <span style={{ fontSize: "12px", color: "#9ca3af" }}>Hover a bar for details</span>
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
                    flex: 1, maxWidth: "80px",  // cap width — prevents month single-bar filling screen
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
  const total = stats.top_threats.reduce((s, t) => s + t.count, 0) || 1
  const THREAT_META: Record<string, { color: string; level: string }> = {
    PROMPT_INJECTION:  { color: "#dc2626", level: "Critical" },
    JAILBREAK:         { color: "#7c3aed", level: "Critical" },
    DATA_EXFILTRATION: { color: "#b91c1c", level: "Critical" },
    MALICIOUS_INTENT:  { color: "#ea580c", level: "High"     },
    PII:               { color: "#9333ea", level: "High"      },
    TOXICITY:          { color: "#d97706", level: "Medium"    },
  }
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>Threat intelligence</p>
      {(stats.top_threats?.length ?? 0) === 0 ? (
        <p style={{ fontSize: "13px", color: "#9ca3af" }}>No threats detected in this period</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr>{["Threat category", "Severity", "Count", "Share"].map(h => <th key={h} style={TH}>{h}</th>)}</tr></thead>
          <tbody>
            {(stats.top_threats ?? []).map((t, i) => {
              const meta  = THREAT_META[t.category] ?? { color: "#6b7280", level: "Low" }
              const share = t.count / total
              return (
                <tr key={t.category} style={{ borderBottom: i < (stats.top_threats?.length ?? 0) - 1 ? "1px solid #f9fafb" : "none" }}>
                  <td style={{ padding: "9px 12px", fontSize: "12px", fontWeight: 500, color: "#374151" }}>
                    {THREAT_LABELS[t.category] || t.category}
                  </td>
                  <td style={{ padding: "9px 12px" }}>
                    <span style={{ fontSize: "11px", fontWeight: 600, padding: "2px 7px", borderRadius: "4px", color: meta.color, background: meta.color + "12" }}>
                      {meta.level}
                    </span>
                  </td>
                  <td style={{ padding: "9px 12px", fontFamily: "monospace", fontSize: "12px", color: "#374151" }}>{num(t.count)}</td>
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
  const total = byReason.reduce((s, r) => s + r.count, 0) || 1
  const LAYERS = [
    { key: "RULE_DETECTOR",              label: "Rule detector",        color: "#670FEF", desc: "Regex + heuristics" },
    { key: "ML_DETECTOR",                label: "ML classifier",        color: "#CD00FF", desc: "TF-IDF + logistic regression" },
    { key: "LLM_DETECTOR",               label: "LLM semantic",         color: "#00B1FF", desc: "Full mode only" },
    { key: "PII_GUARDRAIL_BLOCK",        label: "PII block",            color: "#dc2626", desc: "PII guardrail override" },
    { key: "PII_GUARDRAIL_SANITIZE",     label: "PII sanitize",         color: "#f97316", desc: "PII redaction" },
    { key: "TOXICITY_GUARDRAIL_BLOCK",   label: "Toxicity block",       color: "#d97706", desc: "Toxicity guardrail" },
  ]
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>Detection layer breakdown</p>
      <p style={{ fontSize: "12px", color: "#9ca3af", marginTop: "-8px", marginBottom: "16px" }}>How threats are being caught</p>
      <div style={{ display: "flex", flexDirection: "column", gap: "11px" }}>
        {LAYERS.map(layer => {
          const count = byReason.find(r => r.primary_reason === layer.key)?.count ?? 0
          const share = count / total
          return (
            <div key={layer.key}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                  <div style={{ width: 7, height: 7, borderRadius: "50%", background: layer.color, flexShrink: 0 }} />
                  <span style={{ fontSize: "12px", fontWeight: 500, color: "#374151" }}>{layer.label}</span>
                  <span style={{ fontSize: "11px", color: "#9ca3af" }}>{layer.desc}</span>
                </div>
                <div style={{ display: "flex", gap: "10px", flexShrink: 0 }}>
                  <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#6b7280" }}>{num(count)}</span>
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
  const total = data.reduce((s, d) => s + d.count, 0) || 1
  const BANDS = [
    { band: "HIGH",   label: "High",   color: "#10b981", desc: "Decision is certain — no review needed" },
    { band: "MEDIUM", label: "Medium", color: "#f59e0b", desc: "Consider spot-checking" },
    { band: "LOW",    label: "Low",    color: "#f87171", desc: "Human review recommended" },
  ]
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>Decision confidence distribution</p>
      <p style={{ fontSize: "12px", color: "#9ca3af", marginTop: "-8px", marginBottom: "16px" }}>
        LOW confidence decisions warrant human review
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
        {BANDS.map(b => {
          const count = data.find(d => d.band === b.band)?.count ?? 0
          const share = count / total
          return (
            <div key={b.band}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "5px" }}>
                <div>
                  <span style={{ fontSize: "12px", fontWeight: 500, color: "#374151" }}>{b.label}</span>
                  <span style={{ fontSize: "11px", color: "#9ca3af", marginLeft: "6px" }}>{b.desc}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
                  <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#6b7280" }}>{num(count)}</span>
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
  const total = byReason.reduce((s, r) => s + r.count, 0) || 1
  const LABELS: Record<string, string> = {
    RULE_DETECTOR:               "Rule detector",
    ML_DETECTOR:                 "ML classifier",
    LLM_DETECTOR:                "LLM semantic",
    PII_GUARDRAIL_BLOCK:         "PII guardrail — block",
    PII_GUARDRAIL_SANITIZE:      "PII guardrail — sanitize",
    TOXICITY_GUARDRAIL_BLOCK:    "Toxicity guardrail — block",
    TOXICITY_GUARDRAIL_SANITIZE: "Toxicity guardrail — sanitize",
    NO_THREAT_DETECTED:          "No threat detected",
    SYSTEM_ERROR:                "System error",
  }
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>Primary decision reason</p>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr>{["Reason", "Count", "Share"].map(h => <th key={h} style={TH}>{h}</th>)}</tr></thead>
        <tbody>
          {[...byReason].sort((a, b) => b.count - a.count).map((r, i, arr) => (
            <tr key={r.primary_reason} style={{ borderBottom: i < arr.length - 1 ? "1px solid #f9fafb" : "none" }}>
              <td style={{ padding: "9px 12px", fontSize: "12px", fontWeight: 500, color: "#374151" }}>
                {LABELS[r.primary_reason] || r.primary_reason}
              </td>
              <td style={{ padding: "9px 12px", fontFamily: "monospace", fontSize: "12px", color: "#6b7280" }}>
                {num(r.count)}
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
                  {num(row.total)} req
                </span>
                <span style={{ fontSize: "11px", fontWeight: 600, fontFamily: "monospace", padding: "2px 6px", borderRadius: "4px", flexShrink: 0, color, background: color + "12" }}>
                  {bpct}% blocked
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
  const [groupBy,   setGroupBy]   = useState<"hour" | "day" | "week" | "month">("day")

  const {
    range: timeRange, setRange: setTimeRange, options: timeRangeOptions,
    from, to, customFrom, customTo, setCustomFrom, setCustomTo, customError,
  } = useTimeRange({
    defaultRange: "7d",
    options:      ["24h", "7d", "30d", "90d", "custom"],
  })

  const ANALYTICS_REFRESH = 5 * 60 * 1000 // 5 minutes — historical data doesn't need live polling

  const SWR_OPTS = {
    refreshInterval:   ANALYTICS_REFRESH,
    revalidateOnFocus: false,
    keepPreviousData:  false,
  }

  const { data: stats,       isLoading: statsLoading } = useSWR(["analytics-stats",       from, to], () => getAuditStats({ from, to }),                 SWR_OPTS)
  const { data: attribution, isLoading: attrLoading  } = useSWR(["analytics-attribution", from, to], () => getAttribution({ from, to }),                SWR_OPTS)
  const { data: analytics }                            = useSWR(["analytics-trend", groupBy, from, to], () => getAnalytics({ group_by: groupBy, from, to }), SWR_OPTS)
  const { data: depts } = useSWR("departments-list",  getDepartments)
  const { data: apps  } = useSWR("applications-list", getApplications)

  const deptNames: Record<string, string> = {}
  depts?.departments?.forEach((d: any) => { deptNames[d.id] = d.name })

  const appNames: Record<string, string> = {}
  apps?.applications?.forEach((a: any) => { appNames[a.id] = a.name })

  if ((statsLoading || attrLoading) && !stats) {
    return <Shell title="Analytics"><PageSpinner /></Shell>
  }

  const byReason = attribution?.by_primary_reason ?? []

  return (
    <Shell title="Analytics">
      <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>

        {/* Time range selector */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <p style={{ fontSize: "13px", color: "#6b7280", margin: 0 }}>
              Security intelligence and attribution report
            </p>
            {(statsLoading || attrLoading) && stats && (
              <svg style={{ width: 14, height: 14, animation: "spin 1s linear infinite", color: "#670FEF" }} fill="none" viewBox="0 0 24 24">
                <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
                <circle style={{ opacity: 0.25 }} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path style={{ opacity: 0.75 }} fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
              </svg>
            )}
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "6px" }}>
            <div style={{ display: "flex", gap: "2px", background: "#f3f4f6", borderRadius: "7px", padding: "3px" }}>
              {timeRangeOptions.map(r => (
                <button key={r} onClick={() => setTimeRange(r)} style={{
                  fontSize: "12px", fontWeight: timeRange === r ? 600 : 400,
                  padding: "5px 12px", borderRadius: "5px", border: "none", cursor: "pointer",
                  background: timeRange === r ? "#fff" : "transparent",
                  color: timeRange === r ? "#111827" : "#6b7280",
                  boxShadow: timeRange === r ? "0 1px 3px rgba(0,0,0,0.10)" : "none",
                  transition: "all 0.15s",
                }}>
                  {r === "custom" ? "Custom" : r}
                </button>
              ))}
            </div>

            {/* Custom date pickers — shown only when "custom" is active */}
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
                <span style={{ fontSize: "12px", color: "#9ca3af" }}>to</span>
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
        </div>

        {stats && attribution && <SecuritySummary stats={stats} attribution={attribution} />}

        {(analytics?.trend?.length ?? 0) > 0 ? (
          <TrendChart data={analytics!.trend} groupBy={groupBy} onGroupByChange={setGroupBy} />
        ) : analytics !== undefined && (
          <div style={{ ...CARD, padding: "48px 24px", textAlign: "center" }}>
            <p style={{ fontSize: "13px", fontWeight: 600, color: "#374151", margin: "0 0 4px 0" }}>No trend data</p>
            <p style={{ fontSize: "12px", color: "#9ca3af", margin: 0 }}>
              No requests recorded in this time window. Try a different range.
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
            title="Department risk ranking"
            emptyText="No department data"
            rows={(attribution?.by_department ?? [])
              .sort((a: any, b: any) => b.block_rate - a.block_rate)
              .slice(0, 8)
              .map((r: any) => ({
                name: deptNames[r.dept_id] || r.dept_id || "No department",
                sub: `${num(r.total)} requests`,
                blockRate: r.block_rate, total: r.total,
              }))}
          />
          <AttributionTable
            title="Application risk ranking"
            emptyText="No application data"
            rows={(attribution?.by_application ?? [])
              .sort((a: any, b: any) => b.block_rate - a.block_rate)
              .slice(0, 8)
              .map((r: any) => ({
                name: appNames[r.app_id] || r.app_id || "No application",
                sub: `${num(r.total)} requests · ${r.avg_latency_ms?.toFixed(0) ?? "—"}ms avg`,
                blockRate: r.block_rate, total: r.total,
              }))}
          />
        </div>

        {(attribution?.by_key?.length ?? 0) > 0 && (
          <AttributionTable
            title="API key activity"
            emptyText="No key data"
            rows={(attribution!.by_key as any[])
              .sort((a, b) => b.total - a.total)
              .slice(0, 10)
              .map(r => ({
                name: r.source || r.key_id || "—",
                sub: `${num(r.total)} requests · ${r.avg_latency_ms?.toFixed(0) ?? "—"}ms avg`,
                blockRate: r.block_rate, total: r.total,
              }))}
          />
        )}

      </div>
    </Shell>
  )
}


