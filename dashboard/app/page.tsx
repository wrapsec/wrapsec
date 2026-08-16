// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { useTranslations } from "next-intl"
import { useFormat } from "@/hooks/useFormat"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import { useState } from "react"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { RangeTabs } from "@/components/ui/RangeTabs"
import { KpiCard } from "@/components/ui/KpiCard"
import { PageSpinner } from "@/components/ui/Spinner"
import { TopThreats } from "@/components/overview/TopThreats"
import { RecentRequests } from "@/components/overview/RecentRequests"
import { RequestDetailModal } from "@/components/requests/RequestDetail"
import { getAuditStats, getAuditLogs, getAttribution, getDepartments, getApplications, getApiKeys } from "@/lib/api"
import { POLL_INTERVAL } from "@/lib/constants"
import { AuditStatsResponse, Department, Application, ApiKeysResponse } from "@/lib/types"
import { useTimeRange } from "@/hooks/useTimeRange"
import { timeAgo } from "@/lib/datetime"

// â”€â”€ Shared styles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const CARD: React.CSSProperties = {
  background: "#fff", border: "1px solid #e5e7eb", borderRadius: "8px",
}

const LABEL: React.CSSProperties = {
  fontSize: "10px", fontWeight: 700, color: "#4b5563",
  textTransform: "uppercase" as const, letterSpacing: "0.08em",
  margin: "0 0 6px 0",
}

// â”€â”€ Row 1: Request summary cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function RequestCards({ stats, from, to }: { stats: AuditStatsResponse; from: string; to: string }) {
  const fmt       = useFormat()
  const t         = useTranslations("pages.overview")
  const tc        = useTranslations("common")
  const total     = stats.total_requests
  // Read the authoritative counts. Reconstructing via round(rate * total)
  // loses precision after the API rounds rate to 4 decimals and drifts
  // by one against /v1/audit/logs?decision=... on deep-link.
  const blocked   = stats.block_count
  const sanitized = stats.sanitize_count
  const allowed   = stats.allow_count

  const pctSub = (rate: number) => t("pct_of_requests", { pct: (rate * 100).toFixed(1) })
  const CARDS = [
    { label: t("total_requests"),   value: total,     sub: tc("all_time"),               color: "#111827", accent: "#670FEF", href: `/requests?from=${from}&to=${to}` },
    { label: tc("decision.blocked"),   value: blocked,   sub: pctSub(stats.block_rate),     color: "#dc2626", accent: "#dc2626", href: `/requests?decision=BLOCK&from=${from}&to=${to}` },
    { label: tc("decision.sanitized"), value: sanitized, sub: pctSub(stats.sanitize_rate),  color: "#d97706", accent: "#f59e0b", href: `/requests?decision=SANITIZE&from=${from}&to=${to}` },
    { label: tc("decision.allowed"),   value: allowed,   sub: pctSub(stats.allow_rate),     color: "#16a34a", accent: "#10b981", href: `/requests?decision=ALLOW&from=${from}&to=${to}` },
  ]

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px" }}>
      {CARDS.map(card => (
        <KpiCard
          key={card.label}
          label={card.label}
          value={fmt.number(card.value)}
          sub={card.sub}
          accent={card.accent}
          valueColor={card.color}
          href={card.href}
        />
      ))}
    </div>
  )
}

// â”€â”€ Row 2: Donut â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function DonutChart({ stats }: { stats: AuditStatsResponse }) {
  const fmt       = useFormat()
  const t         = useTranslations("pages.overview")
  const tc        = useTranslations("common")
  const total     = stats.total_requests
  const blocked   = stats.block_count
  const sanitized = stats.sanitize_count
  const allowed   = stats.allow_count

  // `color` drives the bright arc / legend dot / bar (non-text, no contrast rule);
  // `textColor` is the AA-compliant (>=4.5:1) shade for the small percentage label.
  const SEGMENTS = [
    { value: blocked,   color: "#dc2626", textColor: "#b91c1c", label: tc("decision.blocked"),   pct: stats.block_rate    },
    { value: sanitized, color: "#f59e0b", textColor: "#b45309", label: tc("decision.sanitized"), pct: stats.sanitize_rate },
    { value: allowed,   color: "#10b981", textColor: "#047857", label: tc("decision.allowed"),   pct: stats.allow_rate    },
  ]

  const SIZE = 160, STROKE = 24
  const R    = (SIZE - STROKE) / 2
  const CIRC = 2 * Math.PI * R
  let offset = -CIRC * 0.25
  const arcs = SEGMENTS.map(seg => {
    const dash = (total > 0 ? seg.value / total : 0) * CIRC
    const arc  = { ...seg, dash, gap: CIRC - dash, offset }
    offset    += dash
    return arc
  })

  return (
    <div style={{ ...CARD, padding: "20px", display: "flex", alignItems: "center", gap: "20px" }}>
      <div style={{ position: "relative", flexShrink: 0 }}>
        <svg width={SIZE} height={SIZE}>
          <circle cx={SIZE/2} cy={SIZE/2} r={R} fill="none" stroke="#f3f4f6" strokeWidth={STROKE} />
          {arcs.map((arc, i) => (
            <circle key={i} cx={SIZE/2} cy={SIZE/2} r={R} fill="none"
              stroke={arc.color} strokeWidth={STROKE}
              strokeDasharray={`${arc.dash} ${arc.gap}`}
              strokeDashoffset={-arc.offset} strokeLinecap="butt"
            />
          ))}
        </svg>
        <div style={{ position: "absolute", top: "50%", left: "50%",
          transform: "translate(-50%, -50%)", textAlign: "center" }}>
          <p style={{ fontSize: "20px", fontWeight: 700, color: "#111827", margin: 0, lineHeight: 1 }}>
            {fmt.number(total)}
          </p>
          <p style={{ fontSize: "9px", color: "#4b5563", margin: "3px 0 0 0", fontWeight: 600,
            textTransform: "uppercase", letterSpacing: "0.06em" }}>{t("requests")}</p>
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "14px", flex: 1 }}>
        {SEGMENTS.map(seg => (
          <div key={seg.label}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <div style={{ width: 8, height: 8, borderRadius: "2px", background: seg.color }} />
                <span style={{ fontSize: "11px", color: "#6b7280", fontWeight: 500 }}>{seg.label}</span>
              </div>
              <span style={{ fontSize: "12px", fontWeight: 700, color: seg.textColor }}>
                {(seg.pct * 100).toFixed(1)}%
              </span>
            </div>
            <div style={{ height: "4px", background: "#f3f4f6", borderRadius: "2px", overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${seg.pct * 100}%`, background: seg.color, borderRadius: "2px" }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// â”€â”€ Row 2: Latency card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function LatencyCard({ stats, byReason }: { stats: AuditStatsResponse; byReason: { primary_reason: string; count: number }[] }) {
  const fmt      = useFormat()
  const t        = useTranslations("pages.overview")
  const tc       = useTranslations("common")
  const maxMs    = stats.p95_latency_ms || 1
  const avgPct   = Math.min((stats.avg_latency_ms / maxMs) * 100, 100)

  const ruleML = byReason
    .filter(r => r.primary_reason === "RULE_DETECTOR" || r.primary_reason === "ML_DETECTOR")
    .reduce((s, r) => s + r.count, 0)
  const llm    = byReason.find(r => r.primary_reason === "LLM_DETECTOR")?.count ?? 0
  const pii    = byReason
    .filter(r => r.primary_reason.startsWith("PII_GUARDRAIL"))
    .reduce((s, r) => s + r.count, 0)
  const tox    = byReason
    .filter(r => r.primary_reason.startsWith("TOXICITY_GUARDRAIL"))
    .reduce((s, r) => s + r.count, 0)

  return (
    <div style={{ ...CARD, padding: "20px", display: "flex", flexDirection: "column", gap: "16px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <p style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>{t("latency")}</p>
        <span style={{ fontSize: "11px", color: "#4b5563" }}>{tc("all_time")}</span>
      </div>

      {/* Avg vs P95 visual */}
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
          <span style={{ fontSize: "11px", color: "#4b5563" }}>{t("avg")}</span>
          <span style={{ fontSize: "11px", color: "#4b5563" }}>{t("p95")}</span>
        </div>
        <div style={{ position: "relative", height: "8px", background: "#f3f4f6", borderRadius: "4px", overflow: "hidden" }}>
          <div style={{ height: "100%", width: "100%", background: "#e5e7eb", borderRadius: "4px" }} />
          <div style={{ position: "absolute", top: 0, left: 0, height: "100%",
            width: `${avgPct}%`, background: "#670FEF", borderRadius: "4px" }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: "6px" }}>
          <span style={{ fontSize: "16px", fontWeight: 700, color: "#670FEF" }}>
            {stats.avg_latency_ms.toFixed(0)}ms
          </span>
          <span style={{ fontSize: "16px", fontWeight: 700, color: "#374151" }}>
            {stats.p95_latency_ms.toFixed(0)}ms
          </span>
        </div>
      </div>

      {/* Detection mode breakdown */}
      <div style={{ borderTop: "1px solid #f3f4f6", paddingTop: "14px" }}>
        <p style={{ ...LABEL, marginBottom: "10px" }}>{t("detection_breakdown")}</p>
        {[
          { label: t("breakdown.rule_ml"),  count: ruleML, color: "#670FEF" },
          { label: t("breakdown.llm"),      count: llm,    color: "#CD00FF" },
          { label: t("breakdown.pii"),      count: pii,    color: "#dc2626" },
          { label: t("breakdown.toxicity"), count: tox,    color: "#d97706" },
        ].map(d => (
          <div key={d.label} style={{ display: "flex", alignItems: "center",
            justifyContent: "space-between", marginBottom: "5px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: d.color }} />
              <span style={{ fontSize: "11px", color: "#6b7280" }}>{d.label}</span>
            </div>
            <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#374151", fontWeight: 600 }}>
              {fmt.number(d.count)}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// â”€â”€ Row 3: Infrastructure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function InfrastructureCard({ depts, apps, keys }: { depts: { departments: Department[] } | undefined; apps: { applications: Application[] } | undefined; keys: ApiKeysResponse | undefined }) {
  const t            = useTranslations("pages.overview")
  const deptCount    = depts?.departments?.length ?? 0
  const appCount     = apps?.applications?.length ?? 0
  const allKeys      = keys?.keys ?? []
  const liveKeys     = allKeys.filter((k) => k.key_type === "live").length
  const trialKeys    = allKeys.filter((k) => k.key_type === "trial").length
  const neverUsed    = allKeys.filter((k) => !k.last_used_at).length
  const recentlyUsed = allKeys.filter((k) => {
    if (!k.last_used_at) return false
    // eslint-disable-next-line react-hooks/purity -- read-only "active in last 24h" display metric; Date.now() is a relative-age reference, not state or a security control
    return (Date.now() - new Date(k.last_used_at).getTime()) < 24 * 60 * 60 * 1000
  }).length

  const ROWS = [
    // Colors here render as the value NUMBER text (small), so each meets AA
    // (>=4.5:1 on white); the brand-bright variants stay on dots/borders elsewhere.
    { label: t("infra.departments"), value: deptCount,    color: "#670FEF" },
    { label: t("infra.applications"),value: appCount,     color: "#a21caf" },
    { label: t("infra.live_keys"),   value: liveKeys,     color: "#0369a1" },
    { label: t("infra.trial_keys"),  value: trialKeys,    color: "#4b5563" },
    { label: t("infra.active_24h"),  value: recentlyUsed, color: "#15803d" },
    { label: t("infra.never_used"),  value: neverUsed,    color: "#dc2626" },
  ]

  return (
    <div style={{ ...CARD, padding: "20px" }}>
      <p style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: "0 0 14px 0" }}>
        {t("infrastructure")}
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {ROWS.map(row => (
          <div key={row.label} style={{ display: "flex", alignItems: "center",
            justifyContent: "space-between", padding: "6px 0",
            borderBottom: "1px solid #f9fafb" }}>
            <span style={{ fontSize: "12px", color: "#6b7280", fontWeight: 500 }}>{row.label}</span>
            <span style={{ fontSize: "14px", fontWeight: 700, color: row.color,
              fontVariantNumeric: "tabular-nums" }}>
              {row.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// â”€â”€ Row 3: Detection layers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function DetectionLayersCard({ byReason }: { byReason: { primary_reason: string; count: number }[] }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.overview")
  const total = byReason.reduce((s, r) => s + r.count, 0) || 1

  const LAYERS = [
    { key: "RULE_DETECTOR",              label: t("layers.rule_detector"), color: "#670FEF" },
    { key: "ML_DETECTOR",                label: t("layers.ml_classifier"), color: "#CD00FF" },
    { key: "LLM_DETECTOR",               label: t("layers.llm_semantic"),  color: "#00B1FF" },
    { key: "PII_GUARDRAIL_BLOCK",        label: t("layers.pii_block"),     color: "#dc2626" },
    { key: "PII_GUARDRAIL_SANITIZE",     label: t("layers.pii_sanitize"),  color: "#f97316" },
    { key: "TOXICITY_GUARDRAIL_BLOCK",   label: t("layers.toxicity_block"),color: "#d97706" },
    { key: "NO_THREAT_DETECTED",         label: t("layers.no_threat"),     color: "#10b981" },
  ]

  return (
    <div style={{ ...CARD, padding: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "14px" }}>
        <p style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>{t("detection_layers")}</p>
        <span style={{ fontSize: "11px", color: "#4b5563" }}>{t("how_threats_caught")}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: "9px" }}>
        {LAYERS.map(layer => {
          const count = byReason.find(r => r.primary_reason === layer.key)?.count ?? 0
          const pct   = (count / total) * 100
          return (
            <div key={layer.key}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "3px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: layer.color }} />
                  <span style={{ fontSize: "11px", color: "#6b7280" }}>{layer.label}</span>
                </div>
                <span style={{ fontSize: "11px", fontFamily: "monospace", color: "#374151", fontWeight: 600 }}>
                  {fmt.number(count)}
                </span>
              </div>
              <div style={{ height: "3px", background: "#f3f4f6", borderRadius: "2px", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${Math.min(pct, 100)}%`,
                  background: layer.color, borderRadius: "2px" }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// â”€â”€ Row 3: API key activity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function ApiKeyActivityCard({ keys }: { keys: ApiKeysResponse | undefined }) {
  const t       = useTranslations("pages.overview")
  const tc      = useTranslations("common")
  const allKeys = keys?.keys ?? []

  // eslint-disable-next-line react-hooks/purity -- read-only "active in last 24h/7d" display metrics; Date.now() is a relative-age reference, not state or a security control
  const now = Date.now()
  const active24h = allKeys.filter((k) => k.last_used_at &&
    (now - new Date(k.last_used_at).getTime()) < 24 * 60 * 60 * 1000)
  const active7d  = allKeys.filter((k) => k.last_used_at &&
    (now - new Date(k.last_used_at).getTime()) < 7 * 24 * 60 * 60 * 1000)
  const neverUsed = allKeys.filter((k) => !k.last_used_at)

  return (
    <div style={{ ...CARD, padding: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "14px" }}>
        <p style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>{t("api_key_activity")}</p>
        <span style={{ fontSize: "11px", color: "#4b5563" }}>{t("keys_total", { count: allKeys.length })}</span>
      </div>

      {/* Summary pills */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "14px", flexWrap: "wrap" as const }}>
        {[
          { label: t("active_today", { count: active24h.length }),   color: "#166534", bg: "#f0fdf4", border: "#bbf7d0" },
          { label: t("active_7d", { count: active7d.length }),       color: "#0369a1", bg: "#eff6ff", border: "#bfdbfe" },
          { label: t("never_used_count", { count: neverUsed.length }), color: neverUsed.length > 0 ? "#b45309" : "#4b5563",
            bg: neverUsed.length > 0 ? "#fffbeb" : "#f9fafb",
            border: neverUsed.length > 0 ? "#fde68a" : "#e5e7eb" },
        ].map(pill => (
          <span key={pill.label} style={{
            fontSize: "11px", fontWeight: 600, padding: "2px 8px",
            borderRadius: "20px", color: pill.color,
            background: pill.bg, border: `1px solid ${pill.border}`,
          }}>{pill.label}</span>
        ))}
      </div>

      {/* Key list */}
      <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
        {allKeys.slice(0, 5).map((k) => (
          <div key={k.key_id} style={{ display: "flex", alignItems: "center",
            justifyContent: "space-between", padding: "5px 0",
            borderBottom: "1px solid #f9fafb" }}>
            <div style={{ minWidth: 0 }}>
              <p style={{ fontSize: "12px", fontWeight: 500, color: "#374151",
                margin: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const }}>
                {k.name}
              </p>
              <p style={{ fontSize: "10px", color: "#4b5563", margin: "1px 0 0 0" }}>
                {k.dept_name ?? "-"}
              </p>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", flexShrink: 0 }}>
              <span style={{
                fontSize: "10px", fontWeight: 600, padding: "1px 5px",
                borderRadius: "3px",
                color:      k.key_type === "trial" ? "#b45309" : "#670FEF",
                background: k.key_type === "trial" ? "#fffbeb"  : "rgba(103,15,239,0.06)",
                border:     k.key_type === "trial" ? "1px solid #fde68a" : "1px solid rgba(103,15,239,0.15)",
              }}>
                {k.key_type}
              </span>
              <span style={{ fontSize: "10px", color: k.last_used_at ? "#6b7280" : "#dc2626" }}>
                {k.last_used_at ? timeAgo(k.last_used_at) : tc("never")}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// â”€â”€ Severity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function SeveritySummary({ counts }: { counts: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number } }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.overview")
  const LEVELS: { level: keyof typeof counts; color: string; bg: string; border: string; desc: string }[] = [
    // Text colors meet AA (>=4.5:1) against each level's own tinted background.
    { level: "CRITICAL", color: "#b91c1c", bg: "#fef2f2", border: "#fecaca", desc: t("severity_desc.critical") },
    { level: "HIGH",     color: "#b45309", bg: "#fffbeb", border: "#fde68a", desc: t("severity_desc.high")     },
    { level: "MEDIUM",   color: "#0369a1", bg: "#eff6ff", border: "#bfdbfe", desc: t("severity_desc.medium")   },
    { level: "LOW",      color: "#047857", bg: "#f0fdf4", border: "#bbf7d0", desc: t("severity_desc.low")      },
  ]

  return (
    <div style={{ ...CARD, padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "14px" }}>
        <p style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>{t("severity_breakdown")}</p>
        <span style={{ fontSize: "11px", color: "#4b5563" }}>{t("siem_note")}</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "10px" }}>
        {LEVELS.map(l => (
          <div key={l.level} style={{ padding: "12px 14px", borderRadius: "7px",
            background: l.bg, border: `1px solid ${l.border}` }}>
            <p style={{ fontSize: "10px", fontWeight: 700, color: l.color,
              textTransform: "uppercase", letterSpacing: "0.07em", margin: "0 0 4px 0" }}>
              {l.level}
            </p>
            <p style={{ fontSize: "22px", fontWeight: 700, color: l.color,
              margin: "0 0 2px 0", lineHeight: 1 }}>
              {fmt.number(counts[l.level])}
            </p>
            <p style={{ fontSize: "11px", color: l.color, margin: 0 }}>{l.desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// â”€â”€ Page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export default function OverviewPage() {
  const t = useTranslations("pages.overview")
  const { resolve } = useErrorMessage()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  // Time range controls request cards, donut, threats, severity
  // Infrastructure, latency, detection layers, API keys stay all-time
  const { range, setRange, options, from, to } = useTimeRange({
    defaultRange: "24h",
    options:      ["24h", "7d", "30d"],
  })

  const { data: stats,  isLoading: statsLoading, error: statsError } = useSWR(["overview-stats", from, to], () => getAuditStats({ from, to }),           { refreshInterval: POLL_INTERVAL })
  const { data: logs                            } = useSWR("overview-logs",              () => getAuditLogs({ limit: 10, offset: 0 }), { refreshInterval: POLL_INTERVAL })
  const { data: attribution                     } = useSWR("overview-attribution",        () => getAttribution(),                       { refreshInterval: POLL_INTERVAL })
  const { data: depts                           } = useSWR("overview-depts",              getDepartments,                               { refreshInterval: POLL_INTERVAL })
  const { data: apps                            } = useSWR("overview-apps",               getApplications,                              { refreshInterval: POLL_INTERVAL })
  const { data: keys                            } = useSWR("overview-keys",               getApiKeys,                                   { refreshInterval: POLL_INTERVAL })

  const sev      = stats?.severity_counts  ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  const byReason = attribution?.by_primary_reason ?? []

  if (statsLoading && !stats) {
    return <Shell title={t("title")}><PageSpinner /></Shell>
  }

  if (statsError && !stats) {
    return (
      <Shell title={t("title")}>
        <div className="max-w-2xl">
          <div className="bg-red-50 border border-red-200 rounded-xl p-5">
            <p className="text-sm font-semibold text-red-700 mb-1">{t("load_error")}</p>
            <p className="text-xs text-red-500">{resolve(statsError).message}</p>
          </div>
        </div>
      </Shell>
    )
  }

  return (
    <Shell title={t("title")}>
      <PageHeader
        description={t("description")}
        actions={<RangeTabs options={options} value={range} onChange={setRange} />}
      />
      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

        {/* Row 1 - Request summary (time-scoped) */}
        {stats
          ? <RequestCards stats={stats} from={from} to={to} />
          : <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "14px" }}>
              {[0,1,2,3].map(i => (
                <div key={i} style={{ border: "1px solid #e5e7eb",
                  borderRadius: "8px", padding: "16px 20px", height: "88px",
                  background: "linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%)",
                  backgroundSize: "200% 100%",
                  animation: "shimmer 1.5s infinite",
                }} />
              ))}
              {/* eslint-disable-next-line react/jsx-no-literals -- CSS keyframes, not localizable text */}
              <style>{`@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}`}</style>
            </div>
        }

        {/* Row 2 - Donut + Threats (scrollable) + Latency */}
        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr 0.9fr", gap: "16px", alignItems: "stretch" }}>
            <DonutChart stats={stats} />
            <TopThreats threats={stats.top_threats} from={from} to={to} />
            <LatencyCard stats={stats} byReason={byReason} />
          </div>
        )}

        {/* Row 3 - Infrastructure + Detection layers + API key activity */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr 1.4fr", gap: "16px" }}>
          <InfrastructureCard depts={depts} apps={apps} keys={keys} />
          <DetectionLayersCard byReason={byReason} />
          <ApiKeyActivityCard keys={keys} />
        </div>

        {/* Row 4 - Recent requests */}
        <RecentRequests
          items={logs?.items ?? []}
          onSelect={id => setSelectedId(id)}
        />

        {/* Row 5 - Severity (secondary) */}
        {stats && <SeveritySummary counts={sev} />}

      </div>

      {selectedId && (
        <RequestDetailModal
          traceId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </Shell>
  )
}


