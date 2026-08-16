// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { useTranslations } from "next-intl"
import { useTimeRange } from "@/hooks/useTimeRange"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { RangeTabs } from "@/components/ui/RangeTabs"
import { StatCard } from "@/components/ui/StatCard"
import { EmptyState } from "@/components/ui/EmptyState"
import { ErrorState } from "@/components/ui/ErrorState"
import { Card } from "@/components/ui/Card"
import { PageSpinner } from "@/components/ui/Spinner"
import { getBySource } from "@/lib/api"
import { SourceStats, AttackOrigin } from "@/lib/types"
import { DECISION_COLORS, contentSourceLabel, contentSourceTier } from "@/lib/constants"
import { useFormat } from "@/hooks/useFormat"

// Content-source labels + trust tiers come from the centralized constants
// (lib/constants.ts) so the table, drawer, and this page stay in sync. TIER_STYLE
// is this page's local visual mapping for the tier badge.
const TIER_STYLE: Record<string, { text: string; bg: string; border: string }> = {
  untrusted: { text: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
  trusted:   { text: "#16a34a", bg: "#f0fdf4", border: "#bbf7d0" },
  unknown:   { text: "#6b7280", bg: "#f9fafb", border: "#e5e7eb" },
}

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
  textTransform: "uppercase",
  color: "#9ca3af",
  marginBottom: "12px",
  marginTop: 0,
}
const STAT_LABEL: React.CSSProperties = {
  fontSize: "10px",
  fontWeight: 600,
  letterSpacing: "0.05em",
  textTransform: "uppercase",
  color: "#9ca3af",
}

// --- Top Attack Origins -------------------------------------------------------

function TopAttackOrigins({ origins }: { origins: AttackOrigin[] }) {
  const fmt = useFormat()
  const t   = useTranslations("pages.sources.origins")
  if (origins.length === 0) {
    return (
      <div style={CARD}>
        <p style={SECTION_LABEL}>{t("title")}</p>
        <p style={{ fontSize: "13px", color: "#9ca3af", margin: 0 }}>
          {t("empty")}
        </p>
      </div>
    )
  }
  const max = Math.max(...origins.map(o => o.attacks), 1)
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>{t("title")}</p>
      <p style={{ fontSize: "12px", color: "#6b7280", margin: "0 0 16px" }}>
        {t("subtitle")}
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {origins.map((o, i) => (
          <div key={o.input_source} style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div style={{ width: "22px", fontSize: "13px", fontWeight: 700, color: "#9ca3af" }}>
              {i + 1}
            </div>
            <div style={{ width: "170px", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
              {contentSourceLabel(o.input_source)}
            </div>
            <div style={{ flex: 1, background: "#f3f4f6", borderRadius: "5px", height: "22px", overflow: "hidden" }}>
              <div style={{
                width: `${(o.attacks / max) * 100}%`,
                height: "100%",
                background: "#dc2626",
                borderRadius: "5px",
                minWidth: "2px",
                transition: "width 0.3s",
              }} />
            </div>
            <div style={{ width: "60px", textAlign: "right", fontSize: "13px", fontWeight: 700, color: "#111827" }}>
              {fmt.number(o.attacks)}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// --- Decision mix bar ---------------------------------------------------------

function DecisionMix({ s }: { s: SourceStats }) {
  const t     = useTranslations("pages.sources.mix_word")
  const total = s.total || 1
  const seg = [
    { key: "BLOCK",    value: s.blocked,   color: DECISION_COLORS.BLOCK.text },
    { key: "SANITIZE", value: s.sanitized, color: DECISION_COLORS.SANITIZE.text },
    { key: "ALLOW",    value: s.allowed,   color: DECISION_COLORS.ALLOW.text },
  ]
  return (
    <div>
      <div style={{ display: "flex", height: "8px", borderRadius: "4px", overflow: "hidden", background: "#f3f4f6" }}>
        {seg.map(x => x.value > 0 && (
          <div key={x.key} title={`${x.key}: ${x.value}`} style={{ width: `${(x.value / total) * 100}%`, background: x.color }} />
        ))}
      </div>
      <div style={{ display: "flex", gap: "14px", marginTop: "8px" }}>
        {seg.map(x => (
          <div key={x.key} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
            <span style={{ width: "8px", height: "8px", borderRadius: "2px", background: x.color }} />
            <span style={{ fontSize: "11px", color: "#6b7280" }}>
              {x.value} {t(x.key)}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// --- Per-source card ----------------------------------------------------------

function SourceCard({ s }: { s: SourceStats }) {
  const fmt    = useFormat()
  const t      = useTranslations("pages.sources.card")
  const tt     = useTranslations("common.trust_tier")
  const tc     = useTranslations("common.threat_category")
  const tier   = contentSourceTier(s.input_source)
  const badge  = TIER_STYLE[tier]
  const threatEntries = Object.entries(s.threats).sort((a, b) => b[1] - a[1])
  return (
    <div style={CARD}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <div style={{ fontSize: "15px", fontWeight: 700, color: "#111827" }}>
          {contentSourceLabel(s.input_source)}
        </div>
        <span style={{
          fontSize: "10px", fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase",
          padding: "3px 8px", borderRadius: "5px",
          color: badge.text, background: badge.bg, border: `1px solid ${badge.border}`,
        }}>
          {tt.has(tier) ? tt(tier) : tier}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "16px" }}>
        <StatCard label={t("scans")} value={fmt.number(s.total)} />
        <StatCard label={t("block_rate")} value={`${(s.block_rate * 100).toFixed(1)}%`} />
        <StatCard
          label={t("avg_peak_risk")}
          value={<>{s.avg_risk.toFixed(2)} <span className="text-xs text-slate-600 font-semibold">/ {s.max_risk.toFixed(2)}</span></>}
        />
        <StatCard label={t("high_risk")} value={fmt.number(s.high_risk_count)} />
      </div>

      <div style={{ marginBottom: threatEntries.length ? "16px" : 0 }}>
        <div style={{ ...STAT_LABEL, marginBottom: "8px" }}>{t("decisions")}</div>
        <DecisionMix s={s} />
      </div>

      {threatEntries.length > 0 && (
        <div>
          <div style={{ ...STAT_LABEL, marginBottom: "8px" }}>{t("threats_by_source")}</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
            {threatEntries.map(([cat, count]) => (
              <span key={cat} style={{
                fontSize: "11px", fontWeight: 600, color: "#7c2d12",
                background: "#fff7ed", border: "1px solid #fed7aa",
                padding: "3px 8px", borderRadius: "5px",
              }}>
                {tc.has(cat) ? tc(cat) : cat} <span style={{ color: "#c2410c" }}>{count}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// --- Page ---------------------------------------------------------------------

export default function SourcesPage() {
  const t = useTranslations("pages.sources")
  const {
    range: timeRange, setRange: setTimeRange, options: timeRangeOptions, from, to,
  } = useTimeRange({
    defaultRange: "7d",
    options:      ["24h", "7d", "30d", "90d"],
  })

  const { data, isLoading, error } = useSWR(
    ["by-source", from, to],
    () => getBySource({ from, to }),
    { refreshInterval: 5 * 60 * 1000, revalidateOnFocus: false },
  )

  if (isLoading && !data) {
    return <Shell title={t("title")}><PageSpinner /></Shell>
  }
  if (error && !data) {
    return (
      <Shell title={t("title")}>
        <PageHeader description={t("description")} />
        <Card>
          <ErrorState title={t("load_error")} message={error?.message} />
        </Card>
      </Shell>
    )
  }

  const sources = data?.sources ?? []
  const origins = data?.top_attack_origins ?? []

  return (
    <Shell title={t("title")}>
      <PageHeader
        description={t("description")}
        actions={<RangeTabs options={timeRangeOptions} value={timeRange} onChange={setTimeRange} />}
      />
      <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>

        {sources.length === 0 ? (
          <Card>
            <EmptyState
              title={t("empty_title")}
              message={t("empty_body")}
            />
          </Card>
        ) : (
          <>
            <TopAttackOrigins origins={origins} />
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(420px, 1fr))", gap: "16px" }}>
              {sources.map(s => <SourceCard key={s.input_source} s={s} />)}
            </div>
          </>
        )}
      </div>
    </Shell>
  )
}
