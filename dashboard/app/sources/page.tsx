// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { useTimeRange } from "@/hooks/useTimeRange"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { PageSpinner } from "@/components/ui/Spinner"
import { getBySource } from "@/lib/api"
import { SourceStats, AttackOrigin } from "@/lib/types"
import { DECISION_COLORS, THREAT_LABELS } from "@/lib/constants"
import { formatNumber } from "@/lib/format"

// Provenance display metadata. Trust tiers mirror the shipped default config
// (config/settings.py); they are a visual hint only -- policy still lives on the
// backend. An unrecognized source falls back to a title-cased label / unknown.
const SOURCE_LABELS: Record<string, string> = {
  user_prompt:        "User Prompt",
  retrieved_document: "Retrieved Document",
  tool_output:        "Tool Output",
  external_content:   "External Content",
}
const TRUSTED   = new Set(["user_prompt"])
const UNTRUSTED = new Set(["tool_output", "retrieved_document", "external_content"])

function sourceLabel(s: string): string {
  return SOURCE_LABELS[s] ?? s.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())
}
function trustTier(s: string): "trusted" | "untrusted" | "unknown" {
  if (TRUSTED.has(s))   return "trusted"
  if (UNTRUSTED.has(s)) return "untrusted"
  return "unknown"
}
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
const STAT_VALUE: React.CSSProperties = {
  fontSize: "18px",
  fontWeight: 700,
  color: "#111827",
}

// --- Top Attack Origins -------------------------------------------------------

function TopAttackOrigins({ origins }: { origins: AttackOrigin[] }) {
  if (origins.length === 0) {
    return (
      <div style={CARD}>
        <p style={SECTION_LABEL}>Top Attack Origins</p>
        <p style={{ fontSize: "13px", color: "#9ca3af", margin: 0 }}>
          No attacks recorded in this window.
        </p>
      </div>
    )
  }
  const max = Math.max(...origins.map(o => o.attacks), 1)
  return (
    <div style={CARD}>
      <p style={SECTION_LABEL}>Top Attack Origins</p>
      <p style={{ fontSize: "12px", color: "#6b7280", margin: "0 0 16px" }}>
        Where attacks are coming from -- sources ranked by blocked and sanitized volume.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        {origins.map((o, i) => (
          <div key={o.input_source} style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div style={{ width: "22px", fontSize: "13px", fontWeight: 700, color: "#9ca3af" }}>
              {i + 1}
            </div>
            <div style={{ width: "170px", fontSize: "13px", fontWeight: 600, color: "#111827" }}>
              {sourceLabel(o.input_source)}
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
              {formatNumber(o.attacks)}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// --- Decision mix bar ---------------------------------------------------------

function DecisionMix({ s }: { s: SourceStats }) {
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
              {x.value} {x.key.toLowerCase()}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// --- Per-source card ----------------------------------------------------------

function SourceCard({ s }: { s: SourceStats }) {
  const tier   = trustTier(s.input_source)
  const badge  = TIER_STYLE[tier]
  const threatEntries = Object.entries(s.threats).sort((a, b) => b[1] - a[1])
  return (
    <div style={CARD}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <div style={{ fontSize: "15px", fontWeight: 700, color: "#111827" }}>
          {sourceLabel(s.input_source)}
        </div>
        <span style={{
          fontSize: "10px", fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase",
          padding: "3px 8px", borderRadius: "5px",
          color: badge.text, background: badge.bg, border: `1px solid ${badge.border}`,
        }}>
          {tier}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "16px" }}>
        <div>
          <div style={STAT_LABEL}>Scans</div>
          <div style={STAT_VALUE}>{formatNumber(s.total)}</div>
        </div>
        <div>
          <div style={STAT_LABEL}>Block Rate</div>
          <div style={STAT_VALUE}>{(s.block_rate * 100).toFixed(1)}%</div>
        </div>
        <div>
          <div style={STAT_LABEL}>Avg / Peak Risk</div>
          <div style={STAT_VALUE}>{s.avg_risk.toFixed(2)} <span style={{ fontSize: "12px", color: "#9ca3af", fontWeight: 600 }}>/ {s.max_risk.toFixed(2)}</span></div>
        </div>
        <div>
          <div style={STAT_LABEL}>High Risk</div>
          <div style={STAT_VALUE}>{formatNumber(s.high_risk_count)}</div>
        </div>
      </div>

      <div style={{ marginBottom: threatEntries.length ? "16px" : 0 }}>
        <div style={{ ...STAT_LABEL, marginBottom: "8px" }}>Decisions</div>
        <DecisionMix s={s} />
      </div>

      {threatEntries.length > 0 && (
        <div>
          <div style={{ ...STAT_LABEL, marginBottom: "8px" }}>Threats by Source</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
            {threatEntries.map(([cat, count]) => (
              <span key={cat} style={{
                fontSize: "11px", fontWeight: 600, color: "#7c2d12",
                background: "#fff7ed", border: "1px solid #fed7aa",
                padding: "3px 8px", borderRadius: "5px",
              }}>
                {THREAT_LABELS[cat] ?? cat} <span style={{ color: "#c2410c" }}>{count}</span>
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
    return <Shell title="Security by Source"><PageSpinner /></Shell>
  }
  if (error && !data) {
    return (
      <Shell title="Security by Source">
        <div className="max-w-2xl">
          <div className="bg-red-50 border border-red-200 rounded-xl p-5">
            <p className="text-sm font-semibold text-red-700 mb-1">Failed to load source analytics</p>
            <p className="text-xs text-red-500">{error?.message ?? "An unexpected error occurred"}</p>
          </div>
        </div>
      </Shell>
    )
  }

  const sources = data?.sources ?? []
  const origins = data?.top_attack_origins ?? []

  return (
    <Shell title="Security by Source">
      <PageHeader
        description="Threat picture by trust-boundary provenance -- which knowledge sources deliver attacks."
        actions={
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
                {r}
              </button>
            ))}
          </div>
        }
      />
      <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>

        {sources.length === 0 ? (
          <div style={{ ...CARD, textAlign: "center", padding: "48px 20px" }}>
            <p style={{ fontSize: "14px", color: "#6b7280", margin: 0 }}>
              No requests recorded in this time window. Try a different range.
            </p>
          </div>
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
