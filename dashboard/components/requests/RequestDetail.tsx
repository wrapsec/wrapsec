// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { RequestDetail } from "@/lib/types"
import { getRequest } from "@/lib/api"
import { DecisionBadge, ThreatBadge, SourceBadge, SeverityBadge } from "@/components/ui/Badge"
import { CopyButton } from "@/components/ui/CopyButton"
import { Spinner } from "@/components/ui/Spinner"
import { Drawer } from "@/components/ui/Drawer"
import { Tabs, TabDef } from "@/components/ui/Tabs"
import { DetailGrid, DetailRow, SectionLabel } from "@/components/ui/DetailRow"
import { formatTimestamp } from "@/lib/datetime"
import { formatScore, formatLatency, truncateId, formatRun } from "@/lib/format"
import { primaryReasonLabel, contentSourceLabel, contentSourceTier } from "@/lib/constants"

interface RequestDetailModalProps {
  traceId: string
  onClose: () => void
}

const TRUST_TIER_LABELS: Record<string, string> = {
  trusted:   "Trusted origin",
  untrusted: "Untrusted origin - indirect injection surface",
  unknown:   "Unknown origin",
}

// Per-layer presentation for the Security Assessment list. Kept here (not in the
// shared constants) because the colors are drawer-visual, not domain labels.
const DETECTION_LAYERS = [
  { key: "rule", label: "Rule detector",         color: "#3b82f6" },
  { key: "ml",   label: "ML classifier",         color: "#8b5cf6" },
  { key: "llm",  label: "LLM semantic analysis", color: "#f59e0b" },
] as const

const GUARDRAIL_META: Record<string, { label: string; color: string }> = {
  pii:      { label: "PII guardrail",      color: "#ec4899" },
  toxicity: { label: "Toxicity guardrail", color: "#f97316" },
}

function riskColor(score: number): string {
  return score >= 0.7 ? "#dc2626" : score >= 0.4 ? "#d97706" : "#16a34a"
}

// --- Small building blocks ---------------------------------------------------

function ScoreBar({ score, color }: { score: number; color: string }) {
  return (
    <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
      <div className="h-full rounded-full" style={{ width: `${Math.round(score * 100)}%`, backgroundColor: color }} />
    </div>
  )
}

function DecisionChip({ label, decision }: { label: string; decision: string | null }) {
  return (
    <div className="flex flex-col gap-1">
      <p className="text-[11px] text-slate-400">{label}</p>
      {decision
        ? <DecisionBadge decision={decision as any} size="sm" />
        : <span className="text-xs text-slate-300">--</span>}
    </div>
  )
}

function StatusChip({ status }: { status: string }) {
  const colors: Record<string, string> = {
    SUCCESS:        "bg-green-50 text-green-700 border-green-200",
    BLOCKED:        "bg-red-50 text-red-700 border-red-200",
    OUTPUT_BLOCKED: "bg-orange-50 text-orange-700 border-orange-200",
    FAILED:         "bg-red-50 text-red-600 border-red-200",
    TIMEOUT:        "bg-yellow-50 text-yellow-700 border-yellow-200",
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors[status] ?? "bg-slate-50 text-slate-600 border-slate-200"}`}>
      {status}
    </span>
  )
}

function RawBlock({ label, value, note, open = false }: {
  label: string; value: string | null; note?: string; open?: boolean
}) {
  if (!value) return null
  return (
    <details open={open} className="group">
      <summary className="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-500 mb-1.5 list-none">
        <svg className="w-3 h-3 transition-transform group-open:rotate-90" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        {label}
        {note && <span className="text-yellow-600 font-normal">{note}</span>}
      </summary>
      <div className="bg-slate-50 border border-slate-100 rounded-lg px-3 py-2.5 text-xs text-slate-700 font-mono whitespace-pre-wrap break-words max-h-64 overflow-y-auto">
        {value}
      </div>
    </details>
  )
}

// --- Tab bodies --------------------------------------------------------------

function OverviewTab({ detail }: { detail: RequestDetail }) {
  const hasAgent = Boolean(detail.run_id || detail.session_id || detail.turn_index != null)
  const a = detail.attribution
  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Summary</SectionLabel>
        <DetailGrid>
          <DetailRow label="Confidence">
            {detail.confidence !== null
              ? <span className="inline-flex items-center gap-1.5">
                  {Math.round((detail.confidence ?? 0) * 100)}%
                  {detail.confidence_band && (
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                      detail.confidence_band === "HIGH"   ? "bg-green-50 text-green-700 border border-green-200"
                      : detail.confidence_band === "MEDIUM" ? "bg-amber-50 text-amber-700 border border-amber-200"
                      : "bg-red-50 text-red-700 border border-red-200"
                    }`}>{detail.confidence_band}</span>
                  )}
                </span>
              : "--"}
          </DetailRow>
          <DetailRow label="Latency">{formatLatency(detail.processing.latency_ms)}</DetailRow>
          <DetailRow label="Primary reason" span>{primaryReasonLabel(detail.primary_reason)}</DetailRow>
          <DetailRow label="Detection mode">{detail.processing.detection_mode}</DetailRow>
          <DetailRow label="Execution mode">{detail.processing.execution_mode}</DetailRow>
          <DetailRow label="LLM invoked">{detail.processing.llm_invoked ? "Yes" : "No"}</DetailRow>
          <DetailRow label="Input length">
            {detail.input_length != null ? `${detail.input_length} chars` : "--"}
          </DetailRow>
        </DetailGrid>
      </div>

      {hasAgent && (
        <div>
          <SectionLabel>Agent Context</SectionLabel>
          <DetailGrid>
            <DetailRow label="Run" mono>{detail.run_id || "--"}</DetailRow>
            <DetailRow label="Turn">{detail.turn_index != null ? String(detail.turn_index) : "--"}</DetailRow>
            <DetailRow label="Session" mono span>{detail.session_id || "--"}</DetailRow>
          </DetailGrid>
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-3">
          <SectionLabel>Attribution</SectionLabel>
          <span className={`text-[11px] px-2 py-0.5 rounded-full ${
            a.attribution_verified
              ? "bg-green-50 text-green-700 border border-green-200"
              : "bg-amber-50 text-amber-700 border border-amber-200"
          }`}>
            {a.attribution_verified ? "Verified" : "Self-reported"}
          </span>
        </div>
        <DetailGrid>
          <DetailRow label="Source">{a.source || "--"}</DetailRow>
          <DetailRow label="Key ID" mono>{a.key_id || "--"}</DetailRow>
          <DetailRow label="Department">{a.dept_name || a.dept_id || "--"}</DetailRow>
          <DetailRow label="Application">{a.app_name || a.app_id || "--"}</DetailRow>
          <DetailRow label="User ID" mono>{a.user_id || "--"}</DetailRow>
          <DetailRow label="IP address" mono>{a.ip_address || "--"}</DetailRow>
          <DetailRow label="Input hash" mono span>{detail.input_hash}</DetailRow>
        </DetailGrid>
      </div>
    </div>
  )
}

function AssessmentTab({ detail }: { detail: RequestDetail }) {
  // One list of scored contributions, highest-first: the "why was this decided?"
  // answer. Detection layers plus any triggered guardrail.
  const contributions = [
    ...DETECTION_LAYERS.map(m => ({
      label: m.label,
      color: m.color,
      score: detail.detection_scores?.[m.key as keyof typeof detail.detection_scores] ?? 0,
    })),
    ...Object.entries(detail.guardrail_scores || {}).map(([k, v]) => ({
      label: GUARDRAIL_META[k]?.label ?? k,
      color: GUARDRAIL_META[k]?.color ?? "#94a3b8",
      score: (v as number) ?? 0,
    })),
  ].sort((x, y) => y.score - x.score)

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-3">
          <SectionLabel>Layer contributions</SectionLabel>
          <span className="text-[11px] text-slate-400 mb-3">({detail.processing.detection_mode} mode)</span>
        </div>
        <div className="space-y-3">
          {contributions.map(c => (
            <div key={c.label}>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: c.color }} />
                  <span className="text-sm text-slate-700">{c.label}</span>
                </div>
                <span className="text-xs font-mono text-slate-600">{formatScore(c.score)}</span>
              </div>
              <ScoreBar score={c.score} color={c.color} />
            </div>
          ))}
        </div>
      </div>

      {detail.threats.length > 0 && (
        <div>
          <SectionLabel>Threats detected</SectionLabel>
          <div className="flex flex-wrap gap-2">
            {detail.threats.map(t => <ThreatBadge key={t} threat={t} />)}
          </div>
        </div>
      )}
    </div>
  )
}

function ContentContextTab({ detail }: { detail: RequestDetail }) {
  const tier = contentSourceTier(detail.input_source)
  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>Content Context</SectionLabel>
        <div className="flex items-center gap-3 flex-wrap mb-4">
          <SourceBadge source={detail.input_source} />
          <span className="text-xs text-slate-500">{TRUST_TIER_LABELS[tier]}</span>
        </div>
        <DetailGrid>
          <DetailRow label="Content source">{contentSourceLabel(detail.input_source)}</DetailRow>
          <DetailRow label="Trust boundary">{tier}</DetailRow>
        </DetailGrid>
      </div>
    </div>
  )
}

function ProxyTab({ detail }: { detail: RequestDetail }) {
  const p = detail.proxy!
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-3">
        <DecisionChip label="Input decision"  decision={detail.decision} />
        <DecisionChip label="Output decision" decision={p.output_decision} />
        <div className="flex flex-col gap-1">
          <p className="text-[11px] text-slate-400">Execution status</p>
          <div className="w-fit"><StatusChip status={p.execution_status} /></div>
        </div>
      </div>
      <DetailGrid>
        <DetailRow label="Provider">{p.provider || "--"}</DetailRow>
        <DetailRow label="Model">{p.model || "--"}</DetailRow>
        <DetailRow label="Provider latency">
          {p.provider_latency_ms != null ? `${p.provider_latency_ms}ms` : "--"}
        </DetailRow>
        <DetailRow label="Attack type">{p.input_attack_type || "--"}</DetailRow>
      </DetailGrid>
      {p.output_threats && p.output_threats.length > 0 && (
        <div>
          <SectionLabel>Output threats detected</SectionLabel>
          <div className="flex flex-wrap gap-1">
            {p.output_threats.map((t: string) => (
              <span key={t} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-pink-50 text-pink-700 border border-pink-200">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function RawTab({ detail }: { detail: RequestDetail }) {
  const p = detail.proxy!
  const inputRedacted  = Boolean(p.input_sanitized && p.input_sanitized !== p.input_raw)
  const outputRedacted = Boolean(p.output_sanitized && p.output_sanitized !== p.output_raw)
  return (
    <div className="space-y-3">
      <RawBlock label="Input - what the user sent" value={p.input_raw} open />
      {inputRedacted && (
        <RawBlock label="Input - what the provider received" value={p.input_sanitized} note="(PII redacted)" />
      )}
      <RawBlock label="Output - what the provider returned" value={p.output_raw} />
      {outputRedacted && (
        <RawBlock label="Output - what the client received" value={p.output_sanitized} note="(PII redacted)" />
      )}
    </div>
  )
}

// --- Drawer ------------------------------------------------------------------

export function RequestDetailModal({ traceId, onClose }: RequestDetailModalProps) {
  const [detail,  setDetail]  = useState<RequestDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)
  const [tab,     setTab]     = useState("overview")

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const data = await getRequest(traceId)
        if (!cancelled) setDetail(data)
      } catch (e: any) {
        if (!cancelled) setError(e.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [traceId])

  const hasRaw = Boolean(detail?.proxy && (detail.proxy.input_raw || detail.proxy.output_raw))

  const header = (
    <div className="px-6 py-4 pr-12">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold text-slate-900">Request Detail</h2>
        {detail?.is_proxy && (
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium border border-violet-200 bg-violet-50 text-violet-700">
            proxy
          </span>
        )}
      </div>
    </div>
  )

  const footer = detail ? (
    <div className="px-6 py-3 flex items-center gap-2 flex-wrap">
      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide mr-1">
        Recommended actions
      </span>
      {detail.run_id && (
        <ActionButton href={`/agent-runs/${encodeURIComponent(detail.run_id)}`}>
          Open Agent Run
        </ActionButton>
      )}
      {hasRaw && (
        <ActionButton onClick={() => setTab("raw")}>View Raw Request</ActionButton>
      )}
      <ActionButton onClick={() => navigator.clipboard?.writeText(traceId)}>
        Copy Trace ID
      </ActionButton>
    </div>
  ) : undefined

  const tabs: TabDef[] = detail ? [
    { id: "overview",   label: "Overview",            render: () => <OverviewTab detail={detail} /> },
    { id: "assessment", label: "Security Assessment", render: () => <AssessmentTab detail={detail} /> },
    { id: "content",    label: "Content Context",     render: () => <ContentContextTab detail={detail} /> },
    { id: "proxy",      label: "Proxy",  visible: Boolean(detail.is_proxy && detail.proxy), render: () => <ProxyTab detail={detail} /> },
    { id: "raw",        label: "Raw",    visible: hasRaw,                                    render: () => <RawTab detail={detail} /> },
  ] : []

  return (
    <Drawer onClose={onClose} header={header} footer={footer} label="Request detail">
      {loading && (
        <div className="flex items-center justify-center py-16">
          <Spinner className="h-6 w-6" />
        </div>
      )}

      {error && (
        <div className="m-6 px-4 py-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}

      {detail && (
        <>
          {/* Decision hero: Decision -> Risk (primary, horizontal bar) -> Severity */}
          <div className="px-6 pt-5 pb-5 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <DecisionBadge decision={detail.decision} />
              {detail.proxy?.output_decision && detail.proxy.output_decision !== detail.decision && (
                <>
                  <span className="text-[11px] text-slate-400">-&gt;</span>
                  <DecisionBadge decision={detail.proxy.output_decision as any} />
                </>
              )}
            </div>

            <div className="mt-4">
              <div className="flex items-baseline justify-between mb-1.5">
                <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wide">Risk score</span>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold tabular-nums" style={{ color: riskColor(detail.risk_score) }}>
                    {formatScore(detail.risk_score)}
                  </span>
                  <SeverityBadge severity={detail.severity} />
                </div>
              </div>
              <ScoreBar score={detail.risk_score} color={riskColor(detail.risk_score)} />
            </div>

            <div className="mt-4 flex items-center gap-2 flex-wrap text-xs text-slate-500">
              <span className="font-mono text-slate-600">{truncateId(traceId)}</span>
              <CopyButton value={traceId} title="Copy trace id" />
              <span className="text-slate-300">.</span>
              <span>{formatTimestamp(detail.timestamp)}</span>
              <SourceBadge source={detail.input_source} />
              {detail.run_id && (
                <>
                  <span className="text-slate-300">.</span>
                  <span>{formatRun(detail.run_id, detail.turn_index)}</span>
                </>
              )}
            </div>
          </div>

          <Tabs tabs={tabs} activeId={tab} onChange={setTab} />
        </>
      )}
    </Drawer>
  )
}

// --- Recommended-action button ----------------------------------------------

function ActionButton({ href, onClick, children }: {
  href?: string; onClick?: () => void; children: React.ReactNode
}) {
  const cls = "inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-slate-200 text-xs font-medium text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors"
  if (href) return <Link href={href} className={cls}>{children}</Link>
  return <button type="button" onClick={onClick} className={cls}>{children}</button>
}
