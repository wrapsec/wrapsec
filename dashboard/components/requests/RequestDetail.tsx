// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect, useState } from "react"
import { useTranslations } from "next-intl"
import Link from "next/link"
import { RequestDetail, Decision } from "@/lib/types"
import { getRequest } from "@/lib/api"
import { DecisionBadge, ThreatBadge, SourceBadge, SeverityBadge } from "@/components/ui/Badge"
import { CopyButton } from "@/components/ui/CopyButton"
import { Spinner } from "@/components/ui/Spinner"
import { Drawer } from "@/components/ui/Drawer"
import { Tabs, TabDef } from "@/components/ui/Tabs"
import { DetailGrid, DetailRow, SectionLabel } from "@/components/ui/DetailRow"
import { useFormat } from "@/hooks/useFormat"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import { formatScore, formatLatency, truncateId, formatRun } from "@/lib/format"
import { primaryReasonLabel, contentSourceLabel, contentSourceTier } from "@/lib/constants"

interface RequestDetailModalProps {
  traceId: string
  onClose: () => void
}

// Per-layer presentation for the Security Assessment list. Colors are
// drawer-visual; labels resolve from pages.requests.detail.layers/guardrails via
// t() at render (t is a hook, so it cannot run at module scope).
const DETECTION_LAYERS = [
  { key: "rule", color: "#3b82f6" },
  { key: "ml",   color: "#8b5cf6" },
  { key: "llm",  color: "#f59e0b" },
] as const

const GUARDRAIL_COLORS: Record<string, string> = {
  pii:      "#ec4899",
  toxicity: "#f97316",
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
        ? <DecisionBadge decision={decision as Decision} size="sm" />
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
  const t = useTranslations("pages.requests.detail")
  const hasAgent = Boolean(detail.run_id || detail.session_id || detail.turn_index != null)
  const a = detail.attribution
  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>{t("summary")}</SectionLabel>
        <DetailGrid>
          <DetailRow label={t("confidence")}>
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
          <DetailRow label={t("latency")}>{formatLatency(detail.processing.latency_ms)}</DetailRow>
          <DetailRow label={t("primary_reason")} span>{primaryReasonLabel(detail.primary_reason)}</DetailRow>
          <DetailRow label={t("detection_mode")}>{detail.processing.detection_mode}</DetailRow>
          <DetailRow label={t("execution_mode")}>{detail.processing.execution_mode}</DetailRow>
          <DetailRow label={t("llm_invoked")}>{detail.processing.llm_invoked ? t("yes") : t("no")}</DetailRow>
          <DetailRow label={t("input_length")}>
            {detail.input_length != null ? t("input_length_chars", { count: detail.input_length }) : "--"}
          </DetailRow>
        </DetailGrid>
      </div>

      {hasAgent && (
        <div>
          <SectionLabel>{t("agent_context")}</SectionLabel>
          <DetailGrid>
            <DetailRow label={t("run")} mono>{detail.run_id || "--"}</DetailRow>
            <DetailRow label={t("turn")}>{detail.turn_index != null ? String(detail.turn_index) : "--"}</DetailRow>
            <DetailRow label={t("session")} mono span>{detail.session_id || "--"}</DetailRow>
          </DetailGrid>
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-3">
          <SectionLabel>{t("attribution")}</SectionLabel>
          <span className={`text-[11px] px-2 py-0.5 rounded-full ${
            a.attribution_verified
              ? "bg-green-50 text-green-700 border border-green-200"
              : "bg-amber-50 text-amber-700 border border-amber-200"
          }`}>
            {a.attribution_verified ? t("verified") : t("self_reported")}
          </span>
        </div>
        <DetailGrid>
          <DetailRow label={t("source")}>{a.source || "--"}</DetailRow>
          <DetailRow label={t("key_id")} mono>{a.key_id || "--"}</DetailRow>
          <DetailRow label={t("department")}>{a.dept_name || a.dept_id || "--"}</DetailRow>
          <DetailRow label={t("application")}>{a.app_name || a.app_id || "--"}</DetailRow>
          <DetailRow label={t("user_id")} mono>{a.user_id || "--"}</DetailRow>
          <DetailRow label={t("ip_address")} mono>{a.ip_address || "--"}</DetailRow>
          <DetailRow label={t("input_hash")} mono span>{detail.input_hash}</DetailRow>
        </DetailGrid>
      </div>
    </div>
  )
}

function AssessmentTab({ detail }: { detail: RequestDetail }) {
  const t = useTranslations("pages.requests.detail")
  // One list of scored contributions, highest-first: the "why was this decided?"
  // answer. Detection layers plus any triggered guardrail.
  const contributions = [
    ...DETECTION_LAYERS.map(m => ({
      label: t(`layers.${m.key}`),
      color: m.color,
      score: detail.detection_scores?.[m.key as keyof typeof detail.detection_scores] ?? 0,
    })),
    ...Object.entries(detail.guardrail_scores || {}).map(([k, v]) => ({
      label: t.has(`guardrails.${k}`) ? t(`guardrails.${k}`) : k,
      color: GUARDRAIL_COLORS[k] ?? "#94a3b8",
      score: (v as number) ?? 0,
    })),
  ].sort((x, y) => y.score - x.score)

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-3">
          <SectionLabel>{t("layer_contributions")}</SectionLabel>
          <span className="text-[11px] text-slate-400 mb-3">{t("mode_note", { mode: detail.processing.detection_mode })}</span>
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
          <SectionLabel>{t("threats_detected")}</SectionLabel>
          <div className="flex flex-wrap gap-2">
            {detail.threats.map(t => <ThreatBadge key={t} threat={t} />)}
          </div>
        </div>
      )}
    </div>
  )
}

function ContentContextTab({ detail }: { detail: RequestDetail }) {
  const t = useTranslations("pages.requests.detail")
  const tier = contentSourceTier(detail.input_source)
  return (
    <div className="space-y-6">
      <div>
        <SectionLabel>{t("content_context")}</SectionLabel>
        <div className="flex items-center gap-3 flex-wrap mb-4">
          <SourceBadge source={detail.input_source} />
          <span className="text-xs text-slate-500">{t.has(`trust_tier.${tier}`) ? t(`trust_tier.${tier}`) : tier}</span>
        </div>
        <DetailGrid>
          <DetailRow label={t("content_source")}>{contentSourceLabel(detail.input_source)}</DetailRow>
          <DetailRow label={t("trust_boundary")}>{tier}</DetailRow>
        </DetailGrid>
      </div>
    </div>
  )
}

function ProxyTab({ detail }: { detail: RequestDetail }) {
  const t = useTranslations("pages.requests.detail")
  const p = detail.proxy!
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-3">
        <DecisionChip label={t("input_decision")}  decision={detail.decision} />
        <DecisionChip label={t("output_decision")} decision={p.output_decision} />
        <div className="flex flex-col gap-1">
          <p className="text-[11px] text-slate-400">{t("execution_status")}</p>
          <div className="w-fit"><StatusChip status={p.execution_status} /></div>
        </div>
      </div>
      <DetailGrid>
        <DetailRow label={t("provider")}>{p.provider || "--"}</DetailRow>
        <DetailRow label={t("model")}>{p.model || "--"}</DetailRow>
        <DetailRow label={t("provider_latency")}>
          {p.provider_latency_ms != null ? t("provider_latency_ms", { ms: p.provider_latency_ms }) : "--"}
        </DetailRow>
        <DetailRow label={t("attack_type")}>{p.input_attack_type || "--"}</DetailRow>
      </DetailGrid>
      {p.output_threats && p.output_threats.length > 0 && (
        <div>
          <SectionLabel>{t("output_threats")}</SectionLabel>
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
  const t = useTranslations("pages.requests.detail")
  const p = detail.proxy!
  const inputRedacted  = Boolean(p.input_sanitized && p.input_sanitized !== p.input_raw)
  const outputRedacted = Boolean(p.output_sanitized && p.output_sanitized !== p.output_raw)
  return (
    <div className="space-y-3">
      <RawBlock label={t("raw.input_sent")} value={p.input_raw} open />
      {inputRedacted && (
        <RawBlock label={t("raw.input_received")} value={p.input_sanitized} note={t("raw.pii_redacted")} />
      )}
      <RawBlock label={t("raw.output_returned")} value={p.output_raw} />
      {outputRedacted && (
        <RawBlock label={t("raw.output_received")} value={p.output_sanitized} note={t("raw.pii_redacted")} />
      )}
    </div>
  )
}

// --- Drawer ------------------------------------------------------------------

export function RequestDetailModal({ traceId, onClose }: RequestDetailModalProps) {
  const fmt = useFormat()
  const t   = useTranslations("pages.requests.detail")
  const { resolve } = useErrorMessage()
  const [detail,  setDetail]  = useState<RequestDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<unknown>(null)
  const [tab,     setTab]     = useState("overview")

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const data = await getRequest(traceId)
        if (!cancelled) setDetail(data)
      } catch (e) {
        if (!cancelled) setError(e)
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
        <h2 className="text-sm font-semibold text-slate-900">{t("title")}</h2>
        {detail?.is_proxy && (
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium border border-violet-200 bg-violet-50 text-violet-700">
            {t("proxy_badge")}
          </span>
        )}
      </div>
    </div>
  )

  const footer = detail ? (
    <div className="px-6 py-3 flex items-center gap-2 flex-wrap">
      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide mr-1">
        {t("recommended_actions")}
      </span>
      {detail.run_id && (
        <ActionButton href={`/agent-runs/${encodeURIComponent(detail.run_id)}`}>
          {t("open_agent_run")}
        </ActionButton>
      )}
      {hasRaw && (
        <ActionButton onClick={() => setTab("raw")}>{t("view_raw")}</ActionButton>
      )}
      <ActionButton onClick={() => navigator.clipboard?.writeText(traceId)}>
        {t("copy_trace_id")}
      </ActionButton>
    </div>
  ) : undefined

  const tabs: TabDef[] = detail ? [
    { id: "overview",   label: t("tabs.overview"),   render: () => <OverviewTab detail={detail} /> },
    { id: "assessment", label: t("tabs.assessment"), render: () => <AssessmentTab detail={detail} /> },
    { id: "content",    label: t("tabs.content"),    render: () => <ContentContextTab detail={detail} /> },
    { id: "proxy",      label: t("tabs.proxy"), visible: Boolean(detail.is_proxy && detail.proxy), render: () => <ProxyTab detail={detail} /> },
    { id: "raw",        label: t("tabs.raw"),   visible: hasRaw,                                    render: () => <RawTab detail={detail} /> },
  ] : []

  return (
    <Drawer onClose={onClose} header={header} footer={footer} label={t("drawer_label")}>
      {loading && (
        <div className="flex items-center justify-center py-16">
          <Spinner className="h-6 w-6" />
        </div>
      )}

      {error != null && (
        <div className="m-6 px-4 py-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
          {resolve(error).message}
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
                  <DecisionBadge decision={detail.proxy.output_decision as Decision} />
                </>
              )}
            </div>

            <div className="mt-4">
              <div className="flex items-baseline justify-between mb-1.5">
                <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wide">{t("risk_score")}</span>
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
              <CopyButton value={traceId} title={t("copy_trace")} />
              <span className="text-slate-300">.</span>
              <span>{fmt.timestamp(detail.timestamp)}</span>
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
