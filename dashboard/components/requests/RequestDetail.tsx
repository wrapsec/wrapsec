// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect, useState } from "react"
import { RequestDetail } from "@/lib/types"
import { getRequest } from "@/lib/api"
import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { Spinner } from "@/components/ui/Spinner"
import { formatTimestamp } from "@/lib/datetime"
import { formatScore, formatLatency } from "@/lib/utils"

interface RequestDetailModalProps {
  traceId: string
  onClose: () => void
}

function ScoreBar({ score, color }: { score: number; color: string }) {
  return (
    <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
      <div
        className="h-full rounded-full"
        style={{ width: `${Math.round(score * 100)}%`, backgroundColor: color }}
      />
    </div>
  )
}

function MetaChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-slate-50 rounded-lg px-3 py-2.5">
      <p className="text-xs text-slate-400 mb-0.5">{label}</p>
      <p className="text-xs font-mono text-slate-700 truncate">{value}</p>
    </div>
  )
}

function DecisionChip({ label, decision }: { label: string; decision: string | null }) {
  if (!decision) return (
    <div className="flex flex-col gap-0.5">
      <p className="text-xs text-slate-400">{label}</p>
      <span className="text-xs text-slate-300">--</span>
    </div>
  )
  const colors: Record<string, string> = {
    ALLOW:    "bg-green-50 text-green-700 border-green-200",
    SANITIZE: "bg-yellow-50 text-yellow-700 border-yellow-200",
    BLOCK:    "bg-red-50 text-red-700 border-red-200",
  }
  return (
    <div className="flex flex-col gap-1">
      <p className="text-xs text-slate-400">{label}</p>
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border w-fit ${colors[decision] ?? "bg-slate-50 text-slate-600 border-slate-200"}`}>
        {decision}
      </span>
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

function TextBlock({
  label,
  value,
  note,
}: {
  label: string
  value: string | null
  note?: string
}) {
  if (!value) return null
  return (
    <div>
      <div className="flex items-center gap-2 mb-1.5">
        <p className="text-xs font-medium text-slate-500">{label}</p>
        {note && (
          <span className="text-xs text-yellow-600 font-normal">{note}</span>
        )}
      </div>
      <div className="bg-slate-50 border border-slate-100 rounded-lg px-3 py-2.5 text-xs text-slate-700 font-mono whitespace-pre-wrap break-words max-h-36 overflow-y-auto">
        {value}
      </div>
    </div>
  )
}

export function RequestDetailModal({ traceId, onClose }: RequestDetailModalProps) {
  const [detail,  setDetail]  = useState<RequestDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const data = await getRequest(traceId)
        setDetail(data)
      } catch (e: any) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [traceId])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  return (
    <div className="fixed inset-0 bg-black/40 flex items-start justify-center z-50 p-6 overflow-y-auto">
      <div className="bg-white rounded-xl border border-slate-200 w-full max-w-2xl shadow-lg flex flex-col" style={{ maxHeight: "90vh" }}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 flex-shrink-0">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-900">Request Detail</h2>
              {detail?.is_proxy && (
                <span style={{
                  display: "inline-flex",
                  alignItems: "center",
                  padding: "2px 6px",
                  borderRadius: "4px",
                  fontSize: "11px",
                  fontWeight: 500,
                  border: "1px solid #ddd6fe",
                  backgroundColor: "#f5f3ff",
                  color: "#6d28d9",
                }}>
                  proxy
                </span>
              )}
            </div>
            <p className="text-xs font-mono text-slate-400 mt-0.5">{traceId}</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 transition-colors">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Scrollable content */}
        <div className="px-6 py-5 space-y-6 overflow-y-auto flex-1">

          {loading && (
            <div className="flex items-center justify-center py-12">
              <Spinner className="h-6 w-6" />
            </div>
          )}

          {error && (
            <div className="px-4 py-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
              {error}
            </div>
          )}

          {detail && (
            <>
              {/* ── Security summary ── */}
              <div className="flex items-center gap-4 p-4 bg-slate-50 rounded-lg border border-slate-100 flex-wrap">
                <div>
                  <p className="text-xs text-slate-500 mb-1">
                    {detail.is_proxy ? "Input decision" : "Decision"}
                  </p>
                  <DecisionBadge decision={detail.decision} />
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Severity</p>
                  {(() => {
                    const styles: Record<string, [string, string, string]> = {
                      CRITICAL: ["#fef2f2", "#b91c1c", "#fecaca"],
                      HIGH:     ["#fff7ed", "#c2410c", "#fed7aa"],
                      MEDIUM:   ["#fffbeb", "#b45309", "#fde68a"],
                      LOW:      ["#f0fdf4", "#15803d", "#bbf7d0"],
                    }
                    const [bg, color, border] = styles[detail.severity] ?? styles.LOW
                    return (
                      <span style={{
                        display: "inline-flex", alignItems: "center",
                        padding: "2px 8px", borderRadius: "4px",
                        fontSize: "12px", fontWeight: 600,
                        border: `1px solid ${border}`,
                        backgroundColor: bg, color,
                      }}>
                        {detail.severity}
                      </span>
                    )
                  })()}
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Risk score</p>
                  <p className="text-sm font-semibold text-slate-900">{formatScore(detail.risk_score)}</p>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Confidence</p>
                  <div className="flex items-center gap-1.5">
                    <p className="text-sm font-semibold text-slate-900">
                      {detail.confidence !== null ? `${Math.round((detail.confidence ?? 0) * 100)}%` : "--"}
                    </p>
                    {detail.confidence_band && (
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                        detail.confidence_band === "HIGH"   ? "bg-green-50 text-green-700 border border-green-200"
                        : detail.confidence_band === "MEDIUM" ? "bg-amber-50 text-amber-700 border border-amber-200"
                        : "bg-red-50 text-red-700 border border-red-200"
                      }`}>
                        {detail.confidence_band}
                      </span>
                    )}
                  </div>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Primary reason</p>
                  <p className="text-xs font-mono text-slate-600">{detail.primary_reason || "--"}</p>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Latency</p>
                  <p className="text-sm font-semibold text-slate-900">{formatLatency(detail.processing.latency_ms)}</p>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Timestamp</p>
                  <p className="text-sm text-slate-700">{formatTimestamp(detail.timestamp)}</p>
                </div>
              </div>

              {/* Threats */}
              {detail.threats.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
                    Threats Detected
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {detail.threats.map((t) => <ThreatBadge key={t} threat={t} />)}
                  </div>
                </div>
              )}

              {/* Detection layers */}
              <div>
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                  Detection Layers
                  <span className="ml-2 font-normal normal-case text-slate-400">
                    ({detail.processing.detection_mode} mode)
                  </span>
                </p>
                <div className="space-y-3">
                  {[
                    { label: "Rule-based",    key: "rule", color: "#3b82f6" },
                    { label: "ML classifier", key: "ml",   color: "#8b5cf6" },
                    { label: "LLM semantic",  key: "llm",  color: "#f59e0b" },
                  ].map(({ label, key, color }) => {
                    const score = detail.detection_scores?.[key as keyof typeof detail.detection_scores] ?? 0
                    return (
                      <div key={key}>
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-2">
                            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                            <span className="text-sm text-slate-700">{label}</span>
                          </div>
                          <span className="text-xs font-mono text-slate-600">{formatScore(score)}</span>
                        </div>
                        <ScoreBar score={score} color={color} />
                      </div>
                    )
                  })}
                </div>
              </div>

              <div className="border-t border-slate-100" />

              {/* Guardrail layers */}
              <div>
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                  Guardrail Layers
                </p>
                <div className="space-y-3">
                  {Object.entries(detail.guardrail_scores || {}).map(([key, score]) => {
                    const label = key === "pii" ? "PII guardrail"
                      : key === "toxicity" ? "Toxicity guardrail"
                      : key
                    const color = key === "toxicity" ? "#f97316" : "#ec4899"
                    return (
                      <div key={key}>
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-2">
                            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                            <span className="text-sm text-slate-700">{label}</span>
                          </div>
                          <span className="text-xs font-mono text-slate-600">{formatScore(score as number)}</span>
                        </div>
                        <ScoreBar score={score as number} color={color} />
                      </div>
                    )
                  })}
                  {Object.keys(detail.guardrail_scores || {}).length === 0 && (
                    <p className="text-sm text-slate-400">No guardrails triggered</p>
                  )}
                </div>
              </div>

              {/* ── Proxy lifecycle -- only for proxy requests ── */}
              {detail.is_proxy && detail.proxy && (
                <>
                  <div className="border-t border-slate-100" />
                  <div>
                    <div className="flex items-center gap-2 mb-4">
                      <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
                        Proxy Lifecycle
                      </p>
                      <span className="text-xs text-slate-400">
                        {detail.proxy.provider} / {detail.proxy.model}
                      </span>
                    </div>

                    {/* Decisions and status -- clear separation */}
                    <div className="grid grid-cols-3 gap-3 mb-4">
                      <DecisionChip label="Input decision"  decision={detail.decision} />
                      <DecisionChip label="Output decision" decision={detail.proxy.output_decision} />
                      <div className="flex flex-col gap-1">
                        <p className="text-xs text-slate-400">Execution status</p>
                        <div className="w-fit">
                          <StatusChip status={detail.proxy.execution_status} />
                        </div>
                      </div>
                    </div>

                    {/* Latency breakdown */}
                    <div className="grid grid-cols-2 gap-3 mb-4">
                      <MetaChip
                        label="Provider latency"
                        value={detail.proxy.provider_latency_ms != null ? `${detail.proxy.provider_latency_ms}ms` : "--"}
                      />
                      <MetaChip
                        label="Attack type"
                        value={detail.proxy.input_attack_type ?? "--"}
                      />
                    </div>

                    {/* Text blocks -- show only what is relevant */}
                    <div className="space-y-3">
                      {/* Always show what user sent */}
                      <TextBlock
                        label="Input -- what the user sent"
                        value={detail.proxy.input_raw}
                      />

                      {/* Show sanitized input only if different from raw */}
                      {detail.proxy.input_sanitized && detail.proxy.input_sanitized !== detail.proxy.input_raw && (
                        <TextBlock
                          label="Input -- what the provider received"
                          value={detail.proxy.input_sanitized}
                          note="(PII redacted)"
                        />
                      )}

                      {/* Provider response */}
                      <TextBlock
                        label="Output -- what the provider returned"
                        value={detail.proxy.output_raw}
                      />

                      {/* Show sanitized output only if redaction happened */}
                      {detail.proxy.output_sanitized && (
                        <TextBlock
                          label="Output -- what the client received"
                          value={detail.proxy.output_sanitized}
                          note="(PII redacted)"
                        />
                      )}
                    </div>

                    {/* Output threats */}
                    {detail.proxy.output_threats && detail.proxy.output_threats.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs font-medium text-slate-500 mb-1.5">Output threats detected</p>
                        <div className="flex flex-wrap gap-1">
                          {detail.proxy.output_threats.map((t: string) => (
                            <span key={t} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-pink-50 text-pink-700 border border-pink-200">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}

              {/* Attribution */}
              <div className="border-t border-slate-100 pt-4">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
                    Attribution
                  </p>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    detail.attribution.attribution_verified
                      ? "bg-green-50 text-green-700 border border-green-200"
                      : "bg-amber-50 text-amber-700 border border-amber-200"
                  }`}>
                    {detail.attribution.attribution_verified ? "Verified" : "Self-reported"}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: "Source",          value: detail.attribution.source      || "--" },
                    { label: "Key ID",          value: detail.attribution.key_id      || "--" },
                    { label: "Department",      value: detail.attribution.dept_name || detail.attribution.dept_id || "--" },
                    { label: "Application",     value: detail.attribution.app_name  || detail.attribution.app_id  || "--" },
                    { label: "User ID",         value: detail.attribution.user_id     || "--" },
                    { label: "IP address",      value: detail.attribution.ip_address  || "--" },
                    { label: "Detection mode",  value: detail.processing.detection_mode },
                    { label: "Execution mode",  value: detail.processing.execution_mode },
                    { label: "LLM invoked",     value: detail.processing.llm_invoked ? "Yes" : "No" },
                    { label: "Input length",    value: detail.input_length != null ? `${detail.input_length} chars` : "--" },
                    { label: "Input hash",      value: detail.input_hash },
                  ].map(({ label, value }) => (
                    <MetaChip key={label} label={label} value={value} />
                  ))}
                </div>
              </div>

            </>
          )}
        </div>
      </div>
    </div>
  )
}
