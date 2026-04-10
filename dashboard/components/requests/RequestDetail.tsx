"use client"

import { useEffect, useState } from "react"
import { RequestDetail } from "@/lib/types"
import { getRequest } from "@/lib/api"
import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { Spinner } from "@/components/ui/Spinner"
import { formatScore, formatLatency, formatTimestamp } from "@/lib/utils"

interface RequestDetailModalProps {
  traceId:  string
  onClose:  () => void
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

  return (
    <div className="fixed inset-0 bg-black/40 flex items-start justify-center z-50 p-6 overflow-y-auto">
      <div className="bg-white rounded-xl border border-slate-200 w-full max-w-2xl shadow-lg flex flex-col" style={{ maxHeight: "90vh" }}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Request Detail</h2>
            <p className="text-xs font-mono text-slate-400 mt-0.5">{traceId}</p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 transition-colors"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
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
              {/* Decision summary */}
              <div className="flex items-center gap-4 p-4 bg-slate-50 rounded-lg border border-slate-100 flex-wrap">
                <div>
                  <p className="text-xs text-slate-500 mb-1">Decision</p>
                  <DecisionBadge decision={detail.decision} />
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Risk Score</p>
                  <p className="text-sm font-semibold text-slate-900">
                    {formatScore(detail.risk_score)}
                  </p>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Confidence</p>
                  <div className="flex items-center gap-1.5">
                    <p className="text-sm font-semibold text-slate-900">
                      {detail.confidence !== null
                        ? `${Math.round((detail.confidence ?? 0) * 100)}%`
                        : "—"}
                    </p>
                    {detail.confidence_band && (
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                        detail.confidence_band === "HIGH"
                          ? "bg-green-50 text-green-700 border border-green-200"
                          : detail.confidence_band === "MEDIUM"
                          ? "bg-amber-50 text-amber-700 border border-amber-200"
                          : "bg-red-50 text-red-700 border border-red-200"
                      }`}>
                        {detail.confidence_band}
                      </span>
                    )}
                  </div>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Primary Reason</p>
                  <p className="text-xs font-mono text-slate-600">
                    {detail.primary_reason || "—"}
                  </p>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Latency</p>
                  <p className="text-sm font-semibold text-slate-900">
                    {formatLatency(detail.processing.latency_ms)}
                  </p>
                </div>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-xs text-slate-500 mb-1">Timestamp</p>
                  <p className="text-sm text-slate-700">
                    {formatTimestamp(detail.timestamp)}
                  </p>
                </div>
              </div>

              {/* Threats */}
              {detail.threats.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
                    Threats Detected
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {detail.threats.map((t) => (
                      <ThreatBadge key={t} threat={t} />
                    ))}
                  </div>
                </div>
              )}

              {/* Detection scores */}
              <div>
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                  Detection Layers
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
                          <span className="text-xs font-mono text-slate-600">
                            {formatScore(score)}
                          </span>
                        </div>
                        <ScoreBar score={score} color={color} />
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Divider */}
              <div className="border-t border-slate-100" />

              {/* Guardrail scores */}
              <div>
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                  Guardrail Layers
                </p>
                <div className="space-y-3">
                  {Object.entries(detail.guardrail_scores || {}).map(([key, score]) => (
                    <div key={key}>
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className="h-2 w-2 rounded-full bg-pink-500" />
                          <span className="text-sm text-slate-700 capitalize">
                            {key === "pii" ? "PII guardrail" : key}
                          </span>
                        </div>
                        <span className="text-xs font-mono text-slate-600">
                          {formatScore(score as number)}
                        </span>
                      </div>
                      <ScoreBar score={score as number} color="#ec4899" />
                    </div>
                  ))}
                  {Object.keys(detail.guardrail_scores || {}).length === 0 && (
                    <p className="text-sm text-slate-400">No guardrails triggered</p>
                  )}
                </div>
              </div>

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
                    { label: "Source",         value: detail.attribution.source      || "—" },
                    { label: "Key ID",         value: detail.attribution.key_id      || "—" },
                    { label: "Department",     value: detail.attribution.dept_id     || "—" },
                    { label: "Application",    value: detail.attribution.app_id      || "—" },
                    { label: "User ID",        value: detail.attribution.user_id     || "—" },
                    { label: "IP Address",     value: detail.attribution.ip_address  || "—" },
                    { label: "Detection mode", value: detail.processing.detection_mode },
                    { label: "Execution mode", value: detail.processing.execution_mode },
                    { label: "LLM invoked",    value: detail.processing.llm_invoked ? "Yes" : "No" },
                    { label: "Input hash",     value: detail.input_hash },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                      <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                      <p className="text-xs font-mono text-slate-700 truncate">{value}</p>
                    </div>
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