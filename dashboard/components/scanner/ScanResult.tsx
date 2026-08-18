// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { GatewayResponse } from "@/lib/types"
import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { LayerBreakdown } from "./LayerBreakdown"
import { formatScore, formatLatency } from "@/lib/format"

function ConfidenceBadge({ band }: { band: string | null }) {
  if (!band) return null
  const styles = {
    HIGH:   "bg-green-50 text-green-700 border border-green-200",
    MEDIUM: "bg-amber-50 text-amber-700 border border-amber-200",
    LOW:    "bg-red-50 text-red-700 border border-red-200",
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${styles[band as keyof typeof styles] || ""}`}>
      {band}
    </span>
  )
}

function PrimaryReasonBadge({ reason }: { reason: string | null }) {
  const t = useTranslations("pages.scanner.result.reason")
  if (!reason) return null
  return (
    <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200 font-medium">
      {t.has(reason) ? t(reason) : reason}
    </span>
  )
}

export function ScanResult({ result }: { result: GatewayResponse }) {
  const t = useTranslations("pages.scanner.result")
  return (
    <div className="space-y-5">
      {/* Decision banner */}
      <div className="flex items-center gap-4 p-4 rounded-lg border border-slate-200 bg-slate-50 flex-wrap">
        <div>
          <p className="text-xs text-slate-500 mb-1">{t("decision")}</p>
          <DecisionBadge decision={result.decision} />
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">{t("risk_score")}</p>
          <p className="text-sm font-semibold text-slate-900">
            {formatScore(result.risk_score)}
          </p>
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">{t("confidence")}</p>
          <div className="flex items-center gap-1.5">
            <p className="text-sm font-semibold text-slate-900">
              {result.confidence !== null ? `${Math.round((result.confidence ?? 0) * 100)}%` : "-"}
            </p>
            <ConfidenceBadge band={result.confidence_band} />
          </div>
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">{t("primary_reason")}</p>
          <PrimaryReasonBadge reason={result.primary_reason} />
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">{t("latency")}</p>
          <p className="text-sm font-semibold text-slate-900">
            {formatLatency(result.processing.latency_ms)}
          </p>
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">{t("trace_id")}</p>
          <p className="text-xs font-mono text-slate-600">{result.trace_id}</p>
        </div>
      </div>

      {/* Threats */}
      {result.threats.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
            {t("threats_detected")}
          </p>
          <div className="flex flex-wrap gap-2">
            {result.threats.map((t) => (
              <ThreatBadge key={t} threat={t} />
            ))}
          </div>
        </div>
      )}

      {/* Layer breakdown */}
      {result.debug && (
        <LayerBreakdown scores={result.debug} />
      )}

      {/* Sanitized input */}
      {result.sanitized_input && (
        <div>
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
            {t("sanitized_input")}
          </p>
          <p className="text-sm text-slate-700 bg-slate-50 border border-slate-200 rounded-lg px-4 py-3">
            {result.sanitized_input}
          </p>
        </div>
      )}
    </div>
  )
}