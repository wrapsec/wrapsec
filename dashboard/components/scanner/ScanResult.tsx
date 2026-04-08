import { GatewayResponse } from "@/lib/types"
import { DecisionBadge, ThreatBadge } from "@/components/ui/Badge"
import { LayerBreakdown } from "./LayerBreakdown"
import { formatScore, formatLatency } from "@/lib/utils"

export function ScanResult({ result }: { result: GatewayResponse }) {
  return (
    <div className="space-y-5">
      {/* Decision banner */}
      <div className="flex items-center gap-4 p-4 rounded-lg border border-slate-200 bg-slate-50">
        <div>
          <p className="text-xs text-slate-500 mb-1">Decision</p>
          <DecisionBadge decision={result.decision} />
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">Risk Score</p>
          <p className="text-sm font-semibold text-slate-900">
            {formatScore(result.risk_score)}
          </p>
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">Latency</p>
          <p className="text-sm font-semibold text-slate-900">
            {formatLatency(result.processing.latency_ms)}
          </p>
        </div>
        <div className="h-8 w-px bg-slate-200" />
        <div>
          <p className="text-xs text-slate-500 mb-1">Trace ID</p>
          <p className="text-xs font-mono text-slate-600">{result.trace_id}</p>
        </div>
      </div>

      {/* Threats */}
      {result.threats.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
            Threats Detected
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
            Sanitized Input
          </p>
          <p className="text-sm text-slate-700 bg-slate-50 border border-slate-200 rounded-lg px-4 py-3">
            {result.sanitized_input}
          </p>
        </div>
      )}
    </div>
  )
}