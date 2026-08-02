// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { LayerScores, Decision } from "@/lib/types"
import { formatScore } from "@/lib/format"
import { DecisionBadge } from "@/components/ui/Badge"

interface LayerBreakdownProps {
  scores: LayerScores
}

const DETECTION_LAYERS = [
  { key: "rule" as const, label: "Rule-based",    color: "#3b82f6" },
  { key: "ml"   as const, label: "ML classifier", color: "#8b5cf6" },
  { key: "llm"  as const, label: "LLM semantic",  color: "#f59e0b" },
]

const GUARDRAIL_LAYERS = [
  { key: "pii" as const, label: "PII guardrail",  color: "#ec4899" },
]

function getScore(scores: LayerScores, key: string): number {
  if (key === "rule") return scores.rule_score
  if (key === "ml")   return scores.ml_score
  if (key === "llm")  return scores.llm_score
  if (key === "pii")  return scores.pii_score
  return 0
}

function getDecision(score: number, threshold = { block: 0.7, sanitize: 0.4 }): Decision {
  if (score >= threshold.block)    return "BLOCK"
  if (score >= threshold.sanitize) return "SANITIZE"
  return "ALLOW"
}

function LayerRow({
  label,
  color,
  score,
  decision,
}: {
  label:    string
  color:    string
  score:    number
  decision: Decision
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-2">
          <span
            className="h-2 w-2 rounded-full flex-shrink-0"
            style={{ backgroundColor: color }}
          />
          <span className="text-sm text-slate-700">{label}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-slate-600">
            {formatScore(score)}
          </span>
          <DecisionBadge decision={decision} size="sm" />
        </div>
      </div>
      <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{
            width:           `${Math.round(score * 100)}%`,
            backgroundColor: color,
          }}
        />
      </div>
    </div>
  )
}

export function LayerBreakdown({ scores }: LayerBreakdownProps) {
  return (
    <div className="space-y-4">
      {/* Detection layers */}
      <div>
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
          Detection Layers
        </p>
        <div className="space-y-3">
          {DETECTION_LAYERS.map(({ key, label, color }) => (
            <LayerRow
              key={key}
              label={label}
              color={color}
              score={getScore(scores, key)}
              decision={
                key === "rule" ? scores.layer_decisions.rule :
                key === "ml"   ? scores.layer_decisions.ml   :
                                 scores.layer_decisions.llm
              }
            />
          ))}
        </div>
      </div>

      {/* Divider */}
      <div className="border-t border-slate-100" />

      {/* Guardrail layers */}
      <div>
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
          Guardrail Layers
        </p>
        <div className="space-y-3">
          {GUARDRAIL_LAYERS.map(({ key, label, color }) => {
            const score = getScore(scores, key)
            return (
              <LayerRow
                key={key}
                label={label}
                color={color}
                score={score}
                decision={getDecision(score)}
              />
            )
          })}
        </div>
      </div>
    </div>
  )
}