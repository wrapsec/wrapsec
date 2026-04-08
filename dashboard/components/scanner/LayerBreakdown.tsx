import { LayerScores, Decision } from "@/lib/types"
import { formatScore } from "@/lib/utils"
import { DecisionBadge } from "@/components/ui/Badge"

interface LayerBreakdownProps {
  scores: LayerScores
}

const LAYERS = [
  { key: "rule" as const, label: "Rule-based",        color: "#3b82f6" },
  { key: "ml"   as const, label: "ML classifier",     color: "#8b5cf6" },
  { key: "llm"  as const, label: "LLM semantic",      color: "#f59e0b" },
]

export function LayerBreakdown({ scores }: LayerBreakdownProps) {
  return (
    <div className="space-y-3">
      <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
        Layer Breakdown
      </h4>
      {LAYERS.map(({ key, label, color }) => {
        const score    = key === "rule" ? scores.rule_score : key === "ml" ? scores.ml_score : scores.llm_score
        const decision = scores.layer_decisions[key]
        const pct      = Math.round(score * 100)

        return (
          <div key={key}>
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
                <DecisionBadge decision={decision as Decision} size="sm" />
              </div>
            </div>
            <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${pct}%`, backgroundColor: color }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}