import { Decision, ThreatCategory } from "@/lib/types"
import { DECISION_COLORS, THREAT_LABELS } from "@/lib/constants"

interface DecisionBadgeProps {
  decision: Decision
  size?: "sm" | "md"
}

export function DecisionBadge({ decision, size = "md" }: DecisionBadgeProps) {
  const colors = DECISION_COLORS[decision]
  const padding = size === "sm" ? "px-2 py-0.5 text-xs" : "px-2.5 py-1 text-xs"

  return (
    <span
      className={`inline-flex items-center font-medium rounded-md border ${padding}`}
      style={{
        color:           colors.text,
        backgroundColor: colors.bg,
        borderColor:     colors.border,
      }}
    >
      {decision}
    </span>
  )
}

interface ThreatBadgeProps {
  threat: ThreatCategory
}

export function ThreatBadge({ threat }: ThreatBadgeProps) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-md bg-slate-100 text-slate-700 border border-slate-200">
      {THREAT_LABELS[threat] || threat}
    </span>
  )
}