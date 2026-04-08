import { Card } from "@/components/ui/Card"
import { cn } from "@/lib/utils"

interface MetricCardProps {
  label:     string
  value:     string | number
  sub?:      string
  color?:    "default" | "red" | "orange" | "green"
}

const colorMap = {
  default: "text-slate-900",
  red:     "text-red-600",
  orange:  "text-orange-600",
  green:   "text-green-600",
}

export function MetricCard({ label, value, sub, color = "default" }: MetricCardProps) {
  return (
    <Card>
      <p className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-1">
        {label}
      </p>
      <p className={cn("text-3xl font-bold leading-none", colorMap[color])}>
        {value}
      </p>
      {sub && (
        <p className="text-xs text-slate-400 mt-1.5">{sub}</p>
      )}
    </Card>
  )
}