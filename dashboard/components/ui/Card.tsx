import { cn } from "@/lib/utils"

// ── Card ──────────────────────────────────────────────────────────────────

interface CardProps {
  children:    React.ReactNode
  className?:  string
  padding?:    boolean
  accent?:     "violet" | "purple" | "cyan" | "sky" | "none"
}

const ACCENTS = {
  violet: "#670FEF",
  purple: "#CD00FF",
  cyan:   "#00E1FF",
  sky:    "#00B1FF",
  none:   "transparent",
}

export function Card({ children, className, padding = true, accent = "none" }: CardProps) {
  return (
    <div
      className={cn(padding && "p-5", className)}
      style={{
        background:   "var(--card-bg)",
        border:       "1px solid var(--card-border)",
        borderRadius: "8px",
        borderTop:    accent !== "none" ? `3px solid ${ACCENTS[accent]}` : undefined,
        overflow:     "hidden",
      }}
    >
      {children}
    </div>
  )
}

export function CardHeader({ title, subtitle, action }: {
  title:     string
  subtitle?: string
  action?:   React.ReactNode
}) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "16px" }}>
      <div>
        <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)", margin: 0 }}>{title}</h3>
        {subtitle && <p style={{ fontSize: "12px", color: "var(--text-tertiary)", marginTop: "2px" }}>{subtitle}</p>}
      </div>
      {action}
    </div>
  )
}
