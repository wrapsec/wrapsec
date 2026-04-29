interface MetricCardProps {
  label:   string
  value:   string | number
  sub?:    string
  color?:  "default" | "red" | "orange" | "green"
  accent?: "violet" | "purple" | "cyan" | "sky" | "none"
}

const ACCENTS = {
  violet: "#670FEF", purple: "#CD00FF",
  cyan:   "#00E1FF", sky:    "#00B1FF", none: "transparent",
}
const VALUE_COLORS = {
  default: "#111827", red: "#dc2626", orange: "#d97706", green: "#16a34a",
}

export function MetricCard({ label, value, sub, color = "default", accent = "none" }: MetricCardProps) {
  return (
    <div style={{
      background:   "#fff",
      border:       "1px solid #e5e7eb",
      borderTop:    accent !== "none" ? `3px solid ${ACCENTS[accent]}` : "1px solid #e5e7eb",
      borderRadius: "8px",
      padding:      "16px 20px",
    }}>
      <p style={{ fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase", letterSpacing: "0.08em", margin: "0 0 8px 0" }}>
        {label}
      </p>
      <p style={{ fontSize: "26px", fontWeight: 700, color: VALUE_COLORS[color], lineHeight: 1, margin: 0 }}>
        {value}
      </p>
      {sub && <p style={{ fontSize: "11px", color: "#9ca3af", marginTop: "5px", marginBottom: 0 }}>{sub}</p>}
    </div>
  )
}
