import { ThreatCount } from "@/lib/types"
import { formatThreat } from "@/lib/utils"

const THREAT_COLORS: Record<string, string> = {
  PROMPT_INJECTION:  "#dc2626",
  JAILBREAK:         "#7c3aed",
  DATA_EXFILTRATION: "#b91c1c",
  MALICIOUS_INTENT:  "#ea580c",
  PII:               "#9333ea",
  TOXICITY:          "#d97706",
}

export function TopThreats({ threats }: { threats: ThreatCount[] }) {
  const max = threats[0]?.count || 1

  return (
    <div style={{
      background: "#fff", border: "1px solid #e5e7eb",
      borderRadius: "8px", padding: "18px 20px",
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>Top threats</h3>
        <span style={{ fontSize: "11px", color: "#9ca3af" }}>{threats.length} categories</span>
      </div>

      {threats.length === 0 ? (
        <div style={{ padding: "24px 0", textAlign: "center" }}>
          <p style={{ fontSize: "13px", color: "#9ca3af", margin: 0 }}>No threats detected</p>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {threats.map(t => {
            const color = THREAT_COLORS[t.category] ?? "#6b7280"
            const pct   = Math.round((t.count / max) * 100)
            return (
              <div key={t.category}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: color, flexShrink: 0 }} />
                    <span style={{ fontSize: "12px", fontWeight: 500, color: "#374151" }}>
                      {formatThreat(t.category)}
                    </span>
                  </div>
                  <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#6b7280" }}>
                    {t.count.toLocaleString()}
                  </span>
                </div>
                <div style={{ height: "5px", background: "#f3f4f6", borderRadius: "3px", overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: "3px" }} />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
