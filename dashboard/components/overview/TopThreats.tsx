// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import Link from "next/link"
import { useFormat } from "@/hooks/useFormat"
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

export function TopThreats({ threats, from, to }: { threats: ThreatCount[]; from?: string; to?: string }) {
  const fmt = useFormat()
  const max = threats[0]?.count || 1

  return (
    <div style={{
      background: "#fff", border: "1px solid #e5e7eb",
      borderRadius: "8px", padding: "20px",
      display: "flex", flexDirection: "column",
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px", flexShrink: 0 }}>
        <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>Top threats</h3>
        <span style={{ fontSize: "11px", color: "#9ca3af" }}>{threats.length} categories</span>
      </div>

      {threats.length === 0 ? (
        <p style={{ fontSize: "13px", color: "#9ca3af" }}>No threats detected</p>
      ) : (
        <div style={{ overflowY: "auto", overflowX: "hidden", flex: 1, maxHeight: "220px", paddingRight: "8px" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {threats.map(t => {
            const color = THREAT_COLORS[t.category] ?? "#6b7280"
            const pct   = Math.round((t.count / max) * 100)
            return (
              <Link
                key={t.category}
                href={`/requests?threat=${t.category}${from ? `&from=${from}` : ""}${to ? `&to=${to}` : ""}`}
                style={{ display: "block", textDecoration: "none" }}
              >
                <div
                  style={{ borderRadius: "6px", padding: "4px 6px", margin: "-4px -6px" }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#f9fafb"}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "5px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "7px" }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", background: color, flexShrink: 0 }} />
                      <span style={{ fontSize: "12px", fontWeight: 500, color: "#374151" }}>
                        {formatThreat(t.category)}
                      </span>
                    </div>
                    <span style={{ fontSize: "12px", fontFamily: "monospace", color: "#6b7280", flexShrink: 0, marginLeft: "12px" }}>
                      {fmt.number(t.count)}
                    </span>
                  </div>
                  <div style={{ height: "5px", background: "#f3f4f6", borderRadius: "3px", overflow: "hidden" }}>
                    <div style={{
                      height: "100%",
                      width: `${Math.round(pct * 0.6)}%`,
                      background: color,
                      borderRadius: "3px",
                    }} />
                  </div>
                </div>
              </Link>
            )
          })}
          </div>
        </div>
      )}
    </div>
  )
}
