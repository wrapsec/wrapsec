// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useFormat } from "@/hooks/useFormat"

interface SeverityCardProps {
  level:       "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  count:       number
  description: string
}

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#dc2626", accent: "#670FEF" },
  HIGH:     { color: "#d97706", accent: "#CD00FF" },
  MEDIUM:   { color: "#0369a1", accent: "#00B1FF" },
  LOW:      { color: "#059669", accent: "#00E1FF" },
}

export function SeverityCard({ level, count, description }: SeverityCardProps) {
  const cfg = SEVERITY_CONFIG[level]
  const fmt = useFormat()
  return (
    <div style={{
      background:   "#fff",
      border:       "1px solid #e5e7eb",
      borderTop:    `3px solid ${cfg.accent}`,
      borderRadius: "8px",
      padding:      "16px 20px",
    }}>
      <p style={{
        fontSize: "10px", fontWeight: 700, letterSpacing: "0.08em",
        textTransform: "uppercase", color: "#4b5563",
        margin: "0 0 8px 0",
      }}>
        {level}
      </p>
      <p style={{ fontSize: "30px", fontWeight: 700, color: cfg.color, lineHeight: 1, margin: "0 0 5px 0" }}>
        {fmt.number(count)}
      </p>
      <p style={{ fontSize: "11px", color: "#4b5563", margin: 0 }}>{description}</p>
    </div>
  )
}
