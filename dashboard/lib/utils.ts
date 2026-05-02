// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { Decision, ThreatCategory } from "./types"
import { DECISION_COLORS, THREAT_LABELS } from "./constants"

export function formatDecision(decision: Decision) {
  return DECISION_COLORS[decision]
}

export function formatThreat(threat: ThreatCategory): string {
  return THREAT_LABELS[threat] || threat
}

export function formatScore(score: number): string {
  return (score * 100).toFixed(0) + "%"
}

export function formatLatency(ms: number): string {
  if (ms < 1000) return ms.toFixed(0) + "ms"
  return (ms / 1000).toFixed(1) + "s"
}

export function formatRate(rate: number): string {
  return (rate * 100).toFixed(1) + "%"
}

export function formatTimestamp(ts: string): string {
  const date = new Date(ts)
  return date.toLocaleString("en-GB", {
    day:    "2-digit",
    month:  "short",
    hour:   "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

export function timeAgo(ts: string): string {
  // Ensure UTC interpretation if no timezone info
  const normalized = ts.endsWith("Z") || ts.includes("+") ? ts : ts + "Z"
  const diff = Date.now() - new Date(normalized).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60)  return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60)  return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24)   return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n) + "..." : str
}

export function cn(...classes: (string | undefined | false)[]): string {
  return classes.filter(Boolean).join(" ")
}