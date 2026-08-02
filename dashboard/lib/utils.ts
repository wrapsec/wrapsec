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

export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n) + "..." : str
}

export function cn(...classes: (string | undefined | false)[]): string {
  return classes.filter(Boolean).join(" ")
}