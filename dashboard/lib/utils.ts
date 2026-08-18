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

export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n) + "..." : str
}

export function cn(...classes: (string | undefined | false)[]): string {
  return classes.filter(Boolean).join(" ")
}

/**
 * Machine-friendly slug from a display name: lowercase, non-alphanumeric runs
 * collapse to a single hyphen, no leading/trailing hyphens, max 50 chars (to
 * match the backend slug column). Used to auto-derive department / application
 * slugs from the Name field.
 */
export function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, 50)
    .replace(/-+$/, "")
}