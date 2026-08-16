// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect } from "vitest"
import { renderWithIntl, screen } from "./_render"
import { DecisionBadge, ThreatBadge, SeverityBadge, SourceBadge } from "@/components/ui/Badge"
import type { Decision, ThreatCategory } from "@/lib/types"

describe("DecisionBadge", () => {
  // Decision enums are a machine/security contract: rendered VERBATIM, never localized.
  it.each(["BLOCK", "SANITIZE", "ALLOW"] as Decision[])("renders %s verbatim", (d) => {
    renderWithIntl(<DecisionBadge decision={d} />)
    expect(screen.getByText(d)).toBeInTheDocument()
  })
})

describe("ThreatBadge", () => {
  it("renders a known threat category", () => {
    renderWithIntl(<ThreatBadge threat={"PROMPT_INJECTION" as ThreatCategory} />)
    // THREAT_LABELS maps it; assert the badge is present (label or raw code).
    expect(screen.getByText(/prompt.?injection/i)).toBeInTheDocument()
  })

  it("falls back to the raw code for an unknown category", () => {
    renderWithIntl(<ThreatBadge threat={"BRAND_NEW_THREAT" as ThreatCategory} />)
    expect(screen.getByText("BRAND_NEW_THREAT")).toBeInTheDocument()
  })
})

describe("SeverityBadge", () => {
  it.each(["CRITICAL", "HIGH", "MEDIUM", "LOW"])("renders %s verbatim", (sev) => {
    renderWithIntl(<SeverityBadge severity={sev} />)
    expect(screen.getByText(sev)).toBeInTheDocument()
  })

  it("renders a dash placeholder for a null severity", () => {
    renderWithIntl(<SeverityBadge severity={null} />)
    expect(screen.getByText("-")).toBeInTheDocument()
  })
})

describe("SourceBadge", () => {
  it("labels a trusted source and marks it with the user tooltip", () => {
    renderWithIntl(<SourceBadge source="user_prompt" />)
    const badge = screen.getByText("User Prompt")
    expect(badge).toBeInTheDocument()
    expect(badge).not.toHaveAttribute("title", expect.stringContaining("untrusted"))
  })

  it("labels an untrusted (agent-pulled) source with the untrusted tooltip", () => {
    renderWithIntl(<SourceBadge source="tool_output" />)
    const badge = screen.getByText("Tool Output")
    expect(badge).toBeInTheDocument()
    // The untrusted tooltip warns about indirect prompt injection.
    expect(badge.getAttribute("title") ?? "").not.toBe("")
  })
})
