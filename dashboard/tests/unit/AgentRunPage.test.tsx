// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The agent-run page summarises a run. The API returns one record per SCAN, not
// per turn -- a tool call is judged on its arguments and again on its result,
// and one tool listing judges every definition it publishes -- so the page must
// report both numbers rather than presenting the record count as a turn count.
// It previously rendered `count` under a "turns" label, so a real gateway run of
// 16 scans across 2 turns read as "16 turns".
import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderWithIntl, screen, waitFor } from "./_render"
import type { AuditLogItem } from "@/lib/types"

vi.mock("@/components/layout/Shell", () => ({
  Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))
// The page reads its id from useParams, not from props.
let currentRunId = "mcprun_x"
vi.mock("next/navigation", () => ({
  useRouter:       () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname:     () => `/agent-runs/${currentRunId}`,
  useSearchParams: () => new URLSearchParams(),
  useParams:       () => ({ runId: currentRunId }),
}))

const getAgentRun = vi.fn()
vi.mock("@/lib/api", () => ({ getAgentRun: (id: string) => getAgentRun(id) }))

import AgentRunPage from "@/app/agent-runs/[runId]/page"

// Built to the full AuditLogItem contract rather than cast to it: the page
// reads timestamp, trace_id, turn_index, decision, input_source, primary_reason
// and risk_score, and a cast would hide a missing one until render.
function scan(turn_index: number, over: Partial<AuditLogItem> = {}): AuditLogItem {
  return {
    trace_id: `req_${Math.random().toString(16).slice(2, 10)}`,
    timestamp: "2026-09-12T10:00:00.000Z",
    tenant_id: null,
    decision: "ALLOW",
    output_decision: null,
    provider: null,
    model: null,
    primary_reason: "NO_THREAT_DETECTED",
    risk_score: 0,
    confidence: null,
    confidence_band: null,
    threats: [],
    input_hash: "sha256:0",
    input_length: 10,
    detection_mode: "fast",
    execution_mode: "scan_only",
    latency_ms: 1,
    severity: "LOW",
    key_id: null,
    dept_id: null,
    dept_name: null,
    app_id: null,
    app_name: null,
    user_id: null,
    source: null,
    ip_address: null,
    attribution_verified: false,
    policy_source: null,
    run_id: "mcprun_x",
    session_id: "mcpsess_x",
    turn_index,
    input_source: "external_content",
    ...over,
  }
}

/** The real shape a gateway run produces: 14 definition scans in one turn,
 *  then a tool call whose arguments and result share the next turn. */
function gatewayRun() {
  const scans = [
    ...Array.from({ length: 14 }, () => scan(1)),
    scan(2, { input_source: "agent_tool_call" }),
    scan(2, { input_source: "tool_output", decision: "BLOCK",
              primary_reason: "RULE_DETECTOR", risk_score: 0.85 }),
  ]
  return { run_id: "mcprun_x", count: scans.length, scans }
}

beforeEach(() => { getAgentRun.mockReset(); currentRunId = "mcprun_x" })

/** The summary as the viewer reads it, with whitespace normalised. */
function summaryText(container: HTMLElement): string {
  return (container.textContent ?? "").replace(/\s+/g, " ").trim()
}

describe("AgentRunPage", () => {
  it("reports 16 scans across 2 turns for a real gateway run", async () => {
    getAgentRun.mockResolvedValue(gatewayRun())

    const { container } = renderWithIntl(<AgentRunPage />)

    await waitFor(() =>
      expect(summaryText(container)).toMatch(/16 scans across 2 turns/i))
  })

  it("does not present the scan count as a turn count", async () => {
    getAgentRun.mockResolvedValue(gatewayRun())

    const { container } = renderWithIntl(<AgentRunPage />)

    await waitFor(() => expect(summaryText(container)).toMatch(/16 scans/i))
    // "16 turns" was the old, wrong rendering of a 2-turn run.
    expect(summaryText(container)).not.toMatch(/16 turns/i)
  })

  it("derives the turn count from turn_index, not from count", async () => {
    // count deliberately disagrees with the records: if the page echoed count
    // as the turn number this would read "99 scans across 99 turns".
    const scans = [scan(1), scan(1), scan(2)]
    getAgentRun.mockResolvedValue({ run_id: "mcprun_x", count: 99, scans })

    const { container } = renderWithIntl(<AgentRunPage />)

    await waitFor(() => expect(summaryText(container)).toMatch(/99 scans across 2 turns/i))
  })

  it("counts every scan as its own turn when they do not share an index", async () => {
    const scans = [scan(0), scan(1), scan(2)]
    getAgentRun.mockResolvedValue({ run_id: "mcprun_x", count: 3, scans })

    const { container } = renderWithIntl(<AgentRunPage />)

    await waitFor(() => expect(summaryText(container)).toMatch(/3 scans across 3 turns/i))
  })

  it("renders an empty run without inventing turns", async () => {
    getAgentRun.mockResolvedValue({ run_id: "mcprun_x", count: 0, scans: [] })

    const { container } = renderWithIntl(<AgentRunPage />)

    await waitFor(() => expect(summaryText(container)).toMatch(/0 scans across 0 turns/i))
  })
})
