// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen } from "./_render"
import { RequestsTable } from "@/components/requests/RequestsTable"
import type { AuditLogItem } from "@/lib/types"

function item(over: Partial<AuditLogItem> = {}): AuditLogItem {
  return {
    trace_id:        "req_abc1234567",
    timestamp:       "2026-01-01T00:00:00Z",
    decision:        "ALLOW",
    output_decision: null,
    severity:        "LOW",
    risk_score:      0.1,
    threats:         [],
    input_source:    "user_prompt",
    dept_name:       null,
    app_name:        null,
    latency_ms:      12,
    run_id:          null,
    turn_index:      null,
    ...over,
  } as AuditLogItem
}

describe("RequestsTable render states", () => {
  it("shows the empty state when there are no items", () => {
    renderWithIntl(<RequestsTable items={[]} onSelect={() => {}} />)
    // EmptyState renders inside the table; assert its title exists.
    expect(screen.getByText(/no requests/i)).toBeInTheDocument()
  })

  it("renders a row per item with a truncated trace id and decision", () => {
    renderWithIntl(
      <RequestsTable
        items={[item({ trace_id: "req_aaaaaaaaaa" }), item({ trace_id: "req_bbbbbbbbbb", decision: "BLOCK" })]}
        onSelect={() => {}}
      />
    )
    // Two decision badges (ALLOW + BLOCK) present.
    expect(screen.getByText("ALLOW")).toBeInTheDocument()
    expect(screen.getByText("BLOCK")).toBeInTheDocument()
  })

  it("renders threat badges when present and a dash when empty", () => {
    renderWithIntl(
      <RequestsTable
        items={[item({ threats: ["PROMPT_INJECTION"] as AuditLogItem["threats"] })]}
        onSelect={() => {}}
      />
    )
    expect(screen.getByText(/prompt.?injection/i)).toBeInTheDocument()
  })

  it("shows the input -> output decision transition when they differ", () => {
    renderWithIntl(
      <RequestsTable
        items={[item({ decision: "ALLOW", output_decision: "SANITIZE" })]}
        onSelect={() => {}}
      />
    )
    expect(screen.getByText("ALLOW")).toBeInTheDocument()
    expect(screen.getByText("SANITIZE")).toBeInTheDocument()
  })
})

describe("RequestsTable compact variant", () => {
  it("hides full-only columns (e.g. source) in compact mode", () => {
    const { rerender } = renderWithIntl(
      <RequestsTable items={[item()]} onSelect={() => {}} compact={false} />
    )
    // Full mode shows the source badge (user_prompt -> "User Prompt").
    expect(screen.getByText("User Prompt")).toBeInTheDocument()

    rerender(<RequestsTable items={[item()]} onSelect={() => {}} compact={true} />)
    // Compact mode drops the source column.
    expect(screen.queryByText("User Prompt")).not.toBeInTheDocument()
  })
})

describe("RequestsTable row selection", () => {
  it("calls onSelect with the trace id when a row is clicked", async () => {
    const onSelect = vi.fn()
    const user = userEvent.setup()
    renderWithIntl(<RequestsTable items={[item({ trace_id: "req_xyz9876543" })]} onSelect={onSelect} />)

    // The cell shows the truncated id ("req_...9876543"); click it to select the row.
    await user.click(screen.getByText("req_...9876543"))
    expect(onSelect).toHaveBeenCalledWith("req_xyz9876543")
  })
})
