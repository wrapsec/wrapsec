// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen } from "./_render"
import { ApiKeyTable } from "@/components/settings/ApiKeyTable"
import type { ApiKey } from "@/lib/types"

function key(over: Partial<ApiKey> = {}): ApiKey {
  return {
    key_id:       "wsk_live_abc123",
    name:         "Prod key",
    key_type:     "live",
    dept_id:      null,
    dept_name:    null,
    app_id:       null,
    app_name:     null,
    tenant_id:    "t1",
    last_used_at: null,
    created_at:   "2026-01-01T00:00:00Z",
    expires_at:   null,
    ...over,
  } as ApiKey
}

const noop = () => {}
const noopRotate = async () => "wsk_live_rotated"

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ json: async () => ({}) }))
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe("ApiKeyTable render states", () => {
  it("shows the empty state when there are no keys", () => {
    renderWithIntl(
      <ApiKeyTable keys={[]} onRevoke={noop} onRotate={noopRotate} revoking={null} />
    )
    expect(screen.getByText("No API keys yet")).toBeInTheDocument()
  })

  it("renders a row per key with its name and 'Never' for an unused key", () => {
    renderWithIntl(
      <ApiKeyTable
        keys={[key({ name: "Alpha" }), key({ key_id: "wsk_live_def", name: "Beta" })]}
        onRevoke={noop} onRotate={noopRotate} revoking={null}
      />
    )
    expect(screen.getByText("Alpha")).toBeInTheDocument()
    expect(screen.getByText("Beta")).toBeInTheDocument()
    expect(screen.getAllByText("Never").length).toBe(2)
  })

  it("marks a trial key with a trial badge", () => {
    renderWithIntl(
      <ApiKeyTable keys={[key({ key_type: "trial" })]} onRevoke={noop} onRotate={noopRotate} revoking={null} />
    )
    expect(screen.getByText("Trial")).toBeInTheDocument()
  })
})

describe("ApiKeyTable write-action gating (security)", () => {
  it("shows Revoke/Rotate when canWrite is true (default)", () => {
    renderWithIntl(
      <ApiKeyTable keys={[key()]} onRevoke={noop} onRotate={noopRotate} revoking={null} />
    )
    expect(screen.getByRole("button", { name: "Rotate" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument()
  })

  it("HIDES Revoke/Rotate for an API-key session (canWrite=false)", () => {
    renderWithIntl(
      <ApiKeyTable keys={[key()]} onRevoke={noop} onRotate={noopRotate} revoking={null} canWrite={false} />
    )
    expect(screen.queryByRole("button", { name: "Rotate" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument()
  })
})

describe("ApiKeyTable revoke interaction", () => {
  it("requires confirmation before calling onRevoke", async () => {
    const onRevoke = vi.fn()
    const user = userEvent.setup()
    renderWithIntl(
      <ApiKeyTable keys={[key()]} onRevoke={onRevoke} onRotate={noopRotate} revoking={null} />
    )

    // First click reveals the confirmation row; onRevoke is NOT called yet.
    await user.click(screen.getByRole("button", { name: "Revoke" }))
    expect(onRevoke).not.toHaveBeenCalled()

    // Confirm actually invokes the callback with the key id.
    const confirm = screen.getByRole("button", { name: "Confirm revocation" })
    await user.click(confirm)
    expect(onRevoke).toHaveBeenCalledWith("wsk_live_abc123")
  })
})
