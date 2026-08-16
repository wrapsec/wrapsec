// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"

// Mock the API so submit is observable and no real network happens.
vi.mock("@/lib/api", () => ({
  updateThresholds: vi.fn(),
}))
import { ThresholdForm } from "@/components/settings/ThresholdForm"
import { updateThresholds } from "@/lib/api"

// useAuthMode fetches /api/auth/session; return an ADMIN session so the save button
// is enabled (admin write allowed). Individual tests can override the response.
function stubSession(
  session: Record<string, unknown> = { authenticated: true, auth_type: "jwt", role: "ADMIN", is_admin: true, can_write: true },
) {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ json: async () => session }))
}

beforeEach(() => {
  stubSession()
  vi.mocked(updateThresholds).mockReset()
})
afterEach(() => {
  vi.unstubAllGlobals()
})

const valid = { block_threshold: 0.7, sanitize_threshold: 0.4 }

// useAuthMode resolves the session asynchronously, so a DISABLED "Save thresholds"
// (non-JWT branch) renders first and is replaced by the enabled JWT button once the
// session resolves. Wait for the enabled button, then return a FRESH reference.
async function enabledSave() {
  await waitFor(() => expect(screen.getByRole("button", { name: "Save thresholds" })).toBeEnabled())
  return screen.getByRole("button", { name: "Save thresholds" })
}

describe("ThresholdForm validation", () => {
  it("renders the two threshold inputs with the passed values", () => {
    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)
    expect(screen.getByDisplayValue("0.7")).toBeInTheDocument()
    expect(screen.getByDisplayValue("0.4")).toBeInTheDocument()
  })

  it("shows the order error when block <= sanitize", async () => {
    const user = userEvent.setup()
    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)

    // Set block below sanitize -> invalid ordering.
    const block = screen.getByDisplayValue("0.7")
    await user.clear(block)
    await user.type(block, "0.3")

    expect(screen.getByText("Block threshold must be greater than sanitize threshold")).toBeInTheDocument()
  })

  it("shows the block-min error when block is 0", async () => {
    const user = userEvent.setup()
    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)
    const block = screen.getByDisplayValue("0.7")
    await user.clear(block)
    await user.type(block, "0")
    expect(screen.getByText("Block threshold must be greater than 0")).toBeInTheDocument()
  })

  it("disables Save while the form is invalid", async () => {
    const user = userEvent.setup()
    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)
    await enabledSave()   // JWT session resolved -> Save is enabled while valid

    const block = screen.getByDisplayValue("0.7")
    await user.clear(block)
    await user.type(block, "0.3")   // invalid ordering
    expect(screen.getByRole("button", { name: "Save thresholds" })).toBeDisabled()
  })
})

describe("ThresholdForm submit", () => {
  it("calls updateThresholds with the current values and fires onUpdated", async () => {
    const onUpdated = vi.fn()
    vi.mocked(updateThresholds).mockResolvedValue({ block_threshold: 0.7, sanitize_threshold: 0.4 })
    const user = userEvent.setup()

    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={onUpdated} />)
    await user.click(await enabledSave())

    await waitFor(() => expect(updateThresholds).toHaveBeenCalledWith({
      block_threshold: 0.7, sanitize_threshold: 0.4,
    }))
    await waitFor(() => expect(onUpdated).toHaveBeenCalledWith({ block_threshold: 0.7, sanitize_threshold: 0.4 }))
  })

  it("shows the server error message when updateThresholds rejects", async () => {
    vi.mocked(updateThresholds).mockRejectedValue(new Error("server said no"))
    const user = userEvent.setup()

    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)
    await user.click(await enabledSave())

    expect(await screen.findByText("server said no")).toBeInTheDocument()
  })

  it("hides the enabled Save for an API-key session (no write)", async () => {
    stubSession({ authenticated: true, auth_type: "api_key", role: null, is_admin: false, can_write: false })
    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)
    // The non-admin branch renders a DISABLED save + a requires-admin note.
    await waitFor(() => expect(screen.getByRole("button", { name: "Save thresholds" })).toBeDisabled())
  })

  it("disables Save for a VIEWER JWT session (has a session but not admin)", async () => {
    // Regression: write gating must key off the ADMIN role, not merely a JWT
    // session. A VIEWER holds a JWT (can_write true) yet must not see enabled writes.
    stubSession({ authenticated: true, auth_type: "jwt", role: "VIEWER", is_admin: false, can_write: true })
    renderWithIntl(<ThresholdForm thresholds={valid} onUpdated={() => {}} />)
    await waitFor(() => expect(screen.getByRole("button", { name: "Save thresholds" })).toBeDisabled())
  })
})
