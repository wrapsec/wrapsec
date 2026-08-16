// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"

// Mock the API: createApiKey (submit) + the SWR-loaded selectors.
vi.mock("@/lib/api", () => ({
  createApiKey:           vi.fn(),
  getDepartments:         vi.fn().mockResolvedValue({ departments: [{ id: "d1", name: "Engineering" }] }),
  getApplicationsByDept:  vi.fn().mockResolvedValue({ applications: [] }),
}))
import { CreateKeyModal } from "@/components/settings/CreateKeyModal"
import { createApiKey } from "@/lib/api"

beforeEach(() => {
  vi.mocked(createApiKey).mockReset()
})
afterEach(() => {
  vi.unstubAllGlobals()
})

function setup() {
  const onCreated = vi.fn()
  const onClose   = vi.fn()
  renderWithIntl(<CreateKeyModal onCreated={onCreated} onClose={onClose} />)
  return { onCreated, onClose, user: userEvent.setup() }
}

describe("CreateKeyModal validation", () => {
  it("disables Create until both a name and a department are set", async () => {
    const { user } = setup()
    const submit = screen.getByRole("button", { name: "Create key" })
    expect(submit).toBeDisabled()

    // Name only -> still disabled (dept required).
    await user.type(screen.getByPlaceholderText(/finance-bot/i), "My key")
    expect(submit).toBeDisabled()

    // Pick the department (loaded via SWR) -> now enabled.
    await waitFor(() => expect(screen.getByRole("option", { name: "Engineering" })).toBeInTheDocument())
    // First combobox is the department selector.
    await user.selectOptions(screen.getAllByRole("combobox")[0], "d1")
    expect(screen.getByRole("button", { name: "Create key" })).toBeEnabled()
  })
})

describe("CreateKeyModal create flow", () => {
  it("calls createApiKey and reveals the one-time secret on success", async () => {
    const { onCreated, user } = setup()
    vi.mocked(createApiKey).mockResolvedValue({
      api_key: "wsk_live_secret_shown_once", key_id: "k1", key_type: "live", dept_id: "d1", app_id: null,
    } as never)

    await user.type(screen.getByPlaceholderText(/finance-bot/i), "My key")
    await waitFor(() => expect(screen.getByRole("option", { name: "Engineering" })).toBeInTheDocument())
    await user.selectOptions(screen.getAllByRole("combobox")[0], "d1")
    await user.click(screen.getByRole("button", { name: "Create key" }))

    await waitFor(() => expect(createApiKey).toHaveBeenCalledWith("My key", undefined, "d1", "live"))
    // One-time reveal: the plaintext secret + the "copy now, shown once" warning.
    expect(await screen.findByText("wsk_live_secret_shown_once")).toBeInTheDocument()
    expect(screen.getByText(/will not be shown again/i)).toBeInTheDocument()
    expect(onCreated).toHaveBeenCalled()
  })

  it("shows the server error and does NOT reveal a key on failure", async () => {
    const { user } = setup()
    vi.mocked(createApiKey).mockRejectedValue(new Error("quota exceeded"))

    await user.type(screen.getByPlaceholderText(/finance-bot/i), "My key")
    await waitFor(() => expect(screen.getByRole("option", { name: "Engineering" })).toBeInTheDocument())
    await user.selectOptions(screen.getAllByRole("combobox")[0], "d1")
    await user.click(screen.getByRole("button", { name: "Create key" }))

    expect(await screen.findByText("quota exceeded")).toBeInTheDocument()
    expect(screen.queryByText(/will not be shown again/i)).not.toBeInTheDocument()
  })
})

describe("CreateKeyModal close", () => {
  it("closes on Escape", async () => {
    const { onClose, user } = setup()
    await user.keyboard("{Escape}")
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it("closes on Cancel", async () => {
    const { onClose, user } = setup()
    await user.click(screen.getByRole("button", { name: "Cancel" }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
