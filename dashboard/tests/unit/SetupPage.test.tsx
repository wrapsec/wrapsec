// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"

const replace = vi.fn()
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }))
vi.mock("@/lib/api", () => ({
  getSetupStatus: vi.fn(),
  completeSetup:  vi.fn(),
}))

import SetupPage from "@/app/setup/page"
import { getSetupStatus, completeSetup } from "@/lib/api"

const email = () => document.querySelector('input[type="email"]') as HTMLInputElement
const pwInputs = () => Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[]

beforeEach(() => {
  replace.mockReset()
  vi.mocked(getSetupStatus).mockResolvedValue({ initialized: false })
  vi.mocked(completeSetup).mockReset()
})

describe("SetupPage guard", () => {
  it("redirects an already-initialized instance to /login", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue({ initialized: true })
    renderWithIntl(<SetupPage />)
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/login"))
  })

  it("stays on the setup form when not initialized", async () => {
    renderWithIntl(<SetupPage />)
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled())
    expect(replace).not.toHaveBeenCalled()
  })
})

describe("SetupPage create-admin flow", () => {
  it("rejects mismatched passwords without calling completeSetup", async () => {
    const user = userEvent.setup()
    renderWithIntl(<SetupPage />)
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled())

    await user.type(email(), "admin@example.com")
    const [pw, confirm] = pwInputs()
    await user.type(pw, "secret123")
    await user.type(confirm, "different")
    await user.click(screen.getByRole("button", { name: "Create admin account" }))

    expect(await screen.findByText("Passwords do not match.")).toBeInTheDocument()
    expect(completeSetup).not.toHaveBeenCalled()
  })

  it("completes setup with a normalized email and routes to login", async () => {
    vi.mocked(completeSetup).mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderWithIntl(<SetupPage />)
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled())

    await user.type(email(), "  Admin@Example.com ")
    const [pw, confirm] = pwInputs()
    await user.type(pw, "secret123")
    await user.type(confirm, "secret123")
    await user.click(screen.getByRole("button", { name: "Create admin account" }))

    await waitFor(() => expect(completeSetup).toHaveBeenCalledWith("admin@example.com", "secret123"))
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/login?setup=done"))
  })

  it("surfaces the backend error message on failure", async () => {
    vi.mocked(completeSetup).mockRejectedValue(new Error("weak password"))
    const user = userEvent.setup()
    renderWithIntl(<SetupPage />)
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled())

    await user.type(email(), "admin@example.com")
    const [pw, confirm] = pwInputs()
    await user.type(pw, "secret123")
    await user.type(confirm, "secret123")
    await user.click(screen.getByRole("button", { name: "Create admin account" }))

    expect(await screen.findByText("weak password")).toBeInTheDocument()
    expect(replace).not.toHaveBeenCalledWith("/login?setup=done")
  })
})
