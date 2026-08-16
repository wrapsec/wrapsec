// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"

const replace = vi.fn()
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }))
vi.mock("@/lib/auth", async () => {
  const actual = await vi.importActual<typeof import("@/lib/auth")>("@/lib/auth")
  return { ...actual, changePassword: vi.fn(), logout: vi.fn().mockResolvedValue(undefined) }
})

import ChangePasswordPage from "@/app/change-password/page"
import { changePassword, logout, AuthError } from "@/lib/auth"

const pwInputs = () => Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[]

beforeEach(() => {
  replace.mockReset()
  vi.mocked(changePassword).mockReset()
  vi.mocked(logout).mockReset().mockResolvedValue(undefined)
})
afterEach(() => {
  // Guarantee real timers even if a fake-timer test throws before restoring.
  vi.useRealTimers()
})

// Fill current/new/confirm. `next` defaults to a policy-valid password.
async function fill(user: ReturnType<typeof userEvent.setup>, current: string, next: string, confirm = next) {
  const [c, n, cf] = pwInputs()
  if (current) await user.type(c, current)
  if (next)    await user.type(n, next)
  if (confirm) await user.type(cf, confirm)
}

describe("ChangePasswordPage validation gating", () => {
  it("keeps Change disabled until requirements are met AND passwords match", async () => {
    const user = userEvent.setup()
    renderWithIntl(<ChangePasswordPage />)
    const submit = () => screen.getByRole("button", { name: "Change password" })
    expect(submit()).toBeDisabled()

    // A weak new password (no uppercase/digit) keeps it disabled.
    await fill(user, "oldpass1A", "weak", "weak")
    expect(submit()).toBeDisabled()

    // A compliant, matching password enables it.
    await user.clear(pwInputs()[1]); await user.clear(pwInputs()[2])
    await user.type(pwInputs()[1], "StrongPass1")
    await user.type(pwInputs()[2], "StrongPass1")
    expect(submit()).toBeEnabled()
  })

  it("shows a mismatch hint when confirm differs", async () => {
    const user = userEvent.setup()
    renderWithIntl(<ChangePasswordPage />)
    await fill(user, "oldpass1A", "StrongPass1", "StrongPass2")
    expect(screen.getByText("Passwords do not match.")).toBeInTheDocument()
  })
})

describe("ChangePasswordPage submit", () => {
  it("changes the password, shows success, then logs out and redirects", async () => {
    vi.mocked(changePassword).mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderWithIntl(<ChangePasswordPage />)

    await fill(user, "oldpass1A", "StrongPass1")
    await user.click(screen.getByRole("button", { name: "Change password" }))

    await waitFor(() => expect(changePassword).toHaveBeenCalledWith("oldpass1A", "StrongPass1"))
    // Immediate success screen.
    expect(await screen.findByText("Password changed")).toBeInTheDocument()

    // The component logs out + redirects on a 2s delay (real timers, extended wait).
    await waitFor(() => expect(logout).toHaveBeenCalledWith("manual"), { timeout: 3000 })
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/login"), { timeout: 3000 })
  }, 8000)

  it("maps INVALID_PASSWORD to the incorrect-current message and does not log out", async () => {
    vi.mocked(changePassword).mockRejectedValue(new AuthError("INVALID_PASSWORD", "x"))
    const user = userEvent.setup()
    renderWithIntl(<ChangePasswordPage />)

    await fill(user, "wrongcurrent1A", "StrongPass1")
    await user.click(screen.getByRole("button", { name: "Change password" }))

    expect(await screen.findByText("Current password is incorrect.")).toBeInTheDocument()
    expect(logout).not.toHaveBeenCalled()
  })
})

describe("ChangePasswordPage sign-out", () => {
  it("logs out when the Sign out button is clicked", async () => {
    const user = userEvent.setup()
    renderWithIntl(<ChangePasswordPage />)
    await user.click(screen.getByRole("button", { name: "Sign out" }))
    expect(logout).toHaveBeenCalledWith("manual")
  })
})
