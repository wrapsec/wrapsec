// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"

// Router (next/navigation).
const replace = vi.fn()
const push    = vi.fn()
const refresh = vi.fn()
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace, push, refresh }),
}))

// Auth + setup-status.
vi.mock("@/lib/auth", async () => {
  const actual = await vi.importActual<typeof import("@/lib/auth")>("@/lib/auth")
  return {
    ...actual,   // keep the real AuthError class
    loginWithCredentials: vi.fn(),
    loginWithApiKey:      vi.fn(),
  }
})
vi.mock("@/lib/api", () => ({
  getSetupStatus: vi.fn().mockResolvedValue({ initialized: true }),
}))

import LoginPage from "@/app/login/page"
import { loginWithCredentials, loginWithApiKey, AuthError } from "@/lib/auth"
import { getSetupStatus } from "@/lib/api"

beforeEach(() => {
  replace.mockReset(); push.mockReset(); refresh.mockReset()
  vi.mocked(loginWithCredentials).mockReset()
  vi.mocked(loginWithApiKey).mockReset()
  vi.mocked(getSetupStatus).mockResolvedValue({ initialized: true })
})

describe("LoginPage setup redirect guard", () => {
  it("redirects to /setup when the instance is not initialized", async () => {
    vi.mocked(getSetupStatus).mockResolvedValue({ initialized: false })
    renderWithIntl(<LoginPage />)
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/setup"))
  })

  it("does NOT redirect when already initialized", async () => {
    renderWithIntl(<LoginPage />)
    await waitFor(() => expect(getSetupStatus).toHaveBeenCalled())
    expect(replace).not.toHaveBeenCalledWith("/setup")
  })
})

describe("LoginPage credentials flow", () => {
  it("logs in, lowercases/trims the email, and routes to the dashboard", async () => {
    vi.mocked(loginWithCredentials).mockResolvedValue({ force_password_change: false, user: {} as never })
    const user = userEvent.setup()
    renderWithIntl(<LoginPage />)

    await user.type(document.querySelector('input[type="email"]') as HTMLInputElement, "  Admin@Example.com ")
    const pw = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(pw, "secret123")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    await waitFor(() => expect(loginWithCredentials).toHaveBeenCalledWith("admin@example.com", "secret123"))
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/"))
  })

  it("routes to /change-password when force_password_change is set", async () => {
    vi.mocked(loginWithCredentials).mockResolvedValue({ force_password_change: true, user: {} as never })
    const user = userEvent.setup()
    renderWithIntl(<LoginPage />)

    await user.type(document.querySelector('input[type="email"]') as HTMLInputElement, "a@b.com")
    await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, "pw123456")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    await waitFor(() => expect(replace).toHaveBeenCalledWith("/change-password"))
  })

  it("maps ACCOUNT_LOCKED to the locked error message", async () => {
    vi.mocked(loginWithCredentials).mockRejectedValue(new AuthError("ACCOUNT_LOCKED", "x"))
    const user = userEvent.setup()
    renderWithIntl(<LoginPage />)

    await user.type(document.querySelector('input[type="email"]') as HTMLInputElement, "a@b.com")
    await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, "pw123456")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    expect(await screen.findByText(/account locked/i)).toBeInTheDocument()
    expect(replace).not.toHaveBeenCalledWith("/")
  })

  it("maps any other AuthError to the invalid-credentials message", async () => {
    vi.mocked(loginWithCredentials).mockRejectedValue(new AuthError("INVALID_CREDENTIALS", "x"))
    const user = userEvent.setup()
    renderWithIntl(<LoginPage />)

    await user.type(document.querySelector('input[type="email"]') as HTMLInputElement, "a@b.com")
    await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, "pw123456")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    expect(await screen.findByText(/invalid email or password/i)).toBeInTheDocument()
  })
})

describe("LoginPage API-key flow", () => {
  it("switches to the API-key tab and signs in on success", async () => {
    vi.mocked(loginWithApiKey).mockResolvedValue(true)
    const user = userEvent.setup()
    renderWithIntl(<LoginPage />)

    await user.click(screen.getByRole("button", { name: /api key instead/i }))
    const keyInput = document.querySelector('input[type="password"]') as HTMLInputElement
    await user.type(keyInput, "wsk_live_abc")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    await waitFor(() => expect(loginWithApiKey).toHaveBeenCalledWith("wsk_live_abc"))
    await waitFor(() => expect(push).toHaveBeenCalledWith("/"))
  })

  it("shows the invalid-key error when the key is rejected", async () => {
    vi.mocked(loginWithApiKey).mockResolvedValue(false)
    const user = userEvent.setup()
    renderWithIntl(<LoginPage />)

    await user.click(screen.getByRole("button", { name: /api key instead/i }))
    await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, "wsk_live_bad")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    expect(await screen.findByText(/invalid api key/i)).toBeInTheDocument()
  })
})
