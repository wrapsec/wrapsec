// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The API-keys management page orchestrates load/error/populated states, search
// filtering, create-modal gating (JWT only), and revoke/rotate over the API. The
// Shell chrome (sidebar/topbar/inactivity) is mocked to a passthrough so this test
// targets the page's own logic; ApiKeyTable + CreateKeyModal are unit-tested
// separately.
import { describe, it, expect, vi, beforeEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"
import type { ApiKey } from "@/lib/types"

vi.mock("@/components/layout/Shell", () => ({
  Shell: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))

let session = { isAdmin: true }
vi.mock("@/hooks/useAuthMode", () => ({ useAuthMode: () => session }))

vi.mock("@/lib/api", () => ({
  getApiKeys:            vi.fn(),
  revokeApiKey:          vi.fn(),
  rotateApiKey:          vi.fn(),
  // Consumed by CreateKeyModal when it opens.
  getDepartments:        vi.fn().mockResolvedValue({ departments: [] }),
  getApplicationsByDept: vi.fn().mockResolvedValue({ applications: [] }),
}))

import ApiKeysPage from "@/app/settings/keys/page"
import { getApiKeys, revokeApiKey } from "@/lib/api"

function key(over: Partial<ApiKey> = {}): ApiKey {
  return {
    key_id: "wsk_live_a", name: "Alpha", key_type: "live",
    dept_id: null, dept_name: null, app_id: null, app_name: null,
    tenant_id: "t1", last_used_at: null, created_at: "2026-01-01T00:00:00Z", expires_at: null,
    ...over,
  } as ApiKey
}

beforeEach(() => {
  session = { isAdmin: true }
  vi.mocked(getApiKeys).mockReset()
  vi.mocked(revokeApiKey).mockReset()
})

describe("ApiKeysPage data states", () => {
  it("renders the loaded keys", async () => {
    vi.mocked(getApiKeys).mockResolvedValue({ keys: [key({ name: "Alpha" }), key({ key_id: "wsk_live_b", name: "Beta" })] })
    renderWithIntl(<ApiKeysPage />)
    expect(await screen.findByText("Alpha")).toBeInTheDocument()
    expect(screen.getByText("Beta")).toBeInTheDocument()
  })

  it("shows the load-error surface when the fetch fails", async () => {
    vi.mocked(getApiKeys).mockRejectedValue(new Error("boom"))
    renderWithIntl(<ApiKeysPage />)
    expect(await screen.findByText("Failed to load API keys")).toBeInTheDocument()
  })
})

describe("ApiKeysPage search filter", () => {
  it("filters the table by name", async () => {
    vi.mocked(getApiKeys).mockResolvedValue({ keys: [key({ name: "Alpha" }), key({ key_id: "wsk_live_b", name: "Beta" })] })
    const user = userEvent.setup()
    renderWithIntl(<ApiKeysPage />)
    await screen.findByText("Alpha")

    await user.type(screen.getByPlaceholderText("Search keys..."), "beta")
    await waitFor(() => expect(screen.queryByText("Alpha")).not.toBeInTheDocument())
    expect(screen.getByText("Beta")).toBeInTheDocument()
  })
})

describe("ApiKeysPage write gating (security)", () => {
  it("shows the Create button for an ADMIN session", async () => {
    vi.mocked(getApiKeys).mockResolvedValue({ keys: [] })
    renderWithIntl(<ApiKeysPage />)
    await waitFor(() => expect(screen.getByRole("button", { name: /create key/i })).toBeEnabled())
  })

  it("disables Create for a non-admin session (VIEWER/DEVELOPER/API-key)", async () => {
    session = { isAdmin: false }
    vi.mocked(getApiKeys).mockResolvedValue({ keys: [] })
    renderWithIntl(<ApiKeysPage />)
    await waitFor(() => expect(screen.getByRole("button", { name: /create key/i })).toBeDisabled())
  })
})

describe("ApiKeysPage revoke orchestration", () => {
  it("revokes a key (after confirm) and refetches", async () => {
    vi.mocked(getApiKeys).mockResolvedValue({ keys: [key({ key_id: "wsk_live_a", name: "Alpha" })] })
    vi.mocked(revokeApiKey).mockResolvedValue({ revoked: true } as never)
    const user = userEvent.setup()
    renderWithIntl(<ApiKeysPage />)
    await screen.findByText("Alpha")

    await user.click(screen.getByRole("button", { name: "Revoke" }))
    await user.click(screen.getByRole("button", { name: "Confirm revocation" }))

    await waitFor(() => expect(revokeApiKey).toHaveBeenCalledWith("wsk_live_a"))
    // mutate() triggers a refetch of the key list.
    await waitFor(() => expect(vi.mocked(getApiKeys).mock.calls.length).toBeGreaterThan(1))
  })
})

describe("ApiKeysPage create modal", () => {
  it("opens the create modal from the Create button (JWT)", async () => {
    vi.mocked(getApiKeys).mockResolvedValue({ keys: [] })
    const user = userEvent.setup()
    renderWithIntl(<ApiKeysPage />)
    await waitFor(() => expect(screen.getByRole("button", { name: /create key/i })).toBeEnabled())

    await user.click(screen.getByRole("button", { name: /create key/i }))
    // The modal heading appears.
    expect(await screen.findByText("Create API Key")).toBeInTheDocument()
  })
})
