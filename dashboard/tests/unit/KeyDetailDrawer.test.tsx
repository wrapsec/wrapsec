// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The drawer is where a credential's source networks are read and changed, so
// what matters is that it never misreports the restriction: an empty field must
// mean "no restriction", a hidden field must not read as one, and a list that
// would turn the control off must not reach the server looking deliberate.
import { describe, it, expect, vi, beforeEach } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen, waitFor } from "./_render"

vi.mock("@/lib/api", () => ({
  getApiKey:    vi.fn(),
  updateApiKey: vi.fn(),
}))

import { KeyDetailDrawer } from "@/components/settings/KeyDetailDrawer"
import { getApiKey, updateApiKey } from "@/lib/api"

const KEY = {
  key_id:       "wsk_abc123",
  name:         "billing-service",
  key_type:     "live" as const,
  app_id:       null,
  app_name:     null,
  dept_id:      "d1",
  dept_name:    "Engineering",
  is_admin:     false,
  revoked:      false,
  created_at:   "2026-08-01T00:00:00Z",
  expires_at:   null,
  last_used_at: null,
}

beforeEach(() => {
  vi.mocked(getApiKey).mockReset()
  vi.mocked(updateApiKey).mockReset()
  vi.mocked(updateApiKey).mockResolvedValue({ key_id: KEY.key_id, name: KEY.name, ip_allowlist: [] })
})

function open(detail: Record<string, unknown>, canWrite = true) {
  vi.mocked(getApiKey).mockResolvedValue(detail as never)
  const onSaved = vi.fn()
  renderWithIntl(
    <KeyDetailDrawer keyId={KEY.key_id} canWrite={canWrite} onClose={vi.fn()} onSaved={onSaved} />,
  )
  return { onSaved }
}

describe("KeyDetailDrawer", () => {
  it("shows the credential's configured networks", async () => {
    open({ ...KEY, ip_allowlist: ["10.0.0.0/8", "192.0.2.7/32"] })

    const field = await screen.findByLabelText("Source networks")
    expect((field as HTMLTextAreaElement).value).toBe("10.0.0.0/8\n192.0.2.7/32")
  })

  it("says plainly when a credential is unrestricted", async () => {
    open({ ...KEY, ip_allowlist: [] })

    expect(await screen.findByText(/may be used from any address/i)).toBeTruthy()
  })

  it("does not present a hidden restriction as an absent one", async () => {
    // A non-administrator gets no ip_allowlist field at all. Showing an empty
    // box would tell them the key is unrestricted, which it may not be.
    open({ ...KEY }, false)

    expect(await screen.findByText(/only an administrator/i)).toBeTruthy()
    expect(screen.queryByLabelText("Source networks")).toBeNull()
  })

  it("refuses to send a malformed entry", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] })

    const field = await screen.findByLabelText("Source networks")
    await user.type(field, "not-an-ip")

    expect(await screen.findByText(/is not a valid IP address/i)).toBeTruthy()
    const save = screen.getByRole("button", { name: /save changes/i })
    expect((save as HTMLButtonElement).disabled).toBe(true)
    expect(updateApiKey).not.toHaveBeenCalled()
  })

  it("refuses a list that would turn the restriction off", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] })

    const field = await screen.findByLabelText("Source networks")
    await user.type(field, "0.0.0.0/0")

    expect(await screen.findByText(/allows every address/i)).toBeTruthy()
    expect(updateApiKey).not.toHaveBeenCalled()
  })

  it("sends the edited networks", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] })

    const field = await screen.findByLabelText("Source networks")
    await user.type(field, "10.0.0.0/8")
    await user.click(screen.getByRole("button", { name: /save changes/i }))

    await waitFor(() => {
      expect(updateApiKey).toHaveBeenCalledWith(KEY.key_id, KEY.name, ["10.0.0.0/8"])
    })
  })

  it("clears the restriction when the field is emptied", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: ["10.0.0.0/8"] })

    const field = await screen.findByLabelText("Source networks")
    await user.clear(field)
    await user.click(screen.getByRole("button", { name: /save changes/i }))

    // An empty list, not an omitted one: the server reads absence as "leave it
    // alone", so omitting here would make the restriction unremovable.
    await waitFor(() => {
      expect(updateApiKey).toHaveBeenCalledWith(KEY.key_id, KEY.name, [])
    })
  })

  it("surfaces a refusal from the server rather than reporting success", async () => {
    const user = userEvent.setup()
    vi.mocked(updateApiKey).mockRejectedValue(new Error("allows every address"))
    open({ ...KEY, ip_allowlist: [] })

    const field = await screen.findByLabelText("Source networks")
    await user.type(field, "10.0.0.0/8")
    await user.click(screen.getByRole("button", { name: /save changes/i }))

    expect(await screen.findByText(/allows every address/i)).toBeTruthy()
    expect(screen.queryByText(/changes saved/i)).toBeNull()
  })

  it("offers no way to save to someone who cannot edit", async () => {
    open({ ...KEY }, false)

    await screen.findByText(/only an administrator/i)
    expect(screen.queryByRole("button", { name: /save changes/i })).toBeNull()
  })

  it("tells the operator that rotation keeps the restriction", async () => {
    open({ ...KEY, ip_allowlist: ["10.0.0.0/8"] })

    expect(await screen.findByText(/rotating this key keeps/i)).toBeTruthy()
  })
})
