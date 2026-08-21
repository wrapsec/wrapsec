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
  getApiKey:        vi.fn(),
  updateApiKey:     vi.fn(),
  getKeyAddresses:  vi.fn(),
}))

import { KeyDetailDrawer } from "@/components/settings/KeyDetailDrawer"
import { getApiKey, getKeyAddresses, updateApiKey } from "@/lib/api"

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

const NO_ADDRESSES = {
  key_id: KEY.key_id, window_days: 30, observed: [], denied: [],
}

function seen(ip: string, count = 1) {
  return { ip_address: ip, count, last_seen: "2026-08-01T00:00:00Z" }
}

beforeEach(() => {
  vi.mocked(getApiKey).mockReset()
  vi.mocked(updateApiKey).mockReset()
  vi.mocked(getKeyAddresses).mockReset()
  vi.mocked(updateApiKey).mockResolvedValue({ key_id: KEY.key_id, name: KEY.name, ip_allowlist: [] })
  vi.mocked(getKeyAddresses).mockResolvedValue(NO_ADDRESSES as never)
})

function open(
  detail: Record<string, unknown>,
  canWrite = true,
  addresses?: { observed?: unknown[]; denied?: unknown[] },
) {
  vi.mocked(getApiKey).mockResolvedValue(detail as never)
  if (addresses) {
    vi.mocked(getKeyAddresses).mockResolvedValue({
      ...NO_ADDRESSES, ...addresses,
    } as never)
  }
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

// The two lists exist so the restriction is set from evidence rather than from
// memory. What they must never do is make the operator MORE confident than the
// evidence warrants: a list that fails to load, or a warning that stays quiet
// when live traffic would be cut off, is worse than no panel at all.
describe("KeyDetailDrawer address panels", () => {
  it("shows where the credential has actually been used", async () => {
    open({ ...KEY, ip_allowlist: [] }, true, { observed: [seen("203.0.113.10", 4)] })

    expect(await screen.findByText("203.0.113.10")).toBeTruthy()
    expect(screen.getByText(/4 requests/)).toBeTruthy()
  })

  it("adds an observed address as the single address, not the network", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] }, true, { observed: [seen("203.0.113.10")] })

    await screen.findByText("203.0.113.10")
    await user.click(screen.getByRole("button", { name: /^add$/i }))

    const field = screen.getByLabelText("Source networks") as HTMLTextAreaElement
    expect(field.value).toBe("203.0.113.10/32")
  })

  it("does not add a refused address on a single click", async () => {
    // A refused address may be a service that moved, or it may be someone else
    // holding the key. It is not added next to a list of addresses the operator
    // is used to clicking straight through.
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: ["10.0.0.0/8"] }, true, { denied: [seen("198.51.100.9")] })

    await screen.findByText("198.51.100.9")
    await user.click(screen.getByRole("button", { name: /^add$/i }))

    const field = screen.getByLabelText("Source networks") as HTMLTextAreaElement
    expect(field.value).toBe("10.0.0.0/8")
    expect(await screen.findByText(/198\.51\.100\.9\/32\?/)).toBeTruthy()
  })

  it("adds a refused address once it is confirmed", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: ["10.0.0.0/8"] }, true, { denied: [seen("198.51.100.9")] })

    await screen.findByText("198.51.100.9")
    await user.click(screen.getByRole("button", { name: /^add$/i }))
    await user.click(screen.getByRole("button", { name: /add it/i }))

    const field = screen.getByLabelText("Source networks") as HTMLTextAreaElement
    expect(field.value).toBe("10.0.0.0/8\n198.51.100.9/32")
  })

  it("warns before saving a list that would cut off live traffic", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] }, true, { observed: [seen("203.0.113.10", 400)] })

    const field = await screen.findByLabelText("Source networks")
    await user.type(field, "10.0.0.0/8")

    // named inside the warning, not merely present somewhere on the page: the
    // operator has to be told WHICH address stops working
    const alert = await screen.findByRole("alert")
    expect(alert.textContent).toContain("203.0.113.10")
    expect(screen.getByRole("button", { name: /save anyway/i })).toBeTruthy()
  })

  it("stays quiet when the list still admits everything the key uses", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] }, true, { observed: [seen("10.1.2.3")] })

    const field = await screen.findByLabelText("Source networks")
    await user.type(field, "10.0.0.0/8")

    expect(screen.queryByRole("alert")).toBeNull()
    expect(screen.getByRole("button", { name: /save changes/i })).toBeTruthy()
  })

  it("does not warn about an unrestricted list", async () => {
    // An empty field is no restriction, so nothing is being cut off. Warning
    // here would train the operator to click past the warning that matters.
    open({ ...KEY, ip_allowlist: [] }, true, { observed: [seen("203.0.113.10")] })

    await screen.findByText("203.0.113.10")
    expect(screen.queryByRole("alert")).toBeNull()
  })

  it("still warns after adding a refused address that does not cover live traffic", async () => {
    const user = userEvent.setup()
    open({ ...KEY, ip_allowlist: [] }, true, {
      observed: [seen("203.0.113.10")],
      denied:   [seen("198.51.100.9")],
    })

    await screen.findByText("198.51.100.9")
    const adds = screen.getAllByRole("button", { name: /^add$/i })
    await user.click(adds[adds.length - 1])
    await user.click(screen.getByRole("button", { name: /add it/i }))

    // Adding one address turned the restriction ON, which now excludes the
    // address the key actually uses. That is exactly when the warning is needed.
    const alert = await screen.findByRole("alert")
    expect(alert.textContent).toContain("203.0.113.10")
  })

  it("does not report a failed lookup as a key that has never been used", async () => {
    vi.mocked(getKeyAddresses).mockRejectedValue(new Error("nope"))
    open({ ...KEY, ip_allowlist: [] })

    expect(await screen.findByText(/could not load recent addresses/i)).toBeTruthy()
    expect(screen.queryByText(/no requests from this key/i)).toBeNull()
  })

  it("does not ask for addresses it would not be allowed to see", async () => {
    // The endpoint is administrator only. Asking as anyone else produces a
    // refusal that has to be told apart from an empty list, so it is not asked.
    open({ ...KEY }, false)

    await screen.findByText(/only an administrator/i)
    expect(getKeyAddresses).not.toHaveBeenCalled()
  })
})
