// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import * as auth from "@/lib/auth"

function mockFetch() {
  const fn = vi.fn()
  vi.stubGlobal("fetch", fn)
  return fn
}

beforeEach(() => {
  vi.restoreAllMocks()
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe("refreshSession (single-flight)", () => {
  it("shares ONE in-flight request across concurrent callers", async () => {
    // A slow refresh so both calls overlap before it resolves.
    let resolveFetch: (v: unknown) => void = () => {}
    const fetchFn = mockFetch()
    fetchFn.mockReturnValue(new Promise((res) => { resolveFetch = res }))

    const p1 = auth.refreshSession()
    const p2 = auth.refreshSession()

    // Both callers must be joined to the same promise, so fetch fires once.
    expect(fetchFn).toHaveBeenCalledTimes(1)
    expect(fetchFn).toHaveBeenCalledWith("/api/auth/refresh", { method: "POST" })

    resolveFetch({ ok: true })
    expect(await p1).toBe(true)
    expect(await p2).toBe(true)
  })

  it("resets after completion so a later refresh fetches again", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValue({ ok: true })

    expect(await auth.refreshSession()).toBe(true)
    expect(await auth.refreshSession()).toBe(true)
    expect(fetchFn).toHaveBeenCalledTimes(2)   // singleton cleared between expiries
  })

  it("returns false on a failed refresh and on a network error", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValueOnce({ ok: false })
    expect(await auth.refreshSession()).toBe(false)

    fetchFn.mockRejectedValueOnce(new Error("network down"))
    expect(await auth.refreshSession()).toBe(false)
  })
})

describe("logout", () => {
  it("sets isLoggingOut BEFORE the fetch resolves and posts the reason", async () => {
    const fetchFn = mockFetch()
    let sawFlagDuringFetch = false
    fetchFn.mockImplementation(() => {
      sawFlagDuringFetch = auth.isLoggingOut   // flag must already be set
      return Promise.resolve({ ok: true })
    })

    await auth.logout("inactivity")
    expect(sawFlagDuringFetch).toBe(true)
    expect(auth.isLoggingOut).toBe(true)
    expect(fetchFn).toHaveBeenCalledWith("/api/auth/logout", expect.objectContaining({
      method: "POST",
      body:   JSON.stringify({ reason: "inactivity" }),
    }))
  })
})

describe("loginWithCredentials", () => {
  it("returns force_password_change + user on success", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValue({
      ok:   true,
      json: async () => ({ force_password_change: true, user: { id: "u1", email: "a@b.com" } }),
    })
    const r = await auth.loginWithCredentials("a@b.com", "pw")
    expect(r.force_password_change).toBe(true)
    expect(r.user.id).toBe("u1")
  })

  it("maps 429 to ACCOUNT_LOCKED", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValue({ ok: false, status: 429, json: async () => ({ error: { message: "locked" } }) })
    await expect(auth.loginWithCredentials("a@b.com", "pw"))
      .rejects.toMatchObject({ code: "ACCOUNT_LOCKED" })
  })

  it("maps ACCOUNT_DISABLED code", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValue({ ok: false, status: 403, json: async () => ({ error: { code: "ACCOUNT_DISABLED" } }) })
    await expect(auth.loginWithCredentials("a@b.com", "pw"))
      .rejects.toMatchObject({ code: "ACCOUNT_DISABLED" })
  })

  it("maps any other failure to INVALID_CREDENTIALS (no enumeration)", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValue({ ok: false, status: 401, json: async () => ({ error: { code: "WHATEVER" } }) })
    await expect(auth.loginWithCredentials("a@b.com", "pw"))
      .rejects.toMatchObject({ code: "INVALID_CREDENTIALS" })
  })
})

describe("loginWithApiKey", () => {
  it("posts the apiKey and returns response.ok", async () => {
    const fetchFn = mockFetch()
    fetchFn.mockResolvedValue({ ok: true })
    expect(await auth.loginWithApiKey("wsk_live_x")).toBe(true)
    expect(fetchFn).toHaveBeenCalledWith("/api/auth/login", expect.objectContaining({
      method: "POST",
      body:   JSON.stringify({ apiKey: "wsk_live_x" }),
    }))
  })
})

describe("getToken", () => {
  it("always returns null (tokens live only in httpOnly cookies)", () => {
    expect(auth.getToken()).toBeNull()
  })
})
