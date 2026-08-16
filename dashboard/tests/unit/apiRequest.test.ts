// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Tests the shared request() 401 -> silent-refresh -> retry flow and its guards.
// request() is not exported, so it is exercised through scanRequest(), a thin
// wrapper over request<T>("/v1/ai/request", ...).
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"

// Mock the auth module so we control refresh/logout without real fetches.
vi.mock("@/lib/auth", () => ({
  refreshSession: vi.fn(),
  logout:         vi.fn().mockResolvedValue(undefined),
  isLoggingOut:   false,
}))

import { scanRequest } from "@/lib/api"
import * as auth from "@/lib/auth"

function jsonResponse(status: number, body: unknown) {
  return {
    ok:      status >= 200 && status < 300,
    status,
    headers: { get: () => "application/json" },
    json:    async () => body,
  }
}

let fetchFn: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchFn = vi.fn()
  vi.stubGlobal("fetch", fetchFn)
  // jsdom provides window; make location.href assignable + observable.
  vi.stubGlobal("window", { location: { href: "" } })
  vi.mocked(auth.refreshSession).mockReset()
  vi.mocked(auth.logout).mockClear()
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe("request() happy path", () => {
  it("returns parsed JSON on 200 and routes through the /api/proxy prefix", async () => {
    fetchFn.mockResolvedValueOnce(jsonResponse(200, { decision: "ALLOW" }))
    const out = await scanRequest({ input: "hi" } as never)
    expect(out).toEqual({ decision: "ALLOW" })
    expect(fetchFn.mock.calls[0][0]).toBe("/api/proxy/v1/ai/request")
  })
})

describe("request() 401 -> refresh -> retry", () => {
  it("on 401 refreshes once and retries the original request, then succeeds", async () => {
    fetchFn
      .mockResolvedValueOnce(jsonResponse(401, {}))            // first call 401
      .mockResolvedValueOnce(jsonResponse(200, { ok: true }))  // retry succeeds
    vi.mocked(auth.refreshSession).mockResolvedValue(true)

    const out = await scanRequest({ input: "hi" } as never)
    expect(out).toEqual({ ok: true })
    expect(auth.refreshSession).toHaveBeenCalledTimes(1)
    expect(fetchFn).toHaveBeenCalledTimes(2)
    expect(auth.logout).not.toHaveBeenCalled()
  })

  it("logs out + redirects when the refresh fails", async () => {
    fetchFn.mockResolvedValueOnce(jsonResponse(401, {}))
    vi.mocked(auth.refreshSession).mockResolvedValue(false)

    await expect(scanRequest({ input: "hi" } as never)).rejects.toThrow("Session expired")
    expect(auth.logout).toHaveBeenCalledWith("expired")
    expect(window.location.href).toBe("/login")
  })

  it("never retries twice: a 401 on the retried request logs out (guard _retried)", async () => {
    fetchFn
      .mockResolvedValueOnce(jsonResponse(401, {}))   // first 401
      .mockResolvedValueOnce(jsonResponse(401, {}))   // retry ALSO 401
    vi.mocked(auth.refreshSession).mockResolvedValue(true)

    await expect(scanRequest({ input: "hi" } as never)).rejects.toThrow("Session expired")
    // Only ONE refresh attempt, even though two 401s were seen.
    expect(auth.refreshSession).toHaveBeenCalledTimes(1)
    expect(auth.logout).toHaveBeenCalledWith("expired")
  })
})

describe("request() non-401 errors", () => {
  it("throws a parsed ApiError and does NOT redirect on 500", async () => {
    fetchFn.mockResolvedValueOnce(jsonResponse(500, { error: { code: "SYSTEM_ERROR", message: "boom" } }))

    await expect(scanRequest({ input: "hi" } as never)).rejects.toMatchObject({
      status: 500,
      code:   "SYSTEM_ERROR",
      message: "boom",
    })
    expect(auth.refreshSession).not.toHaveBeenCalled()
    expect(window.location.href).toBe("")   // no login redirect for server errors
  })

  it("throws a parsed ApiError on 403 without refreshing", async () => {
    fetchFn.mockResolvedValueOnce(jsonResponse(403, { error: { code: "FORBIDDEN", message: "nope" } }))
    await expect(scanRequest({ input: "hi" } as never)).rejects.toMatchObject({ status: 403, code: "FORBIDDEN" })
    expect(auth.refreshSession).not.toHaveBeenCalled()
  })
})
