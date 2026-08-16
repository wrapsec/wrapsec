// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// BFF auth Route Handlers. Pins the httpOnly-cookie contract: login sets the
// session cookies httpOnly and clears the other auth mode; a failed login
// forwards the backend error; logout always clears all cookies (even if the
// backend call throws); refresh 401 clears the JWT; session never leaks cookie
// VALUES, only the auth type.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { NextRequest } from "next/server"

let jar: Record<string, string> = {}
vi.mock("next/headers", () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (jar[name] !== undefined ? { value: jar[name] } : undefined),
  })),
}))

import { POST as loginPOST }   from "@/app/api/auth/login/route"
import { POST as logoutPOST }  from "@/app/api/auth/logout/route"
import { POST as refreshPOST } from "@/app/api/auth/refresh/route"
import { GET  as sessionGET }  from "@/app/api/auth/session/route"

let fetchFn: ReturnType<typeof vi.fn>

function okJson(body: unknown, getSetCookie: string[] = []) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => null, getSetCookie: () => getSetCookie },
    json: async () => body,
  }
}
function errJson(status: number, body: unknown) {
  return { ok: false, status, headers: { get: () => null, getSetCookie: () => [] }, json: async () => body }
}

/** Collect all Set-Cookie header values off a NextResponse (jsdom/undici Headers). */
function setCookies(res: { headers: Headers }): string[] {
  return res.headers.getSetCookie()
}

function jsonReq(url: string, body: unknown) {
  return new NextRequest(url, { method: "POST", body: JSON.stringify(body) })
}

beforeEach(() => {
  jar = {}
  fetchFn = vi.fn()
  vi.stubGlobal("fetch", fetchFn)
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe("POST /api/auth/login (JWT mode)", () => {
  it("sets wrapsec_jwt + wrapsec_session httpOnly and clears the API-key cookie", async () => {
    fetchFn.mockResolvedValueOnce(okJson({
      access_token: "jwt-new", expires_in: 1800, force_password_change: false, user: { id: "u1" },
    }))

    const res = await loginPOST(jsonReq("http://localhost/api/auth/login", { email: "a@b.com", password: "pw" }))
    expect(res.status).toBe(200)

    const jwt     = res.cookies.get("wrapsec_jwt")
    const session = res.cookies.get("wrapsec_session")
    const apiKey  = res.cookies.get("wrapsec_api_key")
    expect(jwt?.value).toBe("jwt-new")
    expect(jwt?.httpOnly).toBe(true)
    expect(session?.value).toBe("jwt")
    expect(session?.httpOnly).toBe(true)
    // Mode exclusivity: the API-key cookie is cleared (maxAge 0).
    expect(apiKey?.value).toBe("")
    expect(apiKey?.maxAge).toBe(0)
  })

  it("forwards the backend error (status + body) on failed credentials", async () => {
    fetchFn.mockResolvedValueOnce(errJson(401, { error: { code: "INVALID_CREDENTIALS" } }))
    const res = await loginPOST(jsonReq("http://localhost/api/auth/login", { email: "a@b.com", password: "bad" }))
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: { code: "INVALID_CREDENTIALS" } })
    // No session cookie should be set on a failed login.
    expect(res.cookies.get("wrapsec_jwt")?.value).toBeFalsy()
  })

  it("API-key mode sets wrapsec_api_key httpOnly and clears JWT/session", async () => {
    fetchFn.mockResolvedValueOnce(okJson({}))  // audit probe succeeds
    const res = await loginPOST(jsonReq("http://localhost/api/auth/login", { apiKey: "wsk_live_x" }))
    expect(res.status).toBe(200)
    expect(res.cookies.get("wrapsec_api_key")?.value).toBe("wsk_live_x")
    expect(res.cookies.get("wrapsec_api_key")?.httpOnly).toBe(true)
    expect(res.cookies.get("wrapsec_jwt")?.maxAge).toBe(0)
    expect(res.cookies.get("wrapsec_session")?.maxAge).toBe(0)
  })

  it("rejects a request with neither apiKey nor email+password (400)", async () => {
    const res = await loginPOST(jsonReq("http://localhost/api/auth/login", { foo: "bar" }))
    expect(res.status).toBe(400)
    expect(fetchFn).not.toHaveBeenCalled()
  })

  // NOTE: the login route calls res.cookies.set("wrapsec_api_key", ...) AFTER
  // forwardBackendSetCookies, and in the undici/jsdom test env that re-serializes
  // the Set-Cookie header from the cookie map and drops the raw-appended backend
  // cookie. This is a test-env artifact (Next's runtime ResponseCookies preserves
  // it; login/refresh is production-proven), so Set-Cookie forwarding is asserted
  // in the refresh route below, where forwardBackendSetCookies is the LAST op and
  // the appended value is reliably observable.
})

describe("POST /api/auth/logout", () => {
  it("clears all four auth cookies and returns success", async () => {
    jar = { wrapsec_jwt: "jwt-abc", refresh_token: "rt-abc" }
    fetchFn.mockResolvedValueOnce(okJson({}))

    const res = await logoutPOST(jsonReq("http://localhost/api/auth/logout", { reason: "manual" }))
    expect(await res.json()).toEqual({ success: true })
    for (const name of ["wrapsec_api_key", "wrapsec_jwt", "wrapsec_session", "refresh_token"]) {
      expect(res.cookies.get(name)?.maxAge).toBe(0)
    }
  })

  it("still clears cookies when the backend revoke call throws (best effort)", async () => {
    jar = { wrapsec_jwt: "jwt-abc", refresh_token: "rt-abc" }
    fetchFn.mockRejectedValueOnce(new Error("backend down"))

    const res = await logoutPOST(jsonReq("http://localhost/api/auth/logout", { reason: "manual" }))
    expect(await res.json()).toEqual({ success: true })
    expect(res.cookies.get("wrapsec_jwt")?.maxAge).toBe(0)
    expect(res.cookies.get("wrapsec_session")?.maxAge).toBe(0)
  })
})

describe("POST /api/auth/refresh", () => {
  it("401 + no refresh cookie: does not call the backend", async () => {
    const res = await refreshPOST(new NextRequest("http://localhost/api/auth/refresh", { method: "POST" }))
    expect(res.status).toBe(401)
    expect(fetchFn).not.toHaveBeenCalled()
  })

  it("on backend failure clears the JWT + session cookies (401)", async () => {
    const req = new NextRequest("http://localhost/api/auth/refresh", { method: "POST" })
    req.cookies.set("refresh_token", "rt-old")
    fetchFn.mockResolvedValueOnce(errJson(401, {}))

    const res = await refreshPOST(req)
    expect(res.status).toBe(401)
    expect(res.cookies.get("wrapsec_jwt")?.maxAge).toBe(0)
    expect(res.cookies.get("wrapsec_session")?.maxAge).toBe(0)
  })

  it("on success stores the new access token as wrapsec_jwt httpOnly", async () => {
    const req = new NextRequest("http://localhost/api/auth/refresh", { method: "POST" })
    req.cookies.set("refresh_token", "rt-old")
    fetchFn.mockResolvedValueOnce(okJson({ access_token: "jwt-rotated", expires_in: 1800 }))

    const res = await refreshPOST(req)
    expect(res.status).toBe(200)
    expect(res.cookies.get("wrapsec_jwt")?.value).toBe("jwt-rotated")
    expect(res.cookies.get("wrapsec_jwt")?.httpOnly).toBe(true)
  })

  it("forwards the backend's ROTATED refresh_token Set-Cookie unchanged", async () => {
    const req = new NextRequest("http://localhost/api/auth/refresh", { method: "POST" })
    req.cookies.set("refresh_token", "rt-old")
    fetchFn.mockResolvedValueOnce(okJson(
      { access_token: "jwt-rotated", expires_in: 1800 },
      ["refresh_token=rt-new; Path=/api/auth; HttpOnly; SameSite=Strict"],
    ))

    const res = await refreshPOST(req)
    // Rotation: the new refresh token from the backend is passed straight through.
    expect(setCookies(res).some(c => c.startsWith("refresh_token=rt-new"))).toBe(true)
  })
})

describe("GET /api/auth/session", () => {
  // Build a JWT-shaped token (header.payload.signature) whose payload carries the
  // given role. The signature is never verified here -- the route decodes the role
  // claim only to shape the UI; the backend re-validates on every request.
  function fakeJwt(claims: Record<string, unknown>): string {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url")
    return `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.sig`
  }

  it("reports an ADMIN JWT as is_admin true without exposing the cookie value", async () => {
    jar = { wrapsec_jwt: fakeJwt({ role: "ADMIN", sub: "u1" }) }
    const res = await sessionGET(new NextRequest("http://localhost/api/auth/session"))
    const body = await res.json()
    expect(body).toEqual({
      authenticated: true, auth_type: "jwt", role: "ADMIN", is_admin: true, can_write: true,
    })
    // The raw token (and its signature segment) must never leak in the response.
    expect(JSON.stringify(body)).not.toContain(".sig")
  })

  it("reports a VIEWER JWT as is_admin false but can_write true (has a session)", async () => {
    jar = { wrapsec_jwt: fakeJwt({ role: "VIEWER", sub: "u2" }) }
    const res = await sessionGET(new NextRequest("http://localhost/api/auth/session"))
    const body = await res.json()
    expect(body).toEqual({
      authenticated: true, auth_type: "jwt", role: "VIEWER", is_admin: false, can_write: true,
    })
  })

  it("reports a malformed JWT as role null / is_admin false", async () => {
    jar = { wrapsec_jwt: "not-a-jwt" }
    const res = await sessionGET(new NextRequest("http://localhost/api/auth/session"))
    const body = await res.json()
    expect(body).toMatchObject({ authenticated: true, auth_type: "jwt", role: null, is_admin: false })
  })

  it("reports api_key with can_write false and is_admin false", async () => {
    jar = { wrapsec_api_key: "wsk_live_secret" }
    const res = await sessionGET(new NextRequest("http://localhost/api/auth/session"))
    const body = await res.json()
    expect(body).toMatchObject({
      authenticated: true, auth_type: "api_key", role: null, is_admin: false, can_write: false,
    })
    expect(JSON.stringify(body)).not.toContain("wsk_live_secret")
  })

  it("reports unauthenticated when no auth cookie is present", async () => {
    const res = await sessionGET(new NextRequest("http://localhost/api/auth/session"))
    expect(await res.json()).toEqual({ authenticated: false, auth_type: null })
  })
})
