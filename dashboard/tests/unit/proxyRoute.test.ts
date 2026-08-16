// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The BFF proxy catch-all is the frontend/backend security boundary. These tests
// pin: cookie -> auth-header forwarding (JWT wins), 401 when neither cookie is
// present, the recoverable-401 passthrough that must NOT clear cookies, the
// always-JSON guarantee, that the client cannot inject its own auth header, and
// that public paths pass without credentials.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { NextRequest } from "next/server"

// Mutable cookie jar the mocked next/headers reads from.
let jar: Record<string, string> = {}
vi.mock("next/headers", () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (jar[name] !== undefined ? { value: jar[name] } : undefined),
  })),
}))

import { GET, POST } from "@/app/api/proxy/[...path]/route"

let fetchFn: ReturnType<typeof vi.fn>

function backendJson(status: number, body: unknown, contentType = "application/json") {
  return {
    status,
    headers: { get: (h: string) => (h.toLowerCase() === "content-type" ? contentType : null) },
    json: async () => body,
    blob: async () => body,
  }
}

function req(path: string, init: ConstructorParameters<typeof NextRequest>[1] = {}) {
  return new NextRequest(`http://localhost/api/proxy${path}`, init)
}

beforeEach(() => {
  jar = {}
  fetchFn = vi.fn()
  vi.stubGlobal("fetch", fetchFn)
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe("auth cookie -> header forwarding", () => {
  it("forwards wrapsec_jwt as Authorization: Bearer", async () => {
    jar = { wrapsec_jwt: "jwt-abc" }
    fetchFn.mockResolvedValueOnce(backendJson(200, { ok: true }))

    await GET(req("/v1/audit/logs"))

    const [target, opts] = fetchFn.mock.calls[0]
    expect(target).toBe("http://localhost:8000/v1/audit/logs")
    expect((opts.headers as Record<string, string>)["Authorization"]).toBe("Bearer jwt-abc")
    expect((opts.headers as Record<string, string>)["x-api-key"]).toBeUndefined()
  })

  it("forwards wrapsec_api_key as x-api-key", async () => {
    jar = { wrapsec_api_key: "wsk_live_x" }
    fetchFn.mockResolvedValueOnce(backendJson(200, { ok: true }))

    await GET(req("/v1/audit/logs"))

    const headers = fetchFn.mock.calls[0][1].headers as Record<string, string>
    expect(headers["x-api-key"]).toBe("wsk_live_x")
    expect(headers["Authorization"]).toBeUndefined()
  })

  it("JWT wins when both cookies are present (admin write path)", async () => {
    jar = { wrapsec_jwt: "jwt-abc", wrapsec_api_key: "wsk_live_x" }
    fetchFn.mockResolvedValueOnce(backendJson(200, { ok: true }))

    await GET(req("/v1/audit/logs"))

    const headers = fetchFn.mock.calls[0][1].headers as Record<string, string>
    expect(headers["Authorization"]).toBe("Bearer jwt-abc")
    expect(headers["x-api-key"]).toBeUndefined()
  })

  it("does NOT forward a client-supplied Authorization header (no auth override)", async () => {
    jar = { wrapsec_api_key: "wsk_live_x" }
    fetchFn.mockResolvedValueOnce(backendJson(200, { ok: true }))

    await GET(req("/v1/audit/logs", { headers: { Authorization: "Bearer attacker-token" } }))

    const headers = fetchFn.mock.calls[0][1].headers as Record<string, string>
    // Only the cookie-derived credential is forwarded; the client header is ignored.
    expect(headers["Authorization"]).toBeUndefined()
    expect(headers["x-api-key"]).toBe("wsk_live_x")
  })
})

describe("unauthenticated + public paths", () => {
  it("returns 401 JSON when neither cookie is present (no backend call)", async () => {
    const res = await GET(req("/v1/audit/logs"))
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: { code: "UNAUTHORIZED" } })
    expect(fetchFn).not.toHaveBeenCalled()
  })

  it("forwards a public path (/v1/setup/status) with no credentials", async () => {
    fetchFn.mockResolvedValueOnce(backendJson(200, { initialized: false }))
    const res = await GET(req("/v1/setup/status"))
    expect(res.status).toBe(200)
    const headers = fetchFn.mock.calls[0][1].headers as Record<string, string>
    expect(headers["Authorization"]).toBeUndefined()
    expect(headers["x-api-key"]).toBeUndefined()
  })
})

describe("recoverable 401 passthrough", () => {
  it("passes a JWT 401 back as JSON WITHOUT setting any cookie (refresh owns teardown)", async () => {
    jar = { wrapsec_jwt: "jwt-expired" }
    fetchFn.mockResolvedValueOnce(backendJson(401, {}))

    const res = await GET(req("/v1/audit/logs"))
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: { code: "UNAUTHORIZED", message: "Session expired" } })
    // Critical: the proxy must not clear the session on a recoverable 401.
    expect(res.headers.get("set-cookie")).toBeNull()
  })
})

describe("always-JSON guarantee", () => {
  it("returns 502 JSON when the backend body is not JSON", async () => {
    jar = { wrapsec_jwt: "jwt-abc" }
    fetchFn.mockResolvedValueOnce({
      status: 200,
      headers: { get: () => "text/html" },
      json: async () => { throw new Error("not json") },
    })
    const res = await GET(req("/v1/audit/logs"))
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ error: { code: "UPSTREAM_ERROR" } })
  })

  it("returns 500 JSON with a correlation id (never HTML) on a network throw", async () => {
    jar = { wrapsec_jwt: "jwt-abc" }
    fetchFn.mockRejectedValueOnce(new Error("ECONNREFUSED http://internal-host:8000"))
    const res = await GET(req("/v1/audit/logs"))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.error.code).toBe("INTERNAL_ERROR")
    expect(body.error.correlation_id).toBeTruthy()
    // M8: the internal error detail (host, stack) must not leak to the client.
    expect(JSON.stringify(body)).not.toContain("internal-host")
  })
})

describe("request body + method forwarding", () => {
  it("forwards the POST body and method to the backend target", async () => {
    jar = { wrapsec_jwt: "jwt-abc" }
    fetchFn.mockResolvedValueOnce(backendJson(200, { decision: "ALLOW" }))

    await POST(req("/v1/ai/request", { method: "POST", body: JSON.stringify({ input: "hi" }) }))

    const [target, opts] = fetchFn.mock.calls[0]
    expect(target).toBe("http://localhost:8000/v1/ai/request")
    expect(opts.method).toBe("POST")
    expect(opts.body).toBe(JSON.stringify({ input: "hi" }))
  })

  it("preserves the query string on the forwarded target", async () => {
    jar = { wrapsec_jwt: "jwt-abc" }
    fetchFn.mockResolvedValueOnce(backendJson(200, { logs: [] }))
    await GET(req("/v1/audit/logs?limit=10&offset=20"))
    expect(fetchFn.mock.calls[0][0]).toBe("http://localhost:8000/v1/audit/logs?limit=10&offset=20")
  })
})
