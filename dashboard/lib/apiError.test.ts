// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect } from "vitest"
import { errorMessage, parseApiError, ApiError } from "@/lib/apiError"

describe("errorMessage", () => {
  it("returns the message of a plain Error", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom")
  })

  it("returns the message of an ApiError (extends Error)", () => {
    expect(errorMessage(new ApiError({ status: 400, message: "bad request" }))).toBe("bad request")
  })

  it("stringifies a non-Error value rather than throwing", () => {
    expect(errorMessage("plain string")).toBe("plain string")
    expect(errorMessage(null)).toBe("null")
    expect(errorMessage(undefined)).toBe("undefined")
  })
})

describe("parseApiError", () => {
  it("builds a typed ApiError from the WrapSec error envelope", () => {
    const e = parseApiError(422, {
      error: {
        code:           "INVALID_ENUM",
        message:        "not allowed",
        key:            "errors.INVALID_ENUM",
        severity:       "WARNING",
        trace_id:       "req_abc",
        invalid_params: [{ field: "email", code: "bad", key: "errors.email" }],
      },
    })
    expect(e).toBeInstanceOf(ApiError)
    expect(e.status).toBe(422)
    expect(e.code).toBe("INVALID_ENUM")
    expect(e.message).toBe("not allowed")
    expect(e.traceId).toBe("req_abc")
    expect(e.invalidParams).toHaveLength(1)
    expect(e.invalidParams[0].field).toBe("email")
  })

  it("falls back to 'HTTP <status>' when the body carries no message", () => {
    expect(parseApiError(500, null).message).toBe("HTTP 500")
    expect(parseApiError(503, {}).message).toBe("HTTP 503")
  })
})
