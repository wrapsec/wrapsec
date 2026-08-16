// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect } from "vitest"
import { formatScore, formatRate, formatLatency, truncateId, formatRun } from "@/lib/format"

describe("formatScore", () => {
  it("renders a 0..1 score as a whole-number percentage", () => {
    expect(formatScore(0)).toBe("0%")
    expect(formatScore(0.925)).toBe("93%")   // rounds
    expect(formatScore(1)).toBe("100%")
  })
})

describe("formatRate", () => {
  it("renders a 0..1 rate as a one-decimal percentage", () => {
    expect(formatRate(0)).toBe("0.0%")
    expect(formatRate(0.125)).toBe("12.5%")
    expect(formatRate(1)).toBe("100.0%")
  })
})

describe("formatLatency", () => {
  it("uses ms below 1000 and seconds at/above 1000", () => {
    expect(formatLatency(0)).toBe("0ms")
    expect(formatLatency(45.6)).toBe("46ms")   // rounds to whole ms
    expect(formatLatency(999)).toBe("999ms")
    expect(formatLatency(1000)).toBe("1.0s")
    expect(formatLatency(1250)).toBe("1.3s")
  })
})

describe("truncateId", () => {
  it("returns short ids unchanged", () => {
    expect(truncateId("abc")).toBe("abc")
    expect(truncateId("short12")).toBe("short12")   // len 7 <= tail(7)+5
  })

  it("keeps a prefix token (up to the first _) and the tail", () => {
    // underscore at index 3 -> head "wsk_"; last 7 chars "1234567".
    expect(truncateId("wsk_live_abcdef1234567")).toBe("wsk_...1234567")
  })

  it("uses the head-before-underscore when the underscore is early", () => {
    const id = "req_0123456789abcdef"
    expect(truncateId(id)).toBe("req_" + "..." + id.slice(-7))
  })

  it("falls back to the first 4 chars when there is no early underscore", () => {
    const id = "0123456789abcdefghij"
    expect(truncateId(id)).toBe("0123" + "..." + id.slice(-7))
  })

  it("honors a custom tail length", () => {
    const id = "trace_abcdefghijklmnop"
    expect(truncateId(id, 4)).toBe("trace_" + "..." + id.slice(-4))
  })
})

describe("formatRun", () => {
  it("renders a run label from the last 6 chars of the id", () => {
    expect(formatRun("run-abc123def456")).toBe("run def456")
  })

  it("appends the turn index when provided", () => {
    expect(formatRun("run-abc123def456", 2)).toBe("run def456 . turn 2")
  })

  it("omits the turn suffix for null/undefined", () => {
    expect(formatRun("run-abc123def456", null)).toBe("run def456")
    expect(formatRun("run-abc123def456", undefined)).toBe("run def456")
  })

  it("includes turn 0 (not treated as absent)", () => {
    expect(formatRun("run-abc123def456", 0)).toBe("run def456 . turn 0")
  })
})
