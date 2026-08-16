// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi, afterEach } from "vitest"
import {
  ensureUtc, timeAgo, isValidDate, presetRange, customRange, validateCustomRange,
} from "@/lib/datetime"

afterEach(() => {
  vi.useRealTimers()
})

describe("ensureUtc", () => {
  it("parses a Z-suffixed timestamp as UTC", () => {
    expect(ensureUtc("2026-01-02T03:04:05Z").toISOString()).toBe("2026-01-02T03:04:05.000Z")
  })

  it("treats a timezone-LESS string as UTC (not browser-local)", () => {
    // The v1.2.x date-boundary bug: a naive string must not be read as local time.
    expect(ensureUtc("2026-01-02T03:04:05").toISOString()).toBe("2026-01-02T03:04:05.000Z")
  })

  it("respects an explicit +HH:MM offset", () => {
    expect(ensureUtc("2026-01-02T03:04:05+02:00").toISOString()).toBe("2026-01-02T01:04:05.000Z")
  })
})

describe("timeAgo", () => {
  it("renders seconds / minutes / hours / days buckets", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-10T00:00:00Z"))
    expect(timeAgo("2026-01-09T23:59:30Z")).toBe("30s ago")
    expect(timeAgo("2026-01-09T23:30:00Z")).toBe("30m ago")
    expect(timeAgo("2026-01-09T18:00:00Z")).toBe("6h ago")
    expect(timeAgo("2026-01-07T00:00:00Z")).toBe("3d ago")
  })
})

describe("isValidDate", () => {
  it("accepts a well-formed YYYY-MM-DD", () => {
    expect(isValidDate("2026-01-02")).toBe(true)
  })

  it("rejects a wrong shape or an unparseable date", () => {
    expect(isValidDate("2026-1-2")).toBe(false)     // not zero-padded (regex)
    expect(isValidDate("01/02/2026")).toBe(false)   // wrong separator (regex)
    expect(isValidDate("2026-13-01")).toBe(false)   // month 13 -> NaN Date
    expect(isValidDate("")).toBe(false)
  })

  it("validates SHAPE + parseability, not calendar-day validity (JS Date rolls over)", () => {
    // "2026-02-30" matches the regex and new Date() rolls it to Mar 2 (a valid
    // Date), so it passes. Documenting the real contract, not an assumed one.
    expect(isValidDate("2026-02-30")).toBe(true)
  })
})

describe("customRange", () => {
  it("spans full days (00:00:00 -> 23:59:59)", () => {
    expect(customRange("2026-01-01", "2026-01-31")).toEqual({
      from: "2026-01-01T00:00:00",
      to:   "2026-01-31T23:59:59",
    })
  })
})

describe("presetRange", () => {
  it("returns a window of `days` ending now, in second-precision UTC", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-01-10T12:00:00Z"))
    const r = presetRange(7)
    expect(r.to).toBe("2026-01-10T12:00:00")
    expect(r.from).toBe("2026-01-03T12:00:00")
  })
})

describe("validateCustomRange", () => {
  it("returns null for a valid past range", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-06-01T00:00:00Z"))
    expect(validateCustomRange("2026-01-01", "2026-01-31")).toBeNull()
  })

  it("requires both dates", () => {
    expect(validateCustomRange("", "2026-01-31")).toBe("Both dates are required")
    expect(validateCustomRange("2026-01-01", "")).toBe("Both dates are required")
  })

  it("flags malformed start/end dates", () => {
    expect(validateCustomRange("2026-13-01", "2026-01-31")).toBe("Invalid start date")
    expect(validateCustomRange("2026-01-01", "nope")).toBe("Invalid end date")
  })

  it("requires start strictly before end", () => {
    expect(validateCustomRange("2026-01-31", "2026-01-01")).toBe("Start date must be before end date")
    expect(validateCustomRange("2026-01-01", "2026-01-01")).toBe("Start date must be before end date")
  })

  it("rejects an end date in the future", () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date("2026-06-01T00:00:00Z"))
    expect(validateCustomRange("2026-01-01", "2026-12-31")).toBe("End date cannot be in the future")
  })
})
