// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The field check runs before the request is sent. The server validates the same
// rules and is authoritative, so the property that matters most here is that a
// valid network is never rejected: a false accept costs a round trip, a false
// reject costs the operator the feature.
import { describe, it, expect } from "vitest"
import { parseEntries, checkEntries, entriesAreValid } from "@/lib/ipAllowlist"

describe("parseEntries", () => {
  it("takes one entry per line", () => {
    expect(parseEntries("10.0.0.0/8\n192.0.2.7")).toEqual(["10.0.0.0/8", "192.0.2.7"])
  })

  it("ignores blank lines and surrounding spaces", () => {
    expect(parseEntries("  10.0.0.0/8  \n\n\n  192.0.2.7\n")).toEqual([
      "10.0.0.0/8",
      "192.0.2.7",
    ])
  })

  it("treats an empty field as no restriction", () => {
    expect(parseEntries("")).toEqual([])
    expect(parseEntries("   \n  ")).toEqual([])
  })
})

describe("checkEntries", () => {
  it.each([
    "10.0.0.1",
    "10.0.0.0/8",
    "192.0.2.7/32",
    "203.0.113.0/24",
    "2001:db8::1",
    "2001:db8::/32",
    "::1",
    "fe80::1/128",
  ])("accepts %s", (entry) => {
    expect(checkEntries([entry])[0].error).toBeNull()
  })

  it.each([
    "not-an-ip",
    "10.0.0.300",
    "10.0.0.0/33",
    "2001:db8::/129",
    "10.0.0.0/",
    "10.0.0.0/x",
    "10.0.0.0/8/16",
    "10.0.0",
  ])("rejects %s as malformed", (entry) => {
    expect(checkEntries([entry])[0].error).toBe("malformed")
  })

  it.each(["0.0.0.0/0", "::/0"])(
    "flags %s as a restriction that restricts nothing",
    (entry) => {
      expect(checkEntries([entry])[0].error).toBe("allows_everything")
    },
  )

  it("still accepts a narrow network that begins with zeros", () => {
    expect(checkEntries(["0.0.0.0/8"])[0].error).toBeNull()
  })

  it("reports each entry in the order it was typed", () => {
    const checked = checkEntries(["10.0.0.0/8", "nonsense", "192.0.2.7"])
    expect(checked.map((c) => c.error)).toEqual([null, "malformed", null])
    expect(checked[1].value).toBe("nonsense")
  })
})

describe("entriesAreValid", () => {
  it("is true for an empty list, which means no restriction", () => {
    expect(entriesAreValid([])).toBe(true)
  })

  it("is false when any single entry is wrong", () => {
    expect(entriesAreValid(["10.0.0.0/8", "nonsense"])).toBe(false)
  })

  it("is false for a list that would turn the control off", () => {
    expect(entriesAreValid(["0.0.0.0/0"])).toBe(false)
  })
})
