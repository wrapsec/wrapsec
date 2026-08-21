// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The field check runs before the request is sent. The server validates the same
// rules and is authoritative, so the property that matters most here is that a
// valid network is never rejected: a false accept costs a round trip, a false
// reject costs the operator the feature.
import { describe, it, expect } from "vitest"
import {
  parseEntries,
  checkEntries,
  entriesAreValid,
  entryCovers,
  uncoveredAddresses,
  suggestEntry,
} from "@/lib/ipAllowlist"

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

// Coverage is what the lockout warning is built on: if it wrongly reports an
// address as covered, the warning stays silent and the operator saves a list
// that stops production. So the direction of every doubtful case matters as
// much as the arithmetic.
describe("entryCovers", () => {
  it.each([
    ["10.0.0.0/8",     "10.1.2.3",   true],
    ["10.0.0.0/8",     "11.1.2.3",   false],
    ["192.0.2.0/24",   "192.0.2.7",  true],
    ["192.0.2.0/24",   "192.0.3.7",  false],
    ["192.0.2.7/32",   "192.0.2.7",  true],
    ["192.0.2.7/32",   "192.0.2.8",  false],
    ["192.0.2.7",      "192.0.2.7",  true],
    ["0.0.0.0/0",      "203.0.113.1", true],
  ] as const)("%s covers %s -> %s", (entry, address, expected) => {
    expect(entryCovers(entry, address)).toBe(expected)
  })

  it.each([
    ["2001:db8::/32",  "2001:db8::1",      true],
    ["2001:db8::/32",  "2001:db9::1",      false],
    ["2001:db8::1/128", "2001:db8::1",     true],
    ["::1",            "::1",              true],
    ["::/0",           "2001:db8::1",      true],
  ] as const)("%s covers %s -> %s", (entry, address, expected) => {
    expect(entryCovers(entry, address)).toBe(expected)
  })

  it("understands the mapped form a dual-stack host reports", () => {
    expect(entryCovers("::ffff:10.0.0.0/104", "::ffff:10.1.2.3")).toBe(true)
    expect(entryCovers("::ffff:10.0.0.1/128", "::ffff:10.0.0.1")).toBe(true)
  })

  it("does not match one family against the other", () => {
    // 2001:db8::/32 and 10.0.0.0/8 are different address spaces; comparing the
    // numbers alone would let a v6 network appear to cover a v4 address.
    expect(entryCovers("2001:db8::/32", "10.0.0.1")).toBe(false)
    expect(entryCovers("10.0.0.0/8",    "2001:db8::1")).toBe(false)
  })

  it.each([
    ["nonsense",     "10.0.0.1"],
    ["10.0.0.0/8",   "nonsense"],
    ["10.0.0.0/x",   "10.0.0.1"],
    // An empty prefix read as zero would cover everything, which is the one
    // wrong answer here: it would report a typo as full coverage and leave the
    // operator with no warning at all.
    ["10.0.0.0/",    "203.0.113.9"],
    ["10.0.0.0/33",  "10.0.0.1"],
    ["10.0.0.0/8/16", "10.0.0.1"],
    ["2001:db8:::1", "2001:db8::1"],
  ] as const)("reports no coverage when it cannot parse (%s, %s)", (entry, address) => {
    expect(entryCovers(entry, address)).toBe(false)
  })
})

describe("uncoveredAddresses", () => {
  it("turns nothing away when there is no restriction", () => {
    expect(uncoveredAddresses([], ["10.0.0.1", "203.0.113.9"])).toEqual([])
  })

  it("names the addresses the list would stop", () => {
    expect(
      uncoveredAddresses(["10.0.0.0/8"], ["10.1.1.1", "203.0.113.9", "10.2.2.2"]),
    ).toEqual(["203.0.113.9"])
  })

  it("accepts an address covered by any one entry, not all of them", () => {
    expect(
      uncoveredAddresses(["10.0.0.0/8", "203.0.113.0/24"], ["203.0.113.9"]),
    ).toEqual([])
  })

  it("treats an address it cannot read as one that would be stopped", () => {
    expect(uncoveredAddresses(["10.0.0.0/8"], ["not-an-ip"])).toEqual(["not-an-ip"])
  })
})

describe("suggestEntry", () => {
  it("proposes the single address, not the network around it", () => {
    expect(suggestEntry("203.0.113.9")).toBe("203.0.113.9/32")
    expect(suggestEntry("2001:db8::1")).toBe("2001:db8::1/128")
  })
})
