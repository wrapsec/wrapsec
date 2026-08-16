// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect } from "vitest"
import { contentSourceLabel, contentSourceTier, isUntrustedSource } from "@/lib/constants"

describe("contentSourceLabel", () => {
  it("maps known sources to human labels", () => {
    expect(contentSourceLabel("user_prompt")).toBe("User Prompt")
    expect(contentSourceLabel("retrieved_document")).toBe("Retrieved Document")
    expect(contentSourceLabel("tool_output")).toBe("Tool Output")
  })

  it("defaults a null/undefined source to User Prompt", () => {
    expect(contentSourceLabel(null)).toBe("User Prompt")
    expect(contentSourceLabel(undefined)).toBe("User Prompt")
  })

  it("title-cases an unknown source as a fallback", () => {
    expect(contentSourceLabel("some_new_source")).toBe("Some New Source")
  })
})

describe("contentSourceTier (trust classification)", () => {
  it("classifies user_prompt as trusted (incl. the null default)", () => {
    expect(contentSourceTier("user_prompt")).toBe("trusted")
    expect(contentSourceTier(null)).toBe("trusted")
  })

  it("classifies agent-pulled content as untrusted", () => {
    expect(contentSourceTier("tool_output")).toBe("untrusted")
    expect(contentSourceTier("retrieved_document")).toBe("untrusted")
    expect(contentSourceTier("external_content")).toBe("untrusted")
  })

  it("classifies an unrecognized source as unknown (not silently trusted)", () => {
    expect(contentSourceTier("mystery")).toBe("unknown")
  })
})

describe("isUntrustedSource", () => {
  it("is true only for the untrusted tier", () => {
    expect(isUntrustedSource("tool_output")).toBe(true)
    expect(isUntrustedSource("external_content")).toBe(true)
    expect(isUntrustedSource("user_prompt")).toBe(false)
    expect(isUntrustedSource(null)).toBe(false)
    // A source of unknown tier is NOT treated as untrusted here.
    expect(isUntrustedSource("mystery")).toBe(false)
  })
})
