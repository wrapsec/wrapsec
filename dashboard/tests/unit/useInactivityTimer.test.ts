// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The inactivity auto-logout is a security control: after 15 min idle it logs out,
// showing a warning at 2 min remaining. These tests use fake timers to drive the
// thresholds deterministically.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { act, renderHook } from "@testing-library/react"

const logout = vi.fn().mockResolvedValue(undefined)
vi.mock("@/lib/auth", () => ({ logout: (...a: unknown[]) => logout(...a) }))

import { useInactivityTimer } from "@/hooks/useInactivityTimer"

const TIMEOUT_MS = 15 * 60 * 1000
const WARNING_AT = TIMEOUT_MS - 2 * 60 * 1000   // warning fires at 13 min

beforeEach(() => {
  vi.useFakeTimers()
  logout.mockClear()
  // jsdom navigation is not implemented; stub the redirect target.
  vi.stubGlobal("window", { ...window, location: { href: "" }, addEventListener: window.addEventListener.bind(window), removeEventListener: window.removeEventListener.bind(window) })
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe("useInactivityTimer", () => {
  it("does not warn or log out before the thresholds", () => {
    const { result } = renderHook(() => useInactivityTimer())
    expect(result.current.showWarning).toBe(false)
    act(() => { vi.advanceTimersByTime(WARNING_AT - 1000) })   // just before warning
    expect(result.current.showWarning).toBe(false)
    expect(logout).not.toHaveBeenCalled()
  })

  it("shows the warning at 2 minutes remaining", () => {
    const { result } = renderHook(() => useInactivityTimer())
    act(() => { vi.advanceTimersByTime(WARNING_AT) })
    expect(result.current.showWarning).toBe(true)
    expect(result.current.secondsRemaining).toBe(120)
    expect(logout).not.toHaveBeenCalled()
  })

  it("logs out with reason 'inactivity' at the full timeout", () => {
    renderHook(() => useInactivityTimer())
    act(() => { vi.advanceTimersByTime(TIMEOUT_MS) })
    expect(logout).toHaveBeenCalledWith("inactivity")
  })

  it("resetTimer restarts the countdown (clears an active warning)", () => {
    const { result } = renderHook(() => useInactivityTimer())
    act(() => { vi.advanceTimersByTime(WARNING_AT) })
    expect(result.current.showWarning).toBe(true)

    act(() => { result.current.resetTimer() })
    expect(result.current.showWarning).toBe(false)

    // After a reset, advancing to just before the (new) warning still shows nothing.
    act(() => { vi.advanceTimersByTime(WARNING_AT - 1000) })
    expect(result.current.showWarning).toBe(false)
    expect(logout).not.toHaveBeenCalled()
  })

  it("logoutNow logs out immediately with reason 'manual'", () => {
    const { result } = renderHook(() => useInactivityTimer())
    act(() => { result.current.logoutNow() })
    expect(logout).toHaveBeenCalledWith("manual")
  })

  it("counts the warning window down toward zero", () => {
    const { result } = renderHook(() => useInactivityTimer())
    act(() => { vi.advanceTimersByTime(WARNING_AT) })
    expect(result.current.secondsRemaining).toBe(120)
    act(() => { vi.advanceTimersByTime(5000) })   // 5 ticks
    expect(result.current.secondsRemaining).toBe(115)
  })
})
