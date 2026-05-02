// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
/**
 * dashboard/hooks/useInactivityTimer.ts
 *
 * Tracks user inactivity and triggers logout after 15 minutes.
 * Shows a warning modal at 2 minutes remaining.
 *
 * Events tracked: mousemove, mousedown, keydown, touchstart, scroll,
 * visibilitychange (tab switching counts as inactivity when tab is hidden).
 *
 * On timeout: logout("inactivity") → redirect /login
 * See session_management.md §hooks/useInactivityTimer.ts
 */
"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { logout } from "@/lib/auth"

const TIMEOUT_MS  = 15 * 60 * 1000   // 15 minutes
const WARNING_MS  = 2  * 60 * 1000   // show warning at 2 min remaining

const ACTIVITY_EVENTS = [
  "mousemove", "mousedown", "keydown",
  "touchstart", "scroll", "visibilitychange",
] as const

export function useInactivityTimer() {
  const [showWarning,      setShowWarning]      = useState(false)
  const [secondsRemaining, setSecondsRemaining] = useState(0)

  const timerRef       = useRef<ReturnType<typeof setTimeout>  | null>(null)
  const warningRef     = useRef<ReturnType<typeof setTimeout>  | null>(null)
  const intervalRef    = useRef<ReturnType<typeof setInterval> | null>(null)
  const startedAt      = useRef<number>(Date.now())
  // Mirrors showWarning state so the event handler reads the current value
  // without closing over stale state from the initial render.
  const showWarningRef = useRef(false)

  const clearAllTimers = useCallback(() => {
    if (timerRef.current)    clearTimeout(timerRef.current)
    if (warningRef.current)  clearTimeout(warningRef.current)
    if (intervalRef.current) clearInterval(intervalRef.current)
  }, [])

  const doLogout = useCallback(async () => {
    clearAllTimers()
    showWarningRef.current = false
    setShowWarning(false)
    await logout("inactivity")
    window.location.href = "/login"
  }, [clearAllTimers])

  const startTimers = useCallback(() => {
    clearAllTimers()
    startedAt.current = Date.now()
    showWarningRef.current = false
    setShowWarning(false)

    // Warning timer — fires at TIMEOUT - WARNING threshold
    warningRef.current = setTimeout(() => {
      showWarningRef.current = true
      setShowWarning(true)
      setSecondsRemaining(Math.round(WARNING_MS / 1000))

      // Countdown interval
      intervalRef.current = setInterval(() => {
        setSecondsRemaining(prev => {
          if (prev <= 1) {
            if (intervalRef.current) clearInterval(intervalRef.current)
            return 0
          }
          return prev - 1
        })
      }, 1000)
    }, TIMEOUT_MS - WARNING_MS)

    // Logout timer
    timerRef.current = setTimeout(() => {
      doLogout()
    }, TIMEOUT_MS)
  }, [clearAllTimers, doLogout])

  const resetTimer = useCallback(() => {
    startTimers()
  }, [startTimers])

  const logoutNow = useCallback(async () => {
    clearAllTimers()
    setShowWarning(false)
    await logout("manual")
    window.location.href = "/login"
  }, [clearAllTimers])

  useEffect(() => {
    startTimers()

    const handleActivity = (e: Event) => {
      // visibilitychange: only reset if tab becomes visible again
      // Hidden tab = inactivity, don't reset on hide
      if (e.type === "visibilitychange" && document.visibilityState === "hidden") {
        return
      }
      // Only reset if warning is not showing — once warning shows,
      // user must explicitly click "Stay logged in".
      // Use ref (not state) to avoid reading a stale closure value.
      if (!showWarningRef.current) {
        startTimers()
      }
    }

    ACTIVITY_EVENTS.forEach(event => {
      window.addEventListener(event, handleActivity, { passive: true })
    })

    return () => {
      clearAllTimers()
      ACTIVITY_EVENTS.forEach(event => {
        window.removeEventListener(event, handleActivity)
      })
    }
  }, [])   // run once on mount — startTimers ref is stable

  return { showWarning, secondsRemaining, resetTimer, logoutNow }
}
