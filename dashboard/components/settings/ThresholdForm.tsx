// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { Thresholds } from "@/lib/types"
import { updateThresholds } from "@/lib/api"

interface ThresholdFormProps {
  thresholds:  Thresholds
  onUpdated:   (t: Thresholds) => void
}

export function ThresholdForm({ thresholds, onUpdated }: ThresholdFormProps) {
  const [block,    setBlock]    = useState(thresholds.block_threshold)
  const [sanitize, setSanitize] = useState(thresholds.sanitize_threshold)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const [saved,    setSaved]    = useState(false)
  const { isJwt } = useAuthMode()

  const valid = (
    block > 0.0 &&
    block <= 1.0 &&
    sanitize >= 0.0 &&
    sanitize < 1.0 &&
    block > sanitize
  )

  const handleSave = async () => {
    if (!valid) return
    setLoading(true)
    setError(null)
    try {
      const updated = await updateThresholds({
        block_threshold:    block,
        sanitize_threshold: sanitize,
      })
      onUpdated(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-6">
        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1.5">
            Block threshold
          </label>
          <input
            type="number"
            min={0} max={1} step={0.05}
            value={block}
            onChange={(e) => setBlock(parseFloat(e.target.value))}
            className="h-9 w-full px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
          <p className="text-xs text-slate-400 mt-1">
            Requests with risk score ≥ {block} are blocked (min: 0.01, max: 1.0)
          </p>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-700 mb-1.5">
            Sanitize threshold
          </label>
          <input
            type="number"
            min={0} max={1} step={0.05}
            value={sanitize}
            onChange={(e) => setSanitize(parseFloat(e.target.value))}
            className="h-9 w-full px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
          <p className="text-xs text-slate-400 mt-1">
            Requests with risk score ≥ {sanitize} are sanitized (min: 0.0, max: 0.99)
          </p>
        </div>
      </div>

      {!valid && (
        <p className="text-xs text-red-600">
          {block <= 0.0
            ? "Block threshold must be greater than 0"
            : block > 1.0
            ? "Block threshold cannot exceed 1.0"
            : sanitize < 0.0
            ? "Sanitize threshold cannot be negative"
            : sanitize >= 1.0
            ? "Sanitize threshold must be less than 1.0"
            : "Block threshold must be greater than sanitize threshold"}
        </p>
      )}
      {error && (
        <p className="text-xs text-red-600">{error}</p>
      )}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm"onClick={handleSave} loading={loading} disabled={!valid}>
            Save thresholds
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>Save thresholds</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              Requires admin login —{" "}
              <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
            </span>
          </div>
        )}
        {saved && (
          <span className="text-xs text-green-600">Saved successfully</span>
        )}
      </div>
    </div>
  )
}