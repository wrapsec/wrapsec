// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { Layers } from "@/lib/types"
import { updateLayers } from "@/lib/api"
import { useAuthMode } from "@/hooks/useAuthMode"

interface LayerTogglesProps {
  layers:    Layers
  onUpdated: (l: Layers) => void
}

const LAYER_INFO = [
  {
    key:     "rule_enabled" as const,
    label:   "Rule-based detection",
    desc:    "Regex and heuristic patterns — fastest layer, ~0ms",
  },
  {
    key:     "ml_enabled" as const,
    label:   "ML classifier",
    desc:    "TF-IDF + LogisticRegression — probabilistic detection, ~5ms",
  },
  {
    key:     "llm_enabled" as const,
    label:   "LLM semantic analysis",
    desc:    "LLM-based detection — most accurate, conditional invocation",
  },
]

export function LayerToggles({ layers, onUpdated }: LayerTogglesProps) {
  const [state,   setState]   = useState(layers)
  const [loading, setLoading] = useState(false)
  const [saved,   setSaved]   = useState(false)
  const { isJwt } = useAuthMode()

  const handleToggle = (key: keyof Layers) => {
    setState((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const handleSave = async () => {
    setLoading(true)
    try {
      const updated = await updateLayers({
        rule_enabled: state.rule_enabled,
        ml_enabled:   state.ml_enabled,
        llm_enabled:  state.llm_enabled,
      })
      onUpdated(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      {LAYER_INFO.map(({ key, label, desc }) => (
        <div
          key={key}
          className="flex items-start justify-between py-3 border-b border-slate-100 last:border-0"
        >
          <div>
            <p className="text-sm font-medium text-slate-900">{label}</p>
            <p className="text-xs text-slate-500 mt-0.5">{desc}</p>
          </div>
          <button
            onClick={() => handleToggle(key)}
            className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none ${
              state[key] ? "bg-blue-800" : "bg-slate-200"
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                state[key] ? "translate-x-4" : "translate-x-0"
              }`}
            />
          </button>
        </div>
      ))}

      <div className="flex items-center gap-3 pt-2">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={loading}>
            Save layers
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>Save layers</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              Requires admin login —{" "}
              <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>
                sign in with email
              </a>
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