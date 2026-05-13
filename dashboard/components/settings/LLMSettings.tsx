// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { LLMSettings } from "@/lib/types"
import { updateLLMSettings } from "@/lib/api"

interface LLMSettingsFormProps {
  settings:  LLMSettings
  onUpdated: (s: LLMSettings) => void
}

const PROVIDERS = [
  { value: "openai", label: "OpenAI / OpenAI-compatible" },
  { value: "ollama", label: "Ollama (Local)" },
  { value: "custom", label: "Custom (OpenAI-compatible)" },
]

const DEFAULT_URLS: Record<string, string> = {
  openai: "https://api.openai.com/v1",
  ollama: "http://ollama:11434",
  custom: "",
}

const DEFAULT_MODELS: Record<string, string> = {
  openai: "gpt-4o-mini",
  ollama: "llama3.2:latest",
  custom: "",
}

export function LLMSettingsForm({ settings, onUpdated }: LLMSettingsFormProps) {
  const [provider, setProvider] = useState<LLMSettings["provider"]>(settings.provider)
  const [model,    setModel]    = useState(settings.model)
  const [baseUrl,  setBaseUrl]  = useState(settings.base_url)
  const [apiKey,   setApiKey]   = useState("")
  const [timeout,  setTimeout_] = useState(settings.timeout ?? 30)
  const [loading,  setLoading]  = useState(false)
  const [saved,    setSaved]    = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  const handleProviderChange = (p: LLMSettings["provider"]) => {
    setProvider(p)
    setError(null)
    if (p === "openai") {
      setBaseUrl(DEFAULT_URLS.openai)
      setModel(DEFAULT_MODELS.openai)
    } else if (p === "ollama") {
      setBaseUrl(DEFAULT_URLS.ollama)
      setModel(DEFAULT_MODELS.ollama)
    }
  }

  const handleSave = async () => {
    setLoading(true)
    setError(null)
    try {
      const payload: Partial<LLMSettings> & { api_key?: string } = {
        provider,
        model,
        base_url: baseUrl,
        timeout,
      }
      if (apiKey.trim()) payload.api_key = apiKey.trim()
      const updated = await updateLLMSettings(payload)
      onUpdated(updated)
      setApiKey("")   // clear plaintext after save
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
      <div className="grid grid-cols-2 gap-5">

        {/* Provider */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">Provider</label>
          <select
            value={provider}
            onChange={(e) => handleProviderChange(e.target.value as LLMSettings["provider"])}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          >
            {PROVIDERS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
          <p className="text-xs text-slate-400">
            openai covers OpenAI, Groq, Together AI, and any OpenAI-compatible endpoint
          </p>
        </div>

        {/* Default model */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">Model</label>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="gpt-4o-mini"
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">Model name for the selected provider</p>
        </div>

        {/* Base URL */}
        <div className="flex flex-col gap-1 col-span-2">
          <label className="text-xs font-medium text-slate-700">Base URL</label>
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={provider === "ollama" ? "http://ollama:11434" : "https://api.openai.com/v1"}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">
            {provider === "ollama"
              ? "Ollama server URL - use container hostname in Docker (not localhost)"
              : provider === "openai"
              ? "For Groq: https://api.groq.com/openai/v1 · For Together: https://api.together.xyz/v1"
              : "Provider endpoint URL (must be OpenAI-compatible)"}
          </p>
        </div>

        {/* API key - openai / custom only */}
        {provider !== "ollama" && (
          <div className="flex flex-col gap-1 col-span-2">
            <label className="text-xs font-medium text-slate-700">
              API key
              {settings.api_key_masked && (
                <span className="ml-2 font-normal text-slate-400">
                  current: {settings.api_key_masked}
                </span>
              )}
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={settings.api_key_masked ? "Leave blank to keep current key" : "sk-..."}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
            />
            <p className="text-xs text-slate-400">
              Stored encrypted. Never returned in API responses. Masked after save.
              Falls back to <code className="font-mono">OPENAI_API_KEY</code> env var if not set.
            </p>
          </div>
        )}

        {/* Timeout */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">Timeout (seconds)</label>
          <input
            type="number"
            min={5}
            max={120}
            value={timeout}
            onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v)) setTimeout_(v) }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">Request timeout (5 - 120 seconds)</p>
        </div>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={loading}>
            Save
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>Save</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              Requires admin login -{" "}
              <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
            </span>
          </div>
        )}
        {saved && <span className="text-xs text-green-600">Saved successfully</span>}
      </div>
    </div>
  )
}
