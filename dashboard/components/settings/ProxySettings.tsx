// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import {
  getProxySettings,
  updateProxySettings,
  deleteProxySettings,
  getProxyHealth,
} from "@/lib/api"
import { ProxyProviderConfig, ProxyHealthResult } from "@/lib/types"

interface ProxySettingsFormProps {
  config:     ProxyProviderConfig | null
  onUpdated:  (c: ProxyProviderConfig | null) => void
}

const PROVIDERS = [
  { value: "openai", label: "OpenAI / OpenAI-compatible" },
  { value: "ollama", label: "Ollama (Local)" },
  { value: "custom", label: "Custom (OpenAI-compatible)" },
]

export function ProxySettingsForm({ config, onUpdated }: ProxySettingsFormProps) {
  const [provider,  setProvider]  = useState(config?.provider      ?? "openai")
  const [baseUrl,   setBaseUrl]   = useState(config?.base_url       ?? "https://api.openai.com/v1")
  const [apiKey,    setApiKey]    = useState("")
  const [model,     setModel]     = useState(config?.default_model  ?? "gpt-4o")
  const [timeout,   setTimeout_]  = useState(config?.timeout_seconds ?? 60)

  const [saving,         setSaving]         = useState(false)
  const [saved,          setSaved]          = useState(false)
  const [deleting,       setDeleting]       = useState(false)
  const [testing,        setTesting]        = useState(false)
  const [confirmDelete,  setConfirmDelete]  = useState(false)
  const { isJwt } = useAuthMode()
  const [error,          setError]          = useState<string | null>(null)
  const [health,         setHealth]         = useState<ProxyHealthResult | null>(null)

  const handleProviderChange = (p: string) => {
    setProvider(p as any)
    setHealth(null)
    if (p === "ollama") {
      setBaseUrl("http://localhost:11434")
      setModel("llama3.2")
    } else if (p === "openai") {
      setBaseUrl("https://api.openai.com/v1")
      setModel("gpt-4o")
    }
  }

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    setHealth(null)
    try {
      const payload: any = { provider, base_url: baseUrl, default_model: model, timeout }
      if (apiKey.trim()) payload.api_key = apiKey.trim()
      const updated = await updateProxySettings(payload)
      onUpdated(updated)
      setApiKey("")   // clear plaintext after save
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    setConfirmDelete(false)
    setDeleting(true)
    setError(null)
    try {
      await deleteProxySettings()
      onUpdated(null)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setDeleting(false)
    }
  }

  const handleTest = async () => {
    setTesting(true)
    setHealth(null)
    setError(null)
    try {
      const result = await getProxyHealth()
      setHealth(result)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setTesting(false)
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
            onChange={(e) => handleProviderChange(e.target.value)}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          >
            {PROVIDERS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
          <p className="text-xs text-slate-400">
            openai covers OpenAI, Azure, Groq, Together AI, and any OpenAI-compatible endpoint
          </p>
        </div>

        {/* Default model */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">Default model</label>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="gpt-4o"
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">
            Model name used when client specifies provider/model format
          </p>
        </div>

        {/* Base URL */}
        <div className="flex flex-col gap-1 col-span-2">
          <label className="text-xs font-medium text-slate-700">Base URL</label>
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://api.openai.com/v1"
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">
            Provider endpoint URL. For Groq: https://api.groq.com/openai/v1
          </p>
        </div>

        {/* API key -- openai and custom only */}
        {provider !== "ollama" && (
          <div className="flex flex-col gap-1 col-span-2">
            <label className="text-xs font-medium text-slate-700">
              API key
              {config?.api_key_masked && (
                <span className="ml-2 font-normal text-slate-400">
                  current: {config.api_key_masked}
                </span>
              )}
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={config?.api_key_masked ? "Leave blank to keep current key" : "sk-..."}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
            />
            <p className="text-xs text-slate-400">
              Stored encrypted. Never returned in API responses. Masked after save.
            </p>
          </div>
        )}

        {/* Timeout */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">Timeout (seconds)</label>
          <input
            type="number"
            min={10}
            max={300}
            value={timeout}
            onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v)) setTimeout_(v) }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-400">10 - 300 seconds</p>
        </div>
      </div>

      {/* Usage note */}
      <div className="px-4 py-3 text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded-lg">
        <p className="font-medium mb-1">How to use proxy mode</p>
        <p>Point your OpenAI SDK at WrapSec and use the provider/model format:</p>
        <code className="mt-1 block font-mono text-blue-800">
          base_url=&quot;http://localhost:8000/v1&quot; &nbsp; model=&quot;{provider}/{model}&quot;
        </code>
      </div>

      {/* Health result */}
      {health && (
        <div className={`px-4 py-3 text-xs rounded-lg border ${
          health.reachable
            ? "text-green-700 bg-green-50 border-green-200"
            : "text-red-700 bg-red-50 border-red-200"
        }`}>
          {health.reachable
            ? `Connected -- ${health.provider} responded in ${health.latency_ms}ms`
            : `Unreachable -- ${health.error}`
          }
        </div>
      )}

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3 flex-wrap">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={saving}>
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
        <Button size="sm" variant="secondary" onClick={handleTest} loading={testing} disabled={!config}>
          Test connection
        </Button>
        {config && (
          confirmDelete ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-red-600 whitespace-nowrap">Remove proxy?</span>
              <button
                onClick={handleDelete}
                className="text-xs font-medium text-red-600 hover:text-red-800 whitespace-nowrap"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="text-xs text-slate-500 hover:text-slate-700"
              >
                Cancel
              </button>
            </div>
          ) : (
            <Button size="sm" variant="danger" onClick={() => setConfirmDelete(true)} loading={deleting}>
              Remove
            </Button>
          )
        )}
        {saved && <span className="text-xs text-green-600">Saved successfully</span>}
      </div>
    </div>
  )
}
