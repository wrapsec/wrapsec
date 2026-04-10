"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { LLMSettings } from "@/lib/types"
import { updateLLMSettings } from "@/lib/api"

interface LLMSettingsFormProps {
  settings:  LLMSettings
  onUpdated: (s: LLMSettings) => void
}

const PROVIDERS = [
  { value: "ollama", label: "Ollama (Local)" },
  { value: "openai", label: "OpenAI" },
  { value: "groq",   label: "Groq" },
]

export function LLMSettingsForm({ settings, onUpdated }: LLMSettingsFormProps) {
  const [provider,   setProvider]   = useState(settings.provider)
  const [model,      setModel]      = useState(settings.model)
  const [baseUrl,    setBaseUrl]    = useState(settings.base_url)
  const [timeout,    setTimeout_]   = useState(settings.timeout ?? 30)
  const [trigger,    setTrigger]    = useState(settings.llm_trigger)
  const [loading,    setLoading]    = useState(false)
  const [saved,      setSaved]      = useState(false)
  const [error,      setError]      = useState<string | null>(null)

  const handleSave = async () => {
    setLoading(true)
    setError(null)
    try {
      const updated = await updateLLMSettings({
        provider,
        model,
        base_url:    baseUrl,
        timeout,
        llm_trigger: trigger,
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
      <div className="grid grid-cols-2 gap-5">
        {/* Provider */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Provider
          </label>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value as any)}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          >
            {PROVIDERS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
          <p className="text-xs text-slate-400">
            LLM provider for detection and proxy mode
          </p>
        </div>

        {/* Model */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Model
          </label>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder="llama3.2:latest"
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
          <p className="text-xs text-slate-400">
            Model name for the selected provider
          </p>
        </div>

        {/* Base URL — Ollama only */}
        {provider === "ollama" && (
          <div className="flex flex-col gap-1 col-span-2">
            <label className="text-xs font-medium text-slate-700">
              Base URL
            </label>
            <input
              type="text"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:11434"
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
            />
            <p className="text-xs text-slate-400">
              Ollama server URL
            </p>
          </div>
        )}

        {/* Timeout */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Timeout (seconds)
          </label>
          <input
            type="number"
            min={5}
            max={120}
            value={timeout}
            onChange={(e) => {
              const val = parseInt(e.target.value)
              if (!isNaN(val)) setTimeout_(val)
            }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
          <p className="text-xs text-slate-400">
            Request timeout (5 – 120 seconds)
          </p>
        </div>

        {/* LLM Trigger threshold */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            LLM Trigger threshold
          </label>
          <input
            type="number"
            min={0.0}
            max={1.0}
            step={0.05}
            value={trigger}
            onChange={(e) => {
              const val = parseFloat(e.target.value)
              if (!isNaN(val)) setTrigger(val)
            }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
          <p className="text-xs text-slate-400">
            Minimum risk score before LLM detector is invoked (full mode only)
          </p>
        </div>
      </div>

      {/* OpenAI / Groq note */}
      {(provider === "openai" || provider === "groq") && (
        <div className="px-4 py-3 text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded-lg">
          API keys for {provider === "openai" ? "OpenAI" : "Groq"} are configured
          in the server environment (.env file) and are not stored in the database
          for security reasons.
        </div>
      )}

      {error && (
        <p className="text-xs text-red-600">{error}</p>
      )}

      <div className="flex items-center gap-3">
        <Button onClick={handleSave} loading={loading}>
          Save LLM settings
        </Button>
        {saved && (
          <span className="text-xs text-green-600">Saved successfully</span>
        )}
      </div>
    </div>
  )
}