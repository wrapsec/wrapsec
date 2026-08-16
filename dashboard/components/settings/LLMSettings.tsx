// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { LLMSettings } from "@/lib/types"
import { updateLLMSettings } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"

interface LLMSettingsFormProps {
  settings:  LLMSettings
  onUpdated: (s: LLMSettings) => void
}

const PROVIDERS = ["openai", "ollama", "custom"] as const

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
  const t  = useTranslations("pages.settings")
  const tc = useTranslations("common")
  const code = (chunks: React.ReactNode) => <code className="font-mono">{chunks}</code>
  const [provider, setProvider] = useState<LLMSettings["provider"]>(settings.provider)
  const [model,    setModel]    = useState(settings.model)
  const [baseUrl,  setBaseUrl]  = useState(settings.base_url)
  const [apiKey,   setApiKey]   = useState("")
  const [timeout,  setTimeout_] = useState(settings.timeout ?? 30)
  const [loading,  setLoading]  = useState(false)
  const [saved,    setSaved]    = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const { isAdmin } = useAuthMode()

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
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-5">

        {/* Provider */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">{t("llm.provider")}</label>
          <select
            value={provider}
            onChange={(e) => handleProviderChange(e.target.value as LLMSettings["provider"])}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          >
            {PROVIDERS.map((p) => (
              <option key={p} value={p}>{t(`providers.${p}`)}</option>
            ))}
          </select>
          <p className="text-xs text-slate-600">
            {t("llm.provider_hint")}
          </p>
        </div>

        {/* Default model */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">{t("llm.model")}</label>
          <input
            type="text"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder={t("llm.model_placeholder")}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-600">{t("llm.model_hint")}</p>
        </div>

        {/* Base URL */}
        <div className="flex flex-col gap-1 col-span-2">
          <label className="text-xs font-medium text-slate-700">{t("llm.base_url")}</label>
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={provider === "ollama" ? t("llm.base_url_placeholder_ollama") : t("llm.base_url_placeholder_default")}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-600">
            {provider === "ollama"
              ? t("llm.base_url_hint_ollama")
              : provider === "openai"
              ? t("llm.base_url_hint_openai")
              : t("llm.base_url_hint_custom")}
          </p>
        </div>

        {/* API key - openai / custom only */}
        {provider !== "ollama" && (
          <div className="flex flex-col gap-1 col-span-2">
            <label className="text-xs font-medium text-slate-700">
              {t("llm.api_key")}
              {settings.api_key_masked && (
                <span className="ml-2 font-normal text-slate-600">
                  {t("llm.api_key_current", { masked: settings.api_key_masked })}
                </span>
              )}
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={settings.api_key_masked ? t("llm.api_key_placeholder_keep") : t("llm.api_key_placeholder_new")}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
            />
            <p className="text-xs text-slate-600">
              {t.rich("llm.api_key_hint", { code })}
            </p>
          </div>
        )}

        {/* Timeout */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">{t("llm.timeout")}</label>
          <input
            type="number"
            min={5}
            max={120}
            value={timeout}
            onChange={(e) => { const v = parseInt(e.target.value); if (!isNaN(v)) setTimeout_(v) }}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
          <p className="text-xs text-slate-600">{t("llm.timeout_hint")}</p>
        </div>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isAdmin ? (
          <Button size="sm" onClick={handleSave} loading={loading}>
            {t("llm.save")}
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>{t("llm.save")}</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              {tc.rich("requires_admin", {
                link: (chunks) => <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>{chunks}</a>,
              })}
            </span>
          </div>
        )}
        {saved && <span className="text-xs text-green-600">{t("saved")}</span>}
      </div>
    </div>
  )
}
