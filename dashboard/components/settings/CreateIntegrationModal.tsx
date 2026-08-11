// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, useEffect } from "react"
import { useTranslations } from "next-intl"
import useSWR from "swr"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { getConnectorTypes, createWebhook } from "@/lib/api"
import { ConnectorTypeSchema, WebhookEndpointCreated } from "@/lib/types"

interface Props {
  onCreated: () => void
  onClose:   () => void
}

export function CreateIntegrationModal({ onCreated, onClose }: Props) {
  const t = useTranslations("pages.integrations.create_modal")
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", h)
    return () => document.removeEventListener("keydown", h)
  }, [onClose])

  const { data } = useSWR("connector-types", getConnectorTypes)
  const types = data?.connector_types ?? []

  const [selected, setSelected] = useState<ConnectorTypeSchema | null>(null)
  const [url,      setUrl]      = useState("")
  const [desc,     setDesc]     = useState("")
  const [secret,   setSecret]   = useState("")
  const [config,   setConfig]   = useState<Record<string, string>>({})
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const [created,  setCreated]  = useState<WebhookEndpointCreated | null>(null)

  const setField = (k: string, v: string) => setConfig(c => ({ ...c, [k]: v }))

  const handleCreate = async () => {
    if (!selected || !url.trim()) return
    setLoading(true); setError(null)
    try {
      const isGeneric = selected.type === null
      const cleanConfig = Object.fromEntries(
        Object.entries(config).filter(([, v]) => v.trim() !== "")
      )
      const ep = await createWebhook({
        url:            url.trim(),
        description:    desc.trim() || undefined,
        connector_type: isGeneric ? undefined : selected.type!,
        secret:         isGeneric ? undefined : (secret || undefined),
        config:         isGeneric ? undefined : cleanConfig,
      })
      onCreated()
      if (ep.secret) setCreated(ep)   // generic: reveal the signing secret once
      else onClose()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  // --- one-time signing-secret reveal (generic webhooks) ---
  if (created?.secret) {
    return (
      <Overlay>
        <h2 className="text-base font-semibold text-slate-900 mb-1">{t("created_title")}</h2>
        <p className="text-sm text-slate-500 mb-4">
          {t("created_body")}
        </p>
        <div className="bg-slate-50 border border-slate-200 rounded-md p-3 mb-4">
          <code className="text-xs text-slate-800 break-all">{created.secret}</code>
        </div>
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="secondary"
            onClick={() => navigator.clipboard?.writeText(created.secret!)}>
            {t("copy")}
          </Button>
          <Button size="sm" onClick={onClose}>{t("done")}</Button>
        </div>
      </Overlay>
    )
  }

  // --- step 1: destination catalog ---
  if (!selected) {
    return (
      <Overlay>
        <h2 className="text-base font-semibold text-slate-900 mb-1">{t("catalog_title")}</h2>
        <p className="text-sm text-slate-500 mb-4">{t("catalog_body")}</p>
        <div className="grid grid-cols-1 gap-2">
          {types.map(ct => (
            <button
              key={ct.type ?? "generic"}
              onClick={() => setSelected(ct)}
              className="flex items-center justify-between text-left px-4 py-3 rounded-lg border border-slate-200 hover:border-[#670FEF] hover:bg-[rgba(103,15,239,0.04)] transition-colors"
            >
              <span className="text-sm font-medium text-slate-800">{ct.label}</span>
              <span className="text-slate-300">&rsaquo;</span>
            </button>
          ))}
        </div>
        <div className="flex justify-end mt-5">
          <Button size="sm" variant="secondary" onClick={onClose}>{t("cancel")}</Button>
        </div>
      </Overlay>
    )
  }

  // --- step 2: dynamic form ---
  return (
    <Overlay>
      <div className="flex items-center gap-2 mb-4">
        <button onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-700 text-sm">&lsaquo; {t("back")}</button>
        <h2 className="text-base font-semibold text-slate-900">{selected.label}</h2>
      </div>

      <div className="space-y-4">
        <Input
          label={selected.url.label}
          hint={selected.url.help}
          placeholder={t("url_placeholder")}
          value={url}
          onChange={e => setUrl(e.target.value)}
        />

        {!selected.secret.generated && (
          <Input
            label={selected.secret.label}
            type="password"
            autoComplete="new-password"
            placeholder={t("secret_placeholder")}
            value={secret}
            onChange={e => setSecret(e.target.value)}
          />
        )}
        {selected.secret.generated && (
          <p className="text-xs text-slate-400">
            {t("secret_generated_note")}
          </p>
        )}

        {selected.config_fields.map(f => (
          <Input
            key={f.key}
            label={f.required ? `${f.label} *` : f.label}
            hint={f.help}
            value={config[f.key] ?? ""}
            onChange={e => setField(f.key, e.target.value)}
          />
        ))}

        <Input
          label={t("description")}
          placeholder={t("description_placeholder")}
          value={desc}
          onChange={e => setDesc(e.target.value)}
        />

        {error && <p className="text-xs text-red-600">{error}</p>}
      </div>

      <div className="flex justify-end gap-2 mt-5">
        <Button size="sm" variant="secondary" onClick={onClose}>{t("cancel")}</Button>
        <Button size="sm" loading={loading} disabled={!url.trim()} onClick={handleCreate}>
          {t("create")}
        </Button>
      </div>
    </Overlay>
  )
}

function Overlay({ children }: { children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg border border-slate-200 w-full max-w-md p-6 shadow-lg max-h-[90vh] overflow-auto">
        {children}
      </div>
    </div>
  )
}
