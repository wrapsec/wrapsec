// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Button } from "@/components/ui/Button"
import { updateTenant } from "@/lib/api"

interface TenantSettingsFormProps {
  tenant: {
    id:            string
    name:          string
    description:   string | null
    contact_email: string | null
    global_policy?: Record<string, any>
  }
  onUpdated:      (t: any) => void
  // Actual enforced values - from DB settings, not global_policy
  // Passed from parent page which already fetches these via SWR
  blockThreshold?:    number
  sanitizeThreshold?: number
  ruleEnabled?:       boolean
  mlEnabled?:         boolean
  llmEnabled?:        boolean
  rateLimitPerMinute?: number
  rateLimitSource?:   string
}

export function TenantSettingsForm({
  tenant,
  onUpdated,
  blockThreshold,
  sanitizeThreshold,
  ruleEnabled,
  mlEnabled,
  llmEnabled,
  rateLimitPerMinute,
  rateLimitSource,
}: TenantSettingsFormProps) {
  const [name,        setName]        = useState(tenant.name)
  const [description, setDescription] = useState(tenant.description || "")
  const [contact,     setContact]     = useState(tenant.contact_email || "")
  const [saving,      setSaving]      = useState(false)
  const [saved,       setSaved]       = useState(false)
  const { isJwt } = useAuthMode()
  const [error,       setError]       = useState<string | null>(null)

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      const updated = await updateTenant({
        name,
        description:   description || undefined,
        contact_email: contact     || undefined,
      })
      onUpdated(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-5">
      {/* Organisation info */}
      <div className="grid grid-cols-2 gap-4">
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Organisation name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">
            Contact email
          </label>
          <input
            type="email"
            value={contact}
            onChange={(e) => setContact(e.target.value)}
            placeholder="admin@acme.com"
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
        </div>
        <div className="flex flex-col gap-1 col-span-2">
          <label className="text-xs font-medium text-slate-700">
            Description
          </label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Single on-premise installation"
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700"
          />
        </div>
      </div>

      {/* Enforced runtime values - from DB settings, not global_policy */}
      <div>
        <p className="text-xs font-medium text-slate-700 mb-3">
          Enforced runtime settings
          <span className="ml-2 text-xs text-slate-400 font-normal">
            - Tenant-wide defaults. Departments may have their own overrides.
          </span>
        </p>
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Block threshold",    value: blockThreshold    ?? "-" },
            { label: "Sanitize threshold", value: sanitizeThreshold ?? "-" },
            { label: "Rate limit/min",     value: rateLimitPerMinute != null ? `${rateLimitPerMinute} (${rateLimitSource ?? "env"})` : "-" },
            { label: "Rule detector",      value: ruleEnabled != null ? (ruleEnabled ? "Enabled" : "Disabled") : "-" },
            { label: "ML detector",        value: mlEnabled   != null ? (mlEnabled   ? "Enabled" : "Disabled") : "-" },
            { label: "LLM detector",       value: llmEnabled  != null ? (llmEnabled  ? "Enabled" : "Disabled") : "-" },
          ].map(({ label, value }) => (
            <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
              <p className="text-xs text-slate-400 mb-0.5">{label}</p>
              <p className="text-xs font-mono text-slate-700">{String(value)}</p>
            </div>
          ))}
        </div>
        <p className="text-xs text-slate-400 mt-2">
          Manage these values in the cards below. Changes take effect immediately (rate limit within 5 minutes).
        </p>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        {isJwt ? (
          <Button size="sm" onClick={handleSave} loading={saving}>
            Save organisation settings
          </Button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Button size="sm" disabled>Save organisation settings</Button>
            <span style={{ fontSize: "11px", color: "#9ca3af" }}>
              Requires admin login -{" "}
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