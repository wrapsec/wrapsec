"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { updateTenant } from "@/lib/api"

interface TenantSettingsFormProps {
  tenant: {
    id:            string
    name:          string
    description:   string | null
    contact_email: string | null
    global_policy: Record<string, any>
  }
  onUpdated: (t: any) => void
}

export function TenantSettingsForm({ tenant, onUpdated }: TenantSettingsFormProps) {
  const [name,        setName]        = useState(tenant.name)
  const [description, setDescription] = useState(tenant.description || "")
  const [contact,     setContact]     = useState(tenant.contact_email || "")
  const [saving,      setSaving]      = useState(false)
  const [saved,       setSaved]       = useState(false)
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
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
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
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
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
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
        </div>
      </div>

      {/* Global policy read-only view */}
      <div>
        <p className="text-xs font-medium text-slate-700 mb-2">
          Global policy
          <span className="ml-2 text-xs text-slate-400 font-normal">
            — inherited by all departments unless overridden
          </span>
        </p>
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Block threshold",    value: tenant.global_policy?.thresholds?.block    ?? "—" },
            { label: "Sanitize threshold", value: tenant.global_policy?.thresholds?.sanitize ?? "—" },
            { label: "Rate limit/min",     value: tenant.global_policy?.rate_limit?.per_minute ?? "—" },
            { label: "Rule detector",      value: tenant.global_policy?.detection?.rule_enabled !== false ? "Enabled" : "Disabled" },
            { label: "ML detector",        value: tenant.global_policy?.detection?.ml_enabled   !== false ? "Enabled" : "Disabled" },
            { label: "LLM detector",       value: tenant.global_policy?.detection?.llm_enabled  !== false ? "Enabled" : "Disabled" },
          ].map(({ label, value }) => (
            <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
              <p className="text-xs text-slate-400 mb-0.5">{label}</p>
              <p className="text-xs font-mono text-slate-700">{String(value)}</p>
            </div>
          ))}
        </div>
        <p className="text-xs text-slate-400 mt-2">
          Global policy thresholds are managed in the Policy Thresholds card below.
        </p>
      </div>

      {error && <p className="text-xs text-red-600">{error}</p>}

      <div className="flex items-center gap-3">
        <Button onClick={handleSave} loading={saving}>
          Save organisation settings
        </Button>
        {saved && (
          <span className="text-xs text-green-600">Saved successfully</span>
        )}
      </div>
    </div>
  )
}