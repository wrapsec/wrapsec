"use client"

import { useState } from "react"
import { useParams } from "next/navigation"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { Button } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import { getApplication, getDepartment, getKeysByApp, createApiKeyForApp, revokeApiKey } from "@/lib/api"
import Link from "next/link"

export default function ApplicationDetailPage() {
  const { id } = useParams<{ id: string }>()

  const { data: app, isLoading } = useSWR(
    `application-${id}`, () => getApplication(id)
  )
  const { data: dept } = useSWR(
    app ? `department-${app.dept_id}` : null,
    () => getDepartment(app!.dept_id)
  )
  const { data: keysData, mutate: mutateKeys } = useSWR(
    `keys-app-${id}`, () => getKeysByApp(id)
  )

  const [newKeyName,    setNewKeyName]    = useState("")
  const [creatingKey,   setCreatingKey]   = useState(false)
  const [createdKey,    setCreatedKey]    = useState<string | null>(null)
  const [keyError,      setKeyError]      = useState<string | null>(null)
  const [revokingId,    setRevokingId]    = useState<string | null>(null)

  // Filter keys to this application
  const appKeys = (keysData?.keys ?? []).filter(k => k.app_id === id)

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) return
    setCreatingKey(true)
    setKeyError(null)
    setCreatedKey(null)
    try {
      const result = await createApiKeyForApp(newKeyName.trim(), id)
      setCreatedKey(result.api_key)
      setNewKeyName("")
      mutateKeys()
    } catch (e: any) {
      setKeyError(e.message)
    } finally {
      setCreatingKey(false)
    }
  }

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm("Revoke this key? This cannot be undone.")) return
    setRevokingId(keyId)
    try {
      await revokeApiKey(keyId)
      mutateKeys()
    } finally {
      setRevokingId(null)
    }
  }

  if (isLoading) return <Shell title="Application"><PageSpinner /></Shell>
  if (!app)      return <Shell title="Application"><p className="text-sm text-slate-500">Application not found.</p></Shell>

  return (
    <Shell title={app.name}>
      <div className="max-w-2xl space-y-5">
        {/* Back button */}
        <Link
          href="/applications"
          className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to applications
        </Link>

        {/* Application info */}
        <Card>
          <CardHeader title="Application Info" />
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Name",        value: app.name },
              { label: "Slug",        value: app.slug },
              { label: "Department",  value: dept?.name || app.dept_id },
              { label: "Environment", value: app.environment },
              { label: "Owner",       value: app.owner_name  || "—" },
              { label: "Email",       value: app.owner_email || "—" },
              { label: "Description", value: app.description || "—" },
              { label: "Status",      value: app.is_active ? "Active" : "Inactive" },
              { label: "Created",     value: new Date(app.created_at).toLocaleDateString() },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                <p className="text-xs font-mono text-slate-700">{value}</p>
              </div>
            ))}
          </div>
        </Card>

        {/* API Keys */}
        <Card>
          <CardHeader
            title="API Keys"
            subtitle="Keys scoped to this application"
          />

          {/* Newly created key — show once */}
          {createdKey && (
            <div className="mb-4 p-3 bg-emerald-50 border border-emerald-200 rounded-lg">
              <p className="text-xs font-semibold text-emerald-800 mb-1">
                Key created — copy it now. It will not be shown again.
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs font-mono text-emerald-900 bg-emerald-100 px-2 py-1.5 rounded break-all">
                  {createdKey}
                </code>
                <button
                  onClick={() => navigator.clipboard.writeText(createdKey)}
                  className="text-xs text-emerald-700 hover:text-emerald-900 underline whitespace-nowrap"
                >
                  Copy
                </button>
              </div>
            </div>
          )}

          {/* Existing keys */}
          {appKeys.length === 0 ? (
            <p className="text-sm text-slate-400 mb-4">No keys for this application yet.</p>
          ) : (
            <div className="space-y-2 mb-4">
              {appKeys.map(key => (
                <div
                  key={key.key_id}
                  className="flex items-center justify-between px-3 py-2.5 bg-slate-50 rounded-lg border border-slate-100"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-900">{key.name}</p>
                    <p className="text-xs text-slate-400 font-mono">{key.key_id}</p>
                    {key.last_used_at && (
                      <p className="text-xs text-slate-400">
                        Last used {new Date(key.last_used_at).toLocaleDateString()}
                      </p>
                    )}
                  </div>
                  <button
                    onClick={() => handleRevokeKey(key.key_id)}
                    disabled={revokingId === key.key_id}
                    className="text-xs text-red-500 hover:text-red-700 disabled:opacity-50 ml-4 whitespace-nowrap"
                  >
                    {revokingId === key.key_id ? "Revoking..." : "Revoke"}
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Create new key */}
          <div className="flex gap-2 pt-2 border-t border-slate-100">
            <input
              type="text"
              value={newKeyName}
              onChange={e => setNewKeyName(e.target.value)}
              placeholder="Key name e.g. Finance Bot Primary"
              onKeyDown={e => e.key === "Enter" && handleCreateKey()}
              className="flex-1 h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800"
            />
            <Button onClick={handleCreateKey} loading={creatingKey} disabled={!newKeyName.trim()}>
              Create key
            </Button>
          </div>
          {keyError && <p className="text-xs text-red-600 mt-2">{keyError}</p>}
        </Card>

        {/* Policy */}
        <Card>
          <CardHeader
            title="Policy Override"
            subtitle="Application-level policy overrides are available in v1.1"
          />
          <div className="px-4 py-3 text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded-lg">
            Application policy overrides are coming in v1.1.
            Currently this application inherits the policy from
            the <strong>{dept?.name || "parent"}</strong> department.
          </div>
        </Card>
      </div>
    </Shell>
  )
}