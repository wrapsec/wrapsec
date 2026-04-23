"use client"

import { useState } from "react"
import useSWR from "swr"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { ApiKeyCreated } from "@/lib/types"
import { createApiKey, getDepartments, getApplicationsByDept } from "@/lib/api"

interface CreateKeyModalProps {
  onCreated: (key: ApiKeyCreated) => void
  onClose:   () => void
}

export function CreateKeyModal({ onCreated, onClose }: CreateKeyModalProps) {
  const [name,    setName]    = useState("")
  const [deptId,  setDeptId]  = useState("")
  const [appId,   setAppId]   = useState("")
  const [keyType, setKeyType] = useState<"live" | "trial">("live")
  const [loading, setLoading] = useState(false)
  const [created, setCreated] = useState<ApiKeyCreated | null>(null)
  const [error,   setError]   = useState<string | null>(null)

  // Load departments for selector
  const { data: deptsData } = useSWR("departments", getDepartments)
  const departments = deptsData?.departments ?? []

  // Load applications when dept is selected
  const { data: appsData } = useSWR(
    deptId ? `apps-dept-${deptId}` : null,
    () => getApplicationsByDept(deptId)
  )
  const applications = appsData?.applications ?? []

  const handleDeptChange = (id: string) => {
    setDeptId(id)
    setAppId("") // reset app when dept changes
  }

  const handleCreate = async () => {
    if (!name.trim()) return
    setLoading(true)
    setError(null)
    try {
      const key = await createApiKey(
        name.trim(),
        appId   || undefined,
        deptId  || undefined,
        keyType,
      )
      setCreated(key)
      onCreated(key)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const selectClass = "h-9 w-full px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800"

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg border border-slate-200 w-full max-w-md p-6 shadow-lg">
        <h2 className="text-base font-semibold text-slate-900 mb-4">
          Create API Key
        </h2>

        {!created ? (
          <div className="space-y-4">
            {/* Name */}
            <Input
              label="Key name"
              placeholder="e.g. finance-bot"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />

            {/* Department */}
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-slate-700">
                Department <span className="text-slate-400">(required)</span>
              </label>
              <select
                value={deptId}
                onChange={(e) => handleDeptChange(e.target.value)}
                className={selectClass}
              >
                <option value="">Select department...</option>
                {departments.map(d => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
              <p className="text-xs text-slate-400">
                Key will be scoped to this department
              </p>
            </div>

            {/* Key type */}
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-slate-700">Key type</label>
              <select
                value={keyType}
                onChange={(e) => setKeyType(e.target.value as "live" | "trial")}
                className={selectClass}
              >
                <option value="live">Live — full limits, proxy enabled</option>
                <option value="trial">Trial — restricted limits, no proxy</option>
              </select>
              {keyType === "trial" && (
                <p className="text-xs text-amber-600">
                  Trial keys: 10 req/min, 500 char input limit, proxy disabled.
                </p>
              )}
            </div>

            {/* Application — optional, only shown when dept is selected */}
            {deptId && (
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">
                  Application <span className="text-slate-400">(optional)</span>
                </label>
                <select
                  value={appId}
                  onChange={(e) => setAppId(e.target.value)}
                  className={selectClass}
                >
                  <option value="">No application — dept-scoped only</option>
                  {applications.map(a => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
                <p className="text-xs text-slate-400">
                  Optionally scope to a specific application within the department
                </p>
              </div>
            )}

            {error && (
              <p className="text-xs text-red-600">{error}</p>
            )}
            <div className="flex justify-end gap-3">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button
                loading={loading}
                disabled={!name.trim() || !deptId}
                onClick={handleCreate}
              >
                Create
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
              <p className="text-xs font-medium text-amber-800 mb-1">
                Copy this key now — it will not be shown again
              </p>
              <p className="font-mono text-xs text-amber-900 break-all">
                {created.api_key}
              </p>
            </div>
            {/* Show scoping info */}
            <div className="grid grid-cols-2 gap-2 text-xs text-slate-500">
              <div>
                <span className="text-slate-400">Type:</span>{" "}
                <span className={`font-medium ${created.key_type === "trial" ? "text-amber-600" : "text-emerald-600"}`}>
                  {created.key_type === "trial" ? "Trial" : "Live"}
                </span>
              </div>
              {created.dept_id && (
                <div>
                  <span className="text-slate-400">Department:</span>{" "}
                  <span className="font-mono">{created.dept_id.slice(0, 8)}...</span>
                </div>
              )}
              {created.app_id && (
                <div>
                  <span className="text-slate-400">Application:</span>{" "}
                  <span className="font-mono">{created.app_id.slice(0, 8)}...</span>
                </div>
              )}
            </div>
            <div className="flex justify-end">
              <Button onClick={onClose}>Done</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
