"use client"

import { useState } from "react"
import { useParams } from "next/navigation"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { Button } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import { getDepartment, updateDepartment, getApplicationsByDept, getDepartmentStats } from "@/lib/api"
import Link from "next/link"

export default function DepartmentDetailPage() {
  const { id } = useParams<{ id: string }>()

  const { data: dept, isLoading, mutate } = useSWR(
    `department-${id}`, () => getDepartment(id)
  )
  const { data: appsData } = useSWR(
    `apps-dept-${id}`, () => getApplicationsByDept(id)
  )
  const { data: stats } = useSWR(
    `dept-stats-${id}`, () => getDepartmentStats(id)
  )

  const [editing,     setEditing]     = useState(false)
  const [blockVal,    setBlockVal]    = useState("")
  const [sanitizeVal, setSanitizeVal] = useState("")
  const [saving,      setSaving]      = useState(false)
  const [saved,       setSaved]       = useState(false)
  const [error,       setError]       = useState<string | null>(null)

  const handleEditStart = () => {
    const override = dept?.policy_override
    setBlockVal(override?.thresholds?.block?.toString()    ?? "")
    setSanitizeVal(override?.thresholds?.sanitize?.toString() ?? "")
    setEditing(true)
  }

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      const block    = blockVal    ? parseFloat(blockVal)    : null
      const sanitize = sanitizeVal ? parseFloat(sanitizeVal) : null

      const policy_override = (block !== null || sanitize !== null)
        ? {
            thresholds: {
              ...(block    !== null ? { block }    : {}),
              ...(sanitize !== null ? { sanitize } : {}),
            }
          }
        : null

      await updateDepartment(id, { policy_override })
      mutate()
      setEditing(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  if (isLoading) return <Shell title="Department"><PageSpinner /></Shell>
  if (!dept)     return <Shell title="Department"><p className="text-sm text-slate-500">Department not found.</p></Shell>

  return (
    <Shell title={dept.name}>
      <div className="max-w-2xl space-y-5">
        {/* Back button */}
        <Link
          href="/departments"
          className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to departments
        </Link>
        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-4 gap-3">
            {[
              {
                label: "Total requests",
                value: stats.total.toLocaleString(),
              },
              {
                label: "Block rate",
                value: `${Math.round(stats.block_rate * 100)}%`,
                color: stats.block_rate > 0.3 ? "text-red-600" : "text-slate-900",
              },
              {
                label: "Avg latency",
                value: `${stats.avg_latency_ms.toFixed(1)}ms`,
              },
              {
                label: "Top threat",
                value: stats.top_threats[0]?.category ?? "None",
              },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-white rounded-xl border border-slate-200 px-4 py-3">
                <p className="text-xs text-slate-400 mb-1">{label}</p>
                <p className={`text-lg font-semibold ${color ?? "text-slate-900"}`}>{value}</p>
              </div>
            ))}
          </div>
        )}

        {/* Decision breakdown */}
        {stats && stats.total > 0 && (
          <div className="bg-white rounded-xl border border-slate-200 p-4">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Decision breakdown</p>
            <div className="flex gap-3">
              {Object.entries(stats.decisions).map(([decision, count]) => {
                const pct   = Math.round((count / stats.total) * 100)
                const color = decision === "BLOCK"    ? "#f87171" :
                              decision === "SANITIZE" ? "#fbbf24" : "#10b981"
                return (
                  <div key={decision} className="flex-1 bg-slate-50 rounded-lg px-3 py-2.5">
                    <p className="text-xs text-slate-400 mb-1">{decision}</p>
                    <p className="text-sm font-semibold text-slate-900">{count.toLocaleString()}</p>
                    <div className="mt-1.5 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{pct}%</p>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Department info */}
        <Card>
          <CardHeader title="Department Info" />
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Name",          value: dept.name },
              { label: "Slug",          value: dept.slug },
              { label: "Description",   value: dept.description   || "—" },
              { label: "Contact email", value: dept.contact_email || "—" },
              { label: "Status",        value: dept.is_active ? "Active" : "Inactive" },
              { label: "Created",       value: new Date(dept.created_at).toLocaleDateString() },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                <p className="text-xs font-mono text-slate-700">{value}</p>
              </div>
            ))}
          </div>
        </Card>

        {/* Policy overrides */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="Policy Override"
              subtitle="Override global thresholds for this department. Leave blank to inherit."
            />
            {!editing && (
              <Button onClick={handleEditStart} variant="secondary">
                Edit
              </Button>
            )}
          </div>

          {!editing ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-slate-50">
                <span className="text-sm text-slate-600">Block threshold</span>
                <span className="text-sm font-mono text-slate-900">
                  {dept.policy_override?.thresholds?.block ?? (
                    <span className="text-slate-400">Inherits global (0.7)</span>
                  )}
                </span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-sm text-slate-600">Sanitize threshold</span>
                <span className="text-sm font-mono text-slate-900">
                  {dept.policy_override?.thresholds?.sanitize ?? (
                    <span className="text-slate-400">Inherits global (0.4)</span>
                  )}
                </span>
              </div>
              {dept.policy_override === null && (
                <p className="text-xs text-slate-400 pt-1">
                  No overrides set — this department uses the global policy.
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">
                    Block threshold
                  </label>
                  <input
                    type="number"
                    min={0.01} max={1.0} step={0.05}
                    value={blockVal}
                    onChange={(e) => setBlockVal(e.target.value)}
                    placeholder="e.g. 0.5 (global: 0.7)"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800"
                  />
                  <p className="text-xs text-slate-400">Leave blank to inherit global</p>
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-xs font-medium text-slate-700">
                    Sanitize threshold
                  </label>
                  <input
                    type="number"
                    min={0.0} max={0.99} step={0.05}
                    value={sanitizeVal}
                    onChange={(e) => setSanitizeVal(e.target.value)}
                    placeholder="e.g. 0.3 (global: 0.4)"
                    className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800"
                  />
                  <p className="text-xs text-slate-400">Leave blank to inherit global</p>
                </div>
              </div>
              {error && <p className="text-xs text-red-600">{error}</p>}
              <div className="flex items-center gap-3">
                <Button onClick={handleSave} loading={saving}>Save overrides</Button>
                <button
                  onClick={() => { setEditing(false); setError(null) }}
                  className="text-sm text-slate-500 hover:text-slate-700"
                >
                  Cancel
                </button>
                {saved && <span className="text-xs text-green-600">Saved</span>}
              </div>
            </div>
          )}
        </Card>

        {/* Applications */}
        <Card>
          <CardHeader
            title="Applications"
            subtitle="Systems registered under this department"
          />
          {(appsData?.applications ?? []).length === 0 ? (
            <p className="text-sm text-slate-400">No applications registered.</p>
          ) : (
            <div className="space-y-2">
              {(appsData?.applications ?? []).map((app) => (
                <div
                  key={app.id}
                  className="flex items-center justify-between px-3 py-2.5 bg-slate-50 rounded-lg border border-slate-100"
                >
                  <div>
                    <p className="text-sm font-medium text-slate-900">{app.name}</p>
                    <p className="text-xs text-slate-400">{app.slug} · {app.environment}</p>
                  </div>
                  <a
                    href={`/applications/${app.id}`}
                    className="text-xs text-blue-700 hover:underline"
                  >
                    Manage
                  </a>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </Shell>
  )
}