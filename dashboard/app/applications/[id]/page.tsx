"use client"

import { useParams } from "next/navigation"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { PageSpinner } from "@/components/ui/Spinner"
import { getApplication, getDepartment, getKeysByApp } from "@/lib/api"
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
  const { data: keysData } = useSWR(
    `keys-app-${id}`, () => getKeysByApp(id)
  )

  // Filter keys scoped to this application
  const appKeys = (keysData?.keys ?? []).filter(k => k.app_id === id)

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

        {/* API Keys — read only view, managed in /settings/keys */}
        <Card>
          <div className="flex items-center justify-between mb-4">
            <CardHeader
              title="API Keys"
              subtitle="Keys scoped to this application"
            />
            <Link
              href="/settings/keys"
              className="text-xs text-blue-700 hover:underline whitespace-nowrap"
            >
              Manage keys →
            </Link>
          </div>

          {appKeys.length === 0 ? (
            <p className="text-sm text-slate-400">
              No keys for this application.{" "}
              <Link href="/settings/keys" className="text-blue-700 hover:underline">
                Create one in API Keys
              </Link>
            </p>
          ) : (
            <div className="space-y-2">
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
                  <span className="text-xs text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full">
                    Active
                  </span>
                </div>
              ))}
            </div>
          )}
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
