// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, Fragment } from "react"
import { swrKeys } from "@/lib/swrKeys"
import { useAuthMode } from "@/hooks/useAuthMode"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card } from "@/components/ui/Card"
import { Button, PlusIcon } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import { getApplications, getDepartments, createApplication, deleteApplication } from "@/lib/api"
import Link from "next/link"
import { slugify } from "@/lib/utils"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { NameSlug, PolicyBadge } from "@/components/admin/ListCells"

export default function ApplicationsPage() {
  const [showCreate,        setShowCreate]        = useState(false)
  const [name,              setName]              = useState("")
  const [slug,              setSlug]              = useState("")
  const [slugEdited,        setSlugEdited]        = useState(false)
  const [deptId,            setDeptId]            = useState("")
  const [description,       setDescription]       = useState("")
  const [ownerName,         setOwnerName]         = useState("")
  const [ownerEmail,        setOwnerEmail]        = useState("")
  const [environment,       setEnvironment]       = useState("production")
  const [saving,            setSaving]            = useState(false)
  const [error,             setError]             = useState<string | null>(null)
  const [search,            setSearch]            = useState("")
  const [confirmDeactivate, setConfirmDeactivate] = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  const { data,      isLoading, mutate, error: fetchError } = useSWR(swrKeys.applications,  getApplications)
  const { data: deptData }               = useSWR(swrKeys.departments,   getDepartments)

  const handleCreate = async () => {
    if (!name || !slug || !deptId) {
      setError(!name ? "Name is required." : !slug ? "Slug is required." : "Please select a department.")
      return
    }
    setSaving(true)
    setError(null)
    try {
      await createApplication({
        dept_id:     deptId,
        name,
        slug,
        description,
        owner_name:  ownerName,
        owner_email: ownerEmail,
        environment,
      })
      setShowCreate(false)
      setName(""); setSlug(""); setSlugEdited(false); setDeptId("")
      setDescription(""); setOwnerName(""); setOwnerEmail("")
      mutate()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleDeactivate = async (id: string) => {
    setConfirmDeactivate(null)
    try {
      await deleteApplication(id)
      mutate()
    } catch (e: any) {
      setError(e.message)
    }
  }

  const deptName = (deptId: string) =>
    deptData?.departments.find((d) => d.id === deptId)?.name || deptId

  return (
    <Shell title="Applications">
      <PageHeader
        description="Manage applications and their API key assignments."
        actions={
          isJwt ? (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <PlusIcon /> Add application
            </Button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Button size="sm" disabled><PlusIcon /> Add application</Button>
              <span style={{ fontSize: "11px", color: "#9ca3af" }}>
                Requires admin login -{" "}
                <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
              </span>
            </div>
          )
        }
      />
      <div className="space-y-4">

        {/* Create form */}
        {showCreate && (
          <Card>
            <p className="text-sm font-semibold text-slate-900 mb-4">New Application</p>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Name *</label>
                <input type="text" value={name}
                  onChange={(e) => { setName(e.target.value); if (!slugEdited) setSlug(slugify(e.target.value)) }}
                  placeholder="Finance Bot"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Slug *</label>
                <input type="text" value={slug}
                  onChange={(e) => { setSlugEdited(true); setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-")) }}
                  placeholder="finance-bot"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
                <span className="text-[11px] text-slate-400">Auto-generated from the name; edit to override.</span>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Department *</label>
                <select value={deptId} onChange={(e) => setDeptId(e.target.value)}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700">
                  <option value="">Select department</option>
                  {(deptData?.departments ?? []).map((d) => (
                    <option key={d.id} value={d.id}>{d.name}</option>
                  ))}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Environment</label>
                <select value={environment} onChange={(e) => setEnvironment(e.target.value)}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700">
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Owner name</label>
                <input type="text" value={ownerName} onChange={(e) => setOwnerName(e.target.value)}
                  placeholder="John Smith"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Owner email</label>
                <input type="email" value={ownerEmail} onChange={(e) => setOwnerEmail(e.target.value)}
                  placeholder="john@acme.com"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
              </div>
              <div className="flex flex-col gap-1 col-span-2">
                <label className="text-xs font-medium text-slate-700">Description</label>
                <input type="text" value={description} onChange={(e) => setDescription(e.target.value)}
                  placeholder="Finance automation system"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700" />
              </div>
            </div>
            {error && <p className="text-xs text-red-600 mt-3">{error}</p>}
            <div className="flex gap-3 mt-4">
              {isJwt
                ? <Button size="sm" onClick={handleCreate} loading={saving}>Create</Button>
                : <Button size="sm" disabled>Create</Button>
              }
              <Button size="sm" variant="secondary" onClick={() => { setShowCreate(false); setError(null) }}>Cancel</Button>
            </div>
          </Card>
        )}

        {/* Applications table */}
        <Card padding={false}>
          {/* Search bar */}
          <div className="px-5 py-3 border-b border-slate-100">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search applications..."
              className="h-8 w-full max-w-xs px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
            />
          </div>
          {!showCreate && error && <p className="px-5 pb-2 text-xs text-red-600">{error}</p>}
          {isLoading ? (
            <PageSpinner />
          ) : fetchError && !data ? (
            <div className="px-5 py-10 text-center">
              <p className="text-sm font-semibold text-red-600 mb-1">Failed to load applications</p>
              <p className="text-xs text-slate-400">{fetchError?.message ?? "An unexpected error occurred"}</p>
            </div>
          ) : (
            <div style={{ overflowY: "auto", maxHeight: "520px" }}>
              <Table>
                <THead>
                  <tr>
                    {["Name", "Department", "Environment", "Owner", "Policy", ""].map((h) => (
                      <Th key={h}>{h}</Th>
                    ))}
                  </tr>
                </THead>
                <TBody>
                  {(data?.applications ?? []).length === 0 ? (
                    <tr>
                      <Td colSpan={6}>
                        <div className="px-5 py-14 text-center">
                          <div className="text-sm font-semibold text-slate-700 mb-1">No applications yet</div>
                          <div className="text-xs text-slate-400">Register an application to scope API keys and apply per-app policy overrides</div>
                        </div>
                      </Td>
                    </tr>
                  ) : (
                    (data?.applications ?? [])
                      .filter((app) => {
                        if (!search) return true
                        const q = search.toLowerCase()
                        return (
                          app.name.toLowerCase().includes(q) ||
                          app.slug.toLowerCase().includes(q) ||
                          app.environment.toLowerCase().includes(q) ||
                          (app.owner_name ?? "").toLowerCase().includes(q)
                        )
                      })
                      .map((app) => (
                      <Fragment key={app.id}>
                        <Tr hover>
                          <Td><NameSlug name={app.name} slug={app.slug} /></Td>
                          <Td className="text-xs text-slate-600">{deptName(app.dept_id)}</Td>
                          <Td>
                            <span className={`inline-flex items-center text-xs px-2 py-0.5 rounded-full border ${
                              app.environment === "production"
                                ? "bg-green-50 text-green-700 border-green-200"
                                : app.environment === "staging"
                                ? "bg-amber-50 text-amber-700 border-amber-200"
                                : "bg-slate-50 text-slate-600 border-slate-200"
                            }`}>
                              {app.environment}
                            </span>
                          </Td>
                          <Td className="text-xs text-slate-500">{app.owner_name || "-"}</Td>
                          <Td><PolicyBadge overridden={!!app.policy_override} inheritsLabel="Inherits dept" /></Td>
                          <Td align="right">
                            <div className="flex items-center justify-end gap-3">
                              <Link href={`/applications/${app.id}`} className="text-xs text-blue-700 hover:underline">Manage</Link>
                              {isJwt && (
                                <button
                                  onClick={() => setConfirmDeactivate(confirmDeactivate === app.id ? null : app.id)}
                                  className="text-xs text-red-600 hover:underline cursor-pointer"
                                >
                                  Deactivate
                                </button>
                              )}
                            </div>
                          </Td>
                        </Tr>
                        {confirmDeactivate === app.id && (
                          <tr className="bg-red-50">
                            <Td colSpan={6}>
                              <div className="flex items-center gap-3">
                                <p className="text-xs text-red-700 whitespace-nowrap">
                                  This will permanently deactivate the application.
                                </p>
                                <button
                                  onClick={() => handleDeactivate(app.id)}
                                  className="text-xs font-medium text-white bg-red-600 hover:bg-red-700 px-3 py-1 rounded whitespace-nowrap cursor-pointer"
                                >
                                  Confirm deactivate
                                </button>
                                <button
                                  onClick={() => setConfirmDeactivate(null)}
                                  className="text-xs text-slate-500 hover:text-slate-700 cursor-pointer"
                                >
                                  Cancel
                                </button>
                              </div>
                            </Td>
                          </tr>
                        )}
                      </Fragment>
                    ))
                  )}
                </TBody>
              </Table>
            </div>
          )}
        </Card>
      </div>
    </Shell>
  )
}
