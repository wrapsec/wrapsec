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
import { getDepartments, createDepartment, deleteDepartment } from "@/lib/api"
import Link from "next/link"

export default function DepartmentsPage() {
  const [showCreate,        setShowCreate]        = useState(false)
  const [name,              setName]              = useState("")
  const [slug,              setSlug]              = useState("")
  const [description,       setDescription]       = useState("")
  const [contact,           setContact]           = useState("")
  const [saving,            setSaving]            = useState(false)
  const [error,             setError]             = useState<string | null>(null)
  const [search,            setSearch]            = useState("")
  const [confirmDeactivate, setConfirmDeactivate] = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  const { data, isLoading, mutate, error: fetchError } = useSWR(swrKeys.departments, getDepartments)

  const handleCreate = async () => {
    if (!name || !slug) return
    setSaving(true)
    setError(null)
    try {
      await createDepartment({ name, slug, description, contact_email: contact })
      setShowCreate(false)
      setName(""); setSlug(""); setDescription(""); setContact("")
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
      await deleteDepartment(id)
      mutate()
    } catch (e: any) {
      setError(e.message)
    }
  }

  return (
    <Shell title="Departments">
      <PageHeader
        description="Manage departments and their policy overrides."
        actions={
          isJwt ? (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <PlusIcon /> Add department
            </Button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Button size="sm" disabled><PlusIcon /> Add department</Button>
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
            <p className="text-sm font-semibold text-slate-900 mb-4">New Department</p>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Name *</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Finance Department"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Slug *</label>
                <input
                  type="text"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
                  placeholder="finance"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Description</label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Finance division"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">Contact email</label>
                <input
                  type="email"
                  value={contact}
                  onChange={(e) => setContact(e.target.value)}
                  placeholder="finance@acme.com"
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
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

        {/* Departments table */}
        <Card padding={false}>
          {/* Search bar */}
          <div className="px-5 py-3 border-b border-slate-100">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search departments..."
              className="h-8 w-full max-w-xs px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
            />
          </div>
          {error && <p className="px-5 pb-2 text-xs text-red-600">{error}</p>}
          {isLoading ? (
            <PageSpinner />
          ) : fetchError && !data ? (
            <div className="px-5 py-10 text-center">
              <p className="text-sm font-semibold text-red-600 mb-1">Failed to load departments</p>
              <p className="text-xs text-slate-400">{fetchError?.message ?? "An unexpected error occurred"}</p>
            </div>
          ) : (
            <div style={{ overflowY: "auto", maxHeight: "520px" }}>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  {["Name", "Slug", "Description", "Contact", "Policy Override", ""].map((h) => (
                    <th key={h} className="text-left px-5 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(data?.departments ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-5 py-14 text-center">
                      <div style={{ fontSize: "20px", marginBottom: "8px" }}></div>
                      <div className="text-sm font-semibold text-slate-700 mb-1">No departments yet</div>
                      <div className="text-xs text-slate-400">Create a department to organise your API keys and policy overrides</div>
                    </td>
                  </tr>
                ) : (
                  (data?.departments ?? [])
                    .filter((dept) => {
                      if (!search) return true
                      const q = search.toLowerCase()
                      return (
                        dept.name.toLowerCase().includes(q) ||
                        dept.slug.toLowerCase().includes(q) ||
                        (dept.description ?? "").toLowerCase().includes(q)
                      )
                    })
                    .map((dept) => (
                    <Fragment key={dept.id}>
                      <tr
                        className="border-b border-slate-50"
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#f9fafb"}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
                      >
                        <td className="px-5 py-3 font-medium text-slate-900">{dept.name}</td>
                        <td className="px-5 py-3 font-mono text-xs text-slate-500">{dept.slug}</td>
                        <td className="px-5 py-3 text-xs text-slate-500">{dept.description || "-"}</td>
                        <td className="px-5 py-3 text-xs text-slate-500">{dept.contact_email || "-"}</td>
                        <td className="px-5 py-3">
                          {dept.policy_override ? (
                            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                              Overridden
                            </span>
                          ) : (
                            <span className="text-xs text-slate-400">Inherits global</span>
                          )}
                        </td>
                        <td className="px-5 py-3 text-right">
                          <div className="flex items-center justify-end gap-3">
                            <Link
                              href={`/departments/${dept.id}`}
                              style={{ fontSize: "12px", color: "#1d4ed8" }}
                              onMouseEnter={e => (e.currentTarget as HTMLElement).style.textDecoration = "underline"}
                              onMouseLeave={e => (e.currentTarget as HTMLElement).style.textDecoration = "none"}
                            >
                              Manage
                            </Link>
                            {isJwt && dept.slug !== "default" && (
                              <button
                                onClick={() => setConfirmDeactivate(confirmDeactivate === dept.id ? null : dept.id)}
                                style={{ fontSize: "12px", color: "#dc2626", background: "none", border: "none", cursor: "pointer", padding: 0 }}
                                onMouseEnter={e => (e.currentTarget as HTMLElement).style.textDecoration = "underline"}
                                onMouseLeave={e => (e.currentTarget as HTMLElement).style.textDecoration = "none"}
                              >
                                Deactivate
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                      {confirmDeactivate === dept.id && (
                        <tr style={{ background: "#fff5f5" }}>
                          <td colSpan={6} className="px-5 py-3">
                            <div className="flex items-center gap-3">
                              <p className="text-xs text-red-700 whitespace-nowrap">
                                This will permanently deactivate the department and all its keys.
                              </p>
                              <button
                                onClick={() => handleDeactivate(dept.id)}
                                style={{ fontSize: "12px", fontWeight: 500, color: "#fff", background: "#dc2626", border: "none", cursor: "pointer", padding: "4px 12px", borderRadius: "4px", whiteSpace: "nowrap" }}
                                onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#b91c1c"}
                                onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "#dc2626"}
                              >
                                Confirm deactivate
                              </button>
                              <button
                                onClick={() => setConfirmDeactivate(null)}
                                style={{ fontSize: "12px", color: "#6b7280", background: "none", border: "none", cursor: "pointer", padding: 0 }}
                                onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = "#374151"}
                                onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = "#6b7280"}
                              >
                                Cancel
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))
                )}
              </tbody>
            </table>
            </div>
          )}
        </Card>
      </div>
    </Shell>
  )
}
