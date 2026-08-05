// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, useEffect } from "react"
import { swrKeys } from "@/lib/swrKeys"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card } from "@/components/ui/Card"
import { Button, PlusIcon } from "@/components/ui/Button"
import { useAuthMode } from "@/hooks/useAuthMode"
import { PageSpinner } from "@/components/ui/Spinner"
import {
  getUsers, createUser, updateUser, resetUserPassword,
  getDepartments,
} from "@/lib/api"
import type { DashboardUser } from "@/lib/types"

// ── Role badge ─────────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  const styles: Record<string, string> = {
    ADMIN:     "bg-purple-50 text-purple-700 border-purple-200",
    DEVELOPER: "bg-blue-50 text-blue-700 border-blue-200",
    AUDITOR:   "bg-amber-50 text-amber-700 border-amber-200",
    VIEWER:    "bg-slate-50 text-slate-600 border-slate-200",
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${styles[role] ?? styles.VIEWER}`}>
      {role}
    </span>
  )
}

// ── Status badge ───────────────────────────────────────────────────────────────

function StatusBadge({ active }: { active: boolean }) {
  return active ? (
    <span className="text-xs px-2 py-0.5 rounded-full bg-green-50 text-green-700 border border-green-200">
      Active
    </span>
  ) : (
    <span className="text-xs px-2 py-0.5 rounded-full bg-red-50 text-red-600 border border-red-200">
      Inactive
    </span>
  )
}

// ── Input helper ───────────────────────────────────────────────────────────────

function Field({
  label, children,
}: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium text-slate-700">{label}</label>
      {children}
    </div>
  )
}

const inputCls = "h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700 disabled:opacity-50"
const selectCls = inputCls

// ── Create user modal ──────────────────────────────────────────────────────────

function CreateUserModal({
  depts,
  onClose,
  onCreated,
}: {
  depts:     { id: string; name: string }[]
  onClose:   () => void
  onCreated: () => void
}) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  const [email,    setEmail]    = useState("")
  const [password, setPassword] = useState("")
  const [role,     setRole]     = useState("DEVELOPER")
  const [deptId,   setDeptId]   = useState(depts[0]?.id ?? "")
  const [saving,   setSaving]   = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  // ADMIN forbids dept_id; AUDITOR treats it as optional (tenant-wide when
  // empty); DEVELOPER/VIEWER require it. Matches ck_users_dept_required_v2.
  const auditorTenantWide = role === "AUDITOR" && !deptId
  const omitDept          = role === "ADMIN" || auditorTenantWide

  const handleCreate = async () => {
    setError(null)
    setSaving(true)
    try {
      await createUser({
        email,
        password,
        role:    role as any,
        dept_id: omitDept ? undefined : deptId,
      })
      onCreated()
      onClose()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-md bg-white rounded-xl border border-slate-200 shadow-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm font-semibold text-slate-900">New User</p>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="space-y-3">
          <Field label="Email *">
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="user@example.com"
              className={inputCls}
            />
          </Field>
          <Field label="Temporary password *">
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Min 8 chars, 1 upper, 1 lower, 1 digit"
              className={inputCls}
            />
          </Field>
          <Field label="Role *">
            <select value={role} onChange={e => setRole(e.target.value)} className={selectCls}>
              <option value="ADMIN">ADMIN</option>
              <option value="DEVELOPER">DEVELOPER</option>
              <option value="AUDITOR">AUDITOR</option>
              <option value="VIEWER">VIEWER</option>
            </select>
          </Field>
          {role !== "ADMIN" && (
            <Field label={role === "AUDITOR" ? "Department (optional)" : "Department *"}>
              <select value={deptId} onChange={e => setDeptId(e.target.value)} className={selectCls}>
                {role === "AUDITOR" && (
                  <option value="">Tenant-wide (all departments)</option>
                )}
                {depts.map(d => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            </Field>
          )}
        </div>
        {error && <p className="text-xs text-red-600 mt-3">{error}</p>}
        <p className="text-xs text-slate-400 mt-3">
          User will be required to change password on first login.
        </p>
        <div className="flex gap-3 mt-4">
          {isJwt
            ? <Button size="sm" onClick={handleCreate} loading={saving}>Create user</Button>
            : <Button size="sm" disabled>Create user</Button>
          }
          <button
            onClick={onClose}
            className="text-sm text-slate-500 hover:text-slate-700"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Edit user modal ────────────────────────────────────────────────────────────

function EditUserModal({
  user,
  depts,
  onClose,
  onSaved,
}: {
  user:    DashboardUser
  depts:   { id: string; name: string }[]
  onClose: () => void
  onSaved: () => void
}) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  const [role,     setRole]     = useState(user.role)
  // AUDITOR with null dept_id is tenant-wide: seed deptId="" so the
  // "Tenant-wide" option renders as selected rather than silently
  // switching them to the first dept on save.
  const [deptId,   setDeptId]   = useState(
    user.dept_id ?? (user.role === "AUDITOR" ? "" : (depts[0]?.id ?? ""))
  )
  const [saving,   setSaving]   = useState(false)
  const [error,    setError]    = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  const [confirmToggle, setConfirmToggle] = useState(false)
  const [toggling,      setToggling]      = useState(false)

  // Reset password state
  const [showReset,   setShowReset]   = useState(false)
  const [newPassword, setNewPassword] = useState("")
  const [resetting,   setResetting]   = useState(false)
  const [resetError,  setResetError]  = useState<string | null>(null)
  const [resetDone,   setResetDone]   = useState(false)

  // ADMIN forbids dept_id; AUDITOR treats it as optional (tenant-wide when
  // empty); DEVELOPER/VIEWER require it. Matches ck_users_dept_required_v2.
  const auditorTenantWide = role === "AUDITOR" && !deptId
  const nullifyDept       = role === "ADMIN" || auditorTenantWide

  const handleSave = async () => {
    setError(null)
    setSaving(true)
    try {
      await updateUser(user.id, {
        role:    role as any,
        dept_id: nullifyDept ? null : deptId,
      })
      onSaved()
      onClose()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleToggleActive = async () => {
    if (toggling) return
    setToggling(true)
    try {
      await updateUser(user.id, { is_active: !user.is_active })
      onSaved()
      onClose()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setToggling(false)
    }
  }

  const handleResetPassword = async () => {
    setResetError(null)
    setResetting(true)
    try {
      await resetUserPassword(user.id, newPassword)
      setResetDone(true)
      setNewPassword("")
    } catch (e: any) {
      setResetError(e.message)
    } finally {
      setResetting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-md bg-white rounded-xl border border-slate-200 shadow-xl p-6">
        <div className="flex items-start justify-between mb-4">
          <div>
            <p className="text-sm font-semibold text-slate-900">{user.email}</p>
            <p className="text-xs text-slate-400 mt-0.5">{user.tenant_id}</p>
          </div>
          <div className="flex items-center gap-2">
            <StatusBadge active={user.is_active} />
            <button
              onClick={onClose}
              className="ml-1 p-1 rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
            >
              <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        <div className="space-y-3">
          <Field label="Role">
            <select value={role} onChange={e => setRole(e.target.value as any)} className={selectCls}>
              <option value="ADMIN">ADMIN</option>
              <option value="DEVELOPER">DEVELOPER</option>
              <option value="AUDITOR">AUDITOR</option>
              <option value="VIEWER">VIEWER</option>
            </select>
          </Field>
          {role !== "ADMIN" && (
            <Field label={role === "AUDITOR" ? "Department (optional)" : "Department"}>
              <select value={deptId} onChange={e => setDeptId(e.target.value)} className={selectCls}>
                {role === "AUDITOR" && (
                  <option value="">Tenant-wide (all departments)</option>
                )}
                {depts.map(d => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            </Field>
          )}
        </div>

        {error && <p className="text-xs text-red-600 mt-3">{error}</p>}

        <div className="flex gap-2 mt-4">
          {isJwt
            ? <Button size="sm" onClick={handleSave} loading={saving}>Save</Button>
            : <Button size="sm" disabled>Save</Button>
          }
          <Button size="sm" variant="secondary" onClick={onClose}>Cancel</Button>
        </div>

        {/* Reset password section */}
        <div className="mt-3 pt-3 border-t border-slate-100">
          {!showReset && !resetDone && (
            <Button size="sm" variant="secondary" onClick={() => { setShowReset(true); setConfirmToggle(false) }}>
              Reset password
            </Button>
          )}
          {resetDone && (
            <p className="text-xs text-green-600">Password reset. User will be prompted to change it.</p>
          )}
        </div>

        {/* Reset password form */}
        {showReset && !resetDone && (
          <div className="mt-3 space-y-2">
            <Field label="New temporary password">
              <input
                type="password"
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                placeholder="Min 8 chars, 1 upper, 1 lower, 1 digit"
                className={inputCls}
              />
            </Field>
            {resetError && <p className="text-xs text-red-600">{resetError}</p>}
            <div className="flex gap-2">
              <Button size="sm" onClick={handleResetPassword} loading={resetting}>Reset</Button>
              <Button size="sm" variant="secondary" onClick={() => { setShowReset(false); setResetError(null) }}>Cancel</Button>
            </div>
          </div>
        )}

        {/* Deactivate / reactivate section */}
        <div className="pt-3 border-t border-slate-100">
          {!confirmToggle ? (
            <Button
              size="sm"
              variant={user.is_active ? "danger" : "secondary"}
              onClick={() => { setConfirmToggle(true); setShowReset(false); setResetError(null) }}
            >
              {user.is_active ? "Deactivate user" : "Reactivate user"}
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-600">
                {user.is_active ? "Deactivate" : "Reactivate"} this user?
              </span>
              <Button size="sm" variant="danger" onClick={handleToggleActive} loading={toggling}>Confirm</Button>
              <Button size="sm" variant="secondary" onClick={() => setConfirmToggle(false)}>Cancel</Button>
            </div>
          )}
        </div>




      </div>
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function UsersPage() {
  const [showCreate, setShowCreate] = useState(false)
  const [editing,    setEditing]    = useState<DashboardUser | null>(null)
  const [search,     setSearch]     = useState("")
  const { isJwt } = useAuthMode()

  const { data: usersData, isLoading, mutate, error: fetchError } = useSWR("users", () => getUsers())
  const { data: deptsData } = useSWR(swrKeys.departments, getDepartments)

  const depts = (deptsData?.departments ?? []).map(d => ({ id: d.id, name: d.name }))

  const formatDate = (iso: string | null) => {
    if (!iso) return "Never"
    return new Date(iso).toLocaleDateString("en-GB", {
      day: "2-digit", month: "short", year: "numeric",
    })
  }

  return (
    <Shell title="Users">
      <PageHeader
        description="Manage dashboard users and their access."
        actions={
          <Button size="sm" onClick={() => setShowCreate(true)} disabled={!isJwt} title={!isJwt ? "Requires admin login" : undefined}>
            <PlusIcon /> Add user
          </Button>
        }
      />
      <div className="space-y-4">

        <Card padding={false}>
          {/* Search bar */}
          <div className="px-5 py-3 border-b border-slate-100">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search users..."
              className="h-8 w-full max-w-xs px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
            />
          </div>
          {isLoading ? (
            <PageSpinner />
          ) : fetchError && !usersData ? (
            <div className="px-5 py-10 text-center">
              <p className="text-sm font-semibold text-red-600 mb-1">Failed to load users</p>
              <p className="text-xs text-slate-400">{fetchError?.message ?? "An unexpected error occurred"}</p>
            </div>
          ) : (
            <div style={{ overflowY: "auto", maxHeight: "520px" }}>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  {["Email", "Role", "Department", "Status", "Last Login", ""].map(h => (
                    <th key={h} className="text-left px-5 py-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(usersData?.users ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-5 py-14 text-center">
                      <div style={{ fontSize: "20px", marginBottom: "8px" }}></div>
                      <div className="text-sm font-semibold text-slate-700 mb-1">No users yet</div>
                      <div className="text-xs text-slate-400">Invite team members to give them dashboard access</div>
                    </td>
                  </tr>
                ) : (
                  (usersData?.users ?? [])
                    .filter((user) => {
                      if (!search) return true
                      const q = search.toLowerCase()
                      return (
                        user.email.toLowerCase().includes(q) ||
                        user.role.toLowerCase().includes(q)
                      )
                    })
                    .map(user => (
                    <tr
                      key={user.id}
                      className="border-b border-slate-50"
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#f9fafb"}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
                    >
                      <td className="px-5 py-3 font-medium text-slate-900">
                        {user.email}
                        {user.force_password_change && (
                          <span className="ml-2 text-xs text-amber-600">(change required)</span>
                        )}
                      </td>
                      <td className="px-5 py-3">
                        <RoleBadge role={user.role} />
                      </td>
                      <td className="px-5 py-3 text-xs text-slate-500">
                        {depts.find(d => d.id === user.dept_id)?.name ?? (user.dept_id ? user.dept_id.slice(0, 8) + "" : "-")}
                      </td>
                      <td className="px-5 py-3">
                        <StatusBadge active={user.is_active} />
                      </td>
                      <td className="px-5 py-3 text-xs text-slate-500">
                        {formatDate(user.last_login_at)}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          onClick={() => setEditing(user)}
                          style={{ fontSize: "12px", color: "#1d4ed8", background: "none", border: "none", cursor: "pointer", padding: 0 }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.textDecoration = "underline"}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.textDecoration = "none"}
                        >
                          Manage
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
            </div>
          )}
        </Card>
      </div>

      {showCreate && depts.length > 0 && (
        <CreateUserModal
          depts={depts}
          onClose={() => setShowCreate(false)}
          onCreated={() => mutate()}
        />
      )}

      {editing && (
        <EditUserModal
          user={editing}
          depts={depts}
          onClose={() => setEditing(null)}
          onSaved={() => mutate()}
        />
      )}
    </Shell>
  )
}
