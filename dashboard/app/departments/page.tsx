// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, Fragment } from "react"
import { useTranslations } from "next-intl"
import { swrKeys } from "@/lib/swrKeys"
import { useAuthMode } from "@/hooks/useAuthMode"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card } from "@/components/ui/Card"
import { Button, PlusIcon } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import { getDepartments, createDepartment, deleteDepartment } from "@/lib/api"
import Link from "next/link"
import { slugify } from "@/lib/utils"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { NameSlug, PolicyBadge } from "@/components/admin/ListCells"

export default function DepartmentsPage() {
  const t  = useTranslations("pages.departments")
  const tf = useTranslations("forms.department")
  const tc = useTranslations("common")
  const { resolve, fieldErrors } = useErrorMessage()

  const [showCreate,        setShowCreate]        = useState(false)
  const [name,              setName]              = useState("")
  const [slug,              setSlug]              = useState("")
  const [slugEdited,        setSlugEdited]        = useState(false)
  const [description,       setDescription]       = useState("")
  const [contact,           setContact]           = useState("")
  const [saving,            setSaving]            = useState(false)
  const [error,             setError]             = useState<string | null>(null)
  const [search,            setSearch]            = useState("")
  const [confirmDeactivate, setConfirmDeactivate] = useState<string | null>(null)
  const { isJwt } = useAuthMode()

  const { data, isLoading, mutate, error: fetchError } = useSWR(swrKeys.departments, getDepartments)

  // Map a machine field name to its localized label for 422 field errors.
  const labelFor = (field: string) => (tf.has(field) ? tf(field) : field)

  const toMessage = (e: unknown): string => {
    const fe = Object.values(fieldErrors(e, labelFor))
    return fe.length ? fe.join(" ") : resolve(e).message
  }

  const handleCreate = async () => {
    if (!name || !slug) return
    setSaving(true)
    setError(null)
    try {
      await createDepartment({ name, slug, description, contact_email: contact })
      setShowCreate(false)
      setName(""); setSlug(""); setSlugEdited(false); setDescription(""); setContact("")
      mutate()
    } catch (e) {
      setError(toMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const handleDeactivate = async (id: string) => {
    setConfirmDeactivate(null)
    try {
      await deleteDepartment(id)
      mutate()
    } catch (e) {
      setError(toMessage(e))
    }
  }

  const cols = [
    { label: t("table.name"),    align: "left"  as const },
    { label: t("table.apps"),    align: "right" as const },
    { label: t("table.contact"), align: "left"  as const },
    { label: t("table.policy"),  align: "left"  as const },
    { label: "",                 align: "left"  as const },
  ]

  return (
    <Shell title={t("title")}>
      <PageHeader
        description={t("description")}
        actions={
          isJwt ? (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <PlusIcon /> {t("add")}
            </Button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Button size="sm" disabled><PlusIcon /> {t("add")}</Button>
              <span style={{ fontSize: "11px", color: "#9ca3af" }}>
                {tc.rich("requires_admin", {
                  link: (chunks) => <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>{chunks}</a>,
                })}
              </span>
            </div>
          )
        }
      />
      <div className="space-y-4">

        {/* Create form */}
        {showCreate && (
          <Card>
            <p className="text-sm font-semibold text-slate-900 mb-4">{t("new_title")}</p>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">{tf("name")} *</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value)
                    if (!slugEdited) setSlug(slugify(e.target.value))
                  }}
                  placeholder={tf("name_placeholder")}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">{tf("slug")} *</label>
                <input
                  type="text"
                  value={slug}
                  onChange={(e) => { setSlugEdited(true); setSlug(e.target.value.toLowerCase().replace(/\s+/g, "-")) }}
                  placeholder={tf("slug_placeholder")}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
                <span className="text-[11px] text-slate-400">{tf("slug_hint")}</span>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">{tf("description")}</label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder={tf("description_placeholder")}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs font-medium text-slate-700">{tf("contact_email")}</label>
                <input
                  type="email"
                  value={contact}
                  onChange={(e) => setContact(e.target.value)}
                  placeholder={tf("contact_placeholder")}
                  className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
                />
              </div>
            </div>
            {error && <p className="text-xs text-red-600 mt-3">{error}</p>}
            <div className="flex gap-3 mt-4">
              {isJwt
                ? <Button size="sm" onClick={handleCreate} loading={saving}>{tc("buttons.create")}</Button>
                : <Button size="sm" disabled>{tc("buttons.create")}</Button>
              }
              <Button size="sm" variant="secondary" onClick={() => { setShowCreate(false); setError(null) }}>{tc("buttons.cancel")}</Button>
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
              placeholder={t("search_placeholder")}
              className="h-8 w-full max-w-xs px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
            />
          </div>
          {!showCreate && error && <p className="px-5 pb-2 text-xs text-red-600">{error}</p>}
          {isLoading ? (
            <PageSpinner />
          ) : fetchError && !data ? (
            <div className="px-5 py-10 text-center">
              <p className="text-sm font-semibold text-red-600 mb-1">{t("load_error")}</p>
              <p className="text-xs text-slate-400">{resolve(fetchError).message}</p>
            </div>
          ) : (
            <div style={{ overflowY: "auto", maxHeight: "520px" }}>
              <Table>
                <THead>
                  <tr>
                    {cols.map((c, i) => (
                      <Th key={i} align={c.align}>{c.label}</Th>
                    ))}
                  </tr>
                </THead>
                <TBody>
                  {(data?.departments ?? []).length === 0 ? (
                    <tr>
                      <Td colSpan={5}>
                        <div className="px-5 py-14 text-center">
                          <div className="text-sm font-semibold text-slate-700 mb-1">{t("empty_title")}</div>
                          <div className="text-xs text-slate-400">{t("empty_body")}</div>
                        </div>
                      </Td>
                    </tr>
                  ) : (
                    (data?.departments ?? [])
                      .filter((dept) => {
                        if (!search) return true
                        const q = search.toLowerCase()
                        return dept.name.toLowerCase().includes(q) || dept.slug.toLowerCase().includes(q)
                      })
                      .map((dept) => (
                      <Fragment key={dept.id}>
                        <Tr hover>
                          <Td><NameSlug name={dept.name} slug={dept.slug} /></Td>
                          <Td align="right" className="text-sm text-slate-700 tabular-nums">{dept.application_count ?? 0}</Td>
                          <Td className="text-xs text-slate-500">{dept.contact_email || "-"}</Td>
                          <Td><PolicyBadge overridden={!!dept.policy_override} inheritsLabel={t("inherits")} /></Td>
                          <Td align="right">
                            <div className="flex items-center justify-end gap-3">
                              <Link href={`/departments/${dept.id}`} className="text-xs text-blue-700 hover:underline">{tc("buttons.manage")}</Link>
                              {isJwt && dept.slug !== "default" && (
                                <button
                                  onClick={() => setConfirmDeactivate(confirmDeactivate === dept.id ? null : dept.id)}
                                  className="text-xs text-red-600 hover:underline cursor-pointer"
                                >
                                  {tc("buttons.deactivate")}
                                </button>
                              )}
                            </div>
                          </Td>
                        </Tr>
                        {confirmDeactivate === dept.id && (
                          <tr className="bg-red-50">
                            <Td colSpan={5}>
                              <div className="flex items-center gap-3">
                                <p className="text-xs text-red-700 whitespace-nowrap">
                                  {t("deactivate_warning")}
                                </p>
                                <button
                                  onClick={() => handleDeactivate(dept.id)}
                                  className="text-xs font-medium text-white bg-red-600 hover:bg-red-700 px-3 py-1 rounded whitespace-nowrap cursor-pointer"
                                >
                                  {tc("buttons.confirm_deactivate")}
                                </button>
                                <button
                                  onClick={() => setConfirmDeactivate(null)}
                                  className="text-xs text-slate-500 hover:text-slate-700 cursor-pointer"
                                >
                                  {tc("buttons.cancel")}
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
