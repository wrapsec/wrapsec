// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { Suspense } from "react"
import { useTranslations } from "next-intl"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState } from "@/components/ui/ErrorState"
import { PageSpinner } from "@/components/ui/Spinner"
import { useListParams } from "@/hooks/useListParams"
import { useDrawerParam } from "@/hooks/useDrawerParam"
import { useFormat } from "@/hooks/useFormat"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import { swrKeys } from "@/lib/swrKeys"
import { PAGE_SIZE } from "@/lib/constants"
import {
  getEmailDeliveries,
  getEmailSummary,
  getEmailDelivery,
  getDepartments,
} from "@/lib/api"
import type { EmailDelivery } from "@/lib/types"

// The URL is the single source of truth for filters + pagination (deep-linkable,
// refresh-safe). Only non-sensitive navigation state lives here.
const LIST_SPEC = {
  status:    { default: "" },
  type:      { default: "" },
  dept_id:   { default: "" },
  recipient: { default: "", debounce: 400 },
  from:      { default: "" },
  to:        { default: "" },
  offset:    { default: "0" },
} as const

const STATUSES = ["queued", "sending", "provider_accepted", "failed"] as const
// Implemented notification types (dotted <namespace>.<event>); reserved types
// never appear in delivery rows, so the filter only offers these.
const TYPES = ["password.changed", "password.reset_by_admin", "account.locked"] as const

const STATUS_BADGE: Record<string, string> = {
  queued:            "bg-slate-100 text-slate-600 border-slate-200",
  sending:           "bg-blue-50 text-blue-700 border-blue-200",
  provider_accepted: "bg-green-50 text-green-700 border-green-200",
  failed:            "bg-red-50 text-red-700 border-red-200",
}

// Recipient addresses are masked in the dashboard display (the API returns them
// in full to the authorized admin/auditor; masking is a UI courtesy).
function maskEmail(email: string): string {
  const at = email.indexOf("@")
  if (at < 1) return email
  const local  = email.slice(0, at)
  const domain = email.slice(at + 1)
  const shown  = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2)
  return `${shown}***@${domain}`
}

function EmailDeliveryInner() {
  const t   = useTranslations("pages.email_delivery")
  const fmt = useFormat()
  const { resolve } = useErrorMessage()
  // Dotted type value maps to a nested label key; fall back to the raw value for
  // any type without a label (e.g. a future/reserved one).
  const typeLabel = (v: string) => (t.has(`type.${v}`) ? t(`type.${v}`) : v)
  const { values, setParam, setParams, textValue, onTextChange } = useListParams(LIST_SPEC)
  const { openId: selectedId, open, close } = useDrawerParam("peek")

  const offset = parseInt(values.offset, 10) || 0
  const from   = values.from
  const to     = values.to
  const withStart = (v: string) => (v.includes("T") ? v : `${v}T00:00:00`)
  const withEnd   = (v: string) => (v.includes("T") ? v : `${v}T23:59:59`)
  const validRange = !from || !to || from <= to

  // Any filter change resets pagination.
  const setFilter = (patch: Record<string, string>) => setParams({ ...patch, offset: "0" })

  const { data: deptsData } = useSWR(swrKeys.departments, getDepartments)
  const departments = deptsData?.departments ?? []
  const deptName = (id: string | null) =>
    (id && departments.find(d => d.id === id)?.name) || t("detail.none")

  const query = {
    status:            values.status || undefined,
    notification_type: values.type || undefined,
    department_id:     values.dept_id || undefined,
    recipient:         values.recipient || undefined,
    from:              from && validRange ? withStart(from) : undefined,
    to:                to && validRange ? withEnd(to) : undefined,
  }

  const { data: summary } = useSWR(
    ["email-summary", query.status, query.notification_type, query.department_id, query.recipient, query.from, query.to],
    () => getEmailSummary(query),
    { refreshInterval: 30000 },
  )

  const { data, isLoading, error } = useSWR(
    ["email-deliveries", query.status, query.notification_type, query.department_id, query.recipient, query.from, query.to, offset],
    () => getEmailDeliveries({ ...query, limit: PAGE_SIZE, offset }),
    { refreshInterval: 30000 },
  )

  const rows = data?.emails ?? []
  const counts = summary?.counts ?? {}

  return (
    <Shell title={t("title")}>
      <PageHeader description={t("description")} />

      <div className="flex flex-col gap-4">
        {/* Summary strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {STATUSES.map(s => (
            <div key={s} className="bg-white border border-slate-200 rounded-lg px-4 py-3">
              <p className="text-xs text-slate-500">{t(`summary.${s}`)}</p>
              <p className="text-xl font-semibold text-slate-900">{fmt.number(counts[s] ?? 0)}</p>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-end gap-3 bg-white border border-slate-200 rounded-lg p-3">
          <Field label={t("filters.status")}>
            <Select value={values.status} onChange={v => setFilter({ status: v })}>
              <option value="">{t("filters.all_statuses")}</option>
              {STATUSES.map(s => <option key={s} value={s}>{t(`status.${s}`)}</option>)}
            </Select>
          </Field>
          <Field label={t("filters.type")}>
            <Select value={values.type} onChange={v => setFilter({ type: v })}>
              <option value="">{t("filters.all_types")}</option>
              {TYPES.map(ty => <option key={ty} value={ty}>{typeLabel(ty)}</option>)}
            </Select>
          </Field>
          <Field label={t("columns.department")}>
            <Select value={values.dept_id} onChange={v => setFilter({ dept_id: v })}>
              <option value="">{t("detail.none")}</option>
              {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
            </Select>
          </Field>
          <Field label={t("filters.recipient")}>
            <input
              value={textValue("recipient")}
              onChange={e => onTextChange("recipient", e.target.value, { offset: "0" })}
              placeholder={t("filters.recipient_placeholder")}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700"
            />
          </Field>
          <Field label={t("filters.from")}>
            <input type="date" value={from.slice(0, 10)} onChange={e => setFilter({ from: e.target.value })}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900" />
          </Field>
          <Field label={t("filters.to")}>
            <input type="date" value={to.slice(0, 10)} onChange={e => setFilter({ to: e.target.value })}
              className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900" />
          </Field>
          <button
            onClick={() => setParams({ status: "", type: "", dept_id: "", recipient: "", from: "", to: "", offset: "0" })}
            className="h-9 px-3 text-sm text-slate-500 hover:text-slate-900"
          >
            {t("filters.clear")}
          </button>
        </div>

        {/* Table */}
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          {isLoading && !data ? (
            <PageSpinner />
          ) : error ? (
            <ErrorState title={t("load_error")} message={resolve(error).message} severity={resolve(error).severity} />
          ) : rows.length === 0 ? (
            <p className="text-sm text-slate-500 text-center py-10">{t("empty")}</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-100">
                  <th className="px-4 py-2 font-medium">{t("columns.time")}</th>
                  <th className="px-4 py-2 font-medium">{t("columns.notification")}</th>
                  <th className="px-4 py-2 font-medium">{t("columns.recipient")}</th>
                  <th className="px-4 py-2 font-medium">{t("columns.department")}</th>
                  <th className="px-4 py-2 font-medium">{t("columns.status")}</th>
                  <th className="px-4 py-2 font-medium text-right">{t("columns.attempts")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(r => (
                  <tr
                    key={r.id}
                    onClick={() => open(r.id)}
                    className="border-b border-slate-50 hover:bg-slate-50 cursor-pointer"
                  >
                    <td className="px-4 py-2 text-slate-600 whitespace-nowrap">{r.created_at ? fmt.timestamp(r.created_at) : "-"}</td>
                    <td className="px-4 py-2 text-slate-900">{typeLabel(r.notification_type)}</td>
                    <td className="px-4 py-2 text-slate-600 font-mono text-xs">{maskEmail(r.recipient)}</td>
                    <td className="px-4 py-2 text-slate-600">{deptName(r.department_id)}</td>
                    <td className="px-4 py-2"><StatusBadge status={r.status} label={t(`status.${r.status}`)} /></td>
                    <td className="px-4 py-2 text-right text-slate-600">{r.attempt_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {rows.length > 0 && (
            <div className="flex items-center justify-between px-4 py-2 border-t border-slate-100 text-xs text-slate-500">
              <button disabled={offset === 0} onClick={() => setParam("offset", String(Math.max(0, offset - PAGE_SIZE)))}
                className="disabled:opacity-40 hover:text-slate-900">{"<"}</button>
              <span>{offset + 1}-{offset + rows.length}</span>
              <button disabled={rows.length < PAGE_SIZE} onClick={() => setParam("offset", String(offset + PAGE_SIZE))}
                className="disabled:opacity-40 hover:text-slate-900">{">"}</button>
            </div>
          )}
        </div>
      </div>

      {selectedId && <DetailDrawer id={selectedId} deptName={deptName} onClose={close} />}
    </Shell>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium text-slate-500">{label}</label>
      {children}
    </div>
  )
}

function Select({ value, onChange, children }: { value: string; onChange: (v: string) => void; children: React.ReactNode }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-purple-700">
      {children}
    </select>
  )
}

function StatusBadge({ status, label }: { status: string; label: string }) {
  const cls = STATUS_BADGE[status] ?? "bg-slate-100 text-slate-600 border-slate-200"
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>{label}</span>
}

function DetailDrawer({ id, deptName, onClose }: {
  id: string
  deptName: (id: string | null) => string
  onClose: () => void
}) {
  const t   = useTranslations("pages.email_delivery")
  const fmt = useFormat()
  const { data: row, isLoading } = useSWR(["email-delivery", id], () => getEmailDelivery(id))

  const line = (label: string, value: React.ReactNode) => (
    <div className="flex flex-col gap-0.5 py-2 border-b border-slate-50">
      <span className="text-xs text-slate-400">{label}</span>
      <span className="text-sm text-slate-800 break-all">{value ?? t("detail.none")}</span>
    </div>
  )

  return (
    <div className="fixed inset-0 z-40 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/20" />
      <div className="relative w-full max-w-md h-full bg-white shadow-xl overflow-y-auto p-5" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-900">{t("detail.title")}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-900">&times;</button>
        </div>
        {isLoading || !row ? (
          <PageSpinner />
        ) : (
          <div>
            {line(t("detail.status"), <StatusBadge status={row.status} label={t(`status.${row.status}`)} />)}
            {line(t("detail.notification"), t.has(`type.${row.notification_type}`) ? t(`type.${row.notification_type}`) : row.notification_type)}
            {line(t("detail.recipient"), <span className="font-mono text-xs">{maskEmail(row.recipient)}</span>)}
            {line(t("detail.department"), deptName(row.department_id))}
            {line(t("detail.locale"), row.locale ?? t("detail.none"))}
            {line(t("detail.attempts"), row.attempt_count)}
            {line(t("detail.created"), row.created_at ? fmt.timestamp(row.created_at) : t("detail.none"))}
            {line(t("detail.last_attempt"), row.last_attempt_at ? fmt.timestamp(row.last_attempt_at) : t("detail.none"))}
            {line(t("detail.completed"), row.completed_at ? fmt.timestamp(row.completed_at) : t("detail.none"))}
            {line(t("detail.provider_message_id"), <span className="font-mono text-xs">{row.provider_message_id ?? t("detail.none")}</span>)}
            {line(t("detail.trace_id"), <span className="font-mono text-xs">{row.trace_id ?? t("detail.none")}</span>)}
            {line(t("detail.last_error"), row.last_error ?? t("detail.none"))}
          </div>
        )}
      </div>
    </div>
  )
}

export default function EmailDeliveryPage() {
  return <Suspense><EmailDeliveryInner /></Suspense>
}
