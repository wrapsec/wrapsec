// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { Suspense, useState } from "react"
import { useTranslations } from "next-intl"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import { errorMessage } from "@/lib/apiError"
import { swrKeys } from "@/lib/swrKeys"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { ErrorState } from "@/components/ui/ErrorState"
import { RequestFilters } from "@/components/requests/RequestFilters"
import { RequestsTable } from "@/components/requests/RequestsTable"
import { SecurityOverview } from "@/components/requests/SecurityOverview"
import { Pagination } from "@/components/requests/Pagination"
import { PageSpinner } from "@/components/ui/Spinner"
import { RequestDetailModal } from "@/components/requests/RequestDetail"
import { useListParams } from "@/hooks/useListParams"
import { useDrawerParam } from "@/hooks/useDrawerParam"
import { PAGE_SIZE } from "@/lib/constants"
import { getAuditLogs, getAuditStats, exportAuditLogs, getDepartments } from "@/lib/api"

// The URL is the single source of truth for the list view: filters, sort, and
// pagination all live here, so Back / refresh / deep-links restore the exact
// page. Only non-sensitive navigation state -- opaque trace_id and filters.
const LIST_SPEC = {
  trace_id:   { default: "",           debounce: 400 },
  decision:   { default: "" },
  threat:     { default: "" },
  mode:       { default: "" },
  dept_id:    { default: "" },
  from:       { default: "" },
  to:         { default: "" },
  sort_by:    { default: "created_at" },
  sort_order: { default: "desc" },
  offset:     { default: "0" },
} as const

function RequestsPageInner() {
  const t = useTranslations("pages.requests")
  const { resolve } = useErrorMessage()
  const { values, setParams, textValue, onTextChange } = useListParams(LIST_SPEC)
  const { openId: selectedId, open, close } = useDrawerParam("peek")

  const decision   = values.decision
  const threat     = values.threat
  const mode       = values.mode
  const deptId     = values.dept_id
  const from       = values.from
  const to         = values.to
  const sortBy     = values.sort_by
  const sortOrder  = values.sort_order as "asc" | "desc"
  const offset     = parseInt(values.offset, 10) || 0

  const isValidDateRange = !from || !to || from <= to
  const withStart = (v: string) => (v.includes("T") ? v : `${v}T00:00:00`)
  const withEnd   = (v: string) => (v.includes("T") ? v : `${v}T23:59:59`)

  // Any filter change resets pagination to the first page.
  const setFilter = (patch: Record<string, string>) => setParams({ ...patch, offset: "0" })

  const { data: deptsData } = useSWR(swrKeys.departments, getDepartments)
  const departments = (deptsData?.departments ?? []).map(d => ({ id: d.id, name: d.name }))

  const { data, isLoading, error: fetchError } = useSWR(
    ["audit-logs", values.trace_id, decision, threat, mode, deptId, from, to, sortBy, sortOrder, offset],
    () => getAuditLogs({
      trace_id:        values.trace_id || undefined,
      decision:        (decision as any) || undefined,
      threat_category: (threat as any) || undefined,
      execution_mode:  (mode as any) || undefined,
      dept_id:         deptId || undefined,
      from:            from && isValidDateRange ? withStart(from) : undefined,
      to:              to && isValidDateRange ? withEnd(to) : undefined,
      sort_by:         sortBy,
      sort_order:      sortOrder,
      limit:           PAGE_SIZE,
      offset,
    }),
    { refreshInterval: 30000 },
  )

  // Posture strip, scoped to the SAME filters as the table so its counts match
  // the rows below. dept_id is honored for admins and ignored (scope-pinned)
  // for dept-scoped keys, server-side.
  const { data: stats, isLoading: statsLoading } = useSWR(
    ["requests-stats", values.trace_id, decision, threat, mode, deptId, from, to],
    () => getAuditStats({
      trace_id:        values.trace_id || undefined,
      decision:        decision || undefined,
      threat_category: threat || undefined,
      execution_mode:  mode || undefined,
      dept_id:         deptId || undefined,
      from:            from && isValidDateRange ? withStart(from) : undefined,
      to:              to && isValidDateRange ? withEnd(to) : undefined,
    }),
    { refreshInterval: 30000 },
  )

  const [exporting, setExporting] = useState<{ loading: boolean; error: string | null }>({ loading: false, error: null })

  const handleExport = async () => {
    setExporting({ loading: true, error: null })
    try {
      const blob = await exportAuditLogs({
        decision:        decision || undefined,
        threat_category: threat || undefined,
        from:            from && isValidDateRange ? withStart(from) : undefined,
        to:              to && isValidDateRange ? withEnd(to) : undefined,
      })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement("a")
      a.href     = url
      a.download = `wrapsec_audit_${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: unknown) {
      setExporting({ loading: false, error: errorMessage(e) || t("export_error") })
      return
    }
    setExporting({ loading: false, error: null })
  }

  const actions = (
    <>
      {exporting.error && (
        <span style={{ fontSize: "11px", color: "#dc2626", maxWidth: 180 }}>{exporting.error}</span>
      )}
      <button
        onClick={handleExport}
        disabled={exporting.loading}
        style={{
          display: "inline-flex", alignItems: "center", gap: "6px", padding: "6px 14px",
          fontSize: "12px", fontWeight: 500, fontFamily: "inherit", borderRadius: "6px",
          border: "1px solid var(--ws-violet, #670FEF)", background: "transparent",
          color: "var(--ws-violet, #670FEF)", cursor: exporting.loading ? "not-allowed" : "pointer",
          opacity: exporting.loading ? 0.6 : 1, whiteSpace: "nowrap", height: "32px",
        }}
      >
        <svg style={{ width: 13, height: 13 }} fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
        </svg>
        {exporting.loading ? t("exporting") : t("export_csv")}
      </button>
    </>
  )

  return (
    <Shell title={t("title")}>
      <PageHeader
        description={t("description")}
        actions={actions}
      />

      <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
        <RequestFilters
          traceId={textValue("trace_id")} decision={decision}
          threatCategory={threat}         executionMode={mode}
          deptId={deptId}                 departments={departments}
          from={from.slice(0, 10)}        to={to.slice(0, 10)}
          sortBy={sortBy}                 sortOrder={sortOrder}
          onTraceId={v      => onTextChange("trace_id", v, { offset: "0" })}
          onDecision={v     => setFilter({ decision: v })}
          onThreat={v       => setFilter({ threat: v })}
          onExecutionMode={v => setFilter({ mode: v })}
          onDeptId={v       => setFilter({ dept_id: v })}
          onFrom={v         => setFilter({ from: v })}
          onTo={v           => setFilter({ to: v })}
          onSortBy={v       => setFilter({ sort_by: v })}
          onSortOrder={v    => setFilter({ sort_order: v })}
          onClearDates={() => setParams({ from: "", to: "", offset: "0" })}
          onClearAll={() => setParams({
            decision: "", threat: "", mode: "", dept_id: "", from: "", to: "", offset: "0",
          })}
        />

        <SecurityOverview stats={stats} loading={statsLoading} />

        <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: "8px", overflow: "hidden" }}>
          {isLoading && !data ? (
            <PageSpinner />
          ) : fetchError ? (
            <ErrorState
              title={t("load_error")}
              message={resolve(fetchError).message}
              severity={resolve(fetchError).severity}
            />
          ) : (
            <>
              <RequestsTable items={data?.items ?? []} onSelect={open} />
              <Pagination
                total={data?.total ?? 0}
                offset={offset}
                limit={PAGE_SIZE}
                onChange={n => setParams({ offset: String(n) })}
              />
            </>
          )}
        </div>
      </div>

      {selectedId && (
        <RequestDetailModal traceId={selectedId} onClose={close} />
      )}
    </Shell>
  )
}

export default function RequestsPage() {
  return <Suspense><RequestsPageInner /></Suspense>
}
