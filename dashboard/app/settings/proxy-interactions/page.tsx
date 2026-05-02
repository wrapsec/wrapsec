// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import React, { useState } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { PageSpinner } from "@/components/ui/Spinner"
import { Button } from "@/components/ui/Button"
import { getProxyInteractions } from "@/lib/api"
import { ProxyInteraction, Decision, ExecutionStatus } from "@/lib/types"
import { DecisionBadge } from "@/components/ui/Badge"

function StatusBadge({ status }: { status: ExecutionStatus }) {
  const STYLES: Record<string, React.CSSProperties> = {
    SUCCESS:        { background: "rgba(0,225,255,0.10)", color: "#0369a1",  border: "1px solid rgba(0,225,255,0.35)" },
    BLOCKED:        { background: "#fef2f2",              color: "#b91c1c",  border: "1px solid #fecaca" },
    OUTPUT_BLOCKED: { background: "#fff7ed",              color: "#92400e",  border: "1px solid #fed7aa" },
    FAILED:         { background: "#fef2f2",              color: "#b91c1c",  border: "1px solid #fecaca" },
    TIMEOUT:        { background: "#fffbeb",              color: "#92400e",  border: "1px solid #fde68a" },
  }
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 7px", borderRadius: "4px",
      fontSize: "11px", fontWeight: 600, whiteSpace: "nowrap" as const,
      ...(STYLES[status] ?? { background: "#f9fafb", color: "#9ca3af", border: "1px solid #e5e7eb" }),
    }}>
      {status.replace(/_/g, " ")}
    </span>
  )
}

const PAGE_SIZE = 20

// Decision badge colours
function decisionClass(d: Decision | null): string {
  if (d === "BLOCK")    return ""
  if (d === "SANITIZE") return ""
  if (d === "ALLOW")    return ""
  return ""
}

function decisionStyle(d: Decision | null): React.CSSProperties {
  if (d === "BLOCK")    return { background: "#fef2f2", color: "#dc2626", border: "1px solid #fecaca" }
  if (d === "SANITIZE") return { background: "#fffbeb", color: "#d97706", border: "1px solid #fde68a" }
  if (d === "ALLOW")    return { background: "#f0fdf4", color: "#16a34a", border: "1px solid #bbf7d0" }
  return { background: "#f9fafb", color: "#9ca3af", border: "1px solid #e5e7eb" }
}

// Execution status badge colours
function statusClass(s: ExecutionStatus): string { return "" }

function statusStyle(s: ExecutionStatus): React.CSSProperties {
  if (s === "SUCCESS")        return { background: "#f0fdf4", color: "#16a34a", border: "1px solid #bbf7d0" }
  if (s === "BLOCKED")        return { background: "#fef2f2", color: "#dc2626", border: "1px solid #fecaca" }
  if (s === "OUTPUT_BLOCKED") return { background: "#fff7ed", color: "#ea580c", border: "1px solid #fed7aa" }
  if (s === "FAILED")         return { background: "#fef2f2", color: "#dc2626", border: "1px solid #fecaca" }
  if (s === "TIMEOUT")        return { background: "#fffbeb", color: "#d97706", border: "1px solid #fde68a" }
  return { background: "#f9fafb", color: "#9ca3af", border: "1px solid #e5e7eb" }
}

function Badge({ label, style }: { label: string; style?: React.CSSProperties }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 8px", borderRadius: "4px",
      fontSize: "11px", fontWeight: 600, whiteSpace: "nowrap" as const,
      ...style,
    }}>
      {label}
    </span>
  )
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month:   "short",
    day:     "numeric",
    hour:    "2-digit",
    minute:  "2-digit",
    second:  "2-digit",
  })
}

const STATUS_OPTIONS = [
  { value: "",               label: "All statuses" },
  { value: "SUCCESS",        label: "Success" },
  { value: "BLOCKED",        label: "Blocked" },
  { value: "OUTPUT_BLOCKED", label: "Output blocked" },
  { value: "FAILED",         label: "Failed" },
  { value: "TIMEOUT",        label: "Timeout" },
]

export default function ProxyInteractionsPage() {
  const [offset,          setOffset]          = useState(0)
  const [statusFilter,    setStatusFilter]    = useState("")
  const [selectedTrace,   setSelectedTrace]   = useState<string | null>(null)

  const { data, isLoading, error } = useSWR(
    ["proxy-interactions", offset, statusFilter],
    () => getProxyInteractions({
      limit:             PAGE_SIZE,
      offset,
      execution_status:  statusFilter || undefined,
    }),
    { keepPreviousData: true }
  )

  const total = data?.total ?? 0
  const items = data?.items ?? []

  return (
    <Shell title="Proxy Interactions">
      <div className="space-y-4">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              AI Interaction Firewall -- Proxy Log
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Every request through POST /v1/chat/completions is logged here
              with full input and output security decisions.
            </p>
          </div>
          <a
            href="/settings"
style={{ fontSize: "12px", color: "#670FEF", textDecoration: "none", fontWeight: 500 }}
          >
            Back to settings
          </a>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setOffset(0) }}
style={{ height: "32px", padding: "0 10px", fontSize: "12px", borderRadius: "6px", border: "1px solid #e5e7eb", background: "#fff", color: "#374151", outline: "none" }}
          >
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <span className="text-xs text-slate-400">{total} total</span>
        </div>

        {/* Table */}
        <Card padding={false}>
          {isLoading && <div className="p-6"><PageSpinner /></div>}
          {error    && <p className="p-5 text-xs text-red-600">Failed to load interactions.</p>}
          {!isLoading && !error && items.length === 0 && (
            <p className="p-5 text-xs text-slate-400">
              No proxy interactions yet. Send a request to POST /v1/chat/completions to get started.
            </p>
          )}
          {!isLoading && items.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Time</th>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Trace ID</th>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Input</th>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Output</th>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Status</th>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Provider</th>
                    <th style={{ textAlign: "left", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Model</th>
                    <th style={{ textAlign: "right", padding: "10px 16px", fontSize: "10px", fontWeight: 700, color: "#9ca3af", textTransform: "uppercase" as const, letterSpacing: "0.07em", whiteSpace: "nowrap" as const, borderBottom: "1px solid #f3f4f6", background: "#fafafa" }}>Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {items.map((item: ProxyInteraction) => (
                    <tr
                      key={item.trace_id}
                      onClick={() => setSelectedTrace(
                        selectedTrace === item.trace_id ? null : item.trace_id
                      )}
                      style={{ cursor: "pointer", transition: "background 0.1s" }}
                      onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "rgba(103,15,239,0.03)"}
                      onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
                    >
                      <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                        {formatTime(item.created_at)}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">
                        {item.trace_id.slice(0, 20)}...
                      </td>
                      <td className="px-4 py-3">
                        {item.input_decision && <DecisionBadge decision={item.input_decision} size="sm" />}
                        {item.input_attack_type && (
                          <span className="ml-1.5 text-slate-400">
                            {item.input_attack_type}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {item.output_decision
                          ? <DecisionBadge decision={item.output_decision} />
                          : <span className="text-slate-300">--</span>
                        }
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={item.execution_status} />
                      </td>
                      <td className="px-4 py-3 text-slate-600">
                        {item.provider ?? "--"}
                      </td>
                      <td className="px-4 py-3 text-slate-600">
                        {item.model ?? "--"}
                      </td>
                      <td className="px-4 py-3 text-right text-slate-500">
                        {item.total_latency_ms}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Pagination */}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">
              Showing {offset + 1} – {Math.min(offset + PAGE_SIZE, total)} of {total}
            </span>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                size="sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                Previous
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next
              </Button>
            </div>
          </div>
        )}

      </div>
    </Shell>
  )
}
