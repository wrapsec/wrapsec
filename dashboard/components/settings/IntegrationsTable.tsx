// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { WebhookEndpoint } from "@/lib/types"

const CONNECTOR_LABEL: Record<string, string> = {
  splunk_hec:               "Splunk HEC",
  datadog_logs:             "Datadog Logs",
  sentinel_logs_ingestion:  "Microsoft Sentinel",
  elastic_ecs:              "Elastic (ECS)",
}

function typeLabel(t: string | null): string {
  return t ? (CONNECTOR_LABEL[t] ?? t) : "Generic webhook"
}

const STATUS_STYLE: Record<string, { bg: string; fg: string; bd: string; label: string }> = {
  active:        { bg: "#f0fdf4", fg: "#15803d", bd: "#bbf7d0", label: "Active" },
  failing:       { bg: "#fffbeb", fg: "#b45309", bd: "#fde68a", label: "Failing" },
  auto_disabled: { bg: "#fef2f2", fg: "#b91c1c", bd: "#fecaca", label: "Disabled" },
}

function StatusChip({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? { bg: "#f3f4f6", fg: "#374151", bd: "#e5e7eb", label: status }
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "5px",
      padding: "3px 9px", fontSize: "11px", fontWeight: 600, borderRadius: "5px",
      background: s.bg, color: s.fg, border: `1px solid ${s.bd}`,
    }}>
      <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "currentColor" }} />
      {s.label}
    </span>
  )
}

interface Props {
  endpoints:  WebhookEndpoint[]
  canWrite:   boolean
  testingId:  string | null
  deletingId: string | null
  onTest:     (ep: WebhookEndpoint) => void
  onDelete:   (ep: WebhookEndpoint) => void
}

export function IntegrationsTable({ endpoints, canWrite, testingId, deletingId, onTest, onDelete }: Props) {
  if (endpoints.length === 0) {
    return (
      <div className="text-center py-12 text-sm text-slate-400">
        No integrations yet. Add one to forward BLOCK and SANITIZE events to your SIEM.
      </div>
    )
  }

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-xs font-medium text-slate-500 border-b border-slate-200">
          <th className="px-4 py-2.5">Destination</th>
          <th className="px-4 py-2.5">Status</th>
          <th className="px-4 py-2.5">Events</th>
          <th className="px-4 py-2.5 text-right">Actions</th>
        </tr>
      </thead>
      <tbody>
        {endpoints.map(ep => (
          <tr key={ep.id} className="border-b border-slate-100 last:border-0">
            <td className="px-4 py-3">
              <div className="font-medium text-slate-800">{typeLabel(ep.connector_type)}</div>
              <div className="text-xs text-slate-400 break-all">{ep.url}</div>
            </td>
            <td className="px-4 py-3"><StatusChip status={ep.status} /></td>
            <td className="px-4 py-3 text-xs text-slate-500">
              {ep.event_types === null ? "All events" : ep.event_types.join(", ")}
            </td>
            <td className="px-4 py-3">
              <div className="flex items-center justify-end gap-2">
                <button
                  disabled={!canWrite || testingId === ep.id}
                  onClick={() => onTest(ep)}
                  className="text-xs font-medium text-[#670FEF] hover:underline disabled:opacity-40 disabled:no-underline"
                >
                  {testingId === ep.id ? "Testing..." : "Send test"}
                </button>
                <button
                  disabled={!canWrite || deletingId === ep.id}
                  onClick={() => onDelete(ep)}
                  className="text-xs font-medium text-red-600 hover:underline disabled:opacity-40 disabled:no-underline"
                >
                  {deletingId === ep.id ? "Removing..." : "Remove"}
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
