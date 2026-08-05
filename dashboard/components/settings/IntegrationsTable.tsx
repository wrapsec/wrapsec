// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { WebhookEndpoint } from "@/lib/types"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { EmptyState } from "@/components/ui/EmptyState"

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
  paused:        { bg: "#f3f4f6", fg: "#4b5563", bd: "#e5e7eb", label: "Paused" },
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
  pausingId:  string | null
  onTest:     (ep: WebhookEndpoint) => void
  onPause:    (ep: WebhookEndpoint) => void
  onResume:   (ep: WebhookEndpoint) => void
  onDelete:   (ep: WebhookEndpoint) => void
}

export function IntegrationsTable({
  endpoints, canWrite, testingId, deletingId, pausingId,
  onTest, onPause, onResume, onDelete,
}: Props) {
  if (endpoints.length === 0) {
    return (
      <EmptyState
        title="No integrations yet"
        message="Add one to forward BLOCK and SANITIZE events to your SIEM."
      />
    )
  }

  return (
    <Table>
      <THead>
        <tr>
          <Th>Destination</Th>
          <Th>Status</Th>
          <Th>Events</Th>
          <Th align="right">Actions</Th>
        </tr>
      </THead>
      <TBody>
        {endpoints.map(ep => (
          <Tr key={ep.id}>
            <Td>
              <div className="font-medium text-slate-800">{typeLabel(ep.connector_type)}</div>
              <div className="text-xs text-slate-400 break-all">{ep.url}</div>
            </Td>
            <Td><StatusChip status={ep.status} /></Td>
            <Td className="text-xs text-slate-500">
              {ep.event_types === null ? "All events" : ep.event_types.join(", ")}
            </Td>
            <Td align="right">
              <div className="flex items-center justify-end gap-2">
                <button
                  disabled={!canWrite || testingId === ep.id}
                  onClick={() => onTest(ep)}
                  className="text-xs font-medium text-[#670FEF] hover:underline disabled:opacity-40 disabled:no-underline"
                >
                  {testingId === ep.id ? "Testing..." : "Send test"}
                </button>
                {ep.disabled ? (
                  <button
                    disabled={!canWrite || pausingId === ep.id}
                    onClick={() => onResume(ep)}
                    className="text-xs font-medium text-green-700 hover:underline disabled:opacity-40 disabled:no-underline"
                  >
                    {pausingId === ep.id ? "Resuming..." : "Resume"}
                  </button>
                ) : (
                  <button
                    disabled={!canWrite || pausingId === ep.id}
                    onClick={() => onPause(ep)}
                    className="text-xs font-medium text-slate-600 hover:underline disabled:opacity-40 disabled:no-underline"
                  >
                    {pausingId === ep.id ? "Pausing..." : "Pause"}
                  </button>
                )}
                <button
                  disabled={!canWrite || deletingId === ep.id}
                  onClick={() => onDelete(ep)}
                  className="text-xs font-medium text-red-600 hover:underline disabled:opacity-40 disabled:no-underline"
                >
                  {deletingId === ep.id ? "Removing..." : "Remove"}
                </button>
              </div>
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  )
}
