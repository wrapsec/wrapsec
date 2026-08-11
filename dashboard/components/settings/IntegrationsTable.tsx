// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { WebhookEndpoint } from "@/lib/types"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { EmptyState } from "@/components/ui/EmptyState"

// Connector display names are product brand names (the integration targets),
// kept verbatim -- brand names are not localized.
const CONNECTOR_LABEL: Record<string, string> = {
  splunk_hec:               "Splunk HEC",
  datadog_logs:             "Datadog Logs",
  sentinel_logs_ingestion:  "Microsoft Sentinel",
  elastic_ecs:              "Elastic (ECS)",
}

function connectorLabel(type: string | null): string | null {
  return type ? (CONNECTOR_LABEL[type] ?? type) : null
}

const STATUS_STYLE: Record<string, { bg: string; fg: string; bd: string }> = {
  active:        { bg: "#f0fdf4", fg: "#15803d", bd: "#bbf7d0" },
  failing:       { bg: "#fffbeb", fg: "#b45309", bd: "#fde68a" },
  paused:        { bg: "#f3f4f6", fg: "#4b5563", bd: "#e5e7eb" },
  auto_disabled: { bg: "#fef2f2", fg: "#b91c1c", bd: "#fecaca" },
}

function StatusChip({ status }: { status: string }) {
  const t = useTranslations("pages.integrations.table.status_label")
  const s = STATUS_STYLE[status] ?? { bg: "#f3f4f6", fg: "#374151", bd: "#e5e7eb" }
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "5px",
      padding: "3px 9px", fontSize: "11px", fontWeight: 600, borderRadius: "5px",
      background: s.bg, color: s.fg, border: `1px solid ${s.bd}`,
    }}>
      <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "currentColor" }} />
      {t.has(status) ? t(status) : status}
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
  const t = useTranslations("pages.integrations.table")
  if (endpoints.length === 0) {
    return (
      <EmptyState
        title={t("empty_title")}
        message={t("empty_body")}
      />
    )
  }

  return (
    <Table>
      <THead>
        <tr>
          <Th>{t("destination")}</Th>
          <Th>{t("status")}</Th>
          <Th>{t("events")}</Th>
          <Th align="right">{t("actions")}</Th>
        </tr>
      </THead>
      <TBody>
        {endpoints.map(ep => (
          <Tr key={ep.id}>
            <Td>
              <div className="font-medium text-slate-800">{connectorLabel(ep.connector_type) ?? t("generic_webhook")}</div>
              <div className="text-xs text-slate-400 break-all">{ep.url}</div>
            </Td>
            <Td><StatusChip status={ep.status} /></Td>
            <Td className="text-xs text-slate-500">
              {ep.event_types === null ? t("all_events") : ep.event_types.join(", ")}
            </Td>
            <Td align="right">
              <div className="flex items-center justify-end gap-2">
                <button
                  disabled={!canWrite || testingId === ep.id}
                  onClick={() => onTest(ep)}
                  className="text-xs font-medium text-[#670FEF] hover:underline disabled:opacity-40 disabled:no-underline"
                >
                  {testingId === ep.id ? t("testing") : t("send_test")}
                </button>
                {ep.disabled ? (
                  <button
                    disabled={!canWrite || pausingId === ep.id}
                    onClick={() => onResume(ep)}
                    className="text-xs font-medium text-green-700 hover:underline disabled:opacity-40 disabled:no-underline"
                  >
                    {pausingId === ep.id ? t("resuming") : t("resume")}
                  </button>
                ) : (
                  <button
                    disabled={!canWrite || pausingId === ep.id}
                    onClick={() => onPause(ep)}
                    className="text-xs font-medium text-slate-600 hover:underline disabled:opacity-40 disabled:no-underline"
                  >
                    {pausingId === ep.id ? t("pausing") : t("pause")}
                  </button>
                )}
                <button
                  disabled={!canWrite || deletingId === ep.id}
                  onClick={() => onDelete(ep)}
                  className="text-xs font-medium text-red-600 hover:underline disabled:opacity-40 disabled:no-underline"
                >
                  {deletingId === ep.id ? t("removing") : t("remove")}
                </button>
              </div>
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  )
}
