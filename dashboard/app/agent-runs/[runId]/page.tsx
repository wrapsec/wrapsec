// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useParams } from "next/navigation"
import { useTranslations } from "next-intl"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { PageSpinner } from "@/components/ui/Spinner"
import { EmptyState } from "@/components/ui/EmptyState"
import { ErrorState } from "@/components/ui/ErrorState"
import { DecisionBadge, SourceBadge } from "@/components/ui/Badge"
import { useBackNav } from "@/hooks/useBackNav"
import { useFormat } from "@/hooks/useFormat"
import { getAgentRun } from "@/lib/api"
import type { AuditLogItem } from "@/lib/types"

function AgentRunInner() {
  const { runId } = useParams<{ runId: string }>()
  const goBack = useBackNav("/requests")
  const fmt = useFormat()
  const tt = useTranslations("pages.agent_run")

  const { data, isLoading, error } = useSWR(
    ["agent-run", runId],
    () => getAgentRun(runId),
    { refreshInterval: 30000 },
  )

  // One entry per SCAN, not per turn: a tool call is judged on its arguments
  // and again on its result, so several scans can share one turn_index. The
  // turn count is derived here rather than sent, because turn_index is already
  // on every record and a second server-side counter could disagree with it.
  const scans: AuditLogItem[] = data?.scans ?? []
  const blocked   = scans.filter(s => s.decision === "BLOCK").length
  const sanitized = scans.filter(s => s.decision === "SANITIZE").length
  const sources   = Array.from(new Set(scans.map(s => s.input_source ?? "user_prompt")))
  const turnCount = new Set(scans.map(s => s.turn_index)).size

  return (
    <Shell title={tt("title")}>
      <PageHeader
        breadcrumb={[{ label: tt("breadcrumb"), href: "/requests" }, { label: tt("run_label", { id: runId.slice(-6) }) }]}
        onBack={goBack}
      />
      <div className="flex flex-col gap-4">

        {/* Header */}
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <div className="text-xs text-slate-600 mb-1">{tt("run")}</div>
              <div className="font-mono text-sm text-slate-800 break-all">{runId}</div>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div>
                <span className="font-semibold">{data?.count ?? 0}</span>{" "}
                <span className="text-slate-600">{tt("scans")}</span>
                <span className="text-slate-400"> {tt("across")} </span>
                <span className="font-semibold">{turnCount}</span>{" "}
                <span className="text-slate-600">{tt("turns")}</span>
              </div>
              {blocked > 0   && <div className="text-red-600"><span className="font-semibold">{blocked}</span> {tt("blocked")}</div>}
              {sanitized > 0 && <div className="text-amber-600"><span className="font-semibold">{sanitized}</span> {tt("sanitized")}</div>}
            </div>
          </div>
          {sources.length > 0 && (
            <div className="flex items-center gap-2 mt-3 flex-wrap">
              <span className="text-xs text-slate-600">{tt("sources")}</span>
              {sources.map(s => <SourceBadge key={s} source={s} />)}
            </div>
          )}
        </div>

        {/* Timeline */}
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          {isLoading && !data ? (
            <PageSpinner />
          ) : error ? (
            <ErrorState
              title={tt("load_error")}
              message={(error as { message?: string })?.message ?? tt("load_error_body")}
            />
          ) : scans.length === 0 ? (
            <EmptyState
              title={tt("empty_title")}
              message={tt("empty_body")}
            />
          ) : (
            <ol className="relative border-l border-slate-200 ml-3">
              {scans.map((t, i) => (
                <li key={`${t.trace_id}-${i}`} className="mb-6 ml-6">
                  <span className="absolute -left-3 flex items-center justify-center w-6 h-6 rounded-full bg-slate-100 border border-slate-300 text-[11px] font-semibold text-slate-600 tabular-nums">
                    {t.turn_index ?? i}
                  </span>
                  <div className="flex items-center gap-2 flex-wrap">
                    <DecisionBadge decision={t.decision} size="sm" />
                    <SourceBadge source={t.input_source} />
                    {t.primary_reason && (
                      <span className="text-xs text-slate-500">{t.primary_reason}</span>
                    )}
                    <span className="text-xs text-slate-600 ml-auto tabular-nums">
                      {tt("risk", { score: t.risk_score.toFixed(2) })}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-slate-600 flex items-center gap-3 flex-wrap">
                    <span>{fmt.timestamp(t.timestamp)}</span>
                    <span className="font-mono">{t.trace_id}</span>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>

      </div>
    </Shell>
  )
}

export default function AgentRunPage() {
  return <AgentRunInner />
}
