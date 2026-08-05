// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useParams } from "next/navigation"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { PageSpinner } from "@/components/ui/Spinner"
import { EmptyState } from "@/components/ui/EmptyState"
import { ErrorState } from "@/components/ui/ErrorState"
import { DecisionBadge } from "@/components/ui/Badge"
import { useBackNav } from "@/hooks/useBackNav"
import { formatTimestamp } from "@/lib/datetime"
import { getAgentRun } from "@/lib/api"
import type { AuditLogItem } from "@/lib/types"

// Untrusted origins -- content the agent pulled in (the indirect prompt-injection
// surface). Highlighted so a reviewer can see where risk entered the run.
const UNTRUSTED = new Set(["tool_output", "retrieved_document", "external_content"])

function SourceBadge({ source }: { source: string | null }) {
  const s = source ?? "user_prompt"
  const untrusted = UNTRUSTED.has(s)
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${
        untrusted
          ? "bg-amber-50 text-amber-700 border-amber-200"
          : "bg-slate-50 text-slate-600 border-slate-200"
      }`}
      title={untrusted ? "Untrusted origin - indirect prompt-injection surface" : "End-user prompt"}
    >
      {s}
    </span>
  )
}

function AgentRunInner() {
  const { runId } = useParams<{ runId: string }>()
  const goBack = useBackNav("/requests")

  const { data, isLoading, error } = useSWR(
    ["agent-run", runId],
    () => getAgentRun(runId),
    { refreshInterval: 30000 },
  )

  const turns: AuditLogItem[] = data?.turns ?? []
  const blocked   = turns.filter(t => t.decision === "BLOCK").length
  const sanitized = turns.filter(t => t.decision === "SANITIZE").length
  const sources   = Array.from(new Set(turns.map(t => t.input_source ?? "user_prompt")))

  return (
    <Shell title="Agent Run">
      <PageHeader
        breadcrumb={[{ label: "Requests", href: "/requests" }, { label: `Run ${runId.slice(-6)}` }]}
        onBack={goBack}
      />
      <div className="flex flex-col gap-4">

        {/* Header */}
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <div className="text-xs text-slate-400 mb-1">Run</div>
              <div className="font-mono text-sm text-slate-800 break-all">{runId}</div>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div><span className="font-semibold">{data?.count ?? 0}</span> <span className="text-slate-400">turns</span></div>
              {blocked > 0   && <div className="text-red-600"><span className="font-semibold">{blocked}</span> blocked</div>}
              {sanitized > 0 && <div className="text-amber-600"><span className="font-semibold">{sanitized}</span> sanitized</div>}
            </div>
          </div>
          {sources.length > 0 && (
            <div className="flex items-center gap-2 mt-3 flex-wrap">
              <span className="text-xs text-slate-400">sources:</span>
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
              title="Failed to load agent run"
              message={(error as { message?: string })?.message ?? "Unable to reach the API."}
            />
          ) : turns.length === 0 ? (
            <EmptyState
              title="No turns for this run"
              message="Scans tagged with this run_id appear here as an ordered timeline."
            />
          ) : (
            <ol className="relative border-l border-slate-200 ml-3">
              {turns.map((t, i) => (
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
                    <span className="text-xs text-slate-400 ml-auto tabular-nums">
                      risk {t.risk_score.toFixed(2)}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-slate-400 flex items-center gap-3 flex-wrap">
                    <span>{formatTimestamp(t.timestamp)}</span>
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
