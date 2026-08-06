// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import Link from "next/link"

/**
 * Clickable pill linking a request to its agent-run timeline. Used in the
 * requests table and the detail drawer so the navigation affordance is uniform.
 * stopPropagation lets it sit inside a clickable row without also opening the row.
 */
export function RunPill({ runId, turnIndex }: {
  runId:      string
  turnIndex?: number | null
}) {
  return (
    <Link
      href={`/agent-runs/${encodeURIComponent(runId)}`}
      onClick={e => e.stopPropagation()}
      title={`Agent run ${runId} - view timeline`}
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-[#670FEF]/20 bg-[#670FEF]/[0.06] text-[10px] font-medium text-[#670FEF] no-underline hover:bg-[#670FEF]/10 transition-colors whitespace-nowrap"
    >
      <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 5l7 7-7 7M5 12h14" />
      </svg>
      run {runId.slice(-6)}
      {turnIndex != null ? ` - turn ${turnIndex}` : ""}
    </Link>
  )
}
