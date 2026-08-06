// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { DecisionBadge, ThreatBadge, SeverityBadge, SourceBadge } from "@/components/ui/Badge"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { EmptyState } from "@/components/ui/EmptyState"
import { CopyButton } from "@/components/ui/CopyButton"
import { RunPill } from "@/components/ui/RunPill"
import { AuditLogItem } from "@/lib/types"
import { timeAgo } from "@/lib/datetime"
import { formatLatency, formatScore, truncateId } from "@/lib/format"

// Triage-first column set: color anchors (Severity / Decision) and the product's
// headline signal (Content Source) lead; the opaque trace id is demoted to a
// compact, copyable cell; low-signal Detection / Execution move to the drawer.
const HEADERS = [
  "Request", "Time", "Severity", "Decision",
  "Content Source", "Threats", "Dept / App", "Risk", "Latency",
]

export function RequestsTable({ items, onSelect }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}) {
  return (
    <Table>
      <THead>
        <tr>
          {HEADERS.map(h => (
            <Th key={h} align={h === "Risk" || h === "Latency" ? "right" : "left"}>{h}</Th>
          ))}
        </tr>
      </THead>
      <TBody>
        {items.length === 0 ? (
          <tr>
            <Td colSpan={HEADERS.length}>
              <EmptyState
                title="No requests found"
                message="Try adjusting your filters or expanding the time range."
              />
            </Td>
          </tr>
        ) : items.map(item => (
          <Tr key={item.trace_id} onClick={() => onSelect(item.trace_id)}>
            <Td className="whitespace-nowrap">
              <div className="group flex items-center gap-1.5">
                <span className="font-mono text-xs text-slate-600">{truncateId(item.trace_id)}</span>
                <CopyButton
                  value={item.trace_id}
                  title="Copy trace id"
                  className="opacity-0 group-hover:opacity-100"
                />
              </div>
              {item.run_id && (
                <div className="mt-1">
                  <RunPill runId={item.run_id} turnIndex={item.turn_index} />
                </div>
              )}
            </Td>
            <Td className="text-xs text-slate-400 whitespace-nowrap">
              {timeAgo(item.timestamp)}
            </Td>
            <Td><SeverityBadge severity={item.severity} /></Td>
            <Td>
              {item.output_decision && item.output_decision !== item.decision ? (
                <div className="flex items-center gap-1">
                  <DecisionBadge decision={item.decision} size="sm" />
                  <span className="text-[10px] text-slate-400">{"->"}</span>
                  <DecisionBadge decision={item.output_decision} size="sm" />
                </div>
              ) : (
                <DecisionBadge decision={item.decision} size="sm" />
              )}
            </Td>
            <Td><SourceBadge source={item.input_source} /></Td>
            <Td>
              {item.threats.length === 0
                ? <span className="text-xs text-slate-300">-</span>
                : <div className="flex flex-wrap gap-[3px]">{item.threats.map(t => <ThreatBadge key={t} threat={t} />)}</div>
              }
            </Td>
            <Td>
              {(item.dept_name || item.app_name) ? (
                <div className="flex flex-col gap-px">
                  {item.dept_name && <span className="text-xs text-slate-700 font-medium">{item.dept_name}</span>}
                  {item.app_name && <span className="text-[11px] text-slate-400">{item.app_name}</span>}
                </div>
              ) : (
                <span className="text-xs text-slate-300">-</span>
              )}
            </Td>
            <Td className="text-right">
              <RiskValue score={item.risk_score} />
            </Td>
            <Td className="text-right text-xs text-slate-500 whitespace-nowrap tabular-nums">
              {formatLatency(item.latency_ms)}
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  )
}

// Compact risk readout for the row. Color mirrors the policy bands (block /
// sanitize / allow) so a scan of the column matches the decision column.
function RiskValue({ score }: { score: number }) {
  const color = score >= 0.7 ? "#dc2626" : score >= 0.4 ? "#d97706" : "#16a34a"
  return (
    <span className="text-xs font-semibold tabular-nums" style={{ color }}>
      {formatScore(score)}
    </span>
  )
}
