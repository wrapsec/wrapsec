// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import Link from "next/link"
import { DecisionBadge, ThreatBadge, SeverityBadge, ModeBadge } from "@/components/ui/Badge"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { EmptyState } from "@/components/ui/EmptyState"
import { AuditLogItem } from "@/lib/types"
import { timeAgo } from "@/lib/datetime"
import { formatLatency } from "@/lib/format"

const HEADERS = [
  "Trace ID", "Severity", "Decision", "Dept / App",
  "Threats", "Detection", "Execution", "Latency", "Time",
]

export function RequestsTable({ items, onSelect }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}) {
  return (
    <Table>
      <THead>
        <tr>{HEADERS.map(h => <Th key={h}>{h}</Th>)}</tr>
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
            <Td className="font-mono text-xs text-slate-500 whitespace-nowrap">
              <div>{item.trace_id}</div>
              {item.run_id && (
                <Link
                  href={`/agent-runs/${encodeURIComponent(item.run_id)}`}
                  onClick={e => e.stopPropagation()}
                  title={`Agent run ${item.run_id} - view timeline`}
                  className="text-[10px] text-[#670FEF] no-underline"
                >
                  run {item.run_id.slice(-6)}
                  {item.turn_index != null ? ` - turn ${item.turn_index}` : ""}
                </Link>
              )}
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
            <Td>
              {item.threats.length === 0
                ? <span className="text-xs text-slate-300">-</span>
                : <div className="flex flex-wrap gap-[3px]">{item.threats.map(t => <ThreatBadge key={t} threat={t} />)}</div>
              }
            </Td>
            <Td>
              <ModeBadge label={item.detection_mode === "full" ? "full" : "fast"} active={item.detection_mode === "full"} />
            </Td>
            <Td>
              <ModeBadge label={item.execution_mode === "proxy" ? "proxy" : "scan"} active={item.execution_mode === "proxy"} />
            </Td>
            <Td className="text-xs text-slate-500 whitespace-nowrap tabular-nums">
              {formatLatency(item.latency_ms)}
            </Td>
            <Td className="text-xs text-slate-400 whitespace-nowrap">
              {timeAgo(item.timestamp)}
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  )
}
