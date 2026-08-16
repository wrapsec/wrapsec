// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { DecisionBadge, ThreatBadge, SeverityBadge, SourceBadge } from "@/components/ui/Badge"
import { Table, THead, TBody, Th, Tr, Td } from "@/components/ui/Table"
import { EmptyState } from "@/components/ui/EmptyState"
import { CopyButton } from "@/components/ui/CopyButton"
import { AuditLogItem } from "@/lib/types"
import { timeAgo } from "@/lib/datetime"
import { formatLatency, formatScore, truncateId, formatRun } from "@/lib/format"

// Column set. `compact` columns also appear in the Overview "Recent requests"
// card (which reuses this table via the compact variant); the rest are full-view
// only. Keeping one definition means both surfaces stay in sync.
// `key` doubles as the pages.requests.table.<key> localization key for the header.
type Col = { key: string; compact: boolean; align?: "right" }
const COLS: Col[] = [
  { key: "request",  compact: false },
  { key: "time",     compact: true  },
  { key: "severity", compact: true  },
  { key: "decision", compact: true  },
  { key: "source",   compact: false },
  { key: "threats",  compact: true  },
  { key: "deptapp",  compact: false },
  { key: "risk",     compact: true,  align: "right" },
  { key: "latency",  compact: false, align: "right" },
]

export function RequestsTable({ items, onSelect, compact = false }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
  compact?: boolean
}) {
  const t = useTranslations("pages.requests.table")
  const cols = COLS.filter(c => !compact || c.compact)
  const show = (key: string) => cols.some(c => c.key === key)

  return (
    <Table>
      <THead>
        <tr>
          {cols.map(c => <Th key={c.key} align={c.align ?? "left"}>{t(c.key)}</Th>)}
        </tr>
      </THead>
      <TBody>
        {items.length === 0 ? (
          <tr>
            <Td colSpan={cols.length}>
              <EmptyState
                title={compact ? t("empty_title_compact") : t("empty_title")}
                message={compact ? t("empty_body_compact") : t("empty_body")}
              />
            </Td>
          </tr>
        ) : items.map(item => (
          <Tr key={item.trace_id} onClick={() => onSelect(item.trace_id)}>
            {show("request") && (
              <Td className="whitespace-nowrap">
                <div className="group flex items-center gap-1.5">
                  <span className="font-mono text-xs text-slate-600">{truncateId(item.trace_id)}</span>
                  <CopyButton
                    value={item.trace_id}
                    title={t("copy_trace")}
                    className="opacity-0 group-hover:opacity-100"
                  />
                </div>
                {item.run_id && (
                  <div className="mt-1 text-[10px] text-slate-600 whitespace-nowrap">
                    {formatRun(item.run_id, item.turn_index)}
                  </div>
                )}
              </Td>
            )}
            <Td className="text-xs text-slate-600 whitespace-nowrap">
              {timeAgo(item.timestamp)}
            </Td>
            <Td><SeverityBadge severity={item.severity} /></Td>
            <Td>
              {item.output_decision && item.output_decision !== item.decision ? (
                <div className="flex items-center gap-1">
                  <DecisionBadge decision={item.decision} size="sm" />
                  <span className="text-[10px] text-slate-600">{"->"}</span>
                  <DecisionBadge decision={item.output_decision} size="sm" />
                </div>
              ) : (
                <DecisionBadge decision={item.decision} size="sm" />
              )}
            </Td>
            {show("source") && <Td><SourceBadge source={item.input_source} /></Td>}
            <Td>
              {item.threats.length === 0
                ? <span className="text-xs text-slate-500">-</span>
                : <div className="flex flex-wrap gap-[3px]">{item.threats.map(t => <ThreatBadge key={t} threat={t} />)}</div>
              }
            </Td>
            {show("deptapp") && (
              <Td>
                {(item.dept_name || item.app_name) ? (
                  <div className="flex flex-col gap-px">
                    {item.dept_name && <span className="text-xs text-slate-700 font-medium">{item.dept_name}</span>}
                    {item.app_name && <span className="text-[11px] text-slate-600">{item.app_name}</span>}
                  </div>
                ) : (
                  <span className="text-xs text-slate-500">-</span>
                )}
              </Td>
            )}
            <Td className="text-right">
              <RiskValue score={item.risk_score} />
            </Td>
            {show("latency") && (
              <Td className="text-right text-xs text-slate-500 whitespace-nowrap tabular-nums">
                {formatLatency(item.latency_ms)}
              </Td>
            )}
          </Tr>
        ))}
      </TBody>
    </Table>
  )
}

// Compact risk readout for the row. Color mirrors the policy bands (block /
// sanitize / allow) so a scan of the column matches the decision column. Shades
// are chosen to meet WCAG AA (>=4.5:1) as small text on the white row.
function RiskValue({ score }: { score: number }) {
  const color = score >= 0.7 ? "#dc2626" : score >= 0.4 ? "#b45309" : "#15803d"
  return (
    <span className="text-xs font-semibold tabular-nums" style={{ color }}>
      {formatScore(score)}
    </span>
  )
}
