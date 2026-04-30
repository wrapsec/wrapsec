"use client"

import { useState } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { PageSpinner } from "@/components/ui/Spinner"
import { Button } from "@/components/ui/Button"
import { getProxyInteractions } from "@/lib/api"
import { ProxyInteraction, Decision, ExecutionStatus } from "@/lib/types"

const PAGE_SIZE = 20

// Decision badge colours
function decisionClass(d: Decision | null): string {
  if (d === "BLOCK")    return "bg-red-100 text-red-700"
  if (d === "SANITIZE") return "bg-yellow-100 text-yellow-700"
  if (d === "ALLOW")    return "bg-green-100 text-green-700"
  return "bg-slate-100 text-slate-500"
}

// Execution status badge colours
function statusClass(s: ExecutionStatus): string {
  if (s === "SUCCESS")        return "bg-green-100 text-green-700"
  if (s === "BLOCKED")        return "bg-red-100 text-red-700"
  if (s === "OUTPUT_BLOCKED") return "bg-orange-100 text-orange-700"
  if (s === "FAILED")         return "bg-red-100 text-red-600"
  if (s === "TIMEOUT")        return "bg-yellow-100 text-yellow-700"
  return "bg-slate-100 text-slate-500"
}

function Badge({ label, className }: { label: string; className: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${className}`}>
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
            className="text-xs text-blue-700 hover:underline"
          >
            Back to settings
          </a>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setOffset(0) }}
            className="h-8 px-3 text-xs rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800"
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
                  <tr className="border-b border-slate-100 bg-slate-50">
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Time</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Trace ID</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Input</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Output</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Status</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Provider</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-500">Model</th>
                    <th className="px-4 py-2.5 text-right font-medium text-slate-500">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {items.map((item: ProxyInteraction) => (
                    <tr
                      key={item.trace_id}
                      onClick={() => setSelectedTrace(
                        selectedTrace === item.trace_id ? null : item.trace_id
                      )}
                      className="hover:bg-slate-50 cursor-pointer"
                    >
                      <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                        {formatTime(item.created_at)}
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400">
                        {item.trace_id.slice(0, 20)}...
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          label={item.input_decision}
                          className={decisionClass(item.input_decision)}
                        />
                        {item.input_attack_type && (
                          <span className="ml-1.5 text-slate-400">
                            {item.input_attack_type}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {item.output_decision
                          ? <Badge label={item.output_decision} className={decisionClass(item.output_decision)} />
                          : <span className="text-slate-300">--</span>
                        }
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          label={item.execution_status}
                          className={statusClass(item.execution_status)}
                        />
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