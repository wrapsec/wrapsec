"use client"

import { Select } from "@/components/ui/Input"

interface RequestFiltersProps {
  traceId:        string
  decision:       string
  threatCategory: string
  from:           string
  to:             string
  sortBy:         string
  sortOrder:      string
  onTraceId:      (v: string) => void
  onDecision:     (v: string) => void
  onThreat:       (v: string) => void
  onFrom:         (v: string) => void
  onTo:           (v: string) => void
  onSortBy:       (v: string) => void
  onSortOrder:    (v: string) => void
}

export function RequestFilters({
  traceId, decision, threatCategory, from, to, sortBy, sortOrder,
  onTraceId, onDecision, onThreat, onFrom, onTo, onSortBy, onSortOrder,
}: RequestFiltersProps) {
  return (
    <div className="space-y-3">
      {/* Row 1 — search + filters + sort */}
      <div className="flex items-end gap-3 flex-wrap">

        {/* Trace ID search */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">Trace ID</label>
          <div style={{ position: "relative", width: "200px" }}>
            <svg
              style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }}
              className="h-4 w-4 text-slate-400"
              fill="none" stroke="currentColor" strokeWidth={1.75} viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={traceId}
              onChange={(e) => onTraceId(e.target.value)}
              placeholder="Search trace ID..."
              style={{ paddingLeft: "32px", width: "100%" }}
              className="h-9 pr-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
            />
          </div>
        </div>

        <Select
          label="Decision"
          value={decision}
          onChange={(e) => onDecision(e.target.value)}
          options={[
            { value: "",         label: "All decisions" },
            { value: "BLOCK",    label: "Block" },
            { value: "SANITIZE", label: "Sanitize" },
            { value: "ALLOW",    label: "Allow" },
          ]}
          className="w-40"
        />

        <Select
          label="Threat"
          value={threatCategory}
          onChange={(e) => onThreat(e.target.value)}
          options={[
            { value: "",                  label: "All threats" },
            { value: "PROMPT_INJECTION",  label: "Prompt Injection" },
            { value: "JAILBREAK",         label: "Jailbreak" },
            { value: "MALICIOUS_INTENT",  label: "Malicious Intent" },
            { value: "DATA_EXFILTRATION", label: "Data Exfiltration" },
            { value: "PII",               label: "PII" },
            { value: "TOXICITY",          label: "Toxicity" },
          ]}
          className="w-44"
        />

        <Select
          label="Sort by"
          value={sortBy}
          onChange={(e) => onSortBy(e.target.value)}
          options={[
            { value: "created_at", label: "Time" },
            { value: "risk_score", label: "Risk Score" },
            { value: "latency_ms", label: "Latency" },
          ]}
          className="w-36"
        />

        <Select
          label="Order"
          value={sortOrder}
          onChange={(e) => onSortOrder(e.target.value)}
          options={
            sortBy === "created_at"
              ? [
                  { value: "desc", label: "Newest first" },
                  { value: "asc",  label: "Oldest first" },
                ]
              : [
                  { value: "desc", label: "Highest first" },
                  { value: "asc",  label: "Lowest first" },
                ]
          }
          className="w-36"
        />
      </div>

      {/* Row 2 — date range */}
      <div className="flex items-end gap-3">
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">From</label>
          <input
            type="date"
            value={from}
            max={to || undefined}
            onChange={(e) => onFrom(e.target.value)}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-slate-700">To</label>
          <input
            type="date"
            value={to}
            min={from || undefined}
            onChange={(e) => onTo(e.target.value)}
            className="h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800"
          />
        </div>
        {from && to && from > to && (
          <p className="text-xs text-red-600 self-end pb-1">
            To date must be after From date
          </p>
        )}
        {(from || to) && (
          <button
            onClick={() => { onFrom(""); onTo("") }}
            className="h-9 px-3 text-xs text-slate-500 hover:text-slate-900 border border-slate-200 rounded-md hover:bg-slate-50 transition-colors self-end"
          >
            Clear dates
          </button>
        )}
      </div>
    </div>
  )
}