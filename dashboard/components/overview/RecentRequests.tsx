// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { RequestsTable } from "@/components/requests/RequestsTable"
import { AuditLogItem } from "@/lib/types"

// The Overview "recent" preview is the SAME table as /requests (compact column
// set), so the two surfaces render identical badges, truncation, and risk
// coloring. This is a thin card wrapper; the row markup lives in RequestsTable.
export function RecentRequests({ items, onSelect }: {
  items:    AuditLogItem[]
  onSelect: (traceId: string) => void
}) {
  return (
    <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: "8px", overflow: "hidden" }}>
      <div style={{
        padding: "14px 20px", borderBottom: "1px solid #f3f4f6",
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <h3 style={{ fontSize: "13px", fontWeight: 600, color: "#111827", margin: 0 }}>Recent requests</h3>
        <span style={{ fontSize: "11px", color: "#9ca3af" }}>Last 10 . live</span>
      </div>
      <RequestsTable items={items} onSelect={onSelect} compact />
    </div>
  )
}
