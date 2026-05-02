// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { Button } from "@/components/ui/Button"

interface PaginationProps {
  total:    number
  offset:   number
  limit:    number
  onChange: (offset: number) => void
}

export function Pagination({ total, offset, limit, onChange }: PaginationProps) {
  const page       = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit)

  if (totalPages <= 1) return null

  return (
    <div style={{
      display:        "flex",
      alignItems:     "center",
      justifyContent: "space-between",
      padding:        "10px 16px",
      borderTop:      "1px solid #f3f4f6",
    }}>
      <p style={{ fontSize: "12px", color: "#9ca3af", margin: 0 }}>
        Showing{" "}
        <span style={{ fontWeight: 600, color: "#374151" }}>
          {(offset + 1).toLocaleString()}–{Math.min(offset + limit, total).toLocaleString()}
        </span>
        {" "}of{" "}
        <span style={{ fontWeight: 600, color: "#374151" }}>
          {total.toLocaleString()}
        </span>
      </p>

      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset === 0}
          onClick={() => onChange(0)}
        >
          First
        </Button>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </Button>
        <span style={{ fontSize: "12px", color: "#6b7280", padding: "0 4px" }}>
          {page} / {totalPages}
        </span>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
        >
          Next
        </Button>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset + limit >= total}
          onClick={() => onChange((totalPages - 1) * limit)}
        >
          Last
        </Button>
      </div>
    </div>
  )
}
