// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"
import { Button } from "@/components/ui/Button"
import { useFormat } from "@/hooks/useFormat"

interface PaginationProps {
  total:    number
  offset:   number
  limit:    number
  onChange: (offset: number) => void
}

export function Pagination({ total, offset, limit, onChange }: PaginationProps) {
  const fmt        = useFormat()
  const t          = useTranslations("common.pagination")
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
      <p style={{ fontSize: "12px", color: "#4b5563", margin: 0 }}>
        {t.rich("showing", {
          range: `${fmt.number(offset + 1)}-${fmt.number(Math.min(offset + limit, total))}`,
          total: fmt.number(total),
          b: (chunks) => <span style={{ fontWeight: 600, color: "#374151" }}>{chunks}</span>,
        })}
      </p>

      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset === 0}
          onClick={() => onChange(0)}
        >
          {t("first")}
        </Button>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          {t("previous")}
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
          {t("next")}
        </Button>
        <Button
          variant="secondary"
          size="sm"
          disabled={offset + limit >= total}
          onClick={() => onChange((totalPages - 1) * limit)}
        >
          {t("last")}
        </Button>
      </div>
    </div>
  )
}
