// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import Link from "next/link"

interface BreadcrumbItem {
  label: string
  href?: string
}

export function Breadcrumb({ items }: { items: BreadcrumbItem[] }) {
  return (
    <nav aria-label="Breadcrumb">
      <ol style={{ display: "flex", alignItems: "center", gap: "4px", listStyle: "none", padding: 0, margin: 0 }}>
        {items.map((item, i) => (
          <li key={i} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            {i > 0 && (
              <svg style={{ width: 12, height: 12, color: "#d1d5db", flexShrink: 0 }}
                fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
              </svg>
            )}
            {item.href ? (
              <Link
                href={item.href}
                className="hover:text-slate-900 transition-colors"
                style={{ fontSize: "13px", color: "#6b7280", textDecoration: "none" }}
              >
                {item.label}
              </Link>
            ) : (
              <span style={{ fontSize: "13px", color: "#111827", fontWeight: 500 }}>
                {item.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  )
}
