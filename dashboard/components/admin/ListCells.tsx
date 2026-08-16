// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useTranslations } from "next-intl"

// Shared cells for the admin resource listings (departments, applications) so
// they render identity and policy state identically.

/** Identity cell: display name with the machine slug muted beneath it. */
export function NameSlug({ name, slug }: { name: string; slug: string }) {
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="text-sm font-medium text-slate-900 truncate">{name}</span>
      <span className="text-[11px] font-mono text-slate-600 truncate">{slug}</span>
    </div>
  )
}

/** Policy-override state: an "Overridden" chip, or a muted inherit label. */
export function PolicyBadge({ overridden, inheritsLabel }: {
  overridden:    boolean
  inheritsLabel: string
}) {
  const t = useTranslations("common")
  if (overridden) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border bg-blue-50 text-blue-700 border-blue-200">
        {t("overridden")}
      </span>
    )
  }
  return <span className="text-xs text-slate-600">{inheritsLabel}</span>
}
