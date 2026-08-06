// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import Link from "next/link"
import { Breadcrumb } from "@/components/ui/Breadcrumb"

interface Crumb {
  label: string
  href?: string
}

interface PageHeaderProps {
  /** Hierarchical context for a nested/detail route. */
  breadcrumb?:  Crumb[]
  /** One-line context under the breadcrumb (left of the actions). */
  description?: React.ReactNode
  /** Right-aligned action controls (buttons, filters summary, ...). */
  actions?:     React.ReactNode
  /** Back affordance for resource routes. Prefer onBack (useBackNav). */
  onBack?:      () => void
  backHref?:    string
  backLabel?:   string
}

/**
 * The mandatory top-of-content header for every dashboard page.
 *
 * Layout ONLY -- no page-specific colors or styling are baked in, so the later
 * visual (Tailwind) migration can restyle pages without changing this API. The
 * page TITLE stays in the TopBar; PageHeader provides the uniform breadcrumb +
 * back + description + actions row.
 */
export function PageHeader({
  breadcrumb, description, actions, onBack, backHref, backLabel = "Back",
}: PageHeaderProps) {
  const showBack = Boolean(onBack || backHref)
  const showRow  = showBack || Boolean(description) || Boolean(actions)

  return (
    <div className="flex flex-col gap-2 mb-4">
      {breadcrumb && breadcrumb.length > 0 && <Breadcrumb items={breadcrumb} />}

      {showRow && (
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            {showBack && <BackButton onBack={onBack} backHref={backHref} label={backLabel} />}
            {description && (
              <div className="text-sm text-slate-500 min-w-0">{description}</div>
            )}
          </div>
          {actions && (
            <div className="flex items-center gap-2 shrink-0">{actions}</div>
          )}
        </div>
      )}
    </div>
  )
}

function BackButton({ onBack, backHref, label }: { onBack?: () => void; backHref?: string; label: string }) {
  const content = (
    <span className="inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 transition-colors">
      <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
      </svg>
      {label}
    </span>
  )
  // onBack (history-aware) wins; backHref is the static fallback for pages that
  // do not use useBackNav.
  if (onBack) {
    return <button type="button" onClick={onBack} className="cursor-pointer">{content}</button>
  }
  if (backHref) {
    return <Link href={backHref}>{content}</Link>
  }
  return null
}
