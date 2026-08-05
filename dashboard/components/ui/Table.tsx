// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { cn } from "@/lib/utils"

// One table look for the whole dashboard. Encodes the header/row/cell chrome so
// monitoring and management tables render identically; cell CONTENT stays with
// the caller. Wrap in a Card (padding={false}) for the bordered container.

type Align = "left" | "right" | "center"
const ALIGN: Record<Align, string> = { left: "text-left", right: "text-right", center: "text-center" }

export function Table({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className={cn("w-full border-collapse text-sm", className)}>{children}</table>
    </div>
  )
}

export function THead({ children }: { children: React.ReactNode }) {
  return <thead>{children}</thead>
}

export function Th({ children, className, align = "left" }: {
  children?: React.ReactNode; className?: string; align?: Align
}) {
  return (
    <th className={cn(
      "px-4 py-2.5 text-[10px] font-bold uppercase tracking-[0.07em] text-slate-400 whitespace-nowrap border-b border-slate-100 bg-[#fafafa]",
      ALIGN[align], className,
    )}>
      {children}
    </th>
  )
}

export function TBody({ children }: { children: React.ReactNode }) {
  return <tbody>{children}</tbody>
}

export function Tr({ children, onClick, hover, className }: {
  children: React.ReactNode; onClick?: () => void; hover?: boolean; className?: string
}) {
  const clickable = Boolean(onClick)
  const showHover = clickable || hover
  return (
    <tr
      onClick={onClick}
      className={cn(
        "border-b border-slate-50 last:border-0",
        clickable && "cursor-pointer",
        showHover && "hover:bg-[rgba(103,15,239,0.03)]",
        className,
      )}
    >
      {children}
    </tr>
  )
}

export function Td({ children, className, align = "left", colSpan }: {
  children?: React.ReactNode; className?: string; align?: Align; colSpan?: number
}) {
  return (
    <td colSpan={colSpan} className={cn("px-4 py-2.5", ALIGN[align], className)}>
      {children}
    </td>
  )
}
