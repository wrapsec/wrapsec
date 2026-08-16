// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, Fragment } from "react"
import { useTranslations } from "next-intl"
import { ApiKey } from "@/lib/types"
import { Table, THead, TBody, Th, Tr } from "@/components/ui/Table"
import { EmptyState } from "@/components/ui/EmptyState"
import { timeAgo, ensureUtc } from "@/lib/datetime"
import { useFormat } from "@/hooks/useFormat"

interface ApiKeyTableProps {
  keys:      ApiKey[]
  onRevoke:  (keyId: string) => void
  onRotate:  (keyId: string, gracePeriodMinutes: number) => Promise<string>
  revoking:  string | null
  canWrite?: boolean   // false = API key session, hide write actions
}

export function ApiKeyTable({ keys, onRevoke, onRotate, revoking, canWrite = true }: ApiKeyTableProps) {
  const fmt = useFormat()
  const t   = useTranslations("pages.keys.table")
  const [rotating,       setRotating]       = useState<string | null>(null)
  const [rotatedKey,     setRotatedKey]     = useState<{ newKey: string } | null>(null)
  const [graceInput,     setGraceInput]     = useState<string | null>(null)
  const [confirmRevoke,  setConfirmRevoke]  = useState<string | null>(null)

  const GRACE_OPTIONS: { value: string; key: string }[] = [
    { value: "15",   key: "min15" },
    { value: "30",   key: "min30" },
    { value: "60",   key: "hour1" },
    { value: "360",  key: "hour6" },
    { value: "1440", key: "hour24" },
  ]

  if (keys.length === 0) {
    return (
      <EmptyState
        title={t("empty_title")}
        message={t("empty_body")}
      />
    )
  }

  const handleRotateConfirm = async (keyId: string, grace: number) => {
    setRotating(keyId)
    setGraceInput(null)
    try {
      const newKey = await onRotate(keyId, grace)
      setRotatedKey({ newKey })
    } finally {
      setRotating(null)
    }
  }

  return (
    <div className="space-y-3">

      {/* New key banner - shown once after rotation */}
      {rotatedKey && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg">
          <p className="text-xs font-semibold text-emerald-800 mb-1">
            {t("rotated_banner")}
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono text-emerald-900 bg-emerald-100 px-2 py-1.5 rounded break-all">
              {rotatedKey.newKey}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(rotatedKey.newKey)}
              className="text-xs text-emerald-700 hover:text-emerald-900 underline whitespace-nowrap"
            >
              {t("copy")}
            </button>
            <button
              onClick={() => setRotatedKey(null)}
              className="text-xs text-emerald-500 hover:text-emerald-700 whitespace-nowrap"
            >
              {t("dismiss")}
            </button>
          </div>
          <p className="text-xs text-emerald-600 mt-1.5">
            {t("rotated_hint")}
          </p>
        </div>
      )}

      <Table className="table-fixed">
        <colgroup>
          <col style={{ width: "20%" }} />
          <col style={{ width: "18%" }} />
          <col style={{ width: "15%" }} />
          <col style={{ width: "15%" }} />
          <col style={{ width: "12%" }} />
          <col style={{ width: "12%" }} />
          <col style={{ width: "8%" }}  />
        </colgroup>
        <THead>
          <tr>
            {[t("name"), t("key_id"), t("department"), t("application"), t("created"), t("last_used"), ""].map((h, i) => (
              <Th key={h || "actions"} align={i === 6 ? "right" : "left"}>{h}</Th>
            ))}
          </tr>
        </THead>
        <TBody>
          {keys.map((key) => {
            // Grace period is only active if expires_at is set AND in the future.
            // ensureUtc parses the API's aware-UTC value (already carries a Z);
            // it must NOT get a second Z appended (that yields an invalid date).
            const inGrace = !!key.expires_at && ensureUtc(key.expires_at) > new Date()

            return (
              <Fragment key={key.key_id}>
                <Tr hover>

                  {/* Name + badges */}
                  <td className="px-4 py-3 text-sm font-medium text-slate-900">
                    <div className="flex flex-col gap-1">
                      {key.name}
                      <div className="flex gap-1 flex-wrap">
                        {key.key_type === "trial" && (
                          <span className="text-xs px-1.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 whitespace-nowrap w-fit">
                            {t("trial")}
                          </span>
                        )}
                        {inGrace && (
                          <span className="text-xs px-1.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 whitespace-nowrap w-fit">
                            {t("grace_active")}
                          </span>
                        )}
                      </div>
                    </div>
                  </td>

                  <td className="px-4 py-3 font-mono text-xs text-slate-500" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {key.key_id}
                  </td>

                  <td className="px-4 py-3 text-xs text-slate-500">
                    {key.dept_name || (key.dept_id ? (
                      <span className="font-mono">{key.dept_id.slice(0, 8)}...</span>
                    ) : (
                      <span className="text-slate-500">-</span>
                    ))}
                  </td>

                  <td className="px-4 py-3 text-xs text-slate-500">
                    {key.app_name || (
                      <span className="text-slate-500">{t("dept_scoped")}</span>
                    )}
                  </td>

                  <td className="px-4 py-3 text-xs text-slate-500">
                    {fmt.timestamp(key.created_at)}
                  </td>

                  <td className="px-4 py-3 text-xs text-slate-600">
                    {key.last_used_at ? timeAgo(key.last_used_at) : t("never")}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {/* Rotate - hidden for API key sessions */}
                      {canWrite && <button
                        onClick={() => { setConfirmRevoke(null); setGraceInput(key.key_id) }}
                        disabled={rotating === key.key_id || !!revoking || inGrace}
                        title={inGrace
                          ? t("rotate_title_grace")
                          : t("rotate_title")
                        }
                        style={{ fontSize: "12px", color: "#1d4ed8", background: "none", border: "none", cursor: "pointer", padding: 0, opacity: (rotating === key.key_id || !!revoking || inGrace) ? 0.3 : 1 }}
                        onMouseEnter={e => { if (!(rotating === key.key_id || !!revoking || inGrace)) (e.currentTarget as HTMLElement).style.textDecoration = "underline" }}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.textDecoration = "none"}
                      >
                        {rotating === key.key_id ? t("rotating") : t("rotate")}
                      </button>}

                      {/* Revoke - hidden for API key sessions */}
                      {canWrite && (
                        <button
                          disabled={revoking === key.key_id}
                          onClick={() => { setGraceInput(null); setConfirmRevoke(key.key_id) }}
                          title={inGrace
                            ? t("revoke_title_grace")
                            : t("revoke_title")
                          }
                          style={{ fontSize: "12px", color: "#dc2626", background: "none", border: "none", cursor: "pointer", padding: 0, opacity: revoking === key.key_id ? 0.3 : 1 }}
                          onMouseEnter={e => { if (revoking !== key.key_id) (e.currentTarget as HTMLElement).style.textDecoration = "underline" }}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.textDecoration = "none"}
                        >
                          {revoking === key.key_id ? t("revoking") : (inGrace ? t("force_revoke") : t("revoke"))}
                        </button>
                      )}
                    </div>
                  </td>
                </Tr>

                {/* Revoke confirmation row */}
                {confirmRevoke === key.key_id && (
                  <tr className="bg-red-50">
                    <td colSpan={7} className="px-3 py-3">
                      <div className="flex items-center gap-3">
                        <p className="text-xs text-red-700 whitespace-nowrap">
                          {inGrace
                            ? t("confirm_revoke_grace_msg")
                            : t("confirm_revoke_msg")
                          }
                        </p>
                        <button
                          onClick={() => { setConfirmRevoke(null); onRevoke(key.key_id) }}
                          style={{ fontSize: "12px", fontWeight: 500, color: "#fff", background: "#dc2626", border: "none", cursor: "pointer", padding: "4px 12px", borderRadius: "4px", whiteSpace: "nowrap" }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#b91c1c"}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "#dc2626"}
                        >
                          {inGrace ? t("force_revoke") : t("confirm_revoke")}
                        </button>
                        <button
                          onClick={() => setConfirmRevoke(null)}
                          style={{ fontSize: "12px", color: "#6b7280", background: "none", border: "none", cursor: "pointer", padding: 0 }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = "#374151"}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = "#6b7280"}
                        >
                          {t("cancel")}
                        </button>
                      </div>
                    </td>
                  </tr>
                )}

                {/* Grace period selector row */}
                {graceInput === key.key_id && (
                  <tr className="bg-blue-50">
                    <td colSpan={7} className="px-3 py-3">
                      <div className="flex items-center gap-3 flex-wrap">
                        <p className="text-xs text-slate-600 whitespace-nowrap">
                          {t("grace_prompt")}
                        </p>
                        <select
                          defaultValue="60"
                          id={`grace-${key.key_id}`}
                          className="text-xs border border-slate-200 rounded px-2 py-1 bg-white text-slate-700"
                        >
                          {GRACE_OPTIONS.map(o => (
                            <option key={o.value} value={o.value}>{t(`grace.${o.key}`)}</option>
                          ))}
                        </select>
                        <button
                          onClick={() => {
                            const sel = document.getElementById(`grace-${key.key_id}`) as HTMLSelectElement
                            handleRotateConfirm(key.key_id, parseInt(sel.value))
                          }}
                          style={{ fontSize: "12px", fontWeight: 500, color: "#fff", background: "#1d4ed8", border: "none", cursor: "pointer", padding: "4px 12px", borderRadius: "4px" }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "#1e40af"}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = "#1d4ed8"}
                        >
                          {t("confirm_rotate")}
                        </button>
                        <button
                          onClick={() => setGraceInput(null)}
                          style={{ fontSize: "12px", color: "#6b7280", background: "none", border: "none", cursor: "pointer", padding: 0 }}
                          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = "#374151"}
                          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = "#6b7280"}
                        >
                          {t("cancel")}
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </TBody>
      </Table>
    </div>
  )
}
