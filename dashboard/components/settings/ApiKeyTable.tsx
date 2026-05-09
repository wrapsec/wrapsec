// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { useState, Fragment } from "react"
import { Button } from "@/components/ui/Button"
import { ApiKey } from "@/lib/types"
import { formatTimestamp, timeAgo } from "@/lib/utils"

interface ApiKeyTableProps {
  keys:      ApiKey[]
  onRevoke:  (keyId: string) => void
  onRotate:  (keyId: string, gracePeriodMinutes: number) => Promise<string>
  revoking:  string | null
  canWrite?: boolean   // false = API key session, hide write actions
}

export function ApiKeyTable({ keys, onRevoke, onRotate, revoking, canWrite = true }: ApiKeyTableProps) {
  const [rotating,       setRotating]       = useState<string | null>(null)
  const [rotatedKey,     setRotatedKey]     = useState<{ newKey: string } | null>(null)
  const [graceInput,     setGraceInput]     = useState<string | null>(null)
  const [confirmRevoke,  setConfirmRevoke]  = useState<string | null>(null)

  if (keys.length === 0) {
    return (
      <div style={{ padding: "48px 16px", textAlign: "center" }}>
        <div style={{ fontSize: "20px", marginBottom: "8px" }}>🔑</div>
        <div style={{ fontSize: "13px", fontWeight: 600, color: "#374151", marginBottom: "4px" }}>No API keys yet</div>
        <div style={{ fontSize: "12px", color: "#9ca3af" }}>Create a key to start sending requests to the gateway</div>
      </div>
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

      {/* New key banner — shown once after rotation */}
      {rotatedKey && (
        <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg">
          <p className="text-xs font-semibold text-emerald-800 mb-1">
            Key rotated — copy the new key now. It will not be shown again.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono text-emerald-900 bg-emerald-100 px-2 py-1.5 rounded break-all">
              {rotatedKey.newKey}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(rotatedKey.newKey)}
              className="text-xs text-emerald-700 hover:text-emerald-900 underline whitespace-nowrap"
            >
              Copy
            </button>
            <button
              onClick={() => setRotatedKey(null)}
              className="text-xs text-emerald-500 hover:text-emerald-700 whitespace-nowrap"
            >
              Dismiss
            </button>
          </div>
          <p className="text-xs text-emerald-600 mt-1.5">
            Old key will expire after the grace period. Update your integrations before it expires.
          </p>
        </div>
      )}

      <table className="w-full text-sm" style={{ tableLayout: "fixed" }}>
          <colgroup>
            <col style={{ width: "20%" }} />
            <col style={{ width: "18%" }} />
            <col style={{ width: "15%" }} />
            <col style={{ width: "15%" }} />
            <col style={{ width: "12%" }} />
            <col style={{ width: "12%" }} />
            <col style={{ width: "8%" }}  />
          </colgroup>
          <thead>
          <tr className="border-b border-slate-100">
            {["Name", "Key ID", "Department", "Application", "Created", "Last Used", ""].map((h) => (
              <th key={h} className="text-left pb-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {keys.map((key) => {
            // Grace period is only active if expires_at is set AND in the future
            // expires_at from API has no timezone — treat as UTC
            const inGrace = !!key.expires_at && new Date(key.expires_at + "Z") > new Date()

            return (
              <Fragment key={key.key_id}>
                <tr className="border-b border-slate-50">

                  {/* Name + badges */}
                  <td className="py-3 text-sm font-medium text-slate-900">
                    <div className="flex flex-col gap-1">
                      {key.name}
                      <div className="flex gap-1 flex-wrap">
                        {key.key_type === "trial" && (
                          <span className="text-xs px-1.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 whitespace-nowrap w-fit">
                            Trial
                          </span>
                        )}
                        {inGrace && (
                          <span className="text-xs px-1.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 whitespace-nowrap w-fit">
                            Expiring — grace period active
                          </span>
                        )}
                      </div>
                    </div>
                  </td>

                  <td className="py-3 font-mono text-xs text-slate-500" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {key.key_id}
                  </td>

                  <td className="py-3 text-xs text-slate-500">
                    {key.dept_name || (key.dept_id ? (
                      <span className="font-mono">{key.dept_id.slice(0, 8)}...</span>
                    ) : (
                      <span className="text-slate-300">—</span>
                    ))}
                  </td>

                  <td className="py-3 text-xs text-slate-500">
                    {key.app_name || (
                      <span className="text-slate-300">Dept-scoped</span>
                    )}
                  </td>

                  <td className="py-3 text-xs text-slate-500">
                    {formatTimestamp(key.created_at)}
                  </td>

                  <td className="py-3 text-xs text-slate-400">
                    {key.last_used_at ? timeAgo(key.last_used_at) : "Never"}
                  </td>

                  {/* Actions */}
                  <td className="py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {/* Rotate — hidden for API key sessions */}
                      {canWrite && <button
                        onClick={() => setGraceInput(key.key_id)}
                        disabled={rotating === key.key_id || !!revoking || inGrace}
                        title={inGrace
                          ? "This key is already in its grace period. Rotate the new key instead."
                          : "Rotate this key and generate a new secret"
                        }
                        className="text-xs text-slate-500 hover:text-blue-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                      >
                        {rotating === key.key_id ? "Rotating..." : "Rotate"}
                      </button>}

                      {/* Revoke — hidden for API key sessions; two-step inline confirm */}
                      {canWrite && (
                        confirmRevoke === key.key_id ? (
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-red-600 whitespace-nowrap">Revoke?</span>
                            <button
                              onClick={() => { setConfirmRevoke(null); onRevoke(key.key_id) }}
                              className="text-xs font-medium text-red-600 hover:text-red-800 whitespace-nowrap"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setConfirmRevoke(null)}
                              className="text-xs text-slate-500 hover:text-slate-700"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <Button
                            variant="danger"
                            size="sm"
                            loading={revoking === key.key_id}
                            onClick={() => { setGraceInput(null); setConfirmRevoke(key.key_id) }}
                            title={inGrace
                              ? "Immediately revokes this key — integrations still using it will stop working now"
                              : "Revoke this key permanently"
                            }
                          >
                            {inGrace ? "Force revoke" : "Revoke"}
                          </Button>
                        )
                      )}
                    </div>
                  </td>
                </tr>

                {/* Grace period selector row */}
                {graceInput === key.key_id && (
                  <tr className="bg-blue-50">
                    <td colSpan={7} className="px-3 py-3">
                      <div className="flex items-center gap-3 flex-wrap">
                        <p className="text-xs text-slate-600 whitespace-nowrap">
                          How long should the old key remain valid?
                        </p>
                        <select
                          defaultValue="60"
                          id={`grace-${key.key_id}`}
                          className="text-xs border border-slate-200 rounded px-2 py-1 bg-white text-slate-700"
                        >
                          <option value="15">15 minutes</option>
                          <option value="30">30 minutes</option>
                          <option value="60">1 hour</option>
                          <option value="360">6 hours</option>
                          <option value="1440">24 hours</option>
                        </select>
                        <button
                          onClick={() => {
                            const sel = document.getElementById(`grace-${key.key_id}`) as HTMLSelectElement
                            handleRotateConfirm(key.key_id, parseInt(sel.value))
                          }}
                          className="text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 px-3 py-1 rounded transition-colors"
                        >
                          Confirm rotate
                        </button>
                        <button
                          onClick={() => setGraceInput(null)}
                          className="text-xs text-slate-500 hover:text-slate-700"
                        >
                          Cancel
                        </button>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
