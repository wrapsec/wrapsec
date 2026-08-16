// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useEffect } from "react"
import { useTranslations } from "next-intl"
import { Button } from "@/components/ui/Button"
import { WebhookTestResult } from "@/lib/types"

interface Props {
  endpointLabel: string
  result:        WebhookTestResult | null
  loading:       boolean
  onClose:       () => void
}

// SECURITY: response_snippet and error come from the (attacker-controllable)
// receiver. They are rendered as plain text inside <pre> -- React escapes JSX
// children, and we never use dangerouslySetInnerHTML -- so a malicious
// destination cannot inject markup/script into the dashboard.
export function TestResultModal({ endpointLabel, result, loading, onClose }: Props) {
  const t = useTranslations("pages.integrations.test_modal")
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", h)
    return () => document.removeEventListener("keydown", h)
  }, [onClose])

  const ok = result?.ok === true

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg border border-slate-200 w-full max-w-lg p-6 shadow-lg">
        <h2 className="text-base font-semibold text-slate-900 mb-1">{t("title")}</h2>
        <p className="text-xs text-slate-600 mb-4 break-all">{endpointLabel}</p>

        {loading ? (
          <p className="text-sm text-slate-500 py-6 text-center">{t("sending")}</p>
        ) : result ? (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span
                style={{
                  display: "inline-flex", alignItems: "center", gap: "6px",
                  padding: "3px 10px", fontSize: "12px", fontWeight: 600,
                  borderRadius: "6px",
                  ...(ok
                    ? { background: "#f0fdf4", color: "#15803d", border: "1px solid #bbf7d0" }
                    : { background: "#fef2f2", color: "#b91c1c", border: "1px solid #fecaca" }),
                }}
              >
                <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "currentColor" }} />
                {ok ? t("delivered") : t("failed")}
              </span>
              {result.status_code != null && (
                <span className="text-xs text-slate-500">{t("http_status", { code: result.status_code })}</span>
              )}
              {result.duration_ms != null && (
                <span className="text-xs text-slate-600">{result.duration_ms} ms</span>
              )}
            </div>

            {result.error && (
              <div>
                <div className="text-xs font-medium text-slate-600 mb-1">{t("error")}</div>
                <pre className="text-xs text-red-700 bg-red-50 border border-red-100 rounded-md p-2 whitespace-pre-wrap break-all max-h-40 overflow-auto">
                  {result.error}
                </pre>
              </div>
            )}

            {result.response_snippet && (
              <div>
                <div className="text-xs font-medium text-slate-600 mb-1">{t("receiver_response")}</div>
                <pre className="text-xs text-slate-700 bg-slate-50 border border-slate-200 rounded-md p-2 whitespace-pre-wrap break-all max-h-48 overflow-auto">
                  {result.response_snippet}
                </pre>
              </div>
            )}
          </div>
        ) : null}

        <div className="flex justify-end mt-5">
          <Button size="sm" variant="secondary" onClick={onClose}>{t("close")}</Button>
        </div>
      </div>
    </div>
  )
}
