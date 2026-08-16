// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState, useEffect, FormEvent } from "react"
import { useTranslations } from "next-intl"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { Button } from "@/components/ui/Button"
import { useFormat } from "@/hooks/useFormat"

const REQUIREMENTS = [
  { key: "min_length", test: (p: string) => p.length >= 8 },
  { key: "uppercase",  test: (p: string) => /[A-Z]/.test(p) },
  { key: "lowercase",  test: (p: string) => /[a-z]/.test(p) },
  { key: "digit",      test: (p: string) => /\d/.test(p) },
]

interface UserProfile {
  email:                 string
  role:                  string
  dept_id:               string | null
  tenant_id:             string
  force_password_change: boolean
  last_login_at:         string | null
}

// ── Change password modal ──────────────────────────────────────────────────────

function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const t  = useTranslations("pages.profile.modal")
  const tr = useTranslations("pages.profile.password_req")
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  const [current, setCurrent] = useState("")
  const [next,    setNext]    = useState("")
  const [confirm, setConfirm] = useState("")
  const [saving,  setSaving]  = useState(false)
  const [error,   setError]   = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const reqsMet        = REQUIREMENTS.every(r => r.test(next))
  const passwordsMatch = next === confirm && next.length > 0

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!reqsMet || !passwordsMatch) return
    setSaving(true)
    try {
      const res = await fetch("/api/proxy/v1/auth/change-password", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ current_password: current, new_password: next }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        setError(
          data?.error?.code === "INVALID_PASSWORD"
            ? t("err_incorrect")
            : data?.error?.message || t("err_failed")
        )
        return
      }
      setSuccess(true)
    } catch {
      setError(t("err_generic"))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-sm bg-white rounded-xl border border-slate-200 shadow-xl p-6">
        {success ? (
          <div className="text-center">
            <div className="flex justify-center mb-3">
              <div className="h-10 w-10 rounded-full bg-green-100 flex items-center justify-center">
                <svg className="h-5 w-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
            </div>
            <p className="text-sm font-semibold text-slate-900 mb-1">{t("success_title")}</p>
            <p className="text-xs text-slate-500 mb-4">{t("success_body")}</p>
            <Button onClick={onClose}>{t("done")}</Button>
          </div>
        ) : (
          <>
            <p className="text-sm font-semibold text-slate-900 mb-4">{t("title")}</p>
            <form onSubmit={handleSubmit} className="space-y-3">
              <Field label={t("current")}>
                <input
                  type="password" value={current}
                  onChange={e => setCurrent(e.target.value)}
                  required disabled={saving}
                  autoComplete="current-password"
                  className={inputCls}
                />
              </Field>
              <Field label={t("new")}>
                <input
                  type="password" value={next}
                  onChange={e => setNext(e.target.value)}
                  required disabled={saving}
                  autoComplete="new-password"
                  className={inputCls}
                />
                {next.length > 0 && (
                  <ul className="mt-1.5 space-y-1">
                    {REQUIREMENTS.map(r => (
                      <li key={r.key} className={`flex items-center gap-1.5 text-xs ${r.test(next) ? "text-green-600" : "text-slate-600"}`}>
                        <span>{r.test(next) ? "" : "○"}</span>{tr(r.key)}
                      </li>
                    ))}
                  </ul>
                )}
              </Field>
              <Field label={t("confirm")}>
                <input
                  type="password" value={confirm}
                  onChange={e => setConfirm(e.target.value)}
                  required disabled={saving}
                  autoComplete="new-password"
                  className={`${inputCls} ${confirm.length > 0 && !passwordsMatch ? "border-red-400" : ""}`}
                />
                {confirm.length > 0 && !passwordsMatch && (
                  <p className="mt-1 text-xs text-red-500">{t("mismatch")}</p>
                )}
              </Field>
              {error && <p className="text-xs text-red-600">{error}</p>}
              <div className="flex gap-3 pt-1">
                <Button type="submit" loading={saving} disabled={!reqsMet || !passwordsMatch || !current}>
                  {t("submit")}
                </Button>
                <button type="button" onClick={onClose} className="text-sm text-slate-500 hover:text-slate-700">
                  {t("cancel")}
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function ProfilePage() {
  const fmt = useFormat()
  const t   = useTranslations("pages.profile")
  const [profile,       setProfile]       = useState<UserProfile | null>(null)
  const [loading,       setLoading]       = useState(true)
  const [isApiKey,      setIsApiKey]      = useState(false)
  const [showChangePass, setShowChangePass] = useState(false)

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch("/api/proxy/v1/auth/me")
        if (res.ok) setProfile(await res.json())
        else if (res.status === 403) setIsApiKey(true)
      } catch {
        // ignore
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const formatDate = (iso: string | null) =>
    iso ? fmt.timestamp(iso) : t("never")

  return (
    <Shell title={t("title")}>
      <div className="max-w-md space-y-5">
        <Card>
          <CardHeader
            title={t("account")}
            action={
              !isApiKey && !loading && profile ? (
                <button
                  onClick={() => setShowChangePass(true)}
                  className="text-xs text-blue-700 hover:underline"
                >
                  {t("change_password")}
                </button>
              ) : undefined
            }
          />

          {loading ? (
            <p className="text-sm text-slate-600">{t("loading")}</p>
          ) : isApiKey ? (
            <p className="text-sm text-slate-600">
              {t("api_key_notice")}
            </p>
          ) : profile ? (
            <div className="space-y-1">
              <Row label={t("row.email")}      value={profile.email} />
              <Row label={t("row.role")}       value={profile.role} />
              <Row label={t("row.tenant")}     value={profile.tenant_id} mono />
              <Row label={t("row.last_login")} value={formatDate(profile.last_login_at)} />
              {profile.force_password_change && (
                <p className="text-xs text-amber-600 font-medium pt-2">
                  {t("password_required")}
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-600">{t("unable_to_load")}</p>
          )}
        </Card>
      </div>

      {showChangePass && (
        <ChangePasswordModal onClose={() => setShowChangePass(false)} />
      )}
    </Shell>
  )
}

const inputCls = "h-9 px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-700 disabled:opacity-50 w-full"

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium text-slate-700">{label}</label>
      {children}
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-slate-50 last:border-0">
      <span className="text-xs text-slate-500">{label}</span>
      <span className={`text-xs text-slate-900 ${mono ? "font-mono" : "font-medium"}`}>{value}</span>
    </div>
  )
}
