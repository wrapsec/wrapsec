// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import useSWR from "swr"

import { Button } from "@/components/ui/Button"
import { Drawer } from "@/components/ui/Drawer"
import { Input } from "@/components/ui/Input"
import { Spinner } from "@/components/ui/Spinner"
import { getApiKey, updateApiKey } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"
import { checkEntries, parseEntries } from "@/lib/ipAllowlist"
import type { ApiKeyDetail } from "@/lib/types"

/**
 * A key's details, and the networks it may be used from.
 *
 * Editing is confined to administrators, matching the endpoint: whoever can set
 * a restriction can also remove it. A non-administrator sees the details and is
 * told plainly that the networks are not theirs to see, rather than being shown
 * an empty field that reads as "unrestricted".
 */
export function KeyDetailDrawer({
  keyId,
  canWrite,
  onClose,
  onSaved,
}: {
  keyId:    string
  canWrite: boolean
  onClose:  () => void
  onSaved?: () => void
}) {
  const t = useTranslations("pages.keys.drawer")

  const { data, isLoading, error } = useSWR(["api-key", keyId], () => getApiKey(keyId))

  const header = (
    <div>
      <h2 className="text-sm font-semibold text-slate-900">{t("title")}</h2>
      <p className="mt-0.5 text-xs text-slate-600">{keyId}</p>
    </div>
  )

  if (isLoading || !data) {
    return (
      <Drawer onClose={onClose} header={header} label={t("label")}>
        {error != null ? (
          <div className="py-10 text-center">
            <p className="mb-1 text-sm font-semibold text-red-600">{t("load_error")}</p>
            <p className="text-xs text-slate-600">{errorMessage(error)}</p>
          </div>
        ) : (
          <div className="py-10 text-center"><Spinner /></div>
        )}
      </Drawer>
    )
  }

  // Keyed on the credential so opening a different key remounts the form with
  // that key's values, rather than carrying the previous key's edits across.
  return (
    <KeyDetailForm
      key={data.key_id}
      detail={data}
      canWrite={canWrite}
      onClose={onClose}
      onSaved={onSaved}
      header={header}
    />
  )
}

function KeyDetailForm({
  detail,
  canWrite,
  onClose,
  onSaved,
  header,
}: {
  detail:   ApiKeyDetail
  canWrite: boolean
  onClose:  () => void
  onSaved?: () => void
  header:   React.ReactNode
}) {
  const t  = useTranslations("pages.keys.drawer")
  const tc = useTranslations("common")

  const [name,      setName]      = useState(detail.name)
  const [entryText, setEntryText] = useState((detail.ip_allowlist ?? []).join("\n"))
  const [saving,    setSaving]    = useState(false)
  const [saved,     setSaved]     = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const entries = parseEntries(entryText)
  const checked = checkEntries(entries)
  const invalid = checked.filter((c) => c.error !== null)

  // The server decides whether the networks are visible at all. Absent is not
  // the same as empty: one means "not yours to see", the other "no restriction".
  const allowlistVisible = detail.ip_allowlist !== undefined

  const handleSave = async () => {
    if (invalid.length > 0) return
    setSaving(true)
    setSaveError(null)
    try {
      // The parsed list is always sent, so emptying the field clears the
      // restriction. Omitting it would leave no way to remove one.
      await updateApiKey(detail.key_id, name, entries)
      setSaved(true)
      onSaved?.()
    } catch (e) {
      setSaveError(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  const footer = canWrite && allowlistVisible ? (
    <div className="flex items-center justify-end gap-2">
      {saved     && <span className="mr-auto text-xs text-emerald-700">{t("saved")}</span>}
      {saveError && <span className="mr-auto text-xs text-red-600">{saveError}</span>}
      <Button size="sm" variant="secondary" onClick={onClose}>{t("cancel")}</Button>
      <Button
        size="sm"
        onClick={handleSave}
        disabled={saving || invalid.length > 0 || !name.trim()}
      >
        {saving ? t("saving") : t("save")}
      </Button>
    </div>
  ) : undefined

  return (
    <Drawer onClose={onClose} header={header} footer={footer} label={t("label")}>
      <div className="space-y-5">
        <Input
          label={t("name")}
          value={name}
          onChange={(e) => { setName(e.target.value); setSaved(false) }}
          disabled={!canWrite}
        />

        <div>
          <h3 className="text-xs font-medium text-slate-700">{t("allowlist_title")}</h3>

          {!allowlistVisible ? (
            <p className="mt-2 text-xs text-slate-600">{t("allowlist_hidden")}</p>
          ) : (
            <>
              <p className="mt-1 text-xs text-slate-600">{t("allowlist_hint")}</p>

              <textarea
                aria-label={t("allowlist_title")}
                value={entryText}
                onChange={(e) => { setEntryText(e.target.value); setSaved(false) }}
                disabled={!canWrite}
                rows={5}
                spellCheck={false}
                placeholder={t("allowlist_placeholder")}
                className="mt-2 w-full rounded-md border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-slate-900 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-700 disabled:bg-slate-50 disabled:text-slate-600"
              />

              {invalid.length > 0 ? (
                <ul className="mt-2 space-y-1">
                  {invalid.map((c, i) => (
                    <li key={`${c.value}-${i}`} className="text-xs text-red-600">
                      {c.error === "allows_everything"
                        ? t("error_allows_everything", { value: c.value })
                        : t("error_malformed", { value: c.value })}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-xs text-slate-600">
                  {entries.length === 0
                    ? t("allowlist_unrestricted")
                    : t("allowlist_restricted", { count: entries.length })}
                </p>
              )}

              <p className="mt-2 text-xs text-slate-600">{t("rotate_note")}</p>
            </>
          )}
        </div>

        {!canWrite && (
          <p className="text-xs text-slate-600">
            {tc.rich("requires_admin", {
              link: (chunks) => (
                <a href="/login" className="text-purple-700 underline">{chunks}</a>
              ),
            })}
          </p>
        )}
      </div>
    </Drawer>
  )
}
