// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import useSWR from "swr"

import { Button } from "@/components/ui/Button"
import { DetailGrid, DetailRow, SectionLabel } from "@/components/ui/DetailRow"
import { Drawer } from "@/components/ui/Drawer"
import { Input } from "@/components/ui/Input"
import { Spinner } from "@/components/ui/Spinner"
import { useFormat } from "@/hooks/useFormat"
import { getApiKey, getKeyAddresses, updateApiKey } from "@/lib/api"
import { errorMessage } from "@/lib/apiError"
import {
  checkEntries,
  parseEntries,
  suggestEntry,
  uncoveredAddresses,
} from "@/lib/ipAllowlist"
import type { ApiKeyDetail, KeyAddress } from "@/lib/types"

/** How far back the observed and refused lists look. */
const ADDRESS_WINDOW_DAYS = 30

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

  // The drawer shell adds no padding of its own, so each slot brings its own.
  // pr-12 keeps the title clear of the close button pinned at the top right.
  const header = (
    <div className="px-6 py-4 pr-12">
      <h2 className="text-sm font-semibold text-slate-900">{t("title")}</h2>
      <p className="mt-0.5 font-mono text-xs text-slate-600">{keyId}</p>
    </div>
  )

  if (isLoading || !data) {
    return (
      <Drawer onClose={onClose} header={header} label={t("label")}>
        {error != null ? (
          <div className="m-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3">
            <p className="mb-1 text-sm font-semibold text-red-700">{t("load_error")}</p>
            <p className="text-xs text-red-700">{errorMessage(error)}</p>
          </div>
        ) : (
          <div className="flex items-center justify-center py-16"><Spinner className="h-6 w-6" /></div>
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
  const t   = useTranslations("pages.keys.drawer")
  const tc  = useTranslations("common")
  const fmt = useFormat()

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

  // Only fetched when the operator can act on it. The endpoint is administrator
  // only, so asking as anyone else would produce a refusal that has to be told
  // apart from an empty list.
  const { data: addresses, error: addressError } = useSWR(
    allowlistVisible ? ["key-addresses", detail.key_id] : null,
    () => getKeyAddresses(detail.key_id, ADDRESS_WINDOW_DAYS),
  )

  const addEntry = (address: string) => {
    const entry = suggestEntry(address)
    if (entries.includes(entry)) return
    setEntryText([...entries, entry].join("\n"))
    setSaved(false)
  }

  // The warning that makes this feature safe to use. An operator setting a
  // restriction is working from what they believe the traffic is; this compares
  // that belief against what the key has actually been doing. Addresses the list
  // cannot parse count as stopped, so an unreadable one produces a warning
  // rather than silence.
  const wouldStop = addresses
    ? uncoveredAddresses(entries, addresses.observed.map((a) => a.ip_address))
    : []

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
    <div className="flex items-center justify-end gap-2 px-6 py-3">
      {saved     && <span className="mr-auto text-xs text-emerald-700">{t("saved")}</span>}
      {saveError && <span className="mr-auto text-xs text-red-600">{saveError}</span>}
      <Button size="sm" variant="secondary" onClick={onClose}>{t("cancel")}</Button>
      <Button
        size="sm"
        onClick={handleSave}
        disabled={saving || invalid.length > 0 || !name.trim()}
      >
        {saving ? t("saving") : wouldStop.length > 0 ? t("save_anyway") : t("save")}
      </Button>
    </div>
  ) : undefined

  return (
    <Drawer onClose={onClose} header={header} footer={footer} label={t("label")}>
      <div className="px-6 py-5 space-y-6">
        <div>
          <SectionLabel>{t("summary")}</SectionLabel>
          <DetailGrid>
            <DetailRow label={t("key_type")}>{detail.key_type}</DetailRow>
            <DetailRow label={t("department")}>{detail.dept_name ?? "--"}</DetailRow>
            <DetailRow label={t("application")}>{detail.app_name ?? "--"}</DetailRow>
            <DetailRow label={t("created")}>{fmt.timestamp(detail.created_at)}</DetailRow>
            <DetailRow label={t("last_used")}>
              {detail.last_used_at ? fmt.timestamp(detail.last_used_at) : "--"}
            </DetailRow>
            <DetailRow label={t("expires")}>
              {detail.expires_at ? fmt.timestamp(detail.expires_at) : "--"}
            </DetailRow>
          </DetailGrid>
        </div>

        <Input
          label={t("name")}
          value={name}
          onChange={(e) => { setName(e.target.value); setSaved(false) }}
          disabled={!canWrite}
        />

        <div>
          <SectionLabel>{t("allowlist_title")}</SectionLabel>

          {!allowlistVisible ? (
            <p className="text-xs text-slate-600">{t("allowlist_hidden")}</p>
          ) : (
            <>
              <p className="text-xs text-slate-600">{t("allowlist_hint")}</p>

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

              {wouldStop.length > 0 && (
                <div
                  role="alert"
                  className="mt-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2"
                >
                  <p className="text-xs font-semibold text-amber-900">
                    {t("lockout_warning_title")}
                  </p>
                  <p className="mt-1 text-xs text-amber-900">
                    {t("lockout_warning_body", {
                      count:  wouldStop.length,
                      days:   ADDRESS_WINDOW_DAYS,
                      values: wouldStop.join(", "),
                    })}
                  </p>
                </div>
              )}

              <p className="mt-2 text-xs text-slate-600">{t("rotate_note")}</p>
            </>
          )}
        </div>

        {allowlistVisible && (
          addressError != null ? (
            <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2">
              <p className="text-xs text-amber-900">{t("addresses_error")}</p>
            </div>
          ) : (
            <>
              <AddressList
                title={t("addresses_observed_title")}
                empty={t("addresses_observed_empty", { days: ADDRESS_WINDOW_DAYS })}
                rows={addresses?.observed}
                label={(count) => t("addresses_requests", { count })}
                canAdd={canWrite}
                onAdd={addEntry}
                isAdded={(ip) => entries.includes(suggestEntry(ip))}
              />

              <AddressList
                title={t("addresses_denied_title")}
                empty={t("addresses_denied_empty")}
                hint={t("addresses_denied_hint")}
                rows={addresses?.denied}
                label={(count) => t("addresses_refusals", { count })}
                canAdd={canWrite}
                confirmBeforeAdd
                onAdd={addEntry}
                isAdded={(ip) => entries.includes(suggestEntry(ip))}
              />
            </>
          )
        )}

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

/**
 * One list of addresses, with a way to add each to the field above.
 *
 * The refused list adds a confirmation step, and that difference is the point:
 * an address in the observed list is one this credential already authenticated
 * from, while an address in the refused list is by definition one the current
 * restriction rejected. That may be a service that moved, or it may be someone
 * else holding the key. Adding it must be a deliberate act, not a stray click
 * next to the list an operator is used to clicking through.
 */
function AddressList({
  title,
  empty,
  hint,
  rows,
  label,
  canAdd,
  confirmBeforeAdd = false,
  onAdd,
  isAdded,
}: {
  title:             string
  empty:             string
  hint?:             string
  rows:              KeyAddress[] | undefined
  label:             (count: number) => string
  canAdd:            boolean
  confirmBeforeAdd?: boolean
  onAdd:             (ip: string) => void
  isAdded:           (ip: string) => boolean
}) {
  const t   = useTranslations("pages.keys.drawer")
  const fmt = useFormat()

  const [confirming, setConfirming] = useState<string | null>(null)

  return (
    <div>
      <SectionLabel>{title}</SectionLabel>
      {hint && <p className="-mt-2 mb-2 text-xs text-slate-600">{hint}</p>}

      {rows === undefined ? (
        <div className="py-3 text-center"><Spinner /></div>
      ) : rows.length === 0 ? (
        <p className="text-xs text-slate-600">{empty}</p>
      ) : (
        <ul className="divide-y divide-slate-100 border-y border-slate-100">
          {rows.map((row) => {
            const added = isAdded(row.ip_address)
            return (
              <li key={row.ip_address} className="flex flex-wrap items-center gap-3 py-2">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-xs text-slate-900">{row.ip_address}</p>
                  <p className="mt-0.5 flex gap-2 text-xs text-slate-600">
                    <span>{label(row.count)}</span>
                    <span>{fmt.timestamp(row.last_seen)}</span>
                  </p>
                </div>

                {!canAdd ? null : added ? (
                  <span className="shrink-0 text-xs text-slate-600">{t("addresses_added")}</span>
                ) : confirming === row.ip_address ? (
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="text-xs text-slate-700">
                      {t("addresses_confirm", { value: suggestEntry(row.ip_address) })}
                    </span>
                    <Button
                      size="sm"
                      onClick={() => { onAdd(row.ip_address); setConfirming(null) }}
                    >
                      {t("addresses_confirm_yes")}
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => setConfirming(null)}>
                      {t("addresses_confirm_no")}
                    </Button>
                  </div>
                ) : (
                  <Button
                    size="sm"
                    variant="secondary"
                    className="shrink-0"
                    onClick={() =>
                      confirmBeforeAdd ? setConfirming(row.ip_address) : onAdd(row.ip_address)
                    }
                  >
                    {t("addresses_add")}
                  </Button>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
