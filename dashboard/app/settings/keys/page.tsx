// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useAuthMode } from "@/hooks/useAuthMode"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card } from "@/components/ui/Card"
import { Button, PlusIcon } from "@/components/ui/Button"
import { ApiKeyTable } from "@/components/settings/ApiKeyTable"
import { CreateKeyModal } from "@/components/settings/CreateKeyModal"
import { PageSpinner } from "@/components/ui/Spinner"
import { getApiKeys, revokeApiKey, rotateApiKey } from "@/lib/api"
import { ApiKeyCreated } from "@/lib/types"

export default function ApiKeysPage() {
  const [showModal, setShowModal] = useState(false)
  const [revoking,  setRevoking]  = useState<string | null>(null)
  const [search,    setSearch]    = useState("")
  const { isJwt } = useAuthMode()

  const { data, isLoading, mutate } = useSWR("api-keys", getApiKeys)

  const handleRevoke = async (keyId: string) => {
    setRevoking(keyId)
    try {
      await revokeApiKey(keyId)
      mutate()
    } finally {
      setRevoking(null)
    }
  }

  const handleRotate = async (keyId: string, gracePeriodMinutes: number): Promise<string> => {
    const result = await rotateApiKey(keyId, gracePeriodMinutes)
    mutate()
    return result.new_api_key
  }

  const handleCreated = (_key: ApiKeyCreated) => {
    mutate()
  }

  return (
    <Shell title="API Keys">
      <div className="space-y-4">

        {/* Description + primary action */}
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Manage access credentials for the WrapSec API.
          </p>
          {isJwt ? (
            <Button size="sm" onClick={() => setShowModal(true)}>
              <PlusIcon /> Create key
            </Button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Button size="sm" disabled><PlusIcon /> Create key</Button>
              <span style={{ fontSize: "11px", color: "#9ca3af" }}>
                Requires admin login —{" "}
                <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
              </span>
            </div>
          )}
        </div>

        <Card padding={false}>
          <div className="px-5 py-3 border-b border-slate-100">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search keys..."
              className="h-8 w-full max-w-xs px-3 text-sm rounded-md border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-700"
            />
          </div>
          <div className="px-5 py-4">
            {isLoading ? (
              <PageSpinner />
            ) : (
              <ApiKeyTable
                keys={(data?.keys ?? []).filter((k) => {
                  if (!search) return true
                  const q = search.toLowerCase()
                  return (
                    k.name.toLowerCase().includes(q) ||
                    k.key_id.toLowerCase().includes(q) ||
                    (k.dept_name ?? "").toLowerCase().includes(q) ||
                    (k.app_name ?? "").toLowerCase().includes(q)
                  )
                })}
                onRevoke={handleRevoke}
                onRotate={handleRotate}
                revoking={revoking}
                canWrite={isJwt}
              />
            )}
          </div>
        </Card>

      </div>

      {showModal && isJwt && (
        <CreateKeyModal
          onCreated={handleCreated}
          onClose={() => setShowModal(false)}
        />
      )}
    </Shell>
  )
}