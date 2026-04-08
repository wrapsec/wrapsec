"use client"

import { useState } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { Button } from "@/components/ui/Button"
import { ApiKeyTable } from "@/components/settings/ApiKeyTable"
import { CreateKeyModal } from "@/components/settings/CreateKeyModal"
import { PageSpinner } from "@/components/ui/Spinner"
import { getApiKeys, revokeApiKey } from "@/lib/api"
import { ApiKeyCreated } from "@/lib/types"

export default function ApiKeysPage() {
  const [showModal, setShowModal] = useState(false)
  const [revoking,  setRevoking]  = useState<string | null>(null)

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

  const handleCreated = (_key: ApiKeyCreated) => {
    mutate()
  }

  return (
    <Shell title="API Keys">
      <div className="max-w-3xl">
        <Card padding={false}>
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100">
            <CardHeader
              title="API Keys"
              subtitle="Manage access credentials for WrapSec API"
            />
            <Button onClick={() => setShowModal(true)} size="sm">
              Create key
            </Button>
          </div>

          <div className="px-5 py-4">
            {isLoading ? (
              <PageSpinner />
            ) : (
              <ApiKeyTable
                keys={data?.keys ?? []}
                onRevoke={handleRevoke}
                revoking={revoking}
              />
            )}
          </div>
        </Card>
      </div>

      {showModal && (
        <CreateKeyModal
          onCreated={handleCreated}
          onClose={() => setShowModal(false)}
        />
      )}
    </Shell>
  )
}