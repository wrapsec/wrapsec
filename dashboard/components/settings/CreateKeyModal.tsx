"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { ApiKeyCreated } from "@/lib/types"
import { createApiKey } from "@/lib/api"

interface CreateKeyModalProps {
  onCreated: (key: ApiKeyCreated) => void
  onClose:   () => void
}

export function CreateKeyModal({ onCreated, onClose }: CreateKeyModalProps) {
  const [name,    setName]    = useState("")
  const [loading, setLoading] = useState(false)
  const [created, setCreated] = useState<ApiKeyCreated | null>(null)
  const [error,   setError]   = useState<string | null>(null)

  const handleCreate = async () => {
    if (!name.trim()) return
    setLoading(true)
    setError(null)
    try {
      const key = await createApiKey(name.trim())
      setCreated(key)
      onCreated(key)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg border border-slate-200 w-full max-w-md p-6 shadow-lg">
        <h2 className="text-base font-semibold text-slate-900 mb-4">
          Create API Key
        </h2>

        {!created ? (
          <div className="space-y-4">
            <Input
              label="Key name"
              placeholder="e.g. erp-system"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            {error && (
              <p className="text-xs text-red-600">{error}</p>
            )}
            <div className="flex justify-end gap-3">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button
                loading={loading}
                disabled={!name.trim()}
                onClick={handleCreate}
              >
                Create
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
              <p className="text-xs font-medium text-amber-800 mb-1">
                Copy this key now — it will not be shown again
              </p>
              <p className="font-mono text-xs text-amber-900 break-all">
                {created.api_key}
              </p>
            </div>
            <div className="flex justify-end">
              <Button onClick={onClose}>Done</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}