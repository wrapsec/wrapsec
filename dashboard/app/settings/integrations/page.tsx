// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import useSWR from "swr"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Shell } from "@/components/layout/Shell"
import { Card } from "@/components/ui/Card"
import { Button, PlusIcon } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import { IntegrationsTable } from "@/components/settings/IntegrationsTable"
import { CreateIntegrationModal } from "@/components/settings/CreateIntegrationModal"
import { TestResultModal } from "@/components/settings/TestResultModal"
import { getWebhooks, testWebhook, deleteWebhook } from "@/lib/api"
import { WebhookEndpoint, WebhookTestResult } from "@/lib/types"

export default function IntegrationsPage() {
  const { isJwt } = useAuthMode()
  const { data, isLoading, mutate } = useSWR("webhooks", getWebhooks)
  const endpoints = data?.endpoints ?? []

  const [showCreate,  setShowCreate]  = useState(false)
  const [testingId,   setTestingId]   = useState<string | null>(null)
  const [deletingId,  setDeletingId]  = useState<string | null>(null)
  const [testTarget,  setTestTarget]  = useState<WebhookEndpoint | null>(null)
  const [testResult,  setTestResult]  = useState<WebhookTestResult | null>(null)
  const [testLoading, setTestLoading] = useState(false)

  const handleTest = async (ep: WebhookEndpoint) => {
    setTestTarget(ep); setTestResult(null); setTestLoading(true); setTestingId(ep.id)
    try {
      setTestResult(await testWebhook(ep.id))
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e)
      setTestResult({ ok: false, status_code: null, response_snippet: null, duration_ms: null, error })
    } finally {
      setTestLoading(false); setTestingId(null)
    }
  }

  const handleDelete = async (ep: WebhookEndpoint) => {
    if (!window.confirm("Remove this integration? Events will stop being forwarded to it.")) return
    setDeletingId(ep.id)
    try {
      await deleteWebhook(ep.id)
      await mutate()
    } finally {
      setDeletingId(null)
    }
  }

  return (
    <Shell title="Integrations">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Forward BLOCK and SANITIZE events to your SIEM (Splunk, Datadog, Microsoft
            Sentinel, Elastic) or a signed webhook.
          </p>
          {isJwt ? (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <PlusIcon /> Add integration
            </Button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Button size="sm" disabled><PlusIcon /> Add integration</Button>
              <span style={{ fontSize: "11px", color: "#9ca3af" }}>
                Requires admin login -{" "}
                <a href="/login" style={{ color: "#670FEF", textDecoration: "underline" }}>sign in with email</a>
              </span>
            </div>
          )}
        </div>

        <Card padding={false}>
          {isLoading ? (
            <div className="py-12"><PageSpinner /></div>
          ) : (
            <IntegrationsTable
              endpoints={endpoints}
              canWrite={isJwt}
              testingId={testingId}
              deletingId={deletingId}
              onTest={handleTest}
              onDelete={handleDelete}
            />
          )}
        </Card>
      </div>

      {showCreate && (
        <CreateIntegrationModal
          onCreated={() => mutate()}
          onClose={() => setShowCreate(false)}
        />
      )}

      {testTarget && (
        <TestResultModal
          endpointLabel={testTarget.url}
          result={testResult}
          loading={testLoading}
          onClose={() => { setTestTarget(null); setTestResult(null) }}
        />
      )}
    </Shell>
  )
}
