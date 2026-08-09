// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import useSWR from "swr"
import { useAuthMode } from "@/hooks/useAuthMode"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card } from "@/components/ui/Card"
import { Button, PlusIcon } from "@/components/ui/Button"
import { PageSpinner } from "@/components/ui/Spinner"
import { ConfirmModal } from "@/components/ui/ConfirmModal"
import { IntegrationsTable } from "@/components/settings/IntegrationsTable"
import { CreateIntegrationModal } from "@/components/settings/CreateIntegrationModal"
import { TestResultModal } from "@/components/settings/TestResultModal"
import {
  getWebhooks, testWebhook, deleteWebhook, pauseWebhook, resumeWebhook,
} from "@/lib/api"
import { WebhookEndpoint, WebhookTestResult } from "@/lib/types"

export default function IntegrationsPage() {
  const { isJwt } = useAuthMode()
  const { data, isLoading, mutate } = useSWR("webhooks", getWebhooks)
  const endpoints = data?.endpoints ?? []

  const [showCreate,   setShowCreate]   = useState(false)
  const [testingId,    setTestingId]    = useState<string | null>(null)
  const [pausingId,    setPausingId]    = useState<string | null>(null)
  const [testTarget,   setTestTarget]   = useState<WebhookEndpoint | null>(null)
  const [testResult,   setTestResult]   = useState<WebhookTestResult | null>(null)
  const [testLoading,  setTestLoading]  = useState(false)

  // Delete confirmation (replaces window.confirm) + its own in-flight/error state.
  const [deleteTarget, setDeleteTarget] = useState<WebhookEndpoint | null>(null)
  const [deleting,     setDeleting]     = useState(false)
  const [deleteError,  setDeleteError]  = useState<string | null>(null)

  // Surfaced above the table so a failed pause/resume/test is never silent.
  const [actionError,  setActionError]  = useState<string | null>(null)

  const errMessage = (e: unknown) => (e instanceof Error ? e.message : String(e))

  const handleTest = async (ep: WebhookEndpoint) => {
    setActionError(null)
    setTestTarget(ep); setTestResult(null); setTestLoading(true); setTestingId(ep.id)
    try {
      setTestResult(await testWebhook(ep.id))
    } catch (e) {
      setTestResult({ ok: false, status_code: null, response_snippet: null, duration_ms: null, error: errMessage(e) })
    } finally {
      setTestLoading(false); setTestingId(null)
    }
  }

  const handlePauseToggle = async (ep: WebhookEndpoint) => {
    setActionError(null); setPausingId(ep.id)
    try {
      await (ep.disabled ? resumeWebhook(ep.id) : pauseWebhook(ep.id))
      await mutate()
    } catch (e) {
      setActionError(`Could not ${ep.disabled ? "resume" : "pause"} the integration: ${errMessage(e)}`)
    } finally {
      setPausingId(null)
    }
  }

  const confirmDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true); setDeleteError(null)
    try {
      await deleteWebhook(deleteTarget.id)
      await mutate()
      setDeleteTarget(null)
    } catch (e) {
      setDeleteError(errMessage(e))
    } finally {
      setDeleting(false)
    }
  }

  return (
    <Shell title="Integrations">
      <PageHeader
        description="Connect WrapSec to external security platforms and webhooks."
        actions={
          isJwt ? (
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
          )
        }
      />
      <div className="space-y-4">

        {actionError && (
          <div className="bg-red-50 border border-red-200 rounded-md px-4 py-2.5 flex items-center justify-between">
            <p className="text-xs text-red-700">{actionError}</p>
            <button onClick={() => setActionError(null)} className="text-xs text-red-400 hover:text-red-600">Dismiss</button>
          </div>
        )}

        <Card padding={false}>
          {isLoading ? (
            <div className="py-12"><PageSpinner /></div>
          ) : (
            <IntegrationsTable
              endpoints={endpoints}
              canWrite={isJwt}
              testingId={testingId}
              deletingId={deleting ? deleteTarget?.id ?? null : null}
              pausingId={pausingId}
              onTest={handleTest}
              onPause={handlePauseToggle}
              onResume={handlePauseToggle}
              onDelete={setDeleteTarget}
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

      {deleteTarget && (
        <ConfirmModal
          title="Remove integration"
          message={`Events will stop being forwarded to ${deleteTarget.url}. This cannot be undone.`}
          confirmLabel="Remove"
          danger
          loading={deleting}
          error={deleteError}
          onConfirm={confirmDelete}
          onClose={() => { if (!deleting) { setDeleteTarget(null); setDeleteError(null) } }}
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
