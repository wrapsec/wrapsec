"use client"

import { useState } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { ThresholdForm } from "@/components/settings/ThresholdForm"
import { LayerToggles } from "@/components/settings/LayerToggles"
import { LLMSettingsForm } from "@/components/settings/LLMSettings"
import { TenantSettingsForm } from "@/components/settings/TenantSettings"
import { RetentionSettingsForm } from "@/components/settings/RetentionSettings"
import { ProxySettingsForm } from "@/components/settings/ProxySettings"
import { PageSpinner } from "@/components/ui/Spinner"
import {
  getThresholds,
  getLayers,
  getLLMSettings,
  getTenant,
  getRetentionSettings,
  getProxySettings,
  getStorageSettings,
} from "@/lib/api"

export default function SettingsPage() {
  const { data: tenant,     isLoading: tenantLoading,     mutate: mutateN } =
    useSWR("tenant",       getTenant)

  const { data: thresholds, isLoading: tLoading,          mutate: mutateT } =
    useSWR("thresholds",   getThresholds)

  const { data: layers,     isLoading: lLoading,          mutate: mutateL } =
    useSWR("layers",       getLayers)

  const { data: llm,        isLoading: llmLoading,        mutate: mutateM } =
    useSWR("llm-settings", getLLMSettings)

  const { data: retention,  isLoading: retentionLoading,  mutate: mutateR } =
    useSWR("retention",    getRetentionSettings)

  const { data: storage } = useSWR("storage-settings", getStorageSettings)

  // Proxy config -- 404 is expected when not configured, treat as null
  const { data: proxy, mutate: mutateProxy } = useSWR(
    "proxy-settings",
    () => getProxySettings().catch((e) => {
      if (e.message?.includes("404") || e.message?.includes("NOT_FOUND")) return null
      throw e
    })
  )

  if (tenantLoading || tLoading || lLoading || llmLoading || retentionLoading) {
    return <Shell title="Settings"><PageSpinner /></Shell>
  }

  return (
    <Shell title="Settings">
      <div className="max-w-2xl space-y-5">

        {/* Organisation */}
        <Card>
          <CardHeader
            title="Organisation"
            subtitle="Global settings for this WrapSec installation"
          />
          {tenant && (
            <TenantSettingsForm
              tenant={tenant}
              onUpdated={(t) => mutateN(t, false)}
            />
          )}
        </Card>

        {/* Policy Thresholds */}
        <Card>
          <CardHeader
            title="Policy Thresholds"
            subtitle="Configure risk score thresholds for BLOCK and SANITIZE decisions"
          />
          {thresholds && (
            <ThresholdForm
              thresholds={thresholds}
              onUpdated={(t) => mutateT(t, false)}
            />
          )}
        </Card>

        {/* Detection Layers */}
        <Card>
          <CardHeader
            title="Detection Layers"
            subtitle="Enable or disable individual detection layers"
          />
          {layers && (
            <LayerToggles
              layers={layers}
              onUpdated={(l) => mutateL(l, false)}
            />
          )}
        </Card>

        {/* LLM Configuration */}
        <Card>
          <CardHeader
            title="LLM Configuration"
            subtitle="Configure the LLM provider for semantic detection (Layer 3)"
          />
          {llm && (
            <LLMSettingsForm
              settings={llm}
              onUpdated={(s) => mutateM(s, false)}
            />
          )}
        </Card>

        {/* Proxy Provider -- AI Interaction Firewall */}
        <Card>
          <CardHeader
            title="Proxy Provider"
            subtitle="Configure the LLM provider for proxy mode (POST /v1/chat/completions)"
            action={
              <a
                href="/settings/proxy-interactions"
                className="text-xs text-blue-700 hover:underline"
              >
                View interactions
              </a>
            }
          />
          <ProxySettingsForm
            config={proxy ?? null}
            onUpdated={(c) => mutateProxy(c ?? undefined, false)}
          />
        </Card>

        {/* Audit Log Retention */}
        <Card>
          <CardHeader
            title="Audit Log Retention"
            subtitle="Configure how long audit logs are kept in the database"
          />
          {retention && (
            <RetentionSettingsForm
              retentionDays={retention.retention_days}
              source={retention.source}
              proxyRetentionDays={storage?.retention_days_proxy ?? 7}
              storageMode={storage?.storage_mode ?? "masked"}
              onUpdated={(days) => mutateR(
                { ...retention, retention_days: days },
                false
              )}
            />
          )}
        </Card>

      </div>
    </Shell>
  )
}
