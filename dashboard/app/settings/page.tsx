// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
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
import { RateLimitSettingsForm } from "@/components/settings/RateLimitSettings"
import { ProxySettingsForm } from "@/components/settings/ProxySettings"
import { PageSpinner } from "@/components/ui/Spinner"
import {
  getThresholds,
  getLayers,
  getLLMSettings,
  getTenant,
  getRetentionSettings,
  getRateLimitSettings,
  getProxySettings,
  getStorageSettings,
} from "@/lib/api"

const TABS = [
  { id: "organisation", label: "Organisation" },
  { id: "thresholds",   label: "Thresholds" },
  { id: "detection",    label: "Detection" },
  { id: "rate-limits",  label: "Rate Limits" },
  { id: "llm",          label: "LLM" },
  { id: "proxy",        label: "Proxy" },
  { id: "retention",    label: "Retention" },
] as const

type TabId = typeof TABS[number]["id"]

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>("organisation")

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

  const { data: rateLimit, mutate: mutateRL } = useSWR("rate-limit-settings", getRateLimitSettings)
  const { data: storage } = useSWR("storage-settings", getStorageSettings)

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
      <div className="max-w-2xl">

        {/* Tab bar */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: "0",
          borderBottom: "1px solid #e5e7eb", marginBottom: "20px",
        }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: "8px 14px",
                fontSize: "13px",
                fontWeight: activeTab === tab.id ? 600 : 400,
                color: activeTab === tab.id ? "#670FEF" : "#6b7280",
                background: "none",
                border: "none",
                borderBottom: activeTab === tab.id ? "2px solid #670FEF" : "2px solid transparent",
                marginBottom: "-1px",
                cursor: "pointer",
                whiteSpace: "nowrap",
                transition: "color 0.15s",
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab panels */}
        {activeTab === "organisation" && (
          <Card>
            <CardHeader
              title="Organisation"
              subtitle="Global settings for this WrapSec installation"
            />
            {tenant && (
              <TenantSettingsForm
                tenant={tenant}
                onUpdated={(t) => mutateN(t, false)}
                blockThreshold={thresholds?.block_threshold}
                sanitizeThreshold={thresholds?.sanitize_threshold}
                ruleEnabled={layers?.rule_enabled}
                mlEnabled={layers?.ml_enabled}
                llmEnabled={layers?.llm_enabled}
                rateLimitPerMinute={rateLimit?.per_minute}
                rateLimitSource={rateLimit?.source}
              />
            )}
          </Card>
        )}

        {activeTab === "thresholds" && (
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
        )}

        {activeTab === "detection" && (
          <Card>
            <CardHeader
              title="Detection Layers"
              subtitle="Enable or disable individual detection layers"
            />
            {layers && (
              <LayerToggles
                layers={layers}
                llmTrigger={llm?.llm_trigger ?? 0.3}
                onUpdated={(l) => mutateL(l, false)}
              />
            )}
          </Card>
        )}

        {activeTab === "rate-limits" && (
          <Card>
            <CardHeader
              title="Rate Limits"
              subtitle="Configure request rate limits for live and trial keys"
            />
            <RateLimitSettingsForm
              perMinute={rateLimit?.per_minute ?? 60}
              source={rateLimit?.source ?? "environment"}
              trialLimit={10}
              onUpdated={(perMinute, source) => mutateRL({ per_minute: perMinute, source }, false)}
            />
          </Card>
        )}

        {activeTab === "llm" && (
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
        )}

        {activeTab === "proxy" && (
          <Card>
            <CardHeader
              title="Proxy Provider"
              subtitle="Configure the LLM provider for proxy mode (POST /v1/chat/completions)"
            />
            <ProxySettingsForm
              config={proxy ?? null}
              onUpdated={(c) => mutateProxy(c ?? undefined, false)}
            />
          </Card>
        )}

        {activeTab === "retention" && (
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
        )}

      </div>
    </Shell>
  )
}
