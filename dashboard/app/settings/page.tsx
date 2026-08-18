// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card, CardHeader } from "@/components/ui/Card"
import { ThresholdForm } from "@/components/settings/ThresholdForm"
import { LayerToggles } from "@/components/settings/LayerToggles"
import { LLMSettingsForm } from "@/components/settings/LLMSettings"
import { TenantSettingsForm } from "@/components/settings/TenantSettings"
import { RetentionSettingsForm } from "@/components/settings/RetentionSettings"
import { RateLimitSettingsForm } from "@/components/settings/RateLimitSettings"
import { AdminLimitsForm } from "@/components/settings/AdminLimitsForm"
import { ProxySettingsForm } from "@/components/settings/ProxySettings"
import { PageSpinner } from "@/components/ui/Spinner"
import {
  getThresholds,
  getLayers,
  getLLMSettings,
  getTenant,
  getRetentionSettings,
  getRateLimitSettings,
  getAdminLimits,
  getProxySettings,
  getStorageSettings,
} from "@/lib/api"

const TAB_IDS = [
  "organisation", "thresholds", "detection", "rate-limits", "llm", "proxy", "retention",
] as const

type TabId = typeof TAB_IDS[number]

export default function SettingsPage() {
  const t = useTranslations("pages.settings")
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

  const { data: rateLimit,    mutate: mutateRL  } = useSWR("rate-limit-settings", getRateLimitSettings)
  const { data: adminLimits,  mutate: mutateAL  } = useSWR("admin-limits",        getAdminLimits)
  const { data: storage } = useSWR("storage-settings", getStorageSettings)

  const { data: proxy, mutate: mutateProxy } = useSWR(
    "proxy-settings",
    () => getProxySettings().catch((e) => {
      if (e.message?.includes("404") || e.message?.includes("NOT_FOUND")) return null
      throw e
    })
  )

  if (tenantLoading || tLoading || lLoading || llmLoading || retentionLoading) {
    return <Shell title={t("title")}><PageSpinner /></Shell>
  }

  return (
    <Shell title={t("title")}>
      <PageHeader description={t("description")} />
      <div>

        {/* Tab bar */}
        <div style={{
          display: "flex", flexWrap: "wrap", gap: "0",
          borderBottom: "1px solid #e5e7eb", marginBottom: "20px",
        }}>
          {TAB_IDS.map(tabId => (
            <button
              key={tabId}
              onClick={() => setActiveTab(tabId)}
              style={{
                padding: "8px 14px",
                fontSize: "13px",
                fontWeight: activeTab === tabId ? 600 : 400,
                color: activeTab === tabId ? "#670FEF" : "#4b5563",
                background: "none",
                border: "none",
                borderBottom: activeTab === tabId ? "2px solid #670FEF" : "2px solid transparent",
                marginBottom: "-1px",
                cursor: "pointer",
                whiteSpace: "nowrap",
                transition: "color 0.15s",
              }}
            >
              {t(`tabs.${tabId}`)}
            </button>
          ))}
        </div>

        {/* Tab panels */}
        {activeTab === "organisation" && (
          <Card>
            <CardHeader
              title={t("cards.organisation_title")}
              subtitle={t("cards.organisation_subtitle")}
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
              title={t("cards.thresholds_title")}
              subtitle={t("cards.thresholds_subtitle")}
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
              title={t("cards.detection_title")}
              subtitle={t("cards.detection_subtitle")}
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
          <div className="space-y-5">
            <Card>
              <CardHeader
                title={t("cards.rate_limits_title")}
                subtitle={t("cards.rate_limits_subtitle")}
              />
              <RateLimitSettingsForm
                perMinute={rateLimit?.per_minute ?? 60}
                source={rateLimit?.source ?? "environment"}
                trialLimit={10}
                onUpdated={(perMinute, source) => mutateRL({ per_minute: perMinute, source }, false)}
              />
            </Card>

            <Card>
              <CardHeader
                title={t("cards.admin_limits_title")}
                subtitle={t("cards.admin_limits_subtitle")}
              />
              <AdminLimitsForm
                adminWrite={adminLimits?.admin_write_rate_limit ?? 20}
                exportLimit={adminLimits?.audit_export_rate_limit ?? 5}
                source={adminLimits?.source ?? "environment"}
                onUpdated={(adminWrite, exportLimit, source) =>
                  mutateAL(
                    { admin_write_rate_limit: adminWrite, audit_export_rate_limit: exportLimit, source },
                    false
                  )
                }
              />
            </Card>
          </div>
        )}

        {activeTab === "llm" && (
          <Card>
            <CardHeader
              title={t("cards.llm_title")}
              subtitle={t("cards.llm_subtitle")}
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
              title={t("cards.proxy_title")}
              subtitle={t("cards.proxy_subtitle")}
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
              title={t("cards.retention_title")}
              subtitle={t("cards.retention_subtitle")}
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
