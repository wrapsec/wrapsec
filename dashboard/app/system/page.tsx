// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { useTranslations } from "next-intl"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card, CardHeader } from "@/components/ui/Card"
import { PageSpinner } from "@/components/ui/Spinner"
import { getHealth, getHealthConfig } from "@/lib/api"

export default function SystemPage() {
  const t = useTranslations("pages.system")
  const { data: health, isLoading: healthLoading, error: healthError } = useSWR(
    "health-ready",  getHealth,       { refreshInterval: 10000 }
  )
  const { data: config, isLoading: configLoading } = useSWR(
    "health-config", getHealthConfig, { refreshInterval: 30000 }
  )

  if (healthLoading || configLoading) return <Shell title={t("title")}><PageSpinner /></Shell>

  if (healthError && !health) {
    return (
      <Shell title={t("title")}>
        <div className="max-w-2xl">
          <div className="bg-red-50 border border-red-200 rounded-xl p-5">
            <p className="text-sm font-semibold text-red-700 mb-1">{t("health_error_title")}</p>
            <p className="text-xs text-red-500">
              {healthError?.message ?? t("health_error_body")}
            </p>
          </div>
        </div>
      </Shell>
    )
  }

  return (
    <Shell title={t("title")}>
      <PageHeader description={t("description")} />
      <div className="max-w-2xl space-y-5">

        {/* Service health */}
        <Card>
          <CardHeader
            title={t("service_health")}
            subtitle={t("service_health_subtitle")}
          />
          <div className="grid grid-cols-3 gap-3">
            {Object.entries(health?.checks ?? {}).map(([name, status]) => (
              <ServiceStatus key={name} name={name} status={status as string} />
            ))}
          </div>
          <div className="mt-4 flex items-center gap-2">
            <span className={`inline-flex h-2.5 w-2.5 rounded-full ${
              health?.status === "ready" ? "bg-emerald-500" : "bg-red-400"
            }`} style={{ backgroundColor: health?.status === "ready" ? "#10b981" : "#f87171" }} />
            <span className="text-sm font-medium text-slate-700">
              {health?.status === "ready" ? t("operational") : t("degraded")}
            </span>
          </div>
        </Card>

        {/* Active configuration */}
        {config && (
          <>
            <Card>
              <CardHeader
                title={t("config_title")}
                subtitle={t("config_subtitle", { version: config.version, source: config.thresholds?.source ?? t("source_default") })}
              />
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: t("block_threshold"),    value: config.thresholds?.block    },
                  { label: t("sanitize_threshold"), value: config.thresholds?.sanitize },
                  { label: t("rate_limit"),         value: t("rate_limit_value", { count: config.rate_limit?.per_minute ?? "-" }) },
                  { label: t("rate_limit_scope"),   value: config.rate_limit?.scope   },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                    <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                    <p className="text-sm font-mono text-slate-800">{String(value ?? "-")}</p>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <CardHeader
                title={t("layers_title")}
                subtitle={t("source_subtitle", { source: config.detection_layers?.source ?? t("source_default") })}
              />
              <div className="grid grid-cols-3 gap-3">
                {[
                  { key: "rule", enabled: config.detection_layers?.rule },
                  { key: "ml",   enabled: config.detection_layers?.ml   },
                  { key: "llm",  enabled: config.detection_layers?.llm  },
                ].map(({ key, enabled }) => (
                  <div key={key} className="bg-slate-50 rounded-lg px-3 py-3 flex items-center gap-2.5">
                    <span
                      className="h-2 w-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: enabled ? "#10b981" : "#cbd5e1" }}
                    />
                    <div>
                      <p className="text-xs font-medium text-slate-700">{t(`layer.${key}`)}</p>
                      <p className="text-xs" style={{ color: enabled ? "#059669" : "#94a3b8" }}>
                        {enabled ? t("enabled") : t("disabled")}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <CardHeader
                title={t("llm_title")}
                subtitle={t("source_subtitle", { source: config.llm?.source ?? t("source_default") })}
              />
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: t("provider"),    value: config.llm?.provider    },
                  { label: t("model"),       value: config.llm?.model       },
                  { label: t("timeout"),     value: config.llm?.timeout ? t("timeout_value", { count: config.llm.timeout }) : "-" },
                  { label: t("llm_trigger"), value: config.llm?.llm_trigger },
                ].map(({ label, value }) => (
                  <div key={label} className="bg-slate-50 rounded-lg px-3 py-2.5">
                    <p className="text-xs text-slate-400 mb-0.5">{label}</p>
                    <p className="text-sm font-mono text-slate-800">{String(value ?? "-")}</p>
                  </div>
                ))}
              </div>
            </Card>
          </>
        )}
      </div>
    </Shell>
  )
}

function ServiceStatus({ name, status }: { name: string; status: string }) {
  const t           = useTranslations("pages.system")
  const ts          = useTranslations("pages.system.service")
  const ok          = status === "ok" || status === "healthy"
  const displayName = ts.has(name) ? ts(name) : name.replace(/_/g, " ")
  return (
    <div className="bg-slate-50 rounded-lg px-3 py-3 flex items-center gap-2.5">
      <span
        className="h-2 w-2 rounded-full flex-shrink-0"
        style={{ backgroundColor: ok ? "#10b981" : "#f87171" }}
      />
      <div>
        <p className="text-xs font-medium text-slate-700 capitalize">{displayName}</p>
        <p className="text-xs" style={{ color: ok ? "#059669" : "#ef4444" }}>
          {ok ? t("svc_operational") : t("svc_error")}
        </p>
      </div>
    </div>
  )
}
