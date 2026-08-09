// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { PageHeader } from "@/components/ui/PageHeader"
import { Card, CardHeader } from "@/components/ui/Card"
import { PageSpinner } from "@/components/ui/Spinner"
import { getHealth, getHealthConfig } from "@/lib/api"

export default function SystemPage() {
  const { data: health, isLoading: healthLoading, error: healthError } = useSWR(
    "health-ready",  getHealth,       { refreshInterval: 10000 }
  )
  const { data: config, isLoading: configLoading } = useSWR(
    "health-config", getHealthConfig, { refreshInterval: 30000 }
  )

  if (healthLoading || configLoading) return <Shell title="System"><PageSpinner /></Shell>

  if (healthError && !health) {
    return (
      <Shell title="System Status">
        <div className="max-w-2xl">
          <div className="bg-red-50 border border-red-200 rounded-xl p-5">
            <p className="text-sm font-semibold text-red-700 mb-1">Unable to reach health endpoint</p>
            <p className="text-xs text-red-500">
              {healthError?.message ?? "The WrapSec API is not responding. Check that the service is running."}
            </p>
          </div>
        </div>
      </Shell>
    )
  }

  return (
    <Shell title="System Status">
      <PageHeader description="Monitor service health and runtime configuration." />
      <div className="max-w-2xl space-y-5">

        {/* Service health */}
        <Card>
          <CardHeader
            title="Service Health"
            subtitle="Real-time status of WrapSec subsystems"
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
              {health?.status === "ready" ? "All systems operational" : "System degraded"}
            </span>
          </div>
        </Card>

        {/* Active configuration */}
        {config && (
          <>
            <Card>
              <CardHeader
                title="Active Configuration"
                subtitle={`Algorithm version ${config.version} · Settings from ${config.thresholds?.source ?? "database"}`}
              />
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Block threshold",    value: config.thresholds?.block    },
                  { label: "Sanitize threshold", value: config.thresholds?.sanitize },
                  { label: "Rate limit",         value: `${config.rate_limit?.per_minute} req/min` },
                  { label: "Rate limit scope",   value: config.rate_limit?.scope   },
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
                title="Detection Layers"
                subtitle={`Source: ${config.detection_layers?.source ?? "database"}`}
              />
              <div className="grid grid-cols-3 gap-3">
                {[
                  { name: "Rule detector", enabled: config.detection_layers?.rule },
                  { name: "ML classifier", enabled: config.detection_layers?.ml   },
                  { name: "LLM detector",  enabled: config.detection_layers?.llm  },
                ].map(({ name, enabled }) => (
                  <div key={name} className="bg-slate-50 rounded-lg px-3 py-3 flex items-center gap-2.5">
                    <span
                      className="h-2 w-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: enabled ? "#10b981" : "#cbd5e1" }}
                    />
                    <div>
                      <p className="text-xs font-medium text-slate-700">{name}</p>
                      <p className="text-xs" style={{ color: enabled ? "#059669" : "#94a3b8" }}>
                        {enabled ? "Enabled" : "Disabled"}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <CardHeader
                title="LLM Configuration"
                subtitle={`Source: ${config.llm?.source ?? "database"}`}
              />
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Provider",    value: config.llm?.provider    },
                  { label: "Model",       value: config.llm?.model       },
                  { label: "Timeout",     value: config.llm?.timeout ? `${config.llm.timeout}s` : "-" },
                  { label: "LLM trigger", value: config.llm?.llm_trigger },
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

const DISPLAY_NAMES: Record<string, string> = {
  tfidf_detector:       "ML Tier 1 Detector",
  transformer_detector: "ML Tier 2 Detector",
}

function ServiceStatus({ name, status }: { name: string; status: string }) {
  const ok          = status === "ok" || status === "healthy"
  const displayName = DISPLAY_NAMES[name] ?? name.replace(/_/g, " ")
  return (
    <div className="bg-slate-50 rounded-lg px-3 py-3 flex items-center gap-2.5">
      <span
        className="h-2 w-2 rounded-full flex-shrink-0"
        style={{ backgroundColor: ok ? "#10b981" : "#f87171" }}
      />
      <div>
        <p className="text-xs font-medium text-slate-700 capitalize">{displayName}</p>
        <p className="text-xs" style={{ color: ok ? "#059669" : "#ef4444" }}>
          {ok ? "Operational" : "Error"}
        </p>
      </div>
    </div>
  )
}
