"use client"

import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { ThresholdForm } from "@/components/settings/ThresholdForm"
import { LayerToggles } from "@/components/settings/LayerToggles"
import { PageSpinner } from "@/components/ui/Spinner"
import { getThresholds, getLayers } from "@/lib/api"
import { Thresholds, Layers } from "@/lib/types"
import { useState } from "react"

export default function SettingsPage() {
  const { data: thresholds, isLoading: tLoading, mutate: mutateT } =
    useSWR("thresholds", getThresholds)

  const { data: layers, isLoading: lLoading, mutate: mutateL } =
    useSWR("layers", getLayers)

  if (tLoading || lLoading) return <Shell title="Settings"><PageSpinner /></Shell>

  return (
    <Shell title="Settings">
      <div className="max-w-2xl space-y-5">
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
      </div>
    </Shell>
  )
}