"use client"

import { useState } from "react"
import useSWR from "swr"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { ThresholdForm } from "@/components/settings/ThresholdForm"
import { LayerToggles } from "@/components/settings/LayerToggles"
import { LLMSettingsForm } from "@/components/settings/LLMSettings"
import { PageSpinner } from "@/components/ui/Spinner"
import { getThresholds, getLayers, getLLMSettings } from "@/lib/api"
import { Thresholds, Layers, LLMSettings } from "@/lib/types"

export default function SettingsPage() {
  const { data: thresholds, isLoading: tLoading, mutate: mutateT } =
    useSWR("thresholds", getThresholds)

  const { data: layers, isLoading: lLoading, mutate: mutateL } =
    useSWR("layers", getLayers)

  const { data: llm, isLoading: llmLoading, mutate: mutateM } =
    useSWR("llm-settings", getLLMSettings)

  if (tLoading || lLoading || llmLoading) {
    return <Shell title="Settings"><PageSpinner /></Shell>
  }

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

        <Card>
          <CardHeader
            title="LLM Configuration"
            subtitle="Configure the LLM provider for detection and proxy mode"
          />
          {llm && (
            <LLMSettingsForm
              settings={llm}
              onUpdated={(s) => mutateM(s, false)}
            />
          )}
        </Card>
      </div>
    </Shell>
  )
}