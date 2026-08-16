// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
"use client"

import { useState } from "react"
import { useTranslations } from "next-intl"
import { Button } from "@/components/ui/Button"
import { AIRequest } from "@/lib/types"

interface ScannerInputProps {
  onScan:   (req: AIRequest) => void
  loading:  boolean
}

export function ScannerInput({ onScan, loading }: ScannerInputProps) {
  const t = useTranslations("pages.scanner.input")
  const [input,         setInput]         = useState("")
  const [detectionMode, setDetectionMode] = useState<"fast" | "full">("fast")

  const handleScan = () => {
    if (!input.trim()) return
    onScan({
      input,
      detection_mode: detectionMode,
      execution_mode: "scan_only",
      options:        { debug: true },
    })
  }

  return (
    <div className="space-y-3">
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder={t("placeholder")}
        rows={5}
        className="w-full px-4 py-3 text-sm rounded-lg border border-slate-200 bg-white text-slate-900 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-700 focus:border-purple-700 resize-none"
      />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="text-xs font-medium text-slate-600">{t("detection_mode")}</span>
          {(["fast", "full"] as const).map((mode) => (
            <label key={mode} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="radio"
                name="mode"
                value={mode}
                checked={detectionMode === mode}
                onChange={() => setDetectionMode(mode)}
                className="accent-blue-800"
              />
              <span className="text-sm text-slate-700">{t(`mode.${mode}`)}</span>
              <span className="text-xs text-slate-600">
                {t(`mode_hint.${mode}`)}
              </span>
            </label>
          ))}
        </div>
        <Button size="sm"
          onClick={handleScan}
          loading={loading}
          disabled={!input.trim()}
        >
          {t("analyse")}
        </Button>
      </div>
    </div>
  )
}