"use client"

import { useState } from "react"
import { Button } from "@/components/ui/Button"
import { AIRequest } from "@/lib/types"

interface ScannerInputProps {
  onScan:   (req: AIRequest) => void
  loading:  boolean
}

export function ScannerInput({ onScan, loading }: ScannerInputProps) {
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
        placeholder="Enter a prompt to analyse for security threats..."
        rows={5}
        className="w-full px-4 py-3 text-sm rounded-lg border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800 resize-none"
      />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="text-xs font-medium text-slate-600">Detection mode</span>
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
              <span className="text-sm text-slate-700 capitalize">{mode}</span>
              <span className="text-xs text-slate-400">
                {mode === "fast" ? "(rule + ML)" : "(rule + ML + LLM)"}
              </span>
            </label>
          ))}
        </div>
        <Button
          onClick={handleScan}
          loading={loading}
          disabled={!input.trim()}
        >
          Analyse
        </Button>
      </div>
    </div>
  )
}