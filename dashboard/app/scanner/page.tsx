"use client"

import { useState } from "react"
import { Shell } from "@/components/layout/Shell"
import { Card, CardHeader } from "@/components/ui/Card"
import { ScannerInput } from "@/components/scanner/ScannerInput"
import { ScanResult } from "@/components/scanner/ScanResult"
import { GatewayResponse, AIRequest } from "@/lib/types"
import { scanRequest } from "@/lib/api"

export default function ScannerPage() {
  const [result,  setResult]  = useState<GatewayResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState<string | null>(null)

  const handleScan = async (req: AIRequest) => {
    setLoading(true)
    setError(null)
    try {
      const res = await scanRequest(req)
      setResult(res)
    } catch (e: any) {
      setError(e.message || "Scan failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <Shell title="Scanner">
      <div className="max-w-3xl space-y-5">
        <Card>
          <CardHeader
            title="Prompt Scanner"
            subtitle="Analyse any prompt through the WrapSec detection pipeline"
          />
          <ScannerInput onScan={handleScan} loading={loading} />
        </Card>

        {error && (
          <div className="px-4 py-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
            {error}
          </div>
        )}

        {result && (
          <Card>
            <CardHeader title="Analysis Result" />
            <ScanResult result={result} />
          </Card>
        )}
      </div>
    </Shell>
  )
}