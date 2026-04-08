"use client"

import { Select } from "@/components/ui/Input"
import { Decision, ThreatCategory } from "@/lib/types"

interface RequestFiltersProps {
  decision:       string
  threatCategory: string
  onDecision:     (v: string) => void
  onThreat:       (v: string) => void
}

export function RequestFilters({
  decision,
  threatCategory,
  onDecision,
  onThreat,
}: RequestFiltersProps) {
  return (
    <div className="flex items-end gap-3">
      <Select
        label="Decision"
        value={decision}
        onChange={(e) => onDecision(e.target.value)}
        options={[
          { value: "",         label: "All decisions" },
          { value: "BLOCK",    label: "Block" },
          { value: "SANITIZE", label: "Sanitize" },
          { value: "ALLOW",    label: "Allow" },
        ]}
        className="w-40"
      />
      <Select
        label="Threat"
        value={threatCategory}
        onChange={(e) => onThreat(e.target.value)}
        options={[
          { value: "",                  label: "All threats" },
          { value: "PROMPT_INJECTION",  label: "Prompt Injection" },
          { value: "JAILBREAK",         label: "Jailbreak" },
          { value: "MALICIOUS_INTENT",  label: "Malicious Intent" },
          { value: "DATA_EXFILTRATION", label: "Data Exfiltration" },
          { value: "PII",               label: "PII" },
          { value: "TOXICITY",          label: "Toxicity" },
        ]}
        className="w-48"
      />
    </div>
  )
}