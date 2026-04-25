// ── Decision types ────────────────────────────────────────────
export type Decision = "BLOCK" | "SANITIZE" | "ALLOW"
export type DetectionMode = "fast" | "full"
export type ExecutionMode = "scan_only" | "proxy"
export type ThreatCategory =
  | "PROMPT_INJECTION"
  | "JAILBREAK"
  | "MALICIOUS_INTENT"
  | "DATA_EXFILTRATION"
  | "PII"
  | "TOXICITY"

// ── API request ───────────────────────────────────────────────
export interface AIRequest {
  input: string
  detection_mode?: DetectionMode
  execution_mode?: ExecutionMode
  model?: string
  metadata?: {
    tenant_id?: string
    source?: string
    user_id?: string
  }
  context?: {
    user_role?: string
    sensitivity?: string
  }
  options?: {
    stream?: boolean
    debug?: boolean
  }
}

// ── API response ──────────────────────────────────────────────
export interface Processing {
  latency_ms:      number
  llm_invoked:     boolean
  detection_mode:  DetectionMode
  execution_mode:  ExecutionMode
  policy_source?:  string   // present only in GET /v1/ai/requests/{trace_id}
}

export interface LayerScores {
  rule_score: number
  ml_score:   number
  llm_score:  number
  pii_score:  number
  layer_decisions: {
    rule: Decision
    ml:   Decision
    llm:  Decision
  }
}

export interface GatewayResponse {
  trace_id:             string
  decision:             Decision
  decision_version:     string
  risk_score:           number
  primary_reason:       string | null
  confidence:           number | null
  confidence_band:      string | null
  threats:              ThreatCategory[]
  sanitization_applied: boolean
  sanitized_input?:     string        // present only when decision = SANITIZE
  processing:           Processing
  debug?:               LayerScores
}

// ── Audit log ─────────────────────────────────────────────────
export interface AuditLogItem {
  trace_id:             string
  timestamp:            string
  tenant_id:            string | null
  decision:             Decision
  primary_reason:       string | null
  risk_score:           number
  confidence:           number | null
  confidence_band:      string | null
  threats:              ThreatCategory[]
  input_hash:           string
  input_length:         number
  detection_mode:       DetectionMode
  execution_mode:       ExecutionMode
  latency_ms:           number
  severity:             "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  key_id:               string | null
  dept_id:              string | null
  app_id:               string | null
  user_id:              string | null
  source:               string | null
  ip_address:           string | null
  attribution_verified: boolean
  policy_source:        string | null
}

export interface AuditLogsResponse {
  total: number
  items: AuditLogItem[]
}

export interface ThreatCount {
  category: ThreatCategory
  count:    number
}

export interface AuditStatsResponse {
  period_from:    string
  period_to:      string
  total_requests: number
  block_rate:     number
  sanitize_rate:  number
  allow_rate:     number
  avg_latency_ms: number
  p95_latency_ms: number
  top_threats:    ThreatCount[]
}

// ── Settings ──────────────────────────────────────────────────
export interface Thresholds {
  block_threshold:    number
  sanitize_threshold: number
  updated_at?:        string
}

export interface Layers {
  rule_enabled: boolean
  ml_enabled:   boolean
  llm_enabled:  boolean
  updated_at?:  string
}

export interface LLMSettings {
  provider:    "ollama" | "openai" | "groq"
  model:       string
  base_url:    string
  timeout:     number
  llm_trigger: number
  updated_at?: string
}

// ── API Keys ──────────────────────────────────────────────────
export interface ApiKey {
  key_id:       string
  name:         string
  key_type:     "live" | "trial"
  app_id:       string | null
  app_name:     string | null
  dept_id:      string | null
  dept_name:    string | null
  is_admin:     boolean
  revoked:      boolean
  created_at:   string
  expires_at:   string | null
  last_used_at: string | null
}

export interface ApiKeyCreated {
  key_id:     string
  name:       string
  api_key:    string
  key_type:   "live" | "trial"
  dept_id:    string | null
  app_id:     string | null
  tenant_id:  string | null
  created_at: string
  expires_at: string | null
}

export interface ApiKeysResponse {
  keys: ApiKey[]
}

// ── Health ────────────────────────────────────────────────────
export interface HealthResponse {
  status:  string
  version: string
}

export interface HealthReadyResponse {
  status: string
  checks: {
    database: string
    redis:    string
    ml_model: string
  }
}

// ── Retrieve request ──────────────────────────────────────────
export interface RequestDetail {
  trace_id:        string
  timestamp:       string
  execution_mode:  string
  is_proxy:        boolean
  severity:        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  decision:        Decision
  risk_score:      number
  primary_reason:  string | null
  confidence:      number | null
  confidence_band: string | null
  threats:         ThreatCategory[]
  input_hash:      string
  input_length:    number | null
  detection_scores: {
    rule: number
    ml:   number
    llm:  number
  }
  guardrail_scores: {
    pii:          number
    [key: string]: number
  }
  processing: Processing
  attribution: {
    tenant_id:            string | null
    dept_id:              string | null
    dept_name:            string | null
    app_id:               string | null
    app_name:             string | null
    source:               string | null
    user_id:              string | null
    key_id:               string | null
    ip_address:           string | null
    user_agent:           string | null
    attribution_verified: boolean
  }
  proxy?: {
    provider:              string | null
    model:                 string | null
    provider_latency_ms:   number | null
    total_latency_ms:      number | null
    execution_status:      string
    input_raw:             string | null
    input_sanitized:       string | null
    input_primary_reason:  string | null
    input_confidence:      number | null
    input_threats:         string[]
    input_attack_type:     string | null
    output_raw:            string | null
    output_sanitized:      string | null
    output_decision:       string | null
    output_primary_reason: string | null
    output_confidence:     number | null
    output_threats:        string[]
    behavior_flag:         string | null
    output_flags:          string[] | null
  }
}

// ── Filters ───────────────────────────────────────────────────
export interface RequestFilters {
  trace_id?:        string
  decision?:        Decision | ""
  threat_category?: ThreatCategory | ""
  from?:            string
  to?:              string
  sort_by?:         string
  sort_order?:      "asc" | "desc"
  limit:            number
  offset:           number
  execution_mode?:  ExecutionMode | ""
}

// ── Departments ───────────────────────────────────────────────
export interface Department {
  id:              string
  tenant_id:       string
  slug:            string
  name:            string
  description:     string | null
  policy_override: {
    thresholds?: { block?: number; sanitize?: number }
  } | null
  contact_email:   string | null
  is_active:       boolean
  created_at:      string
}

// ── Applications ──────────────────────────────────────────────
export interface Application {
  id:                  string
  tenant_id:           string
  dept_id:             string
  slug:                string
  name:                string
  description:         string | null
  owner_name:          string | null
  owner_email:         string | null
  environment:         string
  metadata:            Record<string, any> | null
  policy_override:     Record<string, any> | null
  rate_limit_override: number | null
  is_active:           boolean
  created_at:          string
}

// ── Proxy Settings ────────────────────────────────────────────
export interface ProxyProviderConfig {
  provider:        "openai" | "ollama" | "custom"
  base_url:        string
  api_key_masked:  string | null
  default_model:   string
  timeout_seconds: number
  created_at:      string | null
  updated_at:      string | null
}

export interface ProxyHealthResult {
  provider:    string
  base_url:    string
  reachable:   boolean
  latency_ms?: number
  error?:      string
}

// ── Proxy Interactions ────────────────────────────────────────
export type ExecutionStatus =
  | "SUCCESS"
  | "BLOCKED"
  | "OUTPUT_BLOCKED"
  | "FAILED"
  | "TIMEOUT"

export interface ProxyInteraction {
  id:                    string
  trace_id:              string
  created_at:            string
  key_id:                string | null
  user_id:               string | null
  input_decision:        Decision
  input_primary_reason:  string
  input_confidence:      number
  input_threats:         string[]
  input_attack_type:     string | null
  provider:              string | null
  model:                 string | null
  provider_latency_ms:   number | null
  execution_status:      ExecutionStatus
  output_decision:       Decision | null
  output_primary_reason: string | null
  output_confidence:     number | null
  output_threats:        string[]
  behavior_flag:         string | null
  output_flags:          string[] | null
  total_latency_ms:      number
}

export interface ProxyInteractionDetail extends ProxyInteraction {
  input_raw:        string | null
  input_sanitized:  string | null
  output_raw:       string | null
  output_sanitized: string | null
}

export interface ProxyInteractionsResponse {
  total:  number
  limit:  number
  offset: number
  items:  ProxyInteraction[]
}

// ── Dashboard Users (JWT auth) ────────────────────────────────
export interface DashboardUser {
  id:                    string
  email:                 string
  role:                  "ADMIN" | "DEVELOPER" | "VIEWER"
  dept_id:               string | null
  tenant_id:             string
  is_active:             boolean
  force_password_change: boolean
  created_at:            string
  last_login_at:         string | null
}

export interface DashboardUsersResponse {
  total: number
  users: DashboardUser[]
}
