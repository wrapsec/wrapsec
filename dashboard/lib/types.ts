// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
// ── Decision types ────────────────────────────────────────────
export type Decision = "BLOCK" | "SANITIZE" | "ALLOW"

export type Role = "ADMIN" | "DEVELOPER" | "VIEWER" | "AUDITOR"
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
  output_decision:      Decision | null
  provider:             string | null
  model:                string | null
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
  dept_name:            string | null
  app_id:               string | null
  app_name:             string | null
  user_id:              string | null
  source:               string | null
  ip_address:           string | null
  attribution_verified: boolean
  policy_source:        string | null
  // v1.7.0 agentic fields
  run_id:               string | null
  session_id:           string | null
  turn_index:           number | null
  input_source:         string | null
}

export interface AuditLogsResponse {
  total: number
  items: AuditLogItem[]
}

export interface AgentRunResponse {
  run_id: string
  count:  number
  turns:  AuditLogItem[]
}

export interface ThreatCount {
  category: ThreatCategory
  count:    number
}

export interface AuditStatsResponse {
  period_from:     string
  period_to:       string
  total_requests:  number
  block_count:     number
  sanitize_count:  number
  allow_count:     number
  block_rate:      number
  sanitize_rate:   number
  allow_rate:      number
  avg_latency_ms:  number
  p95_latency_ms:  number
  avg_risk:        number
  top_threats:     ThreatCount[]
  severity_counts: {
    CRITICAL: number
    HIGH:     number
    MEDIUM:   number
    LOW:      number
  }
}

// --- Security by Source ---------------------------------------
export interface SourceStats {
  input_source:    string
  total:           number
  blocked:         number
  sanitized:       number
  allowed:         number
  block_rate:      number
  avg_risk:        number
  max_risk:        number
  high_risk_count: number
  attacks:         number
  threats:         Record<string, number>
}

export interface AttackOrigin {
  input_source: string
  attacks:      number
  total:        number
}

/** Breakdown returned by GET /v1/audit/attribution. */
export interface AttributionResponse {
  by_key:             { key_id: string; source: string; total: number; blocked: number; block_rate: number; avg_latency_ms: number }[]
  by_department:      { dept_id: string; total: number; blocked: number; block_rate: number }[]
  by_application:     { app_id: string; total: number; blocked: number; block_rate: number; avg_latency_ms: number }[]
  by_primary_reason:  { primary_reason: string; count: number }[]
  by_confidence_band: { band: string; count: number }[]
}

export interface BySourceResponse {
  period_from:        string
  period_to:          string
  dept_id:            string | null
  sources:            SourceStats[]
  top_attack_origins: AttackOrigin[]
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
  provider:       "ollama" | "openai" | "custom"
  model:          string
  base_url:       string
  timeout:        number
  llm_trigger:    number
  api_key_masked: string | null
  updated_at?:    string
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
  // v1.7.0 agentic + provenance fields (projected from the audit record)
  run_id:          string | null
  session_id:      string | null
  turn_index:      number | null
  input_source:    string | null
  detection_scores: {
    rule: number
    ml:   number
    llm:  number
  }
  guardrail_scores: {
    pii?:      number
    toxicity?: number
    [key: string]: number | undefined
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
  dept_id?:         string
  from?:            string
  to?:              string
  sort_by?:         string
  sort_order?:      "asc" | "desc"
  limit:            number
  offset:           number
  execution_mode?:  ExecutionMode | ""
}

// ── Departments ───────────────────────────────────────────────
export interface DeptLLMOverride {
  provider?:       "openai" | "ollama" | "custom"
  model?:          string
  base_url?:       string
  timeout?:        number
  api_key_masked?: string | null
}

export interface DeptProxyOverride {
  provider?:        "openai" | "ollama" | "custom"
  base_url?:        string
  default_model?:   string
  timeout_seconds?: number
  api_key_masked?:  string | null
}

/**
 * A policy-override document (department or application scope, and the payload of
 * setApplicationPolicy). Mirrors the backend policy_override shape: only the
 * fields an operator overrides are present; anything absent inherits.
 */
export interface PolicyOverride {
  thresholds?:     { block?: number; sanitize?: number }
  llm?:            DeptLLMOverride
  proxy_provider?: DeptProxyOverride
}

/**
 * The effective policy after resolution (system defaults -> tenant/platform
 * settings -> department -> application), as returned by the *-policy endpoints.
 * Shape mirrors the backend resolve_policy output; the dashboard reads
 * thresholds today, the rest is carried for faithfulness.
 */
export interface ResolvedPolicy {
  thresholds?: { block?: number; sanitize?: number }
  detection?:  { rule_enabled?: boolean; ml_enabled?: boolean; llm_enabled?: boolean; llm_trigger?: number }
  guardrails?: { pii?: { enabled?: boolean; block_threshold?: number; sanitize_threshold?: number } }
  llm?:        { provider?: string; model?: string; base_url?: string; timeout?: number }
  rate_limit?: { per_minute?: number }
}

export interface Department {
  id:              string
  tenant_id:       string
  slug:            string
  name:            string
  description:     string | null
  policy_override: PolicyOverride | null
  contact_email:   string | null
  is_active:       boolean
  application_count?: number
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
  metadata:            Record<string, unknown> | null
  policy_override:     PolicyOverride | null
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

// ── Dashboard Users (JWT auth) ────────────────────────────────
/** Tenant profile returned by GET and PUT /v1/admin/tenant (both return the full row). */
export interface TenantProfile {
  id:             string
  slug:           string
  name:           string
  description:    string | null
  global_policy?: Record<string, unknown>
  contact_email:  string | null
  is_active:      boolean
  created_at:     string
}

export interface DashboardUser {
  id:                    string
  email:                 string
  role:                  Role
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

// -- Webhooks / SIEM integrations --
export interface WebhookEndpoint {
  id:               string
  url:              string
  description:      string | null
  event_types:      string[] | null
  connector_type:   string | null
  config:           Record<string, string> | null
  disabled:         boolean
  status:           "active" | "failing" | "auto_disabled" | "paused"
  first_failure_at: string | null
  secret_masked:    string
  created_at:       string | null
  updated_at:       string | null
}

export interface WebhookEndpointCreated extends WebhookEndpoint {
  secret?: string   // plaintext signing secret, generic webhooks only, shown once
}

export interface ConnectorField {
  key:      string
  label:    string
  help:     string
  required: boolean
}

export interface ConnectorTypeSchema {
  type:          string | null
  label:         string
  secret:        { label: string; generated: boolean; required: boolean }
  url:           { label: string; help: string }
  config_fields: ConnectorField[]
}

export interface WebhookTestResult {
  ok:               boolean
  status_code:      number | null
  response_snippet: string | null
  duration_ms:      number | null
  error:            string | null
}

// ── Email delivery ────────────────────────────────────────────
export interface EmailDelivery {
  id:                  string
  tenant_id:           string | null
  department_id:       string | null
  user_id:             string | null
  notification_type:   string
  recipient:           string
  locale:              string | null
  status:              string
  attempt_count:       number
  provider_message_id: string | null
  trace_id:            string | null
  last_error:          string | null
  created_at:          string | null
  last_attempt_at:     string | null
  completed_at:        string | null
}

export interface EmailDeliveriesResponse {
  emails: EmailDelivery[]
}

export interface EmailSummary {
  counts: Record<string, number>
}

export interface EmailSettings {
  notifications_enabled: boolean
  max_attempts:          number
  retention_days:        number
  retry_schedule: {
    intervals_seconds:    number[]
    min_attempts:         number
    max_attempts_ceiling: number
  }
}
