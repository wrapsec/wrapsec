// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { logout, isLoggingOut } from "@/lib/auth"
import {
  AIRequest,
  GatewayResponse,
  AuditLogsResponse,
  AgentRunResponse,
  AuditStatsResponse,
  BySourceResponse,
  Thresholds,
  Layers,
  LLMSettings,
  ApiKeysResponse,
  ApiKeyCreated,
  HealthReadyResponse,
  RequestDetail,
  RequestFilters,
  Department,
  Application,
  ProxyProviderConfig,
  ProxyHealthResult,
  DashboardUser,
  DashboardUsersResponse,
  WebhookEndpoint,
  WebhookEndpointCreated,
  ConnectorTypeSchema,
  WebhookTestResult,
} from "./types"

// Internal type for retry tracking
interface RequestOptions extends RequestInit {
  _retried?: boolean
}

async function request<T>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  // All requests go through Next.js proxy at /api/proxy
  // The proxy route reads wrapsec_api_key or wrapsec_jwt cookie server-side
  // and forwards the appropriate auth header to the backend.
  // No auth header needed here - the proxy handles it.
  const proxyPath = `/api/proxy${path}`

  const response = await fetch(proxyPath, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  })

  if (!response.ok) {
    // ── 401 handling - attempt silent refresh, then redirect ──────────────
    if (response.status === 401 && typeof window !== "undefined") {

      // Guard 1: never retry the refresh request itself
      if (path.includes("/api/auth/refresh") || proxyPath.includes("/api/auth/refresh")) {
        await logout("expired")
        window.location.href = "/login"
        throw new Error("Session expired")
      }

      // Guard 2: never retry twice
      if (options._retried) {
        await logout("expired")
        window.location.href = "/login"
        throw new Error("Session expired")
      }

      // Guard 3: logout already in progress - skip refresh
      if (isLoggingOut) {
        window.location.href = "/login"
        throw new Error("Logging out")
      }

      // Attempt silent refresh
      const refreshed = await fetch("/api/auth/refresh", { method: "POST" })
      if (!refreshed.ok) {
        await logout("expired")
        window.location.href = "/login"
        throw new Error("Session expired")
      }

      // Retry original request once
      return request<T>(path, { ...options, _retried: true })
    }

    // ── Non-401 errors - parse safely, show error (do NOT redirect) ───────
    let errMessage = `HTTP ${response.status}`
    const contentType = response.headers.get("content-type") || ""
    if (contentType.includes("application/json")) {
      try {
        const error = await response.json()
        errMessage = error?.error?.message || errMessage
      } catch {
        // not valid JSON - use status code message
      }
    }
    // 500/502/503 are server errors - user sees error, not login redirect
    throw new Error(errMessage)
  }

  return response.json()
}

// ── Setup (unauthenticated - first-run only) ──────────────────
export async function getSetupStatus(): Promise<{ initialized: boolean }> {
  const res = await fetch("/api/proxy/v1/setup/status")
  if (!res.ok) return { initialized: true } // fail safe - don't redirect to setup on error
  return res.json()
}

export async function completeSetup(email: string, password: string): Promise<void> {
  const res = await fetch("/api/proxy/v1/setup", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ email, password }),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data?.detail?.[0]?.msg || data?.error?.message || `Error ${res.status}`)
  }
}

// ── Gateway ───────────────────────────────────────────────────
export async function scanRequest(
  body: AIRequest
): Promise<GatewayResponse> {
  return request<GatewayResponse>("/v1/ai/request", {
    method: "POST",
    body:   JSON.stringify(body),
  })
}

export async function getRequest(
  traceId: string
): Promise<RequestDetail> {
  return request<RequestDetail>(`/v1/ai/requests/${traceId}`)
}

// ── Audit ─────────────────────────────────────────────────────
export async function getAuditLogs(
  filters: Partial<RequestFilters> = {}
): Promise<AuditLogsResponse> {
  const params = new URLSearchParams()
  if (filters.trace_id)        params.set("trace_id",        filters.trace_id)
  if (filters.decision)        params.set("decision",        filters.decision)
  if (filters.threat_category) params.set("threat_category", filters.threat_category)
  if (filters.from)            params.set("from",            filters.from)
  if (filters.to)              params.set("to",              filters.to)
  if (filters.limit)           params.set("limit",           String(filters.limit))
  if (filters.offset)          params.set("offset",          String(filters.offset))
  if (filters.sort_by)         params.set("sort_by",         filters.sort_by)
  if (filters.sort_order)      params.set("sort_order",      filters.sort_order)
  if (filters.execution_mode)  params.set("execution_mode",  filters.execution_mode)
  if (filters.dept_id)         params.set("dept_id",         filters.dept_id)

  const qs = params.toString()
  return request<AuditLogsResponse>(`/v1/audit/logs${qs ? `?${qs}` : ""}`)
}

export async function getAgentRun(runId: string): Promise<AgentRunResponse> {
  return request<AgentRunResponse>(`/v1/agent-runs/${encodeURIComponent(runId)}`)
}

export async function getAuditStats(params: {
  from?: string
  to?:   string
} = {}): Promise<AuditStatsResponse> {
  const p = new URLSearchParams()
  if (params.from) p.set("from", params.from)
  if (params.to)   p.set("to",   params.to)
  const qs = p.toString()
  return request<AuditStatsResponse>(`/v1/audit/stats${qs ? `?${qs}` : ""}`)
}

export async function getAttribution(params: {
  from?: string
  to?:   string
} = {}): Promise<{
  by_key:             { key_id: string; source: string; total: number; blocked: number; block_rate: number; avg_latency_ms: number }[]
  by_department:      { dept_id: string; total: number; blocked: number; block_rate: number }[]
  by_application:     { app_id: string; total: number; blocked: number; block_rate: number; avg_latency_ms: number }[]
  by_primary_reason:  { primary_reason: string; count: number }[]
  by_confidence_band: { band: string; count: number }[]
}> {
  const p = new URLSearchParams()
  if (params.from) p.set("from", params.from)
  if (params.to)   p.set("to",   params.to)
  const qs = p.toString()
  return request(`/v1/audit/attribution${qs ? `?${qs}` : ""}`)
}

export async function getAnalytics(params: {
  group_by?: "hour" | "day" | "week" | "month"
  from?:     string
  to?:       string
  dept_id?:  string
} = {}) {
  const p = new URLSearchParams()
  if (params.group_by) p.set("group_by", params.group_by)
  if (params.from)     p.set("from",     params.from)
  if (params.to)       p.set("to",       params.to)
  if (params.dept_id)  p.set("dept_id",  params.dept_id)
  return request<{
    group_by:   string
    total:      number
    block_rate: number
    trend: {
      period:         string
      total:          number
      blocked:        number
      sanitized:      number
      allowed:        number
      block_rate:     number
      avg_risk_score: number
      avg_latency_ms: number
    }[]
  }>(`/v1/audit/analytics?${p.toString()}`)
}

export async function getBySource(params: {
  from?:    string
  to?:      string
  dept_id?: string
} = {}): Promise<BySourceResponse> {
  const p = new URLSearchParams()
  if (params.from)    p.set("from",    params.from)
  if (params.to)      p.set("to",      params.to)
  if (params.dept_id) p.set("dept_id", params.dept_id)
  const qs = p.toString()
  return request<BySourceResponse>(`/v1/audit/by-source${qs ? `?${qs}` : ""}`)
}

export async function exportAuditLogs(params: {
  decision?:        string
  threat_category?: string
  from?:            string
  to?:              string
  limit?:           number
}): Promise<Blob> {
  const p = new URLSearchParams()
  if (params.decision)        p.set("decision",        params.decision)
  if (params.threat_category) p.set("threat_category", params.threat_category)
  if (params.from)            p.set("from",            params.from)
  if (params.to)              p.set("to",              params.to)
  p.set("limit", String(params.limit ?? 10000))

  // Use the proxy path so the 401 silent-refresh path in request() applies.
  // The proxy returns text/csv which we read as a blob after the auth check.
  const proxyPath = `/api/proxy/v1/audit/export?${p.toString()}`

  // Attempt once; if 401, try silent refresh then retry once.
  const doFetch = () => fetch(proxyPath)

  let response = await doFetch()

  if (response.status === 401 && typeof window !== "undefined") {
    const refreshed = await fetch("/api/auth/refresh", { method: "POST" })
    if (!refreshed.ok) {
      await logout("expired")
      window.location.href = "/login"
      throw new Error("Session expired")
    }
    response = await doFetch()
  }

  if (!response.ok) throw new Error(`Export failed: ${response.status}`)
  return response.blob()
}

// ── Settings ──────────────────────────────────────────────────
export async function getThresholds(): Promise<Thresholds> {
  return request<Thresholds>("/v1/settings/thresholds")
}

export async function updateThresholds(
  data: Partial<Thresholds>
): Promise<Thresholds> {
  return request<Thresholds>("/v1/settings/thresholds", {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function getLayers(): Promise<Layers> {
  return request<Layers>("/v1/settings/layers")
}

export async function updateLayers(
  data: Partial<Layers>
): Promise<Layers> {
  return request<Layers>("/v1/settings/layers", {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function getLLMSettings(): Promise<LLMSettings> {
  return request<LLMSettings>("/v1/settings/llm")
}

export async function updateLLMSettings(
  data: Partial<LLMSettings> & { api_key?: string }
): Promise<LLMSettings> {
  return request<LLMSettings>("/v1/settings/llm", {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function getRetentionSettings(): Promise<{
  retention_days: number
  source: string
}> {
  return request("/v1/settings/retention")
}

export async function updateRetentionSettings(
  retention_days: number
): Promise<{ retention_days: number; updated_at: string }> {
  return request("/v1/settings/retention", {
    method: "PUT",
    body:   JSON.stringify({ retention_days }),
  })
}

export async function getRateLimitSettings(): Promise<{
  per_minute: number
  source:     string
}> {
  return request("/v1/settings/rate_limit")
}

export async function updateRateLimitSettings(
  perMinute: number
): Promise<{ per_minute: number; source: string; updated_at: string }> {
  return request("/v1/settings/rate_limit", {
    method: "PUT",
    body:   JSON.stringify({ per_minute: perMinute }),
  })
}

export async function getStorageSettings(): Promise<{
  storage_mode:         string
  retention_days_proxy: number
}> {
  return request("/v1/settings/storage")
}

export async function getAdminLimits(): Promise<{
  admin_write_rate_limit:  number
  audit_export_rate_limit: number
  source: string
}> {
  return request("/v1/settings/admin_limits")
}

export async function updateAdminLimits(payload: {
  admin_write_rate_limit?:  number
  audit_export_rate_limit?: number
}): Promise<{
  admin_write_rate_limit:  number
  audit_export_rate_limit: number
  source:     string
  updated_at: string
}> {
  return request("/v1/settings/admin_limits", {
    method: "PUT",
    body:   JSON.stringify(payload),
  })
}

// ── Proxy Settings ────────────────────────────────────────────
export async function getProxySettings(): Promise<ProxyProviderConfig> {
  return request<ProxyProviderConfig>("/v1/settings/proxy")
}

export async function updateProxySettings(data: {
  provider:      string
  base_url:      string
  api_key?:      string
  default_model: string
  timeout:       number
}): Promise<ProxyProviderConfig> {
  return request<ProxyProviderConfig>("/v1/settings/proxy", {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function deleteProxySettings(): Promise<void> {
  return request<void>("/v1/settings/proxy", { method: "DELETE" })
}

export async function getProxyHealth(): Promise<ProxyHealthResult> {
  return request<ProxyHealthResult>("/v1/settings/proxy/health")
}

// ── API Keys ──────────────────────────────────────────────────
export async function getApiKeys(): Promise<ApiKeysResponse> {
  return request<ApiKeysResponse>("/v1/keys")
}

export async function createApiKey(
  name:    string,
  appId?:  string,
  deptId?: string,
  keyType: "live" | "trial" = "live",
): Promise<ApiKeyCreated> {
  return request<ApiKeyCreated>("/v1/keys", {
    method: "POST",
    body:   JSON.stringify({
      name,
      key_type: keyType,
      ...(appId  ? { app_id:  appId  } : {}),
      ...(deptId ? { dept_id: deptId } : {}),
    }),
  })
}

export async function revokeApiKey(keyId: string): Promise<void> {
  return request<void>(`/v1/keys/${keyId}`, { method: "DELETE" })
}

export async function rotateApiKey(
  keyId:              string,
  gracePeriodMinutes: number = 60
) {
  return request<{
    new_key_id:           string
    new_api_key:          string
    old_key_id:           string
    old_expires_at:       string
    grace_period_minutes: number
    name:                 string
    created_at:           string
  }>(`/v1/keys/${keyId}/rotate`, {
    method: "POST",
    body:   JSON.stringify({ grace_period_minutes: gracePeriodMinutes }),
  })
}

export async function getKeysByApp(_appId: string) {
  return request<{ keys: {
    key_id:       string
    name:         string
    app_id:       string | null
    dept_id:      string | null
    created_at:   string
    expires_at:   string | null
    last_used_at: string | null
  }[] }>("/v1/keys")
}

// ── Departments ───────────────────────────────────────────────
export async function getDepartments() {
  return request<{ departments: Department[] }>("/v1/admin/departments")
}

export async function getDepartment(id: string) {
  return request<Department>(`/v1/admin/departments/${id}`)
}

export async function createDepartment(data: {
  name:           string
  slug:           string
  description?:   string
  contact_email?: string
}) {
  return request<Department>("/v1/admin/departments", {
    method: "POST",
    body:   JSON.stringify(data),
  })
}

export async function updateDepartment(id: string, data: Partial<Department>) {
  return request<Department>(`/v1/admin/departments/${id}`, {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function deleteDepartment(id: string) {
  return request<{ dept_id: string; deactivated: boolean }>(
    `/v1/admin/departments/${id}`,
    { method: "DELETE" }
  )
}

export async function getDepartmentStats(id: string) {
  return request<{
    dept_id:        string
    total:          number
    decisions:      Record<string, number>
    block_rate:     number
    avg_latency_ms: number
    top_threats:    { category: string; count: number }[]
  }>(`/v1/admin/departments/${id}/stats`)
}

export async function updateDeptLLMOverride(
  id:   string,
  data: {
    provider?: string; model?: string; base_url?: string
    timeout?: number;  api_key?: string; clear?: boolean
  }
) {
  return request<Department>(`/v1/admin/departments/${id}/policy/llm`, {
    method: "PATCH",
    body:   JSON.stringify(data),
  })
}

export async function updateDeptProxyOverride(
  id:   string,
  data: {
    provider?: string; base_url?: string; default_model?: string
    timeout_seconds?: number; api_key?: string; clear?: boolean
  }
) {
  return request<Department>(`/v1/admin/departments/${id}/policy/proxy`, {
    method: "PATCH",
    body:   JSON.stringify(data),
  })
}

// ── Applications ──────────────────────────────────────────────
export async function getApplications() {
  return request<{ applications: Application[] }>("/v1/admin/applications")
}

export async function getApplicationsByDept(deptId: string) {
  return request<{ applications: Application[] }>(
    `/v1/admin/applications?dept_id=${deptId}`
  )
}

export async function getApplication(id: string) {
  return request<Application>(`/v1/admin/applications/${id}`)
}

export async function createApplication(data: {
  dept_id:      string
  name:         string
  slug:         string
  description?: string
  owner_name?:  string
  owner_email?: string
  environment?: string
}) {
  return request<Application>("/v1/admin/applications", {
    method: "POST",
    body:   JSON.stringify(data),
  })
}

export async function updateApplication(id: string, data: Partial<Application>) {
  return request<Application>(`/v1/admin/applications/${id}`, {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function deleteApplication(id: string) {
  return request<{ app_id: string; deactivated: boolean }>(
    `/v1/admin/applications/${id}`,
    { method: "DELETE" }
  )
}

export async function getApplicationPolicy(id: string) {
  return request<{
    app_id:          string
    app_name:        string
    dept_id:         string
    policy_source:   string
    override_set:    boolean
    policy_override: Record<string, any> | null
    resolved_policy: Record<string, any>
  }>(`/v1/admin/applications/${id}/policy`)
}

export async function setApplicationPolicy(
  id:              string,
  policy_override: Record<string, any> | null
) {
  return request<{
    app_id:          string
    policy_override: Record<string, any> | null
    policy_source:   string
    resolved_policy: Record<string, any>
    updated:         boolean
  }>(`/v1/admin/applications/${id}/policy`, {
    method: "PUT",
    body:   JSON.stringify({ policy_override }),
  })
}

export async function resetApplicationPolicy(id: string) {
  return request<{ app_id: string; reset: boolean; message: string }>(
    `/v1/admin/applications/${id}/policy`,
    { method: "DELETE" }
  )
}

export async function updateAppLLMOverride(
  id:   string,
  data: {
    provider?: string; model?: string; base_url?: string
    timeout?: number;  api_key?: string; clear?: boolean
  }
) {
  return request<Application>(`/v1/admin/applications/${id}/policy/llm`, {
    method: "PATCH",
    body:   JSON.stringify(data),
  })
}

export async function updateAppProxyOverride(
  id:   string,
  data: {
    provider?: string; base_url?: string; default_model?: string
    timeout_seconds?: number; api_key?: string; clear?: boolean
  }
) {
  return request<Application>(`/v1/admin/applications/${id}/policy/proxy`, {
    method: "PATCH",
    body:   JSON.stringify(data),
  })
}

// ── Tenant ────────────────────────────────────────────────────
export async function getTenant() {
  return request<{
    id:            string
    slug:          string
    name:          string
    description:   string | null
    global_policy?: Record<string, any>
    contact_email: string | null
    is_active:     boolean
    created_at:    string
  }>("/v1/admin/tenant")
}

export async function updateTenant(data: {
  name?:          string
  description?:   string
  contact_email?: string
  global_policy?: Record<string, any>
}) {
  return request<{
    id:            string
    name:          string
    description:   string | null
    global_policy?: Record<string, any>
    contact_email: string | null
  }>("/v1/admin/tenant", {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

// ── Users (JWT + ADMIN only) ──────────────────────────────────
export async function getUsers(params: {
  role?:      string
  is_active?: boolean
  limit?:     number
  offset?:    number
} = {}): Promise<DashboardUsersResponse> {
  const p = new URLSearchParams()
  if (params.role      != null) p.set("role",      params.role)
  if (params.is_active != null) p.set("is_active", String(params.is_active))
  if (params.limit     != null) p.set("limit",     String(params.limit))
  if (params.offset    != null) p.set("offset",    String(params.offset))
  return request<DashboardUsersResponse>(
    `/v1/admin/users${p.toString() ? `?${p}` : ""}`
  )
}

export async function getUser(userId: string): Promise<DashboardUser> {
  return request<DashboardUser>(`/v1/admin/users/${userId}`)
}

export async function createUser(data: {
  email:    string
  password: string
  role:     "ADMIN" | "DEVELOPER" | "VIEWER" | "AUDITOR"
  dept_id?: string
}): Promise<DashboardUser> {
  return request<DashboardUser>("/v1/admin/users", {
    method: "POST",
    body:   JSON.stringify(data),
  })
}

export async function updateUser(
  userId: string,
  data: {
    role?:      "ADMIN" | "DEVELOPER" | "VIEWER" | "AUDITOR"
    dept_id?:   string | null
    is_active?: boolean
  }
): Promise<DashboardUser> {
  return request<DashboardUser>(`/v1/admin/users/${userId}`, {
    method: "PUT",
    body:   JSON.stringify(data),
  })
}

export async function resetUserPassword(
  userId:      string,
  newPassword: string
): Promise<{ message: string; user_id: string }> {
  return request(`/v1/admin/users/${userId}/reset-password`, {
    method: "POST",
    body:   JSON.stringify({ new_password: newPassword }),
  })
}

// ── Health - routed through Next.js proxy so it works in Docker ─
export async function getHealth(): Promise<HealthReadyResponse> {
  const response = await fetch("/api/proxy/health/ready")
  return response.json()
}

export async function getHealthConfig() {
  return request<{
    version:          string
    thresholds:       { block: number; sanitize: number; source: string }
    detection_layers: { rule: boolean; ml: boolean; llm: boolean; source: string }
    llm:              { provider: string; model: string; llm_trigger: number; timeout: number; source: string }
    rate_limit:       { per_minute: number; scope: string }
  }>("/health/config")
}

// -- Webhooks / SIEM integrations (JWT + ADMIN only) --
export async function getWebhooks(): Promise<{ endpoints: WebhookEndpoint[] }> {
  return request<{ endpoints: WebhookEndpoint[] }>("/v1/admin/webhooks")
}

export async function getConnectorTypes(): Promise<{ connector_types: ConnectorTypeSchema[] }> {
  return request<{ connector_types: ConnectorTypeSchema[] }>(
    "/v1/admin/webhooks/connector-types"
  )
}

export async function createWebhook(body: {
  url:             string
  description?:     string
  connector_type?: string | null
  secret?:         string
  config?:         Record<string, string>
}): Promise<WebhookEndpointCreated> {
  return request<WebhookEndpointCreated>("/v1/admin/webhooks", {
    method: "POST",
    body:   JSON.stringify(body),
  })
}

export async function deleteWebhook(id: string): Promise<void> {
  return request<void>(`/v1/admin/webhooks/${id}`, { method: "DELETE" })
}

export async function testWebhook(id: string): Promise<WebhookTestResult> {
  return request<WebhookTestResult>(`/v1/admin/webhooks/${id}/test`, {
    method: "POST",
  })
}
