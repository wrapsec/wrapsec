# Security Audit: Missing Authentication on Endpoints

**Date:** April 2026  
**Severity:** CRITICAL  
**Status:** Requires immediate remediation

---

## Summary

Multiple protected endpoints are missing explicit authentication dependencies in their function signatures. While some rely on middleware-set `request.state` fields for validation, they do not declare auth dependencies, violating the principle of explicit security.

**Security Impact:** 
- Implicit dependencies are hard to audit
- FASTAPI's dependency system is bypassed
- Easy for future developers to accidentally expose endpoints
- No compiler/linter warnings on missing auth

---

## Missing Authentication Dependencies

### 1. ❌ ai.py — Gateway Endpoints

**File:** `api/v1/endpoints/ai.py`

| Endpoint | Current | Required | Issue |
|---|---|---|---|
| `POST /v1/ai/request` | NO Depends() | `Depends(get_current_principal)` | No auth declared, relies on middleware |
| `GET /v1/ai/requests/{trace_id}` | NO Depends() | `Depends(get_current_principal)` | No auth declared, relies on middleware |

**Current Code (Line 85-90):**
```python
@router.post("/request", response_model=None)
async def ai_request(
    body:    AIRequestSchema,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    # Uses request.state.is_admin, request.state.key_type
    # But does NOT declare auth dependency
```

**Vulnerability:** If middleware is bypassed or misconfigured, endpoints are accessible without auth.

**Fix Required:**
```python
from api.v1.dependencies.auth import get_current_principal

@router.post("/request", response_model=None)
async def ai_request(
    body:       AIRequestSchema,
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    principal:  Principal    = Depends(get_current_principal),  # ADD THIS
):
```

---

### 2. ❌ proxy.py — Proxy Mode Endpoint

**File:** `api/v1/endpoints/proxy.py`

| Endpoint | Current | Required | Issue |
|---|---|---|---|
| `POST /v1/chat/completions` | NO Depends() | `Depends(get_current_principal)` | No auth declared |

**Current Code (Line 284-289):**
```python
@router.post("/chat/completions", response_model=None)
async def proxy_chat_completions(
    body:    ProxyChatRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    # Uses request.state.key_id, request.state.is_admin
    # But does NOT declare auth dependency
```

**Fix Required:**
```python
@router.post("/chat/completions", response_model=None)
async def proxy_chat_completions(
    body:       ProxyChatRequest,
    request:    Request,
    db:         AsyncSession = Depends(get_db),
    principal:  Principal    = Depends(get_current_principal),  # ADD THIS
):
```

---

### 3. ❌ tenant.py — Tenant Management Endpoints

**File:** `api/v1/endpoints/tenant.py`

| Endpoint | Current | Required | Issue |
|---|---|---|---|
| `GET /v1/admin/tenant` | NO Depends() | `Depends(require_admin())` | Allows unauthenticated read |
| `PUT /v1/admin/tenant` | NO Depends() | `Depends(require_admin())` | Allows unauthenticated write |

**Current Code (Line 35-48):**
```python
@router.get("")
async def get_tenant(db: AsyncSession = Depends(get_db)):
    # NO authentication — anyone can read tenant config
    repo   = TenantRepository(db)
    tenant = await repo.get_default()
    return JSONResponse(content=_format(tenant))

@router.put("")
async def update_tenant(
    body: TenantUpdateSchema,
    db:   AsyncSession = Depends(get_db),
):
    # NO authentication — anyone can update tenant config
```

**Vulnerability:** **CRITICAL** — Allows unauthenticated access to sensitive tenant configuration.

**Fix Required:**
```python
from api.v1.dependencies.auth import require_admin

@router.get("")
async def get_tenant(
    db:         AsyncSession = Depends(get_db),
    principal:  Principal    = Depends(require_admin()),  # ADD THIS
):
    ...

@router.put("")
async def update_tenant(
    body:       TenantUpdateSchema,
    db:         AsyncSession = Depends(get_db),
    principal:  Principal    = Depends(require_admin()),  # ADD THIS
):
    ...
```

---

### 4. ❌ proxy_settings.py — Proxy Configuration Endpoints

**File:** `api/v1/endpoints/proxy_settings.py`

| Endpoint | Current | Required | Issue |
|---|---|---|---|
| `GET /v1/settings/proxy` | NO Depends() | `Depends(get_current_principal)` | No auth declared |
| `PUT /v1/settings/proxy` | NO Depends() | `Depends(require_admin())` | No auth declared |
| `DELETE /v1/settings/proxy` | NO Depends() | `Depends(require_admin())` | No auth declared |
| `GET /v1/settings/proxy/health` | NO Depends() | `Depends(get_current_principal)` | No auth declared |

**Current Code (Line 121-232):**
```python
@router.get("/proxy")
async def get_proxy_settings(
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    # Uses request.state.key_id but no auth dependency

@router.put("/proxy")
async def put_proxy_settings(
    request: Request,
    body:    ProxySettingsPutSchema,
    db:      AsyncSession = Depends(get_db),
):
    # No auth dependency — anyone can set provider config

@router.delete("/proxy")
async def delete_proxy_settings(
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    # No auth dependency — anyone can delete config
```

**Vulnerability:** Allows unauthenticated modification of LLM provider credentials.

**Fix Required:**
```python
from api.v1.dependencies.auth import get_current_principal, require_admin

@router.get("/proxy")
async def get_proxy_settings(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),  # ADD THIS
):
    ...

@router.put("/proxy")
async def put_proxy_settings(
    request:   Request,
    body:      ProxySettingsPutSchema,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),  # ADD THIS
):
    ...

@router.delete("/proxy")
async def delete_proxy_settings(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(require_admin()),  # ADD THIS
):
    ...

@router.get("/proxy/health")
async def get_proxy_health(
    request:   Request,
    db:        AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),  # ADD THIS
):
    ...
```

---

### 5. ❌ proxy_interactions.py — Proxy Interaction Query Endpoints

**File:** `api/v1/endpoints/proxy_interactions.py`

| Endpoint | Current | Required | Issue |
|---|---|---|---|
| `GET /v1/proxy/interactions` | NO Depends() | `Depends(get_current_principal)` | No auth declared |
| `GET /v1/proxy/interactions/{trace_id}` | NO Depends() | `Depends(get_current_principal)` | No auth declared |

**Current Code (Line 59-90):**
```python
@router.get("/interactions")
async def list_proxy_interactions(
    request:          Request,
    execution_status: str | None = None,
    limit:            int = 50,
    offset:           int = 0,
    db:               AsyncSession = Depends(get_db),
):
    # No auth dependency — anyone can list proxy interactions

@router.get("/interactions/{trace_id}")
async def get_proxy_interaction(
    trace_id: str,
    db:       AsyncSession = Depends(get_db),
):
    # No auth dependency — anyone can view interaction details
```

**Vulnerability:** Allows unauthenticated access to proxy request/response logs.

**Fix Required:**
```python
from api.v1.dependencies.auth import get_current_principal

@router.get("/interactions")
async def list_proxy_interactions(
    request:          Request,
    execution_status: str | None = None,
    limit:            int = 50,
    offset:           int = 0,
    db:               AsyncSession = Depends(get_db),
    principal:        Principal    = Depends(get_current_principal),  # ADD THIS
):
    ...

@router.get("/interactions/{trace_id}")
async def get_proxy_interaction(
    trace_id: str,
    db:       AsyncSession = Depends(get_db),
    principal: Principal    = Depends(get_current_principal),  # ADD THIS
):
    ...
```

---

### 6. ⚠️ audit.py — Implicit Authentication

**File:** `api/v1/endpoints/audit.py`

| Endpoint | Current | Issue |
|---|---|---|
| `GET /v1/audit/logs` | NO Depends() | Uses `request.state.is_admin` but does not declare dependency |
| `GET /v1/audit/stats` | NO Depends() | Uses `request.state` but does not declare dependency |
| `GET /v1/audit/attribution` | NO Depends() | Uses `request.state` but does not declare dependency |
| `GET /v1/audit/analytics` | NO Depends() | Uses `request.state` but does not declare dependency |
| `GET /v1/audit/export` | NO Depends() | Uses `request.state` but does not declare dependency |

**Current Code (Line 59-81):**
```python
@router.get("/logs")
async def get_audit_logs(
    request:         Request,
    # ... many query params
    db:              AsyncSession = Depends(get_db),
):
    is_admin = getattr(request.state, "is_admin", False)
    if not is_admin:
        dept_id   = getattr(request.state, "dept_id",   None)
        tenant_id = getattr(request.state, "tenant_id", None)
    # ... relies on request.state but NO declared dependency
```

**Issue:** Implicit reliance on middleware. Functions should declare auth explicitly.

**Fix Required:**
```python
from api.v1.dependencies.auth import get_current_principal

@router.get("/logs")
async def get_audit_logs(
    request:         Request,
    # ... many query params
    db:              AsyncSession = Depends(get_db),
    principal:       Principal    = Depends(get_current_principal),  # ADD THIS
):
    # Now explicitly protected
    ...
```

---

## API Documentation Requirements

According to **jwt_reference.md §Endpoint Auth Requirements**, these endpoints should be protected:

```
✅ POST /v1/ai/request                     → API key OR JWT Bearer (currently exposed)
✅ GET /v1/ai/requests/{trace_id}          → API key OR JWT Bearer (currently exposed)
✅ POST /v1/chat/completions               → API key OR JWT Bearer (currently exposed)
✅ GET /v1/settings/proxy                  → API key OR JWT Bearer (currently exposed)
✅ PUT /v1/settings/proxy                  → API key admin only (currently exposed)
✅ DELETE /v1/settings/proxy               → API key admin only (currently exposed)
✅ GET /v1/audit/*                         → API key OR JWT Bearer (currently exposed)
✅ GET /v1/admin/tenant                    → Admin key OR JWT ADMIN (currently exposed)
✅ PUT /v1/admin/tenant                    → Admin key OR JWT ADMIN (currently exposed)
```

---

## Why This Matters

### Current Problem
```
Middleware sets:
  request.state.is_admin = True/False
  request.state.tenant_id = "..."

Endpoint uses it:
  is_admin = getattr(request.state, "is_admin", False)

But never declares:
  principal: Principal = Depends(get_current_principal)
```

**Risk:** If middleware is misconfigured or future developer removes middleware, endpoints are unprotected with no warnings.

### Correct Pattern
```
Endpoint declares:
  principal: Principal = Depends(get_current_principal)

FastAPI enforces:
  - Dependency must run
  - If it raises 401, endpoint is never called
  - Explicit and auditable
```

---

## Remediation Checklist

- [ ] **ai.py**
  - [ ] Add `Depends(get_current_principal)` to POST /v1/ai/request
  - [ ] Add `Depends(get_current_principal)` to GET /v1/ai/requests/{trace_id}
  - [ ] Import Principal, get_current_principal
  - [ ] Test both endpoints with and without auth header

- [ ] **proxy.py**
  - [ ] Add `Depends(get_current_principal)` to POST /v1/chat/completions
  - [ ] Import Principal, get_current_principal
  - [ ] Test with and without auth header

- [ ] **tenant.py** ⚠️ CRITICAL
  - [ ] Add `Depends(require_admin())` to GET /v1/admin/tenant
  - [ ] Add `Depends(require_admin())` to PUT /v1/admin/tenant
  - [ ] Import Principal, require_admin
  - [ ] Test that non-admin gets 403 FORBIDDEN

- [ ] **proxy_settings.py**
  - [ ] Add `Depends(get_current_principal)` to GET /v1/settings/proxy
  - [ ] Add `Depends(require_admin())` to PUT /v1/settings/proxy
  - [ ] Add `Depends(require_admin())` to DELETE /v1/settings/proxy
  - [ ] Add `Depends(get_current_principal)` to GET /v1/settings/proxy/health
  - [ ] Import Principal, get_current_principal, require_admin
  - [ ] Test with/without auth, with/without admin role

- [ ] **proxy_interactions.py**
  - [ ] Add `Depends(get_current_principal)` to GET /v1/proxy/interactions
  - [ ] Add `Depends(get_current_principal)` to GET /v1/proxy/interactions/{trace_id}
  - [ ] Import Principal, get_current_principal
  - [ ] Add dept scoping (non-admin only sees own dept)

- [ ] **audit.py**
  - [ ] Add `Depends(get_current_principal)` to GET /v1/audit/logs
  - [ ] Add `Depends(get_current_principal)` to GET /v1/audit/stats
  - [ ] Add `Depends(get_current_principal)` to GET /v1/audit/attribution
  - [ ] Add `Depends(get_current_principal)` to GET /v1/audit/analytics
  - [ ] Add `Depends(get_current_principal)` to GET /v1/audit/export
  - [ ] Import Principal, get_current_principal
  - [ ] Test with/without auth

- [ ] **Integration Tests**
  - [ ] Test each endpoint WITH valid API key → 200
  - [ ] Test each endpoint WITH valid JWT → 200
  - [ ] Test each endpoint WITHOUT auth → 401 UNAUTHORIZED
  - [ ] Test admin-only endpoints WITH DEVELOPER JWT → 403 FORBIDDEN
  - [ ] Test dept scoping (non-admin gets only own dept)

- [ ] **Update api.md**
  - [ ] Document auth requirement for each endpoint
  - [ ] Update endpoint table with JWT/API key requirements

---

## Testing Template

```python
# tests/integration/test_auth_enforcement.py

@pytest.mark.asyncio
async def test_ai_request_requires_auth(client):
    """POST /v1/ai/request without auth → 401"""
    response = client.post("/v1/ai/request", json={"input": "test"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"

@pytest.mark.asyncio
async def test_ai_request_with_auth(client, jwt_token):
    """POST /v1/ai/request with JWT → 200"""
    response = client.post(
        "/v1/ai/request",
        json={"input": "test"},
        headers={"Authorization": f"Bearer {jwt_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_tenant_requires_admin(client, developer_jwt_token):
    """GET /v1/admin/tenant with DEVELOPER JWT → 403"""
    response = client.get(
        "/v1/admin/tenant",
        headers={"Authorization": f"Bearer {developer_jwt_token}"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"

@pytest.mark.asyncio
async def test_tenant_requires_admin_key(client):
    """GET /v1/admin/tenant with standard API key → 403"""
    response = client.get(
        "/v1/admin/tenant",
        headers={"x-api-key": "wsk_live_standard_key"}
    )
    assert response.status_code == 403  # Only admin key allowed
```

---

## Priority

| Priority | Endpoints | Risk |
|---|---|---|
| 🔴 CRITICAL | `tenant.py` | Unprotected tenant configuration |
| 🔴 CRITICAL | `proxy_settings.py` | Unprotected LLM provider credentials |
| 🟠 HIGH | `ai.py` | Unprotected gateway endpoints |
| 🟠 HIGH | `proxy.py` | Unprotected chat completion proxy |
| 🟡 MEDIUM | `audit.py` | Implicit dependencies |
| 🟡 MEDIUM | `proxy_interactions.py` | Unprotected interaction logs |

---

## References

- **jwt_reference.md** — Endpoint Auth Requirements Matrix
- **JWT_implementation_plan.md** — Section 12: RBAC Dependencies
- **OWASP** — Authentication Cheat Sheet

---

**Status:** Requires immediate remediation before any further deployment.

**Estimated Effort:** 2-3 hours (code changes + tests)

**Testing Required:** Integration tests for all fixed endpoints

---

*Audit completed: April 2026*
*Security-critical issues identified and remediation steps provided*
