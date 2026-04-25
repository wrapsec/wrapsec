# WrapSec — GitHub Issues

---

## 🔐 Identity & Isolation

### 1. Enforce department_id in all DB queries

**Labels:** security, core
**Description:**

* Add `WHERE department_id = ?` to all queries
* Audit audit_logs + proxy_interactions
  **Acceptance:**
* No cross-department data leakage
* Tests added

---

### 2. Attach identity in middleware

**Labels:** core
**Description:**

* Resolve API key → tenant_id, department_id, app_id
* Attach to `request.state`
  **Acceptance:**
* Available in all endpoints

---

### 3. Scope trace_id queries

**Labels:** security
**Description:**

* Ensure trace_id lookup includes department_id
  **Acceptance:**
* Cross-dept trace_id returns 404

---

---

## 🔐 User Auth & RBAC

### 4. Implement user table

**Labels:** auth

* id, email, password_hash, department_id, role

---

### 5. Implement JWT auth

**Labels:** auth

* login endpoint
* token generation + validation

---

### 6. Enforce RBAC on endpoints

**Labels:** auth, security

* ADMIN → settings
* VIEWER → audit
* DEVELOPER → AI endpoints

---

---

## 🧾 Audit & Proxy

### 7. Ensure audit_logs + proxy consistency

**Labels:** core

* Same trace_id + department_id

---

### 8. Implement unified request detail API

**Labels:** api

* Merge audit + proxy data

---

---

## 📊 Observability

### 9. Add structured JSON logging

**Labels:** observability

* Emit per request to stdout

---

### 10. Add severity classification

**Labels:** observability

* BLOCK → HIGH
* SANITIZE → MEDIUM
* ALLOW → LOW

---

### 11. Validate Prometheus metrics

**Labels:** observability

* requests_total
* latency
* errors

---

---

## ⚙️ Infra Controls

### 12. Fix idempotency scoping

**Labels:** core

* tenant_id + department_id + key

---

### 13. Implement rate limiting

**Labels:** infra

* per API key or department

---

---

## 🔒 Demo Safety

### 14. Add demo restrictions

**Labels:** demo

* rate limit
* input size limit
* disable risky proxy

---

---

## 🧠 API Consistency

### 15. Clean decision model

**Labels:** api

* single `decision`
* remove duplicate input_decision

---

### 16. Separate detection vs execution mode

**Labels:** api

---

---

## 🧪 Testing

### 17. Add cross-department isolation tests

**Labels:** testing, security

---

### 18. Add RBAC tests

**Labels:** testing

---

### 19. Add trace_id leakage tests

**Labels:** testing, security

---

### 20. Add failure tests (DB/Redis down)

**Labels:** testing

---

---

## 🚀 v2 Foundation

### 21. Add DetectionEngine interface

**Labels:** architecture

---

### 22. Add basic vs advanced engine switch

**Labels:** architecture

---

---

# 🧪 k6 Load Test Script (save as tests/load/k6/test.js)

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
stages: [
{ duration: '30s', target: 20 },
{ duration: '1m', target: 50 },
{ duration: '30s', target: 100 },
{ duration: '30s', target: 0 },
],
};

const BASE_URL = 'http://localhost:8000';
const API_KEY = 'your_api_key';

export default function () {
const payload = JSON.stringify({
input: "What is the capital of Germany?"
});

const params = {
headers: {
'Content-Type': 'application/json',
'x-api-key': API_KEY,
},
};

const res = http.post(`${BASE_URL}/v1/ai/request`, payload, params);

check(res, {
'status is 200 or 400': (r) => r.status === 200 || r.status === 400,
'has trace_id': (r) => r.json().trace_id !== undefined,
});

sleep(1);
}

---

# 🧪 Run k6

k6 run tests/load/k6/test.js

---

# 🧠 Optional: Proxy Load Test

Change endpoint:

/v1/chat/completions

Add bigger payloads to simulate real usage.

---

# 🏁 Definition of Done (for every issue)

✔ Code implemented
✔ Tests added
✔ No cross-department leak
✔ Logs emitted correctly
✔ Works under load
✔ Reviewed

---

# 💥 Final Note

If you execute just this:

* Issues
* k6 tests
* RBAC
* logs

You’ll move from **project → production-grade system**
