# WrapSec User Guide

*For dashboard administrators and users.*
*Last updated: August 2026*

---

## What is WrapSec?

WrapSec is an AI security gateway. It sits between your applications and LLM providers, inspecting every prompt and response for threats - prompt injection, jailbreak attempts, PII leakage, toxicity, and more.

You interact with WrapSec through this dashboard. Your applications interact with WrapSec through the API.

---

## Logging In

Open the dashboard at `http://your-host:3000`.

**First-time setup:** On a fresh installation with no users, the dashboard redirects to `/setup` automatically. Enter your email and password to create the first admin account. The setup page is permanently disabled after this - it cannot be accessed again once any user exists.

On the login page you have two options:

**Email / Password** - the primary login method for all dashboard users. Enter your email and password. If your account was created by an admin, you will be required to change your password on first login before accessing anything else.

**API Key** - gives read-only access to audit logs, scan endpoints, and (for live keys) settings. **API key sessions cannot modify settings, manage users, manage keys, or change any configuration** - all write operations require an ADMIN account login via Email / Password. Trial keys cannot read settings.

If your account has been locked after too many failed attempts, wait 15 minutes and try again.

If every login fails with a "tenant suspended" error, your organisation's access has been suspended by the platform operator - contact your operator or hosting administrator.

**Session timeout:** The dashboard automatically logs you out after 15 minutes of inactivity. A warning appears at 2 minutes remaining - click **Stay logged in** to continue, or **Log out now** to end your session immediately.

---

## Roles

Every user has one of four roles. Your role determines what you can see and do.

**ADMIN**
Full access to everything. Can manage users, departments, applications, API keys, and settings. Not scoped to any department - sees data across the entire organisation. There must always be at least one active ADMIN account.

**DEVELOPER**
Operational access scoped to their assigned department. Can scan prompts, view audit logs, create and manage API keys, and read settings. Cannot manage users or change settings.

**AUDITOR**
Read-only compliance role. Can view audit logs, request history, settings, and API key metadata. Assigned either tenant-wide (no department - sees audit data across all departments) or scoped to a single department. Cannot create keys or modify anything.

**VIEWER**
Read-only access scoped to their assigned department. Can view audit logs and request history. Cannot create API keys, read settings, or modify anything.

---

## User Management

User management is available to ADMIN users only. Navigate to **Users** in the sidebar under Administration.

### Creating a user

Click **Add user**. Fill in:

- **Email** - must be unique across the system
- **Temporary password** - minimum 8 characters, at least one uppercase letter, one lowercase letter, and one digit
- **Role** - ADMIN, DEVELOPER, AUDITOR, or VIEWER
- **Department** - required for DEVELOPER and VIEWER; optional for AUDITOR (leave empty for tenant-wide audit access); not applicable for ADMIN

The user will be required to change this password on their first login. Share the credentials with them out-of-band (email, Slack, etc.).

### Editing a user

Click **Manage** next to any user. From the modal you can:

- Change their role
- Change their department
- Reset their password (sets a new temporary password - user must change it on next login)
- Deactivate or reactivate their account

When you change a user's role or department, all their active sessions are immediately invalidated. They will need to log in again.

### Deactivating a user

Click **Manage** -> **Deactivate user** -> **Confirm**. The user is immediately signed out of all sessions and cannot log in until reactivated. Their data and audit history are preserved.

You cannot deactivate your own account. You cannot deactivate or demote the last active ADMIN - create another ADMIN first.

### Resetting a password

Click **Manage** -> **Reset password**. Enter a new temporary password. The user will be required to change it on their next login. All their current active sessions are immediately invalidated - they are signed out of all browsers and devices as soon as the reset is confirmed.

---

## Your Profile

Click your avatar in the top-right corner and select **Profile**.

Your profile shows your email, role, tenant, and last login time.

To change your password, click **Change password** in the profile card. You will need your current password. After a successful change, all your other active sessions (other browsers or devices) are signed out.

---

## Departments

Departments represent organisational units (e.g. Engineering, Finance, Legal). Each department can have its own security policy - different detection thresholds, PII sensitivity, or toxicity settings.

Navigate to **Departments** under Administration.

You can create departments, update their details, and configure policy overrides. Applications and API keys are scoped to departments. DEVELOPER and VIEWER users are also scoped to a single department.

If a department has no policy override, it inherits the global settings.

---

## Applications

Applications represent individual systems or services that connect to WrapSec (e.g. a code assistant, a customer support bot, an internal tool).

Navigate to **Applications** under Administration (via the Departments page - each application belongs to a department).

Each application can have its own policy override, further customising detection behaviour for that specific use case.

---

## API Keys

API keys are how your applications authenticate with WrapSec.

Navigate to **API Keys** under Configuration.

### Key types

**Live keys** (`wsk_live_...`) - standard production keys. Full access within their department or application scope.

**Trial keys** (`wsk_trial_...`) - restricted keys for demos. Input limited to 500 characters, rate limited to 10 requests per minute, proxy mode disabled.

### Creating a key

Click **Create key**. Choose a name, assign it to a department or application, and select the key type. The raw key value is shown once - copy it immediately and store it securely. It cannot be retrieved again.

### Rotating a key

Click **Rotate** on any key. A new key is created and the old key remains valid for a configurable grace period (default 60 minutes), giving you time to update your application's configuration before the old key expires.

### Revoking a key

Click **Revoke**. The key is immediately invalidated. Any application using it will start receiving 401 errors.

---

## Requests

The **Requests** page shows all AI requests that have passed through WrapSec.

Each request shows:
- **Trace ID** - unique identifier for the request
- **Decision** - ALLOW, BLOCK, or SANITIZE
- **Risk score** - detection pipeline score (0.0-1.0)
- **Primary reason** - what triggered the decision
- **Latency** - detection processing time

Click any row to see the full detail, including the input hash, detected threats, confidence score, and for proxy requests, the full interaction lifecycle.

### Decisions explained

**ALLOW** - no threat detected, request forwarded to LLM as-is.

**BLOCK** - threat detected, request stopped. The application receives an error response - the LLM was never called.

**SANITIZE** - PII or other sensitive content detected. The content was redacted before being forwarded to the LLM. The sanitized version of the input is available in the detail view.

### Filtering

Filter by decision, threat category, date range, execution mode (scan-only vs proxy), and more. Export filtered results to CSV using the **Export CSV** button.

---

## Analytics

The **Analytics** page shows trends over time - block rates, threat categories, latency, and request volume. Use the date range selector and group-by options (hour, day, week, month) to view the data at the granularity you need.

---

## Scanner

The **Scanner** page lets you test inputs manually. Enter any text and run a scan to see how WrapSec would classify it. Useful for testing policy configuration and understanding detection behaviour before deploying an integration.

---

## Settings

Settings are readable by users with the settings-read permission: ADMIN, DEVELOPER, and AUDITOR accounts, and live API key sessions. VIEWER accounts and trial keys cannot read settings. Only ADMIN users logged in via Email / Password can modify settings. API key sessions see settings but cannot save changes - a "Requires admin login" message is shown on all save buttons.

Settings apply to your organisation. On installations hosting more than one organisation, each organisation has its own independent settings.

### Detection thresholds

Controls how sensitive the detection pipeline is.

- **Block threshold** - risk score at or above this value triggers a BLOCK decision
- **Sanitize threshold** - risk score at or above this value (but below block) triggers SANITIZE

Default: block at 0.7, sanitize at 0.4. Block threshold must always be higher than sanitize threshold.

Guardrail thresholds (PII, toxicity) are configured per department in department policy overrides - they are independent of these detection thresholds.

### Detection layers

Enable or disable individual detection layers:

- **Rule detector** - regex and heuristic patterns, very fast (~1ms)
- **ML detector** - TF-IDF + logistic regression classifier (~5ms)
- **LLM detector** - semantic analysis via LLM, most accurate but slower (~100-500ms additional)

For latency-sensitive applications, disable the LLM detector and use `fast` mode.

### Rate limiting

Controls the global request rate limit for live API keys. Default: 60 requests per minute per key. Cannot be set below the trial key limit (10 req/min).

Changes take effect immediately on save; on multi-node deployments, other nodes pick up the change within 1 minute (cache TTL).

### Retention

Controls how long your organisation's audit logs are kept. Default: 30 days. Range: 7 to 3650 days. Logs older than the retention period are permanently deleted by the daily cleanup worker, which applies each organisation's own retention window.

### Storage mode

Controls whether raw input and output text is stored. Read-only - set via environment variable by your system administrator.

| Mode | Behaviour |
|---|---|
| `masked` | PII is redacted before storing (production default) |
| `full` | Text stored as-is |
| `none` | Text never persisted - only security metadata is stored |

### Proxy settings

Configure the LLM provider for proxy mode. Set the provider (OpenAI, Ollama, or any OpenAI-compatible endpoint via the custom provider), base URL, API key, default model, and timeout. The provider API key is encrypted at rest and never shown in full after saving.

Proxy settings are admin-only, including viewing - configuring an outbound provider and its credentials changes what leaves your system.

Use **Test connection** to verify WrapSec can reach the configured provider.

---

## System

The **System** page shows the current health of all WrapSec components - API, database, Redis, and ML model. Also shows the active configuration snapshot.

---

## Security Concepts

### Severity levels

Every request is assigned a severity level for audit and alerting purposes. Severity is not shown in the scan response - it is stored in the audit log only.

| Severity | Condition |
|---|---|
| CRITICAL | BLOCK with high risk score (0.9 or higher) or blocked by a guardrail |
| HIGH | BLOCK with lower risk score, or a system error |
| MEDIUM | SANITIZE (any reason) |
| LOW | ALLOW |

### Guardrails

Guardrails are independent of the detection pipeline and always take priority over it.

**PII guardrail** - detects and redacts personally identifiable information (30+ types including email addresses, phone numbers, credit card numbers, SSNs, passports, IBAN, SWIFT/BIC, driver licences, medical record numbers, and more). Can BLOCK or SANITIZE depending on configured thresholds.

**Toxicity guardrail** - detects hate speech, harassment, and other toxic content. BLOCK-or-ALLOW only: toxic content above the block threshold blocks the entire request; below it, the toxicity guardrail does not fire. There is no partial redaction tier - toxic text cannot be safely rewritten by pattern substitution.

Guardrail thresholds can be configured independently per department in the department policy override settings.

### Department policy overrides

Each department can override the global detection thresholds and guardrail settings. This allows different teams to have different sensitivity levels - for example, a customer-facing department might have stricter PII detection than an internal engineering tool.

When a department has an override, it shows **Overridden** in the department list. When no override is set, it shows **Inherits global**.

---

## Common Tasks

**I need to add a new team member to the dashboard**
-> Users -> Add user -> set role and department -> share credentials

**A user has left the organisation**
-> Users -> Manage -> Deactivate user

**An API key may have been compromised**
-> API Keys -> Rotate (gives a grace period) or Revoke (immediate)

**I want to see all blocked requests from the last 7 days**
-> Requests -> filter Decision = BLOCK, set date range

**I want to make our Finance department stricter about PII**
-> Departments -> Finance -> Manage -> Policy Override -> set `guardrails.pii.block_threshold` lower

**The LLM detector is adding too much latency**
-> Settings -> Detection layers -> disable LLM detector

**I want to understand why a specific request was blocked**
-> Requests -> find the trace ID -> click row -> view detail panel

---

*WrapSec v1.0 - August 2026*
