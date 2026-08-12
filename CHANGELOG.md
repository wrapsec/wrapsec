# Changelog

All notable changes to WrapSec are documented here.

## [1.8.2] - 2026-08-12

Full dashboard localization. Completes the string migration begun in 1.8.1: the
entire dashboard renders from the localization catalog, ships a German
translation with an in-app language switcher, and adds text-direction support.
Backend responses remain English; no public scan/chat/admin API changes.

### Added
- **Complete dashboard translation.** Every dashboard page and component renders
  from the localization catalog; no hardcoded UI text remains. Enabling a
  language is a data change -- add its catalog under `locales/<locale>/` and
  register it in `locales/_meta.json`.
- **German (de).** A full German dashboard translation, the first non-English
  locale.
- **Language switcher.** A header control lets a signed-in user switch language;
  the choice is saved to their profile and applied immediately. A locale changed
  out of band (via the API/SDK, or a tenant default change) is reflected on the
  next load.
- **Text direction (LTR/RTL).** Each locale declares its text direction and the
  dashboard sets the document direction from it (LTR today; RTL-ready).

### Changed
- The user and tenant locale is now length-bounded at the request layer to match
  its database column -- a tighter contract with no change for valid locales.

## [1.8.1] - 2026-08-11

Error-handling and localization foundation. Reworks every error response onto a
stable, localization-ready contract, adds a locale preference for users and
tenants, and stands up the end-to-end localization pipeline (canonical catalog
-> generated consumer catalogs -> dashboard). Backend responses and the UI stay
English; the machinery is now in place for translated dashboards (the actual UI
string translation lands in a follow-up).

### Added
- **Stable, localization-ready error contract.** Every error response now carries
  `code` (a stable, add-only machine-readable identifier), `severity`
  (`ERROR` / `WARNING` / `INFO`), a localization `key`, and structured `params`,
  alongside the existing `message` and `trace_id`. `code` is a documented public
  contract that SDKs and SIEM rules can branch on; `message` is an English
  convenience and may change without changing the code.
- **Structured field validation (422).** Validation errors now include an
  `invalid_params` array -- one entry per field with the field name, a stable
  `ValidationCode` (`REQUIRED`, `INVALID_EMAIL`, `TOO_LONG`, `INVALID_ENUM`,
  `INVALID_URL`, ...), a localization key, and params -- so a form can attach each
  error to the right input.
- **Locale preference (users and tenants).** A preferred locale (BCP-47) can be
  stored per user and per tenant. `GET /v1/auth/me` returns `locale` (the stored
  preference) and `resolved_locale` (User -> Tenant -> System default -> English);
  the login and refresh responses also return `resolved_locale`, so the effective
  locale is re-resolved continuously (a tenant/user change reaches a live session
  without re-login). A new `PATCH /v1/auth/me`
  lets a user set their own locale; `GET`/`PUT /v1/admin/tenant` expose and set
  the tenant default. Unsupported locales are rejected `422 INVALID_ENUM`.
- **Localization pipeline (single source of truth).** Supported locales, the
  default, and the catalog version are configured in one place -- `locales/_meta.json`
  -- and all localized text lives in `locales/<locale>/*.json` (ICU). A generator
  validates the canonical catalog and emits every consumer artifact (the backend
  English map and the dashboard message catalog + locale config), so no consumer
  keeps a second, drift-prone copy. Operators enable a new language by adding its
  catalog there.
- **Dashboard localization foundation.** The dashboard now renders through a
  localization framework (cookie-based), consuming the generated catalog. The
  active locale comes from the backend's resolved value (the frontend never
  re-derives precedence); the UI remains English until strings are translated.
- **New error codes.** `CANNOT_DEACTIVATE_SELF` and `LAST_ADMIN` (both `409`) make
  the admin user-management guards explicit and client-actionable;
  `INVALID_PASSWORD` and `IDEMPOTENCY_CONFLICT` are now first-class catalog codes.

### Changed
- **Error messages refined for a security console** (for example
  `INVALID_CREDENTIALS` -> "Invalid credentials."). Wording is presentation and
  localization-driven; the stable codes are unchanged.
- **Rate-limit code unified.** The login and middleware rate-limit responses now
  use `RATE_LIMIT_EXCEEDED` (previously `RATE_LIMITED` in two paths) -- one
  canonical code for the condition.
- **Admin self-deactivation / last-admin guards** return `409` with the dedicated
  codes above instead of a generic `400 INVALID_REQUEST`.
- **Responses no longer echo internal identifiers or raw validator text.**
  Not-found responses name the resource but not the id; validator detail (SSRF
  URL reason, password-strength rules) is logged and correlated via `trace_id`,
  never returned. The top-level `422` message is generic; the specifics live in
  `invalid_params`.
- `key_type` on API-key creation is validated as an enum, producing a structured
  `422 INVALID_ENUM` instead of an ad-hoc message.

### Database
- Nullable `locale` column added to `users` and `tenants` (migration `0013`,
  additive and non-locking; a no-op on a fresh install).

### Migration notes
- Additive on the wire: the new envelope fields are added, not removed, so
  clients that read `error.message` keep working. Clients that branch on the
  error CODE should note the `RATE_LIMITED` -> `RATE_LIMIT_EXCEEDED` unification
  and the new `409` admin-guard codes.

## [1.8.0] - 2026-08-10

RAG-security and dashboard release. Adds source-aware policy posture, a batch
scan endpoint with RAG-security SDK helpers, a Security-by-Source dashboard,
and a RAG evaluation corpus; a ground-up overhaul of the Requests experience
with a unified visual system across every dashboard page; uniform
department/application listings; two authenticated-session fixes; and a pass
of server-side input validation. No public scan/chat/admin API changes; the
scan, proxy, and audit contracts are wire-compatible with 1.7.x clients.

### Added
- **Source-aware policy posture (opt-in).** Trust-boundary provenance can now
  influence the policy decision: untrusted origins (`retrieved_document`,
  `tool_output`, `external_content`) may be held to tighter block/sanitize
  thresholds than `user_prompt`. A small pipeline does it -- a Source Registry
  (`engine/provenance`) classifies `input_source` into a trust tier, and a
  Posture + Policy Adapter (`engine/policy/posture`) lowers the thresholds the
  policy engine applies. Config-driven and fully opt-in:
  `UNTRUSTED_THRESHOLD_DELTA` defaults to `0` (no change on upgrade), with
  `TRUSTED_INPUT_SOURCES` / `UNTRUSTED_INPUT_SOURCES` /
  `TREAT_UNKNOWN_AS_UNTRUSTED` controlling classification. When a source shifts
  the thresholds, the scan response `assessment` gains a `posture` block
  (`tier`, `applied_delta`, effective thresholds) for transparency.
  **Architectural rule: source affects POLICY only -- never detection or the
  assessment's detector scores.** Identical content scores identically whatever
  origin it claims, so a caller cannot weaken detection by misdeclaring a source.
- **Batch scan endpoint.** `POST /v1/ai/scan-batch` scans many items in one
  call, each with its own `input_source`, and returns a per-item decision +
  assessment plus a `summary` (blocked/sanitized/allowed, highest risk and the
  item that produced it, and the union of threats). Every item runs the same
  pipeline as a single scan and is audited independently; a batch is charged as
  N units against the rate limit so it cannot amplify throughput.
- **RAG-security SDK helpers.** The Python and Node SDKs gain `scan_batch()`
  plus per-source convenience wrappers `scan_documents()` / `scan_tool_outputs()`
  / `scan_external()` and `filter_safe()` -- a one-call "drop the poisoned
  chunks" helper for a retrieval pipeline. New `BatchScanResult` / `BatchItemResult`
  models.
- **Security by Source dashboard.** A new `/sources` view and
  `GET /v1/audit/by-source` endpoint group audit data by `input_source`: per
  source it shows scan volume, decision mix, block rate, risk distribution, and
  threat-category counts, plus a **Top Attack Origins** leaderboard ranking
  sources by attack volume.
- **RAG evaluation corpora + calibration.** New `tests/eval/corpus_rag/`
  (poisoned retrieved documents + benign documents that legitimately discuss
  attacks) and a `calibrate_source_posture.py` sweep that reports poisoned-doc
  catch-rate versus benign false-positive rate across delta values. On the
  current FAST-mode detector the aggregated risk score is bimodal, so the delta
  shows no change on this corpus -- the calibrated recommendation is to keep the
  default `0` until graded/mid-band scoring (Tier-2 transformer) lands. The
  eval harness now carries `input_source` per case.
- **Requests triage table with a detail drawer.** The Requests page is now a
  triage surface: a compact table of scans opens a right-side detail drawer
  with a verdict hero (decision, risk, primary reason), config-driven tabs,
  and recommended actions. Agent, provenance, and content-source fields are
  projected into the drawer, and a single "Open Agent Run" link is the one
  navigation into an agent run's timeline.
- **Filter-scoped Security Overview strip.** The Requests view carries a
  Security Overview strip that recomputes against the active filters, showing
  average risk and the severity distribution for exactly the rows in view.
- **Webhook pause/resume.** A destination can be paused and resumed from the
  Integrations page, guarded by a confirmation modal, with hardened error
  handling on the toggle.

### Changed
- **Unified dashboard visual system.** Every page now shares one component
  set -- `PageHeader`, `Table`, `StatCard`, `KpiCard`, `RangeTabs`, and a
  single badge geometry across decision / threat / severity / mode / source.
  Overview and Analytics KPI cards are one `KpiCard`; page headers are
  vertically aligned with range controls folded into the header; the
  collapsed sidebar rail hides its scrollbar. Header and section copy was
  rewritten for a consistent professional tone (the request drawer's
  "Verdict" section is now "Summary").
- **URL is the source of truth for list and drawer state.** List filters,
  pagination, and the open detail drawer are driven from the URL
  (drawer-peek + resource-route navigation), so views are shareable and
  back/forward behaves correctly. List-param writes read the live URL.
- **Requests filter toolbar and labels.** A single-row filter toolbar with a
  flexible search replaces the two-row layout that wrapped unevenly; the
  primary count is renamed from "Total" to "Requests" with compact counts and
  uniform KPI accents; the redundant chip row and the static trust-boundary
  blurb were removed. A run renders as plain text in both the row and the
  drawer.
- **Uniform department and application listings.** Departments and
  applications share one listing table with a consistent name + slug identity
  and a policy badge, and the department row shows its application count.
  Slugs auto-derive from the name (still editable).

### Fixed
- **Webhook deletion 500.** Removing a webhook endpoint that had delivery
  history failed with a foreign-key violation (the `webhook_delivery_attempts`
  FK has no `ON DELETE CASCADE`). Deletion now clears the endpoint's delivery
  history first, in the same transaction.
- **Silent logout mid-session.** The session-indicator cookie was scoped to
  the access-token lifetime, so it expired while the refresh token was still
  valid and dropped the user mid-session. It now lives as long as the refresh
  token.
- **Spurious logouts under concurrent token refresh.** Refreshes are now
  single-flight (all in-flight refreshes share one request), and the proxy no
  longer clears the session on a recoverable 401, preventing the rotating
  refresh token from racing itself into a false logout.
- **Requests filter clear behavior.** "Clear all" and clearing a date now
  compose their URL updates in a single tick, fixing a regression where the
  pending-ref path left filters in an inconsistent state.
- **Duplicate error message on create.** Opening a department/application
  create form no longer shows the same validation error twice; the 422 email
  message is a concise, field-scoped line instead of the raw email-validator
  sentence.

### Security
- **Server-side input validation hardening.** Contact and owner emails are
  validated as email addresses (`EmailStr`); names and descriptions carry
  length caps; API `key_type` is an enum; UUID and ISO fields are format-
  checked; the application `environment` is validated against a
  `production` / `staging` / `development` enum; and webhook subscriptions
  accept only allowlisted event types. These are enforced at the API
  boundary, so malformed or oversized input is rejected before it reaches the
  data layer.
- **Slug integrity for departments and applications.** Slugs are canonicalized
  server-side and are unique per tenant among active records; a colliding slug
  is rejected with 409 instead of silently creating a duplicate identity.

## [1.7.0] - 2026-08-04

### Added
- **Input provenance (trust boundary).** An optional `input_source` field on the
  scan request (`user_prompt` default, plus `tool_output`, `retrieved_document`,
  `external_content`) records where the scanned text came from. The untrusted
  origins mark content an agent pulled in -- the indirect prompt-injection
  surface. It is labeled, persisted, and scanned by the same pipeline and never
  relaxes detection. Stored on `audit_logs` (NOT NULL, default `user_prompt`) and
  forwarded by the Python and Node SDKs.
- **Security assessment in the scan response.** Every scan now returns an
  always-present `assessment` object -- a self-contained structured verdict
  (decision, risk score, risk level, primary reason, threats, confidence) plus
  per-layer detector contributions from the full layer bag (not just the five
  fixed keys). Exposed on the Python and Node SDK `ScanResult`, so agents and
  tools can reason about the "why", not just BLOCK/ALLOW.
- **Agent-run timeline.** A new `GET /v1/agent-runs/{run_id}` endpoint returns
  every scan in one agent run, ordered by turn index and tenant/department
  scoped, plus a dashboard timeline view that renders the run with per-turn
  decision and provenance (reachable from a run link on each request row). The
  scan endpoint now also persists the previously-accepted `session_id`,
  `turn_index`, and `run_id` fields.
- **Function-calling tool manifest.** The Python SDK exposes `wrapsec_scan` as a
  function-calling tool: `scan_tool_schema()` (a canonical JSON-Schema
  definition) plus `openai_tool()` and `anthropic_tool()` adapters, so any agent
  framework can register WrapSec as a security tool.
- **MCP server (opt-in).** A Model Context Protocol server (`python -m
  mcp_server`, installed via `requirements-mcp.txt`) exposes `wrapsec_scan` over
  MCP so any MCP-compatible agent can call it natively. It is a thin interface
  adapter over the SDK client and enforces the API key on every scan.

## [1.6.0] - 2026-08-04

### Added
- **Input normalization and evasion-resistant detection.** A new deterministic
  preprocessing subsystem (`engine/normalization`) canonicalizes every prompt
  before detection -- folding cross-script homoglyphs (a TR39-style confusable
  table, beyond what NFKC alone catches), zero-width and bidi controls, and
  whitespace -- and emits bounded decode-views for leetspeak and base64. Rule and
  ML detection now scan the canonical form plus every view and take the strongest
  signal (`engine/detection/view_evaluator`), so obfuscation can no longer evade
  by hiding intent in an alternate encoding. The LLM detector and the proxy call
  always receive the original text; normalization makes no policy decision and
  does not affect the risk score. On the evaluation corpus this lifts
  encoding-evasion catch-rate from 83.3% to 100% with the false-positive rate
  unchanged (benign inputs generate no views, so they pay no extra latency and
  cannot be newly false-flagged). Obfuscated inputs incur a bounded number of
  extra detection passes, capped by the view limits and the per-detector timeout.

### Changed
- **Reduced detection over-defense (rule precision).** The `jailbreak` and
  `developer mode` rule patterns were bare nouns that fired on legitimate non-AI
  uses (device jailbreaking, IDE/browser developer mode) and definitional
  questions about the terms. They now match the attack construction (activation
  and targeting forms -- "enable developer mode", "in developer mode you...",
  "jailbroken", "jailbreak mode"), which is evasion-robust because real attacks use
  those forms. On the evaluation corpus this cuts the benign-but-suspicious
  false-positive rate from 32% to 20% and the overall false-positive rate from
  14.5% to 9.1%, with catch-rate, out-of-distribution catch, and every attack
  category unchanged.

## [1.5.0] - 2026-08-02

### Added
- **Red-team / guardrail-evaluation harness.** A new `tests/eval` tier scores
  the detection pipeline against a labeled adversarial corpus -- prompt
  injection, jailbreak, encoding/obfuscation evasion, indirect injection, and
  data exfiltration, plus benign and "benign-but-suspicious" over-defense sets
  and a held-out out-of-distribution set. It reports catch-rate, false-positive
  rate (including over-defense), per-category breakdown, OOD generalisation, and
  the explicit bypass and false-positive lists. The run is fully offline (no LLM
  provider, database, or Redis). `make eval` prints the report and runs a
  regression gate (catch-rate floor and false-positive ceiling), so a change
  that weakens detection or worsens over-defense fails CI. Doubles as a
  reproducible, publishable measure of detection efficacy.

## [1.4.1] - 2026-08-02

### Fixed
- **API key grace-period badge.** After the 1.4.0 timestamp change, the
  "Expiring - grace period active" badge on a rotated key stopped appearing
  (along with the grace-aware Rotate/Revoke states), because a stale
  client-side workaround double-appended `Z` to the now-`Z`-suffixed
  `expires_at`, producing an invalid date. The dashboard now parses the value
  correctly.

### Changed
- **Dashboard date, number, and cache-key handling consolidated.** Date and
  time formatting plus time-range logic moved to a single module, number
  formatting to another, and the shared entity cache keys to a third. Behaviour
  is unchanged apart from a more consistent relative-time label on the overview
  key-activity card.

## [1.4.0] - 2026-08-02

### Changed
- **Timestamps are timezone-aware UTC end to end.** Every event timestamp is
  stored as PostgreSQL `TIMESTAMPTZ`, and every timestamp returned by the API or
  emitted in an export or webhook payload is ISO-8601 UTC with a trailing `Z`
  (for example `2026-08-02T09:15:42.123Z`) at millisecond precision. Some
  responses previously carried no timezone marker, which a client could misread
  as local time; the format is now consistent, so clients that parse timestamps
  should expect the `Z` form. Timezone conversion is a presentation concern.
  Time handling is now defined in a single internal source.
- **Timestamp columns migrated on upgrade.** Migration `0010` converts existing
  timestamp columns to `TIMESTAMPTZ` in place, preserving every value as UTC;
  the partitioned `webhook_delivery_attempts` table is migrated with a
  data-preserving rebuild (no rows lost). It runs automatically on API startup
  and is a no-op on a fresh install. Database sessions are pinned to UTC.
- **Consistent audit date-range filtering.** A date-only upper bound
  (`to=2026-04-16`) now covers the whole day on every audit endpoint instead of
  only its first instant on some. Full ISO 8601 bounds behave as before.
- **Centralized Redis key names.** Runtime cache and lock keys are built from a
  single internal registry, removing duplicated key strings; key values are
  unchanged.

### Added
- **Plugin discovery and capabilities endpoint.** Optional plugins are
  discovered through an entry-point mechanism at startup, and
  `GET /v1/capabilities` reports the running edition and the set of enabled
  capabilities. The base build loads no plugins.

## [1.3.1] - 2026-07-31

### Added
- **Dashboard Integrations settings page.** Configure SIEM/webhook destinations
  from the dashboard: a destination catalog, schema-driven per-connector forms,
  a health chip per endpoint (active / failing / auto-disabled), and a one-click
  "Send test" that shows the receiver's response.
- **Connector-type schema endpoint.** `GET /v1/admin/webhooks/connector-types`
  returns the per-connector field spec (labels, required config keys) so the
  dashboard form is driven by the API rather than hardcoded in the frontend.
- **Synthetic test-send endpoint.** `POST /v1/admin/webhooks/{id}/test` sends a
  clearly-marked test event and returns the receiver's status, body, and timing.
  Side-effect-free (no queue, no delivery-attempt row, no circuit-breaker
  impact), ADMIN-only and tenant-scoped, and it never returns the secret.

### Security
- **Webhook egress SSRF hardening.** Webhook/SIEM destinations are resolved at
  connect time and blocked if they map to a private/loopback/link-local/metadata
  address, and https is required -- secure by default. This is distinct from the
  LLM proxy target, which is often an internal service and stays permissive. An
  on-prem SIEM on a private address is allowed by listing its host or CIDR in
  `WEBHOOK_EGRESS_ALLOWLIST`. The check runs on every delivery, closing the gap
  where a destination that was public at create time is later repointed
  internally.

### Fixed
- Removed references to internal-only docs from public files (CHANGELOG, API
  reference, and a source comment).

## [1.3.0] - 2026-07-30

### Added
- **Outbound webhooks on BLOCK/SANITIZE decisions.** Every block or
  sanitize decision fans out to the tenant's configured destinations via
  a background task, so the scan hot path never blocks on delivery. The
  event body mirrors `GET /v1/audit/logs`, reusing the canonical
  `severity` and `primary_reason` taxonomy; ALLOW is not emitted.
- **Signed generic webhooks.** HMAC-SHA256 signing with per-endpoint
  secrets and `webhook-id` / `webhook-timestamp` / `webhook-signature`
  headers. Secret rotation keeps the old secret valid for a grace window
  so receivers can update verifier config without dropped deliveries.
- **Reliable delivery pipeline.** Redis Streams queue (main / delayed /
  dead-letter) and a delivery worker started in the API lifespan on a
  dedicated Redis connection. Fixed retry schedule
  (5s, 5m, 30m, 2h, 5h, 10h, 10h) then dead-letter; a circuit breaker
  auto-disables an endpoint after 120h of continuous failure. Every
  attempt is logged to the partitioned `webhook_delivery_attempts` table.
- **SIEM connectors.** `splunk_hec`, `datadog_logs`,
  `sentinel_logs_ingestion` (Azure Monitor Logs Ingestion API with an
  Entra client-credentials bearer, cached in Redis), and `elastic_ecs`
  (Bulk API NDJSON, ECS-normalized). Each connector's request shape is
  built to the vendor's documented contract.
- **Webhook admin API.** `GET/POST/PUT/DELETE /v1/admin/webhooks` and
  `POST /v1/admin/webhooks/{id}/rotate-secret` (ADMIN only). Connector
  endpoints take a customer-supplied ingest token (never echoed back) and
  are validated per connector (unknown type, missing secret, and missing
  required `config` keys are rejected at create). Destination URLs are
  SSRF-validated. Read projections expose a computed `status`
  (`active` / `failing` / `auto_disabled`).

### Changed
- **Integration tests run on a disposable PostgreSQL, not SQLite.**
  `make test-integration` provisions an ephemeral `postgres:16-alpine`,
  points the app and the tests at it, and tears it down. The tier skips
  gracefully when no disposable database is configured. Real-PG parity
  surfaced foreign-key defects that SQLite had masked.

### Database
- `webhook_endpoints` gains `connector_type` and `config` columns
  (migration `0009`, nullable and non-locking).

## [1.2.4] - 2026-07-29

### Fixed
- **Overview badge count did not match the filtered Requests view.**
  Clicking a decision badge on the Overview (e.g. "14 BLOCKED in 24h")
  deep-linked to `/requests` with a full ISO `from`/`to` window, but the
  Requests page stripped the time portion when it stored the params in
  state. The fetch effect then re-attached `T00:00:00` / `T23:59:59`,
  widening a 24h window to ~48h and inflating the result badge against
  the Overview number (observed 204 -> 213 for total, 14 -> 15 for
  BLOCKED). State now preserves the T-portion; the `<input type="date">`
  widget receives `from.slice(0, 10)` at the render boundary; the fetch
  code is unchanged and still re-attaches boundary times when the user
  edits the plain date input. Follow-up to the v1.2.2 fix which
  addressed the input-rejection symptom but introduced the widening.

### Changed
- `GET /v1/audit/stats` now returns `block_count`, `sanitize_count`, and
  `allow_count` alongside the existing rate fields. Dashboard overview
  cards and the donut chart consume the counts directly instead of
  recomputing via `Math.round(rate * total)`. Reconstructing from the
  rate drifted by one against `/v1/audit/logs?decision=...` because the
  API rounds `*_rate` to 4 decimals before returning.

### Internal
- Gitignored `scripts/seed_dashboard_test_traffic.py` and
  `scripts/.seed_keys.json`. Local-only harness for repopulating the
  dashboard with sample traffic; not for the public repo.

## [1.2.3] - 2026-07-28

### Added
- **Testcontainers-backed integration tests.** New `pg_client` fixture in
  `tests/integration/conftest.py` runs API tests against a real
  PostgreSQL instance instead of SQLite. URL resolution order:
  `WRAPSEC_TEST_PG_URL` env var, then `settings.database_url` if
  reachable (zero-overhead reuse of `make up-dev`), then a
  session-scoped `postgres:16-alpine` container via
  `testcontainers-python`. Tests marked `@pytest.mark.pg` skip cleanly
  when none of the three paths resolve. Same pattern used by Airflow,
  dbt-core, Superset, and Prefect. Four regression tests seeded in
  `tests/integration/test_api_audit_pg.py` covering the v1.2.1
  `jsonb_array_elements_text`, `percentile_cont`, and asyncpg
  tz-aware-bind bugs plus the v1.2.2 dept-scope leak. The pre-existing
  `_postgres_db_setup` autouse fixture now degrades gracefully when the
  app's PG is unreachable, so SQLite-only integration tests keep
  running instead of session-erroring.

### Fixed
- **JSON vs JSONB drift in the schema.** Every `Column(JSON, ...)` in
  `db/models.py` was actually being queried via jsonb operators
  (`jsonb_array_elements_text`, `cast(.., JSONB).contains(..)`). The
  live database had those columns as `jsonb` from a pre-baseline
  hand-alter that never made it into a tracked migration, so
  production kept working; a fresh install from `0001_baseline` would
  have created `json` columns and 500'd on the first `/v1/audit/stats`
  request with `function jsonb_array_elements_text(json) does not
  exist`. Migration `0006_json_to_jsonb` conditionally alters the
  affected columns to `jsonb` on PostgreSQL (skips columns already at
  `jsonb`, no-op on SQLite); models now use a `JSONVariant` alias that
  maps to `JSONB` on PostgreSQL and falls back to `JSON` on SQLite.
  Twelve columns across seven tables affected: `tenants.global_policy`,
  `departments.policy_override`, `applications.metadata`,
  `applications.policy_override`, `applications.rate_limit_override`,
  `audit_logs.threats`, `audit_logs.detection_scores`,
  `audit_logs.guardrail_scores`, `admin_events.metadata`,
  `proxy_interactions.input_threats`,
  `proxy_interactions.output_threats`,
  `proxy_interactions.output_flags`. Caught by the new
  testcontainers-backed regression tests running against a fresh
  postgres:16-alpine.

### Internal
- `pytest.ini` registers a `pg` marker so `-m pg` selects the
  PostgreSQL-backed subset and `-m 'not pg'` skips them.
- `requirements-dev.txt` pins `testcontainers[postgres]==4.13.1`.

## [1.2.2] - 2026-07-28

### Security
- `GET /v1/audit/stats` was not applying department scope. A
  dept-scoped caller (non-admin, incl. dept-scoped AUDITOR) received
  tenant-wide aggregate counts -- `total`, `block_count`,
  `sanitize_count`, `allow_count`, `avg_latency_ms`, `p95_latency_ms`,
  and `top_threats` -- covering departments they cannot list via
  `/v1/audit/logs`. Per-row endpoints (`/logs`, `/attribution`,
  `/analytics`, `/export`) were already dept-scoped; only `/stats`
  leaked. Fixed by threading `dept_id` from the request scope through
  `AuditRepository.get_stats` and the inline severity-count query in
  the endpoint, matching the pattern already used for `/logs`. Admin
  callers are unaffected because their scope carries no `dept_id`.

### Fixed
- Dashboard Requests page: date filters deep-linked from the Overview
  and Analytics badges did not pre-populate. `useTimeRange` emits
  `YYYY-MM-DDTHH:MM:SS`, but the URL sanitiser produced that same
  format and `<input type="date">` silently rejects any value
  containing `T`. `sanitiseDate` now accepts both `YYYY-MM-DD` and
  `YYYY-MM-DDTHH:MM:SS` and always hands the input the date portion;
  the existing fetch code re-attaches `T00:00:00` / `T23:59:59` so
  the request is unchanged.

## [1.2.1] - 2026-07-28

### Fixed
- `GET /v1/audit/stats` returned 500 whenever `from` or `to` was
  passed. `_parse_dt` produced a tz-aware datetime but
  `audit_logs.created_at` is `TIMESTAMP WITHOUT TIME ZONE`, so asyncpg
  rejected the bind ("can't subtract offset-naive and offset-aware
  datetimes"). The bug shipped in v1.2.0 and earlier -- the
  integration test does not pass a date range so it was never hit in
  CI. Now stripped in the repo, matching the pattern the endpoint
  already uses for its other four query sites.

### Changed
- Grafana bootstrap-credential guard extracted from `setup.sh` into a
  sourceable helper at `scripts/lib/grafana_password_guard.sh`, so the
  same code the deploy script runs is exercised by CI
  (`tests/integration/test_grafana_password_guard.py` -- 22 cases
  covering the denylist, empty/unset, and the 12-character boundary).
  Follows the Bats / Homebrew / nvm convention of putting reusable
  shell functions under `scripts/lib/`. Byte-equivalent behaviour to
  the previous inline block.
- `GET /v1/audit/stats` aggregation runs in SQL on PostgreSQL.
  Previously the endpoint fetched every `latency_ms` and `threats`
  array into Python and looped for avg, p95, and top-threat counts --
  fine at 10K rows, OOMs at 10M. Now uses `AVG()`,
  `percentile_cont(0.95)`, and `jsonb_array_elements_text()`
  in-database. Response shape is unchanged. SQLite unit tests fall
  through to the Python path since it lacks these functions.

### Internal
- Documented the DOTALL flag on the rule-pattern registry
  (`engine/detection/rule_patterns/general.py`). Every regex compiles
  with `re.IGNORECASE | re.DOTALL`; the expanded comment records the
  multi-line evasion the flag defends against and the future
  catastrophic-backtracking trade-off to watch for.

## [1.2.0] - 2026-07-28 - Enterprise plumbing

Enterprise-plumbing release. Adds audit tamper-evidence, session and
multi-turn attribution on scan requests, broader PII coverage, a fourth
compliance-oriented user role, an OTLP metrics bridge, and a startup
guard on the Grafana bootstrap credential. Existing scan, chat, and
admin endpoints remain wire-compatible with 1.0.x and 1.1.x clients.

### Added

- **Session and turn tracking on scan requests.** Optional `session_id`,
  `turn_index`, and `run_id` fields on `POST /v1/ai/request` and
  `POST /v1/chat/completions`, with matching kwargs on the Python and
  Node SDKs. Field names follow LangSmith and OpenAI Assistants
  conventions so existing agent-framework instrumentation slots in
  directly. Values are captured on every audit row for post-hoc replay
  of multi-turn or agent sessions. Fields are optional; 1.0.x and 1.1.x
  clients are unaffected.
- **Tamper-evident audit log.** Every `audit_logs` row now carries a
  SHA-256 `entry_hash` computed over the row payload plus the previous
  row's `entry_hash` (hash chain). A PostgreSQL trigger rejects `UPDATE`
  and `DELETE` on the table, so log tampering requires database-superuser
  access and leaves obvious gaps in the chain. Chain verification is a
  single pass over the table and can run offline against a database
  dump.
- **Fourth user role: AUDITOR.** Read-only role scoped for SOC 2 and
  ISO 27001 audit work. Carries `audit:read`, `dashboard:read`,
  `settings:read`, and `keys:read` -- broader than `VIEWER` so a
  compliance auditor can inspect policy configuration and API key
  inventory without any write path. Departmental scoping is flexible:
  `dept_id` may be `NULL` for tenant-wide audit scope or set for a
  department-scoped auditor. Available in the dashboard user creation
  and edit forms.
- **OTLP export for existing Prometheus metrics.** Optional OpenTelemetry
  Collector sidecar bridges the existing `/metrics` endpoint to any
  OTLP-compatible backend without re-instrumenting the application.
  Enable with `docker compose --profile otlp up -d`. Configure via the
  standard OpenTelemetry Protocol Exporter environment variables
  (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
  `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_INSECURE`).
  Metric names, labels, and help text are preserved as-scraped.

### Changed

- **PII coverage expanded from 22 to 30 entity types.** Added IBAN,
  SWIFT/BIC, passport numbers, driver licence numbers, MAC addresses,
  ITIN, medical record numbers, and additional national identifiers,
  broadening international coverage. Detectors, thresholds, and the
  BLOCK / SANITIZE policy are unchanged; new entity types are covered
  by the same policy as the existing set.
- **Permission enforcement is now segment-wise.** The `has_permission`
  check activates alongside the AUDITOR role and matches permissions
  segment by segment (for example, `keys:create` matches `keys:*` but
  not `*:create`). Wildcards match a single segment only; a bare `*`
  matches any single segment, not the entire permission string.
  `has_role` is unchanged.

### Security

- **Grafana bootstrap credential guard.**
  `docker compose -f docker-compose.prod.yml up` now refuses to start
  when `GRAFANA_PASSWORD` is unset or empty. `setup.sh --prod`
  additionally rejects a denylist of well-known weak values (`admin`,
  `changeme`, `password`, `grafana`, ...) and enforces a 12-character
  minimum per NIST SP 800-63B. Closes the "operator forgot to change
  the default password" class of finding, which is the most common
  Grafana exposure indexed by internet-facing scanners.
- **Audit log immutability at the database layer.** The
  `UPDATE`/`DELETE` trigger on `audit_logs` means tampering cannot
  succeed silently even if application-layer controls are bypassed.
  Chain verification detects any gap.

### Migration notes

- **Fresh install:** no action -- startup runs `alembic upgrade head`.
- **Upgrade from 1.1.x:** startup runs one new migration adding
  nullable `session_id`, `turn_index`, `run_id`, `entry_hash`, and
  `prev_entry_hash` columns to `audit_logs`, plus the immutability
  trigger on PostgreSQL. The migration is idempotent. Existing rows
  are not back-hashed; the chain starts at the first row written under
  1.2.0. SQLite deployments (development only) get the columns but not
  the trigger.
- **Grafana admin password:** if you were relying on the default
  `changeme_before_deploy` value for a production deploy, generate a
  strong password (`openssl rand -base64 24`) and set
  `GRAFANA_PASSWORD` in `.env` before starting the stack, or the
  deploy will halt.
- **OTLP export:** off by default. No change unless you opt in with
  the `otlp` compose profile.
- **AUDITOR role:** additive. Existing ADMIN / DEVELOPER / VIEWER
  users and their permissions are unchanged.

## [1.1.5] - 2026-07-27

### Fixed
- Docker healthcheck for the api service was permanently `unhealthy`
  because the check ran `curl -f http://localhost:8000/health` but
  `curl` was never installed in the `python:3.10-slim` base. Added
  `curl` to the apt install list (~10 MB) and moved `HEALTHCHECK` from
  `docker-compose.yml` into the Dockerfile itself, so the image is
  self-describing under bare `docker run`, swarm, or portainer, and
  matches the FastAPI/Django convention. No application behaviour
  change.

## [1.1.4] - 2026-07-27

### Fixed
- Alembic revision id `0002_reencrypt_secrets_v2_envelope` (34 chars)
  exceeded the default `alembic_version.version_num VARCHAR(32)`,
  causing `alembic upgrade head` to fail with
  `StringDataRightTruncationError` on any database that had `0001_baseline`
  already applied. Renamed to `0002_envelope_reencrypt` (23 chars) to
  match the alembic convention of short revision ids (Airflow, Superset,
  Sentry all keep them under 32). No schema change; migration behaviour
  is identical.

  Upgrade note: if you already have `0002_reencrypt_secrets_v2_envelope`
  recorded in your `alembic_version` table, run
  `UPDATE alembic_version SET version_num='0002_envelope_reencrypt';`
  before deploying v1.1.4.

- Docker API image dropped from 9.68 GB to 1.18 GB (~87%). Two causes:
  (1) build context had no `.dockerignore`, so `.venv/` (1.1 GB),
  `dashboard/.next/` (1 GB), `.git/`, sibling checkouts, and caches were
  all shipped into the image; (2) `RUN chown -R wrapsec:wrapsec /app`
  after `COPY . .` created a full duplicate layer of the application
  tree. Added a root `.dockerignore` and replaced the two-step copy with
  a single `COPY --chown=wrapsec:wrapsec . .`.

## [1.1.3] - 2026-07-27

### Fixed
- Dashboard image build (`Dockerfile.dashboard`) failed under `npm ci`
  after the v1.1.2 bump because the lockfile -- generated on Windows --
  did not include the linux-musl platform-specific optional dependencies
  that `sharp@0.35.3` pulls in on Alpine (missing `@emnapi/*`, missing
  `@img/sharp-libvips-linuxmusl-x64`, etc.). Regenerated the lockfile
  inside a `node:20-alpine` container with `--include=optional`, so
  every platform variant is now pinned and `npm ci` succeeds on Alpine.
  No dependency version changes.

## [1.1.2] - 2026-07-27

### Security
- Dashboard: bump `next` from 16.2.10 to 16.2.12. Clears 8 CVEs
  affecting the App Router runtime, including a middleware /
  proxy bypass, two Server-Side Request Forgery classes (Server
  Actions on custom servers; rewrites with attacker-controlled
  hostnames), unauthenticated disclosure of internal Server
  Function endpoints, cache confusion on request bodies, DoS in
  the Image Optimization API via SVGs, and unbounded Server
  Action payloads on the Edge runtime.
- Dashboard: pin `sharp >= 0.35.0` via package.json `overrides`
  to clear inherited libvips CVEs (CVE-2026-33327 / -33328 /
  -35590 / -35591). Verified against `next build` -- static +
  dynamic pages generate cleanly.

## [1.1.1] - 2026-07-27

### Security
- Bump `click` from 8.3.2 to 8.3.3 to clear PYSEC-2026-2132
  (command injection in `click.edit()`). WrapSec does not call
  `click.edit()` or `click.launch()`, so there is no known
  exploit path; the bump keeps the dependency scan clean.

## [1.1.0] - 2026-07-27 - Foundation

Foundation release. Closes six architectural blockers that gate the v1.2+
roadmap (enterprise plumbing, SIEM, deployment IaC, SSO, semantic cache).
No public API changes; existing scan, chat, and admin endpoints are wire-
compatible with 1.0.x clients.

### Added
- **Alembic migrations.** DB schema now advances through versioned migrations
  under `db/migrations/versions/`. Application startup runs
  `alembic upgrade head`. Baseline `0001_baseline` is idempotent against
  existing v1.0.11 databases; `0002_reencrypt_secrets_v2_envelope` upgrades
  existing ciphertexts to the new envelope format (see below).
- **Envelope encryption (KEK/DEK) for stored provider secrets.** New
  ciphertext format `v2:base64(wrapped_dek || nonce || ciphertext || tag)`
  with a per-record random 32-byte DEK wrapped by a `KeyEncryptionKey`.
  Default KEK derives from `SECRET_KEY`; the interface is designed for
  drop-in KMS/Vault backends in v1.5+. Legacy v1 ciphertexts still decrypt
  transparently.
- **AuthProvider interface.** `services/auth/providers/` defines the
  contract `AuthProvider.authenticate(credentials, db) -> AuthenticationOutcome`
  used by `AuthService.login()`. Ships `PasswordAuthProvider` (identical
  semantics to v1.0.x login). Lockout, `is_active` checks, session
  issuance, and audit-event logging remain in `AuthService` since they
  apply to any provider. Unblocks OIDC / SAML / SCIM in v1.5+.
- **DetectionPipeline preprocessor slot.** New `BasePreprocessor` ABC with
  an empty default preprocessor list; failing preprocessors are logged and
  skipped rather than blocking a scan. Unblocks OCR (v1.6+) and other
  text-in text-out normalisation layers without touching detector code.

### Changed
- **Password hashing upgraded to Argon2id.** New user passwords are hashed
  with Argon2id (Password Hashing Competition winner; GPU/ASIC resistant).
  Legacy bcrypt hashes still verify. On the next successful login for a
  legacy user, the stored hash is transparently rehashed to Argon2id --
  no admin action required, no user prompt. Rehash failure never denies
  a valid login (logged as `PASSWORD_HASH_UPGRADE_FAILED`).
- **LayerScores is now a dict.** `domain/scoring.py::LayerScores` is
  backed by a dict with a `__getattr__` compatibility shim, so existing
  attribute-style access (`scores.rule`, `scores.ml`) still works while
  new detectors can contribute keys without touching the schema. Extra
  scores from `ScoringResult.extra_scores` flow into `layer_scores` at
  the gateway boundary.

### Security
- New provider secrets and per-tenant/department/application encrypted
  settings are written in v2 envelope format. Existing rows are migrated
  in-place by `0002_reencrypt_secrets_v2_envelope`; the migration is
  idempotent (already-v2 rows are skipped) and one-way (no downgrade).

### Migration notes
- **Fresh install:** no action -- startup runs `alembic upgrade head`.
- **Upgrade from 1.0.x:** startup will run both migrations. Back up your
  database first (`0002_reencrypt_secrets_v2_envelope` rewrites every
  encrypted provider-key column). Any rows the migration cannot decrypt
  are logged with `unreadable=true` and left as-is; investigate before
  reusing those provider configs.
- **Legacy password hashes:** no action -- users are silently migrated
  to Argon2id on their next successful login.

## [1.0.0] - 2026-05-13

Initial release.

- Multi-layer detection pipeline: rule-based, two-tier ML (TF-IDF + optional DeBERTa-v3 transformer), and LLM-backed analysis
- Scan-only and proxy execution modes with OpenAI-compatible API
- Multi-tenant architecture with department-level policy configuration
- Next.js dashboard, Prometheus metrics, and Grafana dashboards
- Python SDK (`wrapsec-python`) and Node.js SDK (`wrapsec-node`)
