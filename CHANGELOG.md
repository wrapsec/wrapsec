# Changelog

All notable changes to WrapSec are documented here.

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
