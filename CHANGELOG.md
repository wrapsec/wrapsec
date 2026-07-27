# Changelog

All notable changes to WrapSec are documented here.

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
