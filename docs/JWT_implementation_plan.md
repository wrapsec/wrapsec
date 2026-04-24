# WrapSec — JWT & RBAC Implementation Plan

*Version 8.0 — 25 Apr 2026*
*All seven review cycles incorporated and closed.*
*Single source of truth. Implementation starts from this document.*
*No further changes without team sign-off.*

---

## ✅ All Review Items Closed — Do Not Raise These Again

Every point from all seven review cycles is listed here with its exact fix location.
If a point appears in this table, it is fully implemented in this document.

| Review | Item | Fix location |
|---|---|---|
| R1 | dept_id NOT NULL | §1.4 — ADMIN null intentional, DB CHECK enforces non-admin |
| R1 | Header precedence | §1.2 — API key always wins, absolute rule |
| R1 | Simplified JWT payload | §7.1 — minimal claims, type + aud retained with rationale |
| R1 | Bootstrap uses get_default() | §13 — explicit default tenant fetch |
| R1 | Roles only in v1 | §3.2 — permissions exist, not enforced, explicit comment |
| R1 | Scanner Option B | §1.5 — JWT accepted on scan endpoints |
| R1 | httpOnly cookie | §9.1, §14.1, §14.2 |
| R1 | force_password_change | §4.1, §8.2 step 6, §9.1, §10.5 |
| R2 | tenant_id four-layer enforcement | §1.3 — DB + JWT + middleware + principal |
| R2 | Admin NULL dept query | §1.4 — conditional filter pattern |
| R2 | user_role set in middleware | §8.2 step 5 |
| R2 | Refresh cleanup AND revoked_at | §7.3, §15 |
| R2 | JWT audience claim | §6.3, §7.1 |
| R2 | Email normalization everywhere | §6.1 normalize_email() |
| R2 | api_keys.tenant_id migration | §5 — full migration |
| R2 | Partial index on refresh_tokens | §4.2, §5 |
| R2 | Dummy hash timing fix | §6.1 verify_dummy() |
| R2 | Auth event logging | §6.4, §11 |
| R2 | Prevent last admin deactivation | §10.4 |
| R3 | Token versioning | §4.1, §4.2, §6.3, §6.4 |
| R3 | Account lockout Redis TTL | §6.2 — full implementation |
| R3 | Principal raises ValueError not assert | §3.3 |
| R3 | Four-layer tenant enforcement | §1.3, §3.3, §5, §6.3, §8.2 |
| R4 | Admin key "admin" string removed | §3.3, §8.3 — real tenant_id from DB |
| R4 | token_version in RefreshTokenModel | §4.2 |
| R4 | token_version in repository.create() | §4.3, §6.4 |
| R4 | JWT tenant_id vs DB cross-validation | §8.2 step 3 |
| R4 | api_keys.tenant_id NOT NULL | §5 |
| R4 | Case-insensitive email unique index | §4.1, §5 |
| R4 | tenant_id validation after DB load | §8.2 step 2b |
| R4 | Transaction boundary per auth flow | §6.4 — single commit |
| R4 | JWT error message generic to client | §6.3 |
| R4 | Redis lock TTL behavior documented | §6.2 |
| R4 | Email uniqueness scope decision | §5 — global, documented |
| R4 | Permissions field clarity | §3.2 |
| R5 | JWT dept_id mismatch logging | §8.2 step 3b |
| R5 | key_id prefixed user: / key: | §8.1, §8.2, §8.3 |
| R5 | Refresh token race condition SELECT FOR UPDATE | §4.3, §6.4 |
| R5 | Hardcoded dummy hash (not dynamic) | §6.1 |
| R5 | LOWER() comment in get_by_email() | §4.3 |
| R5 | force_password_change enforced in middleware | §8.2 step 6 |
| R5 | dept_id tenant integrity validation in repo | §4.3 |
| R5 | _unauthorized() always logs reason + path | §8.4 |
| R5 | Cookie path documented + convention added | §14.2, §19 |
| R5 | Admin principal_id uses key: prefix | §8.3 |
| R6 | DB-level dept_id ↔ tenant composite FK | §5 migration |
| R6 | READ COMMITTED isolation documented | §5, §19 convention 31 |
| R6 | JWT dept mismatch in monitoring pipeline | §19 convention 32 |
| R6 | 401 behavior documented for frontend | §9, §19 convention 33 |
| R6 | Default password safety check in production | §13 bootstrap |
| R6 | Secondary refresh token cleanup (90 days) | §15 retention |
| R6 | has_permission() raises NotImplementedError in v1 | §3.2 principal |
| R7 | UUID/string type boundary — explicit invariant | §1.3, §3.3, §8.1 |
| R7 | cleanup_expired() contract shows both clauses | §4.3 repository |
| R7 | Role + composite role/is_active index added | §5 migration |
| R7 | stderr print for production password warning | §13 bootstrap |
| R7 | JWT dept mismatch marked as deployment requirement | §19 convention 32 |

---

## 1. Architecture — Absolute Rules

### 1.1 Dual Identity Model

Two auth systems coexist. Both resolve to identical fields on `request.state`. All downstream code is completely auth-agnostic — it never checks which auth method was used.

```
x-api-key header     → API_KEY principal  (machine — applications, services)
Authorization Bearer → USER principal     (human — dashboard users)
```

### 1.2 Header Precedence — Absolute, No Exceptions

```
IF x-api-key header present (non-empty after strip):
    → ALWAYS use API key path
    → IGNORE Authorization header — even if it contains a valid JWT
    → This is unconditional. No case where JWT takes priority.

ELIF Authorization header starts with "Bearer " (case-insensitive):
    → JWT path

ELSE:
    → 401 UNAUTHORIZED
```

First code in middleware `dispatch()` — before any other logic:

```python
api_key = request.headers.get("x-api-key", "").strip()
auth    = request.headers.get("authorization", "").strip()

if api_key:
    return await self._authenticate_api_key(api_key, request, call_next)
elif auth.lower().startswith("bearer "):
    return await self._authenticate_jwt(auth[7:], request, call_next)
else:
    return _unauthorized(request, "missing_credentials")
```

### 1.3 Tenant Enforcement — Four Layers, All Mandatory

`tenant_id` is the outermost security boundary. A missing `tenant_id` means cross-tenant data access is possible. Enforce at all four layers — all must hold.

```
Layer 1 — Database schema:
    users.tenant_id NOT NULL
    api_keys.tenant_id NOT NULL (after migration)
    refresh_tokens.token_version NOT NULL

Layer 2 — JWT decode (services/auth/token.py):
    sub, tenant_id, role, ver — all must be present and non-null
    Missing any → JWTError → 401

Layer 3 — Middleware (api/v1/middleware/auth.py):
    JWT path:
        user.tenant_id must not be None → 401
        payload["tenant_id"] must match str(user.tenant_id) → 401
    API key path:
        key.tenant_id must not be None → 401

Layer 4 — Principal construction (domain/entities/principal.py):
    build_principal_from_user(): raises ValueError if tenant_id is None
    build_principal_from_api_key(): raises ValueError if tenant_id is None
```

**Absolute rule:** `tenant_id` and `dept_id` ALWAYS from authenticated identity. NEVER from request body, query params, path params, or any client-provided source.

**UUID/string type boundary (R7 fix):**
This invariant must be maintained at every layer — inconsistency causes silent bugs in comparisons, logs, and DB joins:

```
DB layer       → UUID objects    (SQLAlchemy UUID columns, FK joins)
API/JWT/state  → string objects  (request.state, JWT claims, audit logs, responses)

Cast at boundary:
    DB → string:  str(user.tenant_id)        in middleware and builders
    String → DB:  UUID(tenant_id_string)     in repository queries
```

All builder functions (`build_principal_from_user`, `build_principal_from_api_key`)
cast to string before returning. Middleware always reads `str(user.tenant_id)` from DB.
Repository methods always accept UUID or cast string to UUID internally.

### 1.4 Admin NULL dept — Query Pattern, Mandatory Everywhere

```
ADMIN     → dept_id = NULL → sees ALL data for the tenant
DEVELOPER → dept_id set   → sees only own dept data
VIEWER    → dept_id set   → sees only own dept data
```

Every protected query — no exceptions:

```python
query = base_query.where(table.tenant_id == request.state.tenant_id)
if request.state.dept_id:
    query = query.where(table.dept_id == request.state.dept_id)
# If dept_id is None (ADMIN) → no dept filter → sees all tenant data
```

**NEVER** write `WHERE dept_id = NULL` — SQL NULL comparison always returns zero rows.

### 1.5 Scan Endpoints — Both Auth Methods Accepted (Option B)

JWT users treated identically to API key users on scan/proxy endpoints.
Only audit log differs: `principal_type = "user"` vs `"api_key"`.

---

## 2. Environment Variables

### 2.1 `.env` additions

```env
# JWT (secret_key and jwt_algorithm already exist — do not add again)
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Bootstrap first admin (used once on first startup when users table is empty)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ChangeMe!OnFirstLogin

# Account lockout (Redis TTL)
AUTH_MAX_FAILED_ATTEMPTS=5
AUTH_LOCKOUT_DURATION_SECONDS=900
```

### 2.2 `config/settings.py` additions

```python
jwt_access_token_expire_minutes: int = 30
jwt_refresh_token_expire_days:   int = 30
admin_email:                     str = Field(default="admin@localhost")
admin_password:                  str = Field(default="ChangeMe!OnFirstLogin")
auth_max_failed_attempts:        int = 5
auth_lockout_duration_seconds:   int = 900
```

---

## 3. Domain Layer

### 3.1 `domain/enums.py` — additions

```python
class PrincipalType(str, Enum):
    USER       = "user"
    API_KEY    = "api_key"
    AGENT      = "agent"       # Phase 3 stub — not implemented in v1
    MCP_CLIENT = "mcp_client"  # Phase 3 stub — not implemented in v1

class UserRole(str, Enum):
    ADMIN     = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER    = "VIEWER"
```

### 3.2 `domain/entities/principal.py` — new file

```python
from dataclasses import dataclass
from domain.enums import PrincipalType

# ── Role → permission strings ─────────────────────────────────────────────────
#
# v1 ENFORCEMENT RULE:
#   These permission strings are defined for FUTURE USE (v2+) ONLY.
#   In v1, all endpoint guards use has_role() / require_role() exclusively.
#   has_permission() must NOT be called in any v1 endpoint guard.
#   When v2 granular access control is implemented, replace require_role()
#   with require_permission() at that time.
#   Reviewers: this is intentional — do not flag as unused.
#
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "ADMIN":     ["*"],
    "DEVELOPER": ["scan:*", "audit:read", "settings:read", "keys:*", "dashboard:read"],
    "VIEWER":    ["audit:read", "dashboard:read"],
}


@dataclass
class Principal:
    id:           str            # user UUID string | "key:{key_id}" | "key:admin"
    type:         PrincipalType
    tenant_id:    str            # NEVER None — enforced at construction (Layer 4)
    dept_id:      str | None     # None for ADMIN role only
    roles:        list[str]
    permissions:  list[str]      # from ROLE_PERMISSIONS — v2+ use only, not enforced in v1
    is_admin:     bool
    email:        str | None = None    # USER principals only
    # Phase 3 extension points — always None in v1
    agent_id:     str | None = None
    triggered_by: str | None = None

    def has_role(self, *roles: str) -> bool:
        """Check if principal has any of the specified roles. Used in v1 guards."""
        return any(r in self.roles for r in roles)

    def has_permission(self, permission: str) -> bool:
        """
        Wildcard permission check.

        v1 HARD GUARD (R6 fix):
            Raises NotImplementedError in v1 to prevent accidental use.
            All v1 access control uses has_role() exclusively.
            If this is called in v1, it is a bug — fail loud, not silent.

        v2+:
            Remove the NotImplementedError guard.
            Replace require_role() with require_permission() calls.
            Implement the wildcard logic below.

        Wildcards (for v2+ reference):
            "*"         → matches everything
            "scan:*"    → matches "scan:read", "scan:write"
            "tool:db:*" → matches "tool:db:read", "tool:db:write"
        """
        raise NotImplementedError(
            "has_permission() is not enforced in v1. "
            "Use has_role() for all v1 access control. "
            "See ROLE_PERMISSIONS for v2+ permission strings."
        )
        # v2+ implementation (unreachable in v1 — remove guard above when ready):
        # if "*" in self.permissions:
        #     return True
        # if permission in self.permissions:
        #     return True
        # parts = permission.split(":")
        # for p in self.permissions:
        #     p_parts = p.split(":")
        #     if len(p_parts) == len(parts):
        #         if all(a == b or b == "*" for a, b in zip(parts, p_parts)):
        #             return True
        # return False
```

### 3.3 Principal Builder Functions

```python
def build_principal_from_user(user: "UserModel") -> Principal:
    """
    Builds Principal from UserModel after DB load.
    Called by JWT middleware.

    Raises ValueError (NOT assert) if tenant_id is None.
    Using ValueError instead of assert: Python assert can be disabled
    with -O flag and must never be used for security checks.
    """
    if not user.tenant_id:
        raise ValueError(
            f"User {user.id} has no tenant_id — cannot build Principal. "
            "This is a data integrity issue — investigate immediately."
        )
    return Principal(
        id          = str(user.id),
        type        = PrincipalType.USER,
        tenant_id   = str(user.tenant_id),
        dept_id     = str(user.dept_id) if user.dept_id else None,
        roles       = [user.role],
        permissions = ROLE_PERMISSIONS.get(user.role, []),
        is_admin    = (user.role == "ADMIN"),
        email       = user.email,
    )


def build_principal_from_api_key(key: "APIKeyModel") -> Principal:
    """
    Builds Principal from APIKeyModel after DB load.
    Called by API key middleware for non-admin application keys.

    The hardcoded admin key (wrapsec_admin_key) is NEVER in the api_keys table
    and is handled separately by _authenticate_admin_key() which fetches the
    default tenant from DB. This function is NEVER called for the admin key.

    All DB rows in api_keys are non-admin application keys — they must have
    tenant_id. Raises ValueError (NOT assert) if tenant_id is missing.
    """
    if not key.tenant_id:
        raise ValueError(
            f"API key {key.key_id} has no tenant_id — cannot build Principal. "
            "Run migration to enforce NOT NULL on api_keys.tenant_id."
        )
    return Principal(
        id          = key.key_id,   # stored as-is — prefixing done at request.state level
        type        = PrincipalType.API_KEY,
        tenant_id   = str(key.tenant_id),
        dept_id     = str(key.dept_id) if key.dept_id else None,
        roles       = ["DEVELOPER"],
        permissions = ["scan:*", "audit:read"],
        is_admin    = False,
    )
```

---

## 4. Database Models

### 4.1 `db/models.py` — `UserModel`

```python
class UserModel(Base):
    __tablename__ = "users"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    tenant_id             = Column(UUID(as_uuid=True), ForeignKey("tenants.id"),
                                   nullable=False)
    # NOT NULL enforced at DB level — Layer 1 of tenant enforcement.

    dept_id               = Column(UUID(as_uuid=True), ForeignKey("departments.id"),
                                   nullable=True)
    # NULL is valid ONLY for ADMIN role.
    # DB CHECK constraint ck_users_dept_required enforces:
    #   role = 'ADMIN' OR dept_id IS NOT NULL
    # API level also validates this on user creation (belt and suspenders).
    # dept_id must belong to the same tenant — validated in UserRepository.create()
    # and update() by querying departments WHERE id = dept_id AND tenant_id = tenant_id.

    email                 = Column(String(255), nullable=False)
    # NOT unique=True on the column — uniqueness enforced by the case-insensitive index
    # ux_users_email_lower: CREATE UNIQUE INDEX ON users (LOWER(email))
    # get_by_email() MUST use func.lower() — see repository contract.
    # Always stored lowercase — normalize_email() called before every write.

    password_hash         = Column(String(255), nullable=False)
    # bcrypt via passlib — NEVER store plaintext, MD5, SHA-1, or any fast hash.

    role                  = Column(String(50), nullable=False, default="DEVELOPER")
    # Valid values: ADMIN | DEVELOPER | VIEWER
    # DB CHECK constraint ck_users_role enforces valid values.

    is_active             = Column(Boolean, nullable=False, default=True)

    force_password_change = Column(Boolean, nullable=False, default=False)
    # Set True on: bootstrap admin creation, admin-initiated password reset.
    # Enforced at middleware level — NOT just frontend:
    #   JWT middleware rejects all requests except /v1/auth/change-password,
    #   /v1/auth/logout, and /v1/auth/me when this is True.
    # Set False when user successfully changes their own password.

    token_version         = Column(Integer, nullable=False, default=1)
    # Increment to immediately invalidate ALL active sessions for this user.
    # JWT middleware checks: payload["ver"] == user.token_version
    # Mismatch → SESSION_INVALIDATED 401, even if token is not yet expired.
    # Incremented by: logout_all_sessions(), which is called on password change,
    # role change, account deactivation, admin password reset.

    created_at            = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at         = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_users_tenant", "tenant_id"),
        Index("ix_users_dept",   "dept_id"),
        # Email uniqueness: case-insensitive index created in migration.
        # See ux_users_email_lower in add_users.sql.
    )
```

### 4.2 `db/models.py` — `RefreshTokenModel`

```python
class RefreshTokenModel(Base):
    __tablename__ = "refresh_tokens"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id       = Column(UUID(as_uuid=True),
                           ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False)

    token_hash    = Column(String(64), nullable=False, unique=True)
    # SHA-256 of the raw token — raw token NEVER stored server-side.
    # If DB is compromised, raw tokens CANNOT be reconstructed from hashes.

    token_version = Column(Integer, nullable=False, default=1)
    # Stores user.token_version AT THE TIME this token was issued.
    # Checked in refresh flow: token_rec.token_version != user.token_version
    # → session was invalidated after this token was issued → SESSION_INVALIDATED 401.
    # This allows logout_all_sessions() to work without a DB scan —
    # just incrementing user.token_version is sufficient.

    expires_at    = Column(DateTime, nullable=False)

    revoked_at    = Column(DateTime, nullable=True)
    # NULL = active token.
    # Set to NOW() on: logout, token rotation (old token), revoke_all_for_user().

    created_at    = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_refresh_tokens_user",    "user_id"),
        Index("ix_refresh_tokens_hash",    "token_hash"),
        Index("ix_refresh_tokens_expires", "expires_at"),
        # Partial index — only active tokens (revoked_at IS NULL).
        # Dramatically reduces index size and query cost for active token lookups.
        # SELECT FOR UPDATE in get_by_hash() uses this index.
        Index(
            "ix_refresh_active",
            "user_id",
            postgresql_where="revoked_at IS NULL",
        ),
    )
```

### 4.3 Repository Contracts

**`db/repositories/user.py`**

```python
class UserRepository(BaseRepository):

    async def get_by_email(self, email: str) -> UserModel | None:
        """
        Case-insensitive email lookup using LOWER() to match ux_users_email_lower index.

        CRITICAL: ALWAYS use func.lower() in the WHERE clause.
        NEVER use WHERE email = :email — that query does NOT use the index
        and breaks case-insensitive uniqueness.

        Query: WHERE LOWER(email) = :email
        (email parameter must already be normalized via normalize_email())
        """
        result = await self.session.execute(
            select(UserModel).where(func.lower(UserModel.email) == email)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: UUID) -> UserModel | None:
        """Standard UUID lookup."""

    async def create(self, data: dict) -> UserModel:
        """
        Creates a new user.

        Required keys: tenant_id, email (pre-normalized), password_hash, role
        Optional keys: dept_id, force_password_change

        Validations performed before insert:
        1. role must be in (ADMIN, DEVELOPER, VIEWER) — raises ValueError otherwise
        2. dept_id required if role != ADMIN — raises ValueError if missing
        3. dept_id tenant integrity check (R5 fix):
               If dept_id is provided, verifies that the department belongs to
               the same tenant as the user:
               SELECT id FROM departments WHERE id = dept_id AND tenant_id = tenant_id
               Raises ValueError if dept does not belong to tenant.
               This prevents cross-tenant data linkage via bad data.
        """

    async def update(self, user_id: UUID, data: dict) -> UserModel | None:
        """
        Updates user fields. Uses exclude_unset pattern — allows setting fields to None.

        If dept_id is being changed, performs the same tenant integrity check
        as create(): verifies dept belongs to same tenant.
        """

    async def list_by_tenant(
        self,
        tenant_id: UUID,
        dept_id:   UUID | None = None,
        role:      str  | None = None,
        is_active: bool | None = None,
        limit:     int  = 50,
        offset:    int  = 0,
    ) -> tuple[list[UserModel], int]:
        """Returns (users, total_count)."""

    async def count_by_tenant(self, tenant_id: UUID) -> int:
        """Used by bootstrap to check if any users exist."""

    async def count_active_admins(self, tenant_id: UUID) -> int:
        """
        Returns count of users WHERE role='ADMIN' AND is_active=TRUE.
        Used by last-admin protection before role change or deactivation.
        """

    async def increment_token_version(self, user_id: UUID) -> int:
        """
        Atomically increments token_version by 1. Returns new version.
        All existing JWTs with the old ver claim become immediately invalid.
        Called by logout_all_sessions() only.
        """

    async def update_last_login(self, user_id: UUID) -> None:
        """
        Sets last_login_at = NOW().
        Called in same DB transaction as refresh token creation in login().
        """
```

**`db/repositories/refresh_token.py`**

```python
class RefreshTokenRepository(BaseRepository):

    async def create(
        self,
        user_id:       UUID,
        token_hash:    str,
        expires_at:    datetime,
        token_version: int,       # REQUIRED — user.token_version at time of issuance
    ) -> RefreshTokenModel:
        """Inserts new active refresh token row."""

    async def get_by_hash(self, token_hash: str) -> RefreshTokenModel | None:
        """
        Looks up an active (non-revoked, non-expired) refresh token by its hash.

        Uses SELECT ... FOR UPDATE to prevent race conditions on parallel refresh
        requests with the same token. This ensures only one request can revoke
        the token and create a new one — the second request sees revoked_at IS NOT NULL
        and returns None → 401.

        Returns None if:
        - Token not found
        - revoked_at IS NOT NULL (already revoked)
        - expires_at < NOW() (expired)
        """
        result = await self.session.execute(
            select(RefreshTokenModel)
            .where(
                RefreshTokenModel.token_hash == token_hash,
                RefreshTokenModel.revoked_at.is_(None),
                RefreshTokenModel.expires_at > datetime.utcnow(),
            )
            .with_for_update()  # Row-level lock — prevents race condition
        )
        return result.scalar_one_or_none()

    async def revoke(self, token_hash: str) -> None:
        """
        Sets revoked_at = NOW(). Idempotent — safe if already revoked.
        """

    async def revoke_all_for_user(self, user_id: UUID) -> int:
        """
        Revokes all active (revoked_at IS NULL) tokens for a user.
        Returns count of revoked tokens.
        Called exclusively by logout_all_sessions().
        """

    async def cleanup_expired(self) -> int:
        """
        Deletes refresh tokens using two clauses (R7 fix — both implemented here):

        Clause 1 (primary — preserves recent audit trail):
            DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
            Keeps: expired-but-active (failed naturally, audit value remains)
            Keeps: revoked-but-not-expired (recent termination, investigation value)
            Deletes: BOTH expired AND explicitly revoked — audit value exhausted.

        Clause 2 (secondary — prevents unbounded table growth):
            DELETE WHERE expires_at < NOW() - 90 days
            Deletes ALL tokens older than 3x the refresh token lifetime (30 days).
            Covers tokens from users who abandoned sessions without logout.
            At 90 days, audit value is exhausted regardless of revocation state.

        Combined: no token older than 90 days survives.
        Recently expired tokens preserved until also revoked or age out.

        Called by background retention worker daily.
        Returns total deleted rows from both clauses combined.
        """
```

---

## 5. Database Migration — `db/migrations/add_users.sql`

Run before first startup with JWT enabled. Idempotent — safe to run multiple times.

```sql
-- ═══════════════════════════════════════════════════════════════════════════
-- WrapSec JWT Migration v1
-- Creates:   users, refresh_tokens
-- Modifies:  audit_logs (principal_type), api_keys (tenant_id NOT NULL)
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Users ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id                    UUID    PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id             UUID    NOT NULL REFERENCES tenants(id),
    dept_id               UUID    REFERENCES departments(id),
    -- NULL for ADMIN only. Enforced by ck_users_dept_required below.
    -- dept_id must belong to same tenant — validated at application level,
    -- not DB level (composite FK requires non-PK unique constraint on departments).
    email                 VARCHAR(255) NOT NULL,
    -- No UNIQUE on column — uniqueness enforced by ux_users_email_lower index.
    -- Always stored lowercase. normalize_email() MUST be called before insert.
    password_hash         VARCHAR(255) NOT NULL,
    role                  VARCHAR(50)  NOT NULL DEFAULT 'DEVELOPER',
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    -- Enforced at middleware level (not just frontend) — see auth middleware §8.2 step 6.
    token_version         INT     NOT NULL DEFAULT 1,
    created_at            TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at         TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_tenant      ON users(tenant_id);
CREATE INDEX IF NOT EXISTS ix_users_dept        ON users(dept_id);
CREATE INDEX IF NOT EXISTS ix_users_role        ON users(role);
-- Covers: single-column role lookups
CREATE INDEX IF NOT EXISTS ix_users_role_active ON users(role, is_active);
-- Covers: count_active_admins() → WHERE role='ADMIN' AND is_active=TRUE
-- Prevents full table scan on last-admin protection check (called on every role change)

-- Case-insensitive unique email index.
-- MUST be used with func.lower() in all queries — see UserRepository.get_by_email().
-- Scope: GLOBAL uniqueness (one email across all tenants).
-- Decision: v1 is single-tenant. Revisit in 2027 for multi-tenant SaaS
--           with composite (tenant_id, LOWER(email)) index.
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower
    ON users (LOWER(email));

-- Role constraint
ALTER TABLE users
    ADD CONSTRAINT IF NOT EXISTS ck_users_role
    CHECK (role IN ('ADMIN', 'DEVELOPER', 'VIEWER'));

-- dept_id required for non-admin roles (belt-and-suspenders — API also validates)
ALTER TABLE users
    ADD CONSTRAINT IF NOT EXISTS ck_users_dept_required
    CHECK (role = 'ADMIN' OR dept_id IS NOT NULL);

-- ── dept_id ↔ tenant composite integrity constraint (R6 fix) ────────────────
-- Application validates dept_id belongs to tenant on every write (§4.3).
-- This DB-level constraint adds a second layer — prevents corruption from
-- direct DB writes, admin tools, or migrations that bypass application logic.
--
-- Step 1: Add UNIQUE constraint on departments(id, tenant_id)
--         id is already PK (unique), so this adds no new uniqueness —
--         it creates the composite key that the FK below can reference.
ALTER TABLE departments
    ADD CONSTRAINT IF NOT EXISTS uq_departments_id_tenant
    UNIQUE (id, tenant_id);

-- Step 2: Add composite FK on users(dept_id, tenant_id)
--         Ensures: if dept_id is set, it must exist in departments with
--         the same tenant_id as the user. Cross-tenant dept linkage is
--         impossible even via direct DB writes.
ALTER TABLE users
    ADD CONSTRAINT IF NOT EXISTS fk_users_dept_tenant
    FOREIGN KEY (dept_id, tenant_id)
    REFERENCES departments(id, tenant_id);
-- Note: NULL dept_id (ADMIN role) is allowed — FK is not checked when dept_id IS NULL.

-- ── DB Isolation Level note (R6 fix) ──────────────────────────────────────────
-- System assumes PostgreSQL default READ COMMITTED isolation level.
-- SELECT FOR UPDATE in RefreshTokenRepository.get_by_hash() relies on this.
-- Do NOT change isolation level to SERIALIZABLE or REPEATABLE READ without
-- reviewing the refresh token rotation flow for deadlock risk.
-- See Convention 31 in §19.

-- ── Refresh tokens ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    VARCHAR(64) NOT NULL UNIQUE,
    token_version INT  NOT NULL DEFAULT 1,
    -- Stores user.token_version at token issuance time.
    -- Checked on every refresh: mismatch → SESSION_INVALIDATED.
    expires_at    TIMESTAMP NOT NULL,
    revoked_at    TIMESTAMP,
    -- NULL = active. Set to NOW() on logout, rotation, revoke_all.
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user    ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_hash    ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_expires ON refresh_tokens(expires_at);

-- Partial index — active tokens only.
-- Faster lookup and SELECT FOR UPDATE in get_by_hash().
CREATE INDEX IF NOT EXISTS ix_refresh_active
    ON refresh_tokens(user_id)
    WHERE revoked_at IS NULL;

-- ── Audit logs: principal attribution ────────────────────────────────────────

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS principal_type VARCHAR(20) DEFAULT 'api_key';

CREATE INDEX IF NOT EXISTS ix_audit_principal_type
    ON audit_logs(principal_type);

-- ── API keys: enforce tenant_id NOT NULL ─────────────────────────────────────
-- The hardcoded admin key (wrapsec_admin_key) is NEVER stored in this table.
-- All DB rows are non-admin application keys — all must have tenant_id.
-- Step 1: Fill any NULL rows defensively (should be none after prior migrations)
UPDATE api_keys
    SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default' LIMIT 1)
    WHERE tenant_id IS NULL;

-- Step 2: Enforce NOT NULL
ALTER TABLE api_keys ALTER COLUMN tenant_id SET NOT NULL;

-- Step 3: Remove old CHECK constraints (now obsolete — no admin rows in table)
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS ck_api_keys_non_admin_tenant;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS ck_api_keys_tenant_required;
```

---

## 6. Service Layer

### 6.1 `services/auth/password.py`

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pre-computed bcrypt hash for timing equalisation in login().
#
# WHY hardcoded (R5 fix):
#   A dynamically computed hash (pwd_context.hash(...) at module load time)
#   produces a different hash on every process restart, introducing slight
#   timing variation between restarts. A hardcoded hash is fully stable.
#
# HOW to regenerate if needed:
#   from passlib.context import CryptContext
#   print(CryptContext(["bcrypt"]).hash("__wrapsec_timing_dummy__"))
#
# NEVER change the sentinel string — update the hash if you do.
_DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGrmlfebYcSGR/Q3pnK.Bj2SL8."


def normalize_email(email: str) -> str:
    """
    Normalizes email to lowercase + stripped whitespace.

    MUST be called before:
    - Every DB write (user creation, bootstrap, password reset)
    - Every DB read (login lookup, existence check)

    Ensures User@Company.com and user@company.com are treated as identical.
    The ux_users_email_lower index stores LOWER(email) — all queries must match.
    """
    return email.lower().strip()


def hash_password(password: str) -> str:
    """
    Returns bcrypt hash. Always call validate_password_strength() before this.
    """
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Constant-time bcrypt comparison via passlib.
    Timing-safe — bcrypt work factor equalises comparison time.
    """
    return pwd_context.verify(plain, hashed)


def verify_dummy() -> None:
    """
    Runs a dummy bcrypt verify against _DUMMY_HASH.

    MUST be called when user is not found in login flow — immediately before
    raising InvalidCredentialsException. This equalises response timing between
    the 'user not found' and 'wrong password' paths.

    Without this: response time differs because bcrypt verify is slow.
    Timing difference reveals whether an email address is registered.
    This prevents email enumeration via timing analysis.
    """
    pwd_context.verify("__dummy_input__", _DUMMY_HASH)


def validate_password_strength(password: str) -> None:
    """
    Raises ValueError with descriptive message if password is too weak.
    Call before hash_password() on: user creation, password change.

    Requirements: ≥8 chars, ≥1 uppercase, ≥1 lowercase, ≥1 digit.
    """
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in password):
        errors.append("at least one uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("at least one digit")
    if errors:
        raise ValueError(f"Password must contain: {', '.join(errors)}")
```

### 6.2 `services/auth/lockout.py`

```python
"""
Account lockout — Redis TTL keys.
Protects POST /v1/auth/login from brute-force attacks.

Redis key scheme:
    auth:failed:{normalized_email}  — INCR failure counter
    auth:locked:{normalized_email}  — lock flag

Both keys use normalized (lowercase, stripped) email.
Prevents case-bypass: USER@x.com and user@x.com share the same counter.

TTL behavior (explicit — R4 fix):
    Failure counter key:
        TTL is set on FIRST failure with EXPIRE.
        NOT reset on subsequent failures within the window.
        After TTL expires: key deleted by Redis → fresh window starts.

    Lock key:
        Uses SETEX on every failure >= MAX.
        SETEX always overwrites existing key — each failure DURING lockout
        extends the lockout duration. Attacker who keeps trying extends
        their own lockout. This is intentional and desirable.

Flow:
    1. is_locked(email)  → True → 429 (no DB query — fast fail)
    2. attempt auth
    3. success → clear_failures(email) → delete both keys
    4. failure → record_failure(email)
                 if count >= MAX → setex lock key → next attempt gets 429
"""

from cache.redis_client import get_redis
from config.settings import get_settings

settings = get_settings()


def _failed_key(email: str) -> str:
    return f"auth:failed:{email}"


def _locked_key(email: str) -> str:
    return f"auth:locked:{email}"


async def is_locked(email: str) -> bool:
    """Returns True if account is currently locked. Does not query DB."""
    redis = get_redis()
    return await redis.exists(_locked_key(email)) > 0


async def record_failure(email: str) -> tuple[int, bool]:
    """
    Records one failed login attempt.
    Returns (attempt_count, is_now_locked).
    Counter TTL set on first failure only (fixed window).
    Lock key TTL reset on every failure >= MAX (extends lockout on retry).
    """
    redis        = get_redis()
    failed_key   = _failed_key(email)
    locked_key   = _locked_key(email)
    max_attempts = settings.auth_max_failed_attempts
    ttl          = settings.auth_lockout_duration_seconds

    count = await redis.incr(failed_key)
    if count == 1:
        await redis.expire(failed_key, ttl)  # Fixed window — set once

    is_now_locked = False
    if count >= max_attempts:
        await redis.setex(locked_key, ttl, "1")  # Overwrites — extends lockout
        is_now_locked = True

    return count, is_now_locked


async def clear_failures(email: str) -> None:
    """
    Clears failure counter and lock on successful login.
    Called immediately after successful credential verification.
    """
    redis = get_redis()
    await redis.delete(_failed_key(email))
    await redis.delete(_locked_key(email))


async def get_lockout_remaining(email: str) -> int:
    """
    Returns seconds remaining in lockout. Returns 0 if not locked.
    Used to populate retry_after in 429 response.
    """
    redis = get_redis()
    ttl   = await redis.ttl(_locked_key(email))
    return max(0, ttl)
```

### 6.3 `services/auth/token.py`

```python
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from config.settings import get_settings

logger   = logging.getLogger("wrapsec.auth")
settings = get_settings()

ACCESS_TOKEN_AUDIENCE = "wrapsec-dashboard"
# Audience claim: prevents tokens issued for the dashboard from being reused
# against other services even if they share the same secret_key.
# Must match exactly on token creation and validation.


def create_access_token(user: "UserModel") -> str:
    """
    Creates short-lived JWT access token.

    All claims and their purposes:
        sub        — user UUID string (JWT subject — standard claim)
        type       — "access": rejects refresh tokens used as access tokens
        ver        — user.token_version: detects session invalidation
        role       — user.role: used by RBAC dependencies (require_role)
        tenant_id  — security boundary: set on request.state from DB value
        dept_id    — isolation boundary: None for ADMIN, str UUID for others
        aud        — ACCESS_TOKEN_AUDIENCE: cross-service token reuse prevention
        iat        — issued-at (standard JWT)
        exp        — expiry (standard JWT)

    Deliberately excluded:
        email       — unnecessary in token, reduces exposure if token is logged
        principal   — redundant with type claim
        permissions — not enforced in v1 (roles only)
    """
    now     = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub":       str(user.id),
        "type":      "access",
        "ver":       user.token_version,
        "role":      user.role,
        "tenant_id": str(user.tenant_id),
        "dept_id":   str(user.dept_id) if user.dept_id else None,
        "aud":       ACCESS_TOKEN_AUDIENCE,
        "iat":       now,
        "exp":       expires,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token() -> tuple[str, str]:
    """
    Creates opaque refresh token pair.
    Returns: (raw_token, token_hash)

    raw_token  — 32 random bytes, URL-safe base64
                 Sent to client ONCE via httpOnly cookie
                 NEVER stored server-side (not in DB, not in Redis, not in logs)

    token_hash — SHA-256(raw_token.encode())
                 Stored in refresh_tokens.token_hash
                 Raw token cannot be reconstructed from hash

    Security: DB compromise cannot yield raw refresh tokens.
    """
    raw    = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def decode_access_token(token: str) -> dict:
    """
    Decodes and validates JWT access token.

    Error handling (R4 fix):
        Full error detail logged internally at WARNING level.
        Generic error message raised to caller.
        Caller MUST NOT pass error details to client — prevents token oracle attacks.

    Validates in order:
        1. Signature — HMAC-SHA256 with secret_key
        2. Expiry    — exp claim not in the past
        3. Audience  — aud == ACCESS_TOKEN_AUDIENCE
        4. Type      — type == "access" (rejects refresh tokens used as access)
        5. Required  — sub, tenant_id, role, ver all present and non-null

    Raises: JWTError with GENERIC message on any failure.
    Returns: validated payload dict.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms = [settings.jwt_algorithm],
            audience   = ACCESS_TOKEN_AUDIENCE,
        )
    except JWTError as e:
        logger.warning("auth token_decode_failed reason=%s", str(e))
        raise JWTError("Token validation failed")  # Generic — no details to client

    if payload.get("type") != "access":
        logger.warning("auth token_decode_failed reason=wrong_type type=%s",
                       payload.get("type"))
        raise JWTError("Token validation failed")  # Generic

    required = ["sub", "tenant_id", "role", "ver"]
    missing  = [f for f in required if payload.get(f) is None]
    if missing:
        logger.warning("auth token_decode_failed reason=missing_fields fields=%s", missing)
        raise JWTError("Token validation failed")  # Generic

    return payload


def hash_refresh_token(raw_token: str) -> str:
    """SHA-256 hash of raw token. Used for DB lookup in refresh and logout."""
    return hashlib.sha256(raw_token.encode()).hexdigest()
```

### 6.4 `services/auth/service.py`

```python
"""
AuthService — authentication and session management.

Transaction safety (R4 fix):
    Each method uses a SINGLE db.commit() at the end.
    All writes within one method are in the same transaction.
    On exception: SQLAlchemy async session auto-rollbacks.

    login():           create refresh_token + update_last_login → one commit
    refresh():         revoke old + create new refresh_token → one commit
    logout():          revoke refresh_token → one commit
    logout_all():      increment token_version + revoke_all → one commit
    change_password(): update password + logout_all → two commits (separate ops)
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("wrapsec.auth")


@dataclass
class LoginResult:
    access_token:          str
    refresh_token:         str    # raw token — caller sets as httpOnly cookie
    expires_in:            int    # seconds
    force_password_change: bool
    user:                  "UserModel"


@dataclass
class RefreshResult:
    access_token:  str
    refresh_token: str  # new rotated raw token
    expires_in:    int


class AuthService:

    async def login(self, email: str, password: str, db: AsyncSession) -> LoginResult:
        """
        Full login flow. Steps are in order — do not reorder.

        Step 1  — normalize_email()
        Step 2  — is_locked() → 429 if locked (no DB query)
        Step 3  — get_by_email() from DB
        Step 4  — If not found: verify_dummy() [MANDATORY timing eq] + record_failure + 401
                  Same error message as wrong password — no user enumeration
        Step 5  — verify_password() — constant-time bcrypt
        Step 6  — If wrong: record_failure + 401
        Step 7  — If not is_active: 401 ACCOUNT_DISABLED (no failure recorded)
        Step 8  — clear_failures()
        Step 9  — create_access_token()
        Step 10 — create_refresh_token() → (raw, hash)
        Step 11 — [TRANSACTION]
                    RefreshTokenRepository.create(token_version=user.token_version)
                    UserRepository.update_last_login()
                  [db.commit() — single atomic commit]
        Step 12 — Log LOGIN_SUCCESS auth event
        Step 13 — Return LoginResult
        """
        from services.auth.password import (
            normalize_email, verify_password, verify_dummy,
            validate_password_strength,
        )
        from services.auth.token import create_access_token, create_refresh_token
        from services.auth.lockout import (
            is_locked, record_failure, clear_failures, get_lockout_remaining,
        )
        from db.repositories.user import UserRepository
        from db.repositories.refresh_token import RefreshTokenRepository
        from errors.exceptions import (
            AuthenticationError, AccountLockedException, AccountDisabledException,
        )
        from config.settings import get_settings

        _settings = get_settings()
        email     = normalize_email(email)

        if await is_locked(email):
            remaining = await get_lockout_remaining(email)
            logger.warning("auth_event LOGIN_LOCKED email=%s remaining_secs=%d",
                           email, remaining)
            raise AccountLockedException(retry_after=remaining)

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_email(email)

        if not user:
            verify_dummy()  # MANDATORY — equalises timing vs wrong_password path
            await record_failure(email)
            logger.warning("auth_event LOGIN_FAILED email=%s reason=user_not_found",
                           email)
            raise AuthenticationError("Invalid email or password")

        if not verify_password(password, user.password_hash):
            count, locked = await record_failure(email)
            logger.warning(
                "auth_event LOGIN_FAILED email=%s reason=wrong_password "
                "attempt=%d is_now_locked=%s", email, count, locked,
            )
            raise AuthenticationError("Invalid email or password")

        if not user.is_active:
            logger.warning("auth_event LOGIN_FAILED email=%s reason=account_disabled",
                           email)
            raise AccountDisabledException()

        await clear_failures(email)

        access_token          = create_access_token(user)
        refresh_raw, ref_hash = create_refresh_token()
        expires_at            = datetime.now(timezone.utc) + timedelta(
                                    days=_settings.jwt_refresh_token_expire_days)

        # Single transaction — both writes commit together or neither does
        rt_repo = RefreshTokenRepository(db)
        await rt_repo.create(
            user_id       = user.id,
            token_hash    = ref_hash,
            expires_at    = expires_at,
            token_version = user.token_version,  # REQUIRED — stored for session validation
        )
        await user_repo.update_last_login(user.id)
        await db.commit()

        logger.info(
            "auth_event LOGIN_SUCCESS user_id=%s email=%s role=%s tenant_id=%s",
            user.id, user.email, user.role, user.tenant_id,
        )

        return LoginResult(
            access_token          = access_token,
            refresh_token         = refresh_raw,
            expires_in            = _settings.jwt_access_token_expire_minutes * 60,
            force_password_change = user.force_password_change,
            user                  = user,
        )

    async def refresh(self, refresh_token_raw: str, db: AsyncSession) -> RefreshResult:
        """
        Rotates refresh token and issues new access token.

        Race condition protection (R5 fix):
            get_by_hash() uses SELECT FOR UPDATE — row-level DB lock.
            Parallel refresh requests with the same token:
              Request A: gets lock → proceeds → revokes old → creates new → commits
              Request B: blocks until A commits → sees revoked_at IS NOT NULL → 401
            This guarantees rotation is atomic and one-at-a-time.

        Steps:
        Step 1 — hash_refresh_token(raw)
        Step 2 — get_by_hash() with SELECT FOR UPDATE — returns None if not found/revoked/expired
        Step 3 — get user, check is_active
        Step 4 — token_version check — if mismatch → session invalidated → revoke + 401
        Step 5 — create_access_token()
        Step 6 — create_refresh_token() → (new_raw, new_hash)
        Step 7 — [TRANSACTION] revoke old + create new [db.commit()]
        Step 8 — Log TOKEN_REFRESHED
        Step 9 — Return RefreshResult
        """
        from services.auth.token import (
            create_access_token, create_refresh_token, hash_refresh_token,
        )
        from db.repositories.user import UserRepository
        from db.repositories.refresh_token import RefreshTokenRepository
        from errors.exceptions import InvalidTokenException, SessionInvalidatedException
        from config.settings import get_settings

        _settings  = get_settings()
        token_hash = hash_refresh_token(refresh_token_raw)
        rt_repo    = RefreshTokenRepository(db)
        token_rec  = await rt_repo.get_by_hash(token_hash)  # SELECT FOR UPDATE

        if not token_rec:
            raise InvalidTokenException("Invalid or expired token")

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_id(token_rec.user_id)

        if not user or not user.is_active:
            await rt_repo.revoke(token_hash)
            await db.commit()
            raise InvalidTokenException("User not found or disabled")

        if token_rec.token_version != user.token_version:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.warning(
                "auth_event SESSION_INVALIDATED user_id=%s "
                "token_ver=%d user_ver=%d",
                user.id, token_rec.token_version, user.token_version,
            )
            raise SessionInvalidatedException()

        new_access        = create_access_token(user)
        new_raw, new_hash = create_refresh_token()
        expires_at        = datetime.now(timezone.utc) + timedelta(
                                days=_settings.jwt_refresh_token_expire_days)

        # Single transaction — revoke old and create new atomically
        await rt_repo.revoke(token_hash)
        await rt_repo.create(
            user_id       = user.id,
            token_hash    = new_hash,
            expires_at    = expires_at,
            token_version = user.token_version,
        )
        await db.commit()

        logger.info("auth_event TOKEN_REFRESHED user_id=%s", user.id)

        return RefreshResult(
            access_token  = new_access,
            refresh_token = new_raw,
            expires_in    = _settings.jwt_access_token_expire_minutes * 60,
        )

    async def logout(self, refresh_token_raw: str, db: AsyncSession) -> None:
        """
        Revokes provided refresh token. Access token expires naturally (≤30 min).
        Idempotent — safe with already-revoked or not-found token.
        """
        from services.auth.token import hash_refresh_token
        from db.repositories.refresh_token import RefreshTokenRepository

        token_hash = hash_refresh_token(refresh_token_raw)
        rt_repo    = RefreshTokenRepository(db)
        token_rec  = await rt_repo.get_by_hash(token_hash)
        if token_rec:
            await rt_repo.revoke(token_hash)
            await db.commit()
            logger.info("auth_event LOGOUT user_id=%s", token_rec.user_id)

    async def logout_all_sessions(self, user_id: UUID, db: AsyncSession) -> None:
        """
        Immediately invalidates ALL active sessions for a user.

        Mechanism — two-step:
        1. Increment user.token_version → all existing JWTs now carry stale ver
           claim → middleware rejects with SESSION_INVALIDATED on next request.
        2. Revoke all refresh tokens → rotation impossible even if client retries.

        Access tokens: expire naturally — max 30 min residual window.
        Refresh tokens: revoked immediately — no rotation possible.

        MUST be called on:
        - User changes own password (change_password())
        - Admin changes user role (PUT /v1/admin/users/{id})
        - Admin deactivates user account
        - Admin resets user password

        Single transaction — version increment and token revocation are atomic.
        """
        from db.repositories.user import UserRepository
        from db.repositories.refresh_token import RefreshTokenRepository

        user_repo = UserRepository(db)
        rt_repo   = RefreshTokenRepository(db)

        new_ver = await user_repo.increment_token_version(user_id)
        revoked = await rt_repo.revoke_all_for_user(user_id)
        await db.commit()

        logger.info(
            "auth_event SESSION_INVALIDATED user_id=%s "
            "new_token_version=%d refresh_tokens_revoked=%d",
            user_id, new_ver, revoked,
        )

    async def change_password(
        self,
        user_id:          UUID,
        current_password: str,
        new_password:     str,
        db:               AsyncSession,
    ) -> None:
        """
        Changes password and invalidates all sessions.

        Step 1 — load user
        Step 2 — verify_password(current_password) → 401 if wrong
        Step 3 — validate_password_strength(new_password)
        Step 4 — [TRANSACTION]
                   update password_hash + force_password_change = False
                 [db.commit()]
        Step 5 — logout_all_sessions() → separate transaction
        Step 6 — Log PASSWORD_CHANGED
        """
        from services.auth.password import (
            verify_password, hash_password, validate_password_strength,
        )
        from db.repositories.user import UserRepository
        from errors.exceptions import AuthenticationError

        user_repo = UserRepository(db)
        user      = await user_repo.get_by_id(user_id)
        if not user:
            raise AuthenticationError("User not found")

        if not verify_password(current_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect")

        validate_password_strength(new_password)

        await user_repo.update(user_id, {
            "password_hash":         hash_password(new_password),
            "force_password_change": False,
        })
        await db.commit()

        await self.logout_all_sessions(user_id, db)

        logger.info("auth_event PASSWORD_CHANGED user_id=%s", user_id)
```

---

## 7. JWT Token Design

### 7.1 Access Token Payload

```json
{
    "sub":       "550e8400-e29b-41d4-a716-446655440000",
    "type":      "access",
    "ver":       1,
    "role":      "DEVELOPER",
    "tenant_id": "42a083bf-5cad-4b65-84d1-b81def88c9f3",
    "dept_id":   "4111d663-47e3-4632-bf92-46a6b24a92f8",
    "aud":       "wrapsec-dashboard",
    "iat":       1714000000,
    "exp":       1714001800
}
```

### 7.2 Claim Reference

| Claim | Type | Purpose | Validated on decode |
|---|---|---|---|
| `sub` | string UUID | User identifier | ✅ must be present |
| `type` | "access" | Prevents refresh token misuse as access token | ✅ must equal "access" |
| `ver` | integer | Session invalidation — matched against user.token_version | ✅ must be present; re-checked in middleware |
| `role` | string | RBAC — passed to RBAC dependencies | ✅ must be present |
| `tenant_id` | string UUID | Security boundary — cross-validated against DB | ✅ must match DB value |
| `dept_id` | string UUID / null | Isolation boundary — null for ADMIN | logged if mismatch |
| `aud` | string | Cross-service token reuse prevention | ✅ jwt.decode() validates |
| `iat` | timestamp | Issued-at (standard) | automatic |
| `exp` | timestamp | Expiry (standard) | ✅ automatic by jwt.decode() |

Excluded: `email` (unnecessary exposure), `principal` (redundant), permissions (v2+).

### 7.3 Refresh Token

```
Format:     secrets.token_urlsafe(32) — 32 random bytes, URL-safe base64
Storage:    SHA-256(raw) stored in DB — raw NEVER server-side
Delivery:   httpOnly cookie — JS cannot read, XSS cannot steal
Rotation:   Every use — old revoked, new issued (SELECT FOR UPDATE prevents race)
Revocation: On logout, password change, role change, deactivation
Cleanup:    Daily — two clauses (R6 fix):
            1. WHERE expires_at < NOW() AND revoked_at IS NOT NULL
            2. WHERE expires_at < NOW() - 90 days (prevents unbounded growth)
```

---

## 8. Middleware — `api/v1/middleware/auth.py`

### 8.1 request.state fields — set by all auth paths

```python
# Existing fields (API key path — unchanged)
request.state.is_admin    # bool
request.state.key_type    # "live" | "trial"
request.state.key_name    # display name
request.state.app_id      # string | None
request.state.dept_id     # string | None
request.state.tenant_id   # string | None (always real UUID — never "admin" string)

# New fields — set by BOTH paths
request.state.principal_type  # "api_key" | "user"
request.state.user_id         # None (API key) | user UUID string (JWT)
request.state.user_role       # None (API key) | role string (JWT) — used by RBAC

# key_id prefixed to prevent namespace collision (R5 fix):
#   JWT users:    request.state.key_id = f"user:{user.id}"
#   API keys:     request.state.key_id = f"key:{key.key_id}"
#   Admin key:    request.state.key_id = "key:admin"
# Rate limiter, metrics, and logs all use key_id — prefix ensures no collision
# between user UUIDs and API key_id strings even if they share characters.
request.state.key_id      # prefixed string — see above
```

### 8.2 JWT authentication path — `_authenticate_jwt()`

```python
async def _authenticate_jwt(self, token: str, request: Request, call_next) -> Response:
    """
    JWT authentication. Only called when:
        - x-api-key header is absent (or empty after strip)
        - Authorization header starts with "Bearer "

    Steps are numbered — do not reorder.
    """

    # Step 1 — Decode and validate JWT
    # decode_access_token() validates signature, expiry, audience, type, required fields.
    # Logs full error internally. Raises generic JWTError.
    try:
        payload = decode_access_token(token)
    except JWTError:
        # Logged inside decode_access_token() — do not double-log here
        return _unauthorized(request, "invalid_or_expired_token")

    # Step 2 — Parse and validate sub claim
    user_id = payload.get("sub")
    try:
        user_uuid = UUID(user_id)
    except (ValueError, TypeError):
        logger.warning("auth JWT invalid_sub_format user_id=%s path=%s",
                       user_id, request.url.path)
        return _unauthorized(request, "invalid_token")

    # Step 2a — Load user from DB
    async with AsyncSessionFactory() as session:
        repo = UserRepository(session)
        user = await repo.get_by_id(user_uuid)

    # Step 2b — User existence check
    if not user:
        logger.warning("auth JWT user_not_found user_id=%s path=%s",
                       user_id, request.url.path)
        return _unauthorized(request, "invalid_token")

    # Step 2c — Active check
    if not user.is_active:
        logger.warning("auth JWT user_disabled user_id=%s path=%s",
                       user_id, request.url.path)
        return _unauthorized(request, "account_disabled")

    # Step 2d — tenant_id present in DB (Layer 3 enforcement)
    if not user.tenant_id:
        logger.error("auth JWT user_missing_tenant user_id=%s path=%s",
                     user_id, request.url.path)
        return _unauthorized(request, "invalid_token")

    # Step 3 — Cross-validate tenant_id: JWT claim vs DB value
    # Use DB value for request.state — JWT value only used for this check.
    # Detects tampered or stale tenant_id in token.
    if str(user.tenant_id) != payload.get("tenant_id"):
        logger.error(
            "auth JWT tenant_mismatch user_id=%s "
            "token_tenant=%s db_tenant=%s path=%s",
            user_id, payload.get("tenant_id"), str(user.tenant_id),
            request.url.path,
        )
        return _unauthorized(request, "invalid_token")

    # Step 3b — Log dept_id mismatch (warning only — not rejection)
    # dept_id in token may be stale if admin changed user dept since last login.
    # We always use DB value for request.state — token value is informational only.
    # Mismatch resolves itself on next token refresh.
    token_dept = payload.get("dept_id")
    db_dept    = str(user.dept_id) if user.dept_id else None
    if token_dept != db_dept:
        logger.warning(
            "auth JWT dept_mismatch user_id=%s token_dept=%s db_dept=%s "
            "— using DB value (expected if dept changed since last login)",
            user_id, token_dept, db_dept,
        )
    # Always use DB value — state is populated from user object below

    # Step 4 — Token version check (session invalidation)
    if payload.get("ver") != user.token_version:
        logger.warning(
            "auth JWT session_invalidated user_id=%s "
            "token_ver=%s user_ver=%s path=%s",
            user_id, payload.get("ver"), user.token_version, request.url.path,
        )
        return JSONResponse(
            status_code=401,
            content={"error": {
                "code":    "SESSION_INVALIDATED",
                "message": "Session has been invalidated. Please log in again.",
            }}
        )

    # Step 5 — Populate request.state from DB values (never from JWT claims)
    request.state.principal_type = "user"
    request.state.key_id         = f"user:{user.id}"   # prefixed (R5 fix)
    request.state.key_name       = user.email
    request.state.key_type       = "live"
    request.state.is_admin       = (user.role == "ADMIN")
    request.state.dept_id        = str(user.dept_id)   if user.dept_id   else None
    request.state.tenant_id      = str(user.tenant_id) # always from DB
    request.state.app_id         = None
    request.state.user_id        = str(user.id)
    request.state.user_role      = user.role  # CRITICAL — used by RBAC dependencies

    # Step 6 — force_password_change enforcement (R5 fix)
    # Enforced here at middleware level — not just frontend.
    # Prevents API bypass: a user with force_password_change=True who calls
    # the API directly (curl, SDK) gets 403 on all endpoints except the
    # allowed paths below.
    FORCE_CHANGE_ALLOWED = {
        "/v1/auth/change-password",
        "/v1/auth/logout",
        "/v1/auth/me",  # allowed so dashboard can read force_password_change flag
    }
    if user.force_password_change and request.url.path not in FORCE_CHANGE_ALLOWED:
        return JSONResponse(
            status_code=403,
            content={"error": {
                "code":    "PASSWORD_CHANGE_REQUIRED",
                "message": "You must change your password before accessing this resource.",
                "hint":    "POST /v1/auth/change-password",
            }}
        )

    return await call_next(request)
```

### 8.3 Admin key authentication path — `_authenticate_admin_key()`

```python
async def _authenticate_admin_key(self, request: Request, call_next) -> Response:
    """
    Handles the hardcoded admin key (settings.admin_api_key).
    Admin key is NEVER in the api_keys DB table.
    Fetches default tenant from DB to get a real tenant_id UUID.

    request.state.tenant_id is ALWAYS a real UUID — never the string "admin"
    or any other placeholder. This was fixed in R4 and must not regress.
    """
    async with AsyncSessionFactory() as session:
        tenant_repo = TenantRepository(session)
        tenant      = await tenant_repo.get_default()

    if not tenant:
        logger.error("auth admin_key no_default_tenant path=%s", request.url.path)
        return _unauthorized(request, "system_configuration_error")

    request.state.principal_type = "api_key"
    request.state.key_id         = "key:admin"   # prefixed (R5 fix)
    request.state.key_name       = "Admin Key"
    request.state.key_type       = "live"
    request.state.is_admin       = True
    request.state.dept_id        = None
    request.state.tenant_id      = str(tenant.id)  # Real UUID from DB — never "admin"
    request.state.app_id         = None
    request.state.user_id        = None
    request.state.user_role      = None

    return await call_next(request)
```

### 8.4 `_unauthorized()` helper — always logs

```python
def _unauthorized(request: Request, reason: str) -> JSONResponse:
    """
    Returns 401 JSONResponse. Always logs reason and path (R5 fix).
    Every auth rejection is visible in logs — no silent 401s.
    reason: snake_case string, no spaces, used in log (not exposed to client).
    """
    logger.warning(
        "auth rejected reason=%s path=%s method=%s",
        reason, request.url.path, request.method,
    )
    return JSONResponse(
        status_code=401,
        content={"error": {
            "code":    "UNAUTHORIZED",
            "message": "Missing or invalid credentials",
            "trace_id": getattr(request.state, "trace_id", None),
        }}
    )
```

---

## 9. Auth Endpoints

### 9.1 POST /v1/auth/login

```
Request:  { "email": "alice@acme.com", "password": "SecurePass1" }

Success (200):
{
    "access_token":          "eyJ...",
    "token_type":            "bearer",
    "expires_in":            1800,
    "force_password_change": false,
    "user": {
        "id":        "550e8400-...",
        "email":     "alice@acme.com",
        "role":      "DEVELOPER",
        "dept_id":   "4111d663-...",
        "tenant_id": "42a083bf-..."
    }
}
Set-Cookie: refresh_token=<raw>; HttpOnly; Secure; SameSite=Strict;
            Path=/v1/auth; Max-Age=2592000

Errors:
  401 INVALID_CREDENTIALS — wrong email OR wrong password
                            IDENTICAL message for both — no enumeration
  401 ACCOUNT_DISABLED    — is_active = false
  429 ACCOUNT_LOCKED      — { "code": "ACCOUNT_LOCKED",
                               "message": "Too many failed attempts",
                               "retry_after": 847 }
```

### 9.2 POST /v1/auth/refresh

```
Request: No body. Refresh token read from httpOnly cookie.
         Cookie name: refresh_token
         Cookie path: /v1/auth
         IMPORTANT: browser only sends cookie to /v1/auth/* paths.
         If API prefix changes, cookie Path must also change.

Success (200):
{
    "access_token": "eyJ...",
    "token_type":   "bearer",
    "expires_in":   1800
}
Set-Cookie: refresh_token=<new_rotated>; HttpOnly; Secure; ...

Errors:
  401 INVALID_TOKEN        — expired, revoked, or not found
  401 SESSION_INVALIDATED  — token_version mismatch
```

### 9.3 POST /v1/auth/logout

```
Auth:    JWT Bearer required
Request: No body. Refresh token from cookie.

Success (200): { "message": "Logged out successfully" }
Set-Cookie: refresh_token=; HttpOnly; Secure; SameSite=Strict;
            Path=/v1/auth; Max-Age=0   ← clears cookie
```

### 9.4 GET /v1/auth/me

```
Auth:    JWT Bearer required

Success (200):
{
    "id":                    "550e8400-...",
    "email":                 "alice@acme.com",
    "role":                  "DEVELOPER",
    "dept_id":               "4111d663-...",
    "tenant_id":             "42a083bf-...",
    "is_active":             true,
    "force_password_change": false,
    "last_login_at":         "2026-04-25T09:00:00Z"
}
```

### 9.5 POST /v1/auth/change-password

```
Auth:    JWT Bearer required (accessible even if force_password_change=True)
Request: { "current_password": "OldPass1", "new_password": "NewPass1!" }

Success (200): { "message": "Password changed. All sessions have been invalidated." }
Set-Cookie: refresh_token=; HttpOnly; Max-Age=0   ← re-login required

Errors:
  400 VALIDATION_ERROR — new password too weak
  401 INVALID_PASSWORD — current password wrong
```

---

## 10. User Management Endpoints

### 10.1 POST /v1/admin/users

```
Auth:    JWT + ADMIN role
Request:
{
    "email":    "bob@acme.com",
    "password": "TempPass1",
    "role":     "DEVELOPER",
    "dept_id":  "4111d663-..."   ← required for DEVELOPER/VIEWER, absent for ADMIN
}
Behaviour:
  - normalize_email() before store
  - validate_password_strength() on password
  - role != ADMIN and no dept_id → 400
  - dept_id provided → verify belongs to same tenant (R5 fix)
  - force_password_change = True automatically
  - User must change password on first login
  - Middleware enforces force_password_change at API level (not just frontend)
```

### 10.2-10.3 GET /v1/admin/users and GET /v1/admin/users/{user_id}

Standard list + get. Auth: JWT + ADMIN.

### 10.4 PUT /v1/admin/users/{user_id}

```
Auth:    JWT + ADMIN role
Request: { "role"?, "dept_id"?, "is_active"? }

Pre-flight validation (BEFORE any DB change):
  If changing role away from ADMIN OR setting is_active=False for ADMIN user:
    count = UserRepository.count_active_admins(tenant_id)
    if count <= 1:
        raise 400 ValidationError(
            "Cannot demote or deactivate the last active admin. "
            "Create another admin first."
        )

  If dept_id being changed:
    Verify new dept_id belongs to same tenant (R5 fix).

Post-change side effects (AFTER DB update):
  If role changed OR is_active=False:
    await auth_service.logout_all_sessions(user_id)
```

### 10.5 POST /v1/admin/users/{user_id}/reset-password

```
Auth:    JWT + ADMIN role
Request: { "new_password": "TempPass1" }
Behaviour:
  - validate_password_strength(new_password)
  - hash and store
  - force_password_change = True
  - logout_all_sessions()
```

---

## 11. Auth Event Logging

All events logged via `logger = logging.getLogger("wrapsec.auth")`.
Format: `auth_event EVENT_NAME key=value ...`

```
LOGIN_SUCCESS:      user_id, email, role, tenant_id
LOGIN_FAILED:       email, reason (user_not_found|wrong_password|account_disabled),
                    attempt (count), is_now_locked
LOGIN_LOCKED:       email, remaining_secs
LOGOUT:             user_id
TOKEN_REFRESHED:    user_id
SESSION_INVALIDATED: user_id, new_token_version, refresh_tokens_revoked
PASSWORD_CHANGED:   user_id
JWT_TENANT_MISMATCH: user_id, token_tenant, db_tenant, path (ERROR level)
JWT_DEPT_MISMATCH:  user_id, token_dept, db_dept (WARNING — not rejection)
AUTH_REJECTED:      reason (snake_case), path, method (via _unauthorized() helper)
```

---

## 12. RBAC Dependencies — `api/v1/dependencies/auth.py`

```python
async def get_current_principal(request: Request) -> Principal:
    """
    Builds Principal from request.state. Accepts API key AND JWT.
    Use on endpoints that accept both (scan, audit).
    Raises 401 if not authenticated.
    """

async def require_jwt(principal: Principal = Depends(get_current_principal)) -> Principal:
    """
    Requires JWT specifically. Rejects API key with 403.
    Use on all dashboard management endpoints.
    """

def require_role(*roles: str):
    """
    Factory — requires JWT + one of the given roles.
    Always implies require_jwt().

    Usage:
        Depends(require_role("ADMIN"))
        Depends(require_role("ADMIN", "DEVELOPER"))
    """

def require_admin():
    """Shorthand for Depends(require_role("ADMIN"))."""
```

### 12.1 Endpoint Protection Matrix

```
Public (no auth):
    GET  /health*
    GET  /metrics
    POST /v1/auth/login
    POST /v1/auth/refresh

JWT required (any role):
    POST /v1/auth/logout
    GET  /v1/auth/me
    POST /v1/auth/change-password

JWT + ADMIN:
    ALL  /v1/admin/tenant*
    ALL  /v1/admin/departments*
    ALL  /v1/admin/applications*
    ALL  /v1/admin/users*
    PUT  /v1/settings/*            ← write

JWT + ADMIN or DEVELOPER:
    GET  /v1/settings/*            ← read
    ALL  /v1/keys/*

API key OR JWT:
    POST /v1/ai/request
    POST /v1/chat/completions
    GET  /v1/ai/requests/{trace_id}
    GET  /v1/audit/*               ← scoped by dept_id from principal
```

---

## 13. Bootstrap — `api/main.py`

```python
async def bootstrap_admin(db: AsyncSession) -> None:
    """
    Creates first admin if users table is empty for the default tenant.
    Runs on every startup — skips if users exist.
    Non-fatal — system starts even if bootstrap fails.
    Sets force_password_change=True — enforced at middleware level, not just frontend.
    """
    try:
        tenant = await TenantRepository(db).get_default()
        if not tenant:
            logger.error("bootstrap no_default_tenant")
            return

        if await UserRepository(db).count_by_tenant(tenant.id) > 0:
            return

        email = normalize_email(settings.admin_email)
        try:
            validate_password_strength(settings.admin_password)
        except ValueError as e:
            logger.error("bootstrap admin_password_too_weak: %s", e)
            return

        await UserRepository(db).create({
            "tenant_id":             tenant.id,
            "dept_id":               None,
            "email":                 email,
            "password_hash":         hash_password(settings.admin_password),
            "role":                  "ADMIN",
            "force_password_change": True,
        })
        await db.commit()

        # Production safety check (R6+R7 fix):
        # If ADMIN_PASSWORD has not been changed from the default value in production:
        # - Log ERROR (persisted in log file + monitoring pipeline)
        # - ALSO print to stderr (visible immediately in console/terminal even if
        #   logs are not being watched at startup time)
        # force_password_change=True handles the UI flow but does not prevent the
        # insecure default from existing in .env.
        DEFAULT_PASSWORD = "ChangeMe!OnFirstLogin"
        if (settings.environment == "production"
                and settings.admin_password == DEFAULT_PASSWORD):
            import sys
            warning_msg = (
                "
"
                "╔══════════════════════════════════════════════════════════════╗
"
                "║  ⚠  WRAPSEC SECURITY WARNING                                 ║
"
                "║  Default ADMIN_PASSWORD detected in production environment.  ║
"
                "║  Change ADMIN_PASSWORD in .env IMMEDIATELY.                  ║
"
                "║  Do not allow any user to log in until this is changed.      ║
"
                "╚══════════════════════════════════════════════════════════════╝
"
            )
            print(warning_msg, file=sys.stderr, flush=True)
            logger.error(
                "bootstrap SECURITY_RISK default_admin_password_in_production "
                "— change ADMIN_PASSWORD in .env immediately"
            )

        logger.info("bootstrap admin_created email=%s", email)
        logger.warning(
            "bootstrap CHANGE_PASSWORD — force_password_change=True is set. "
            "Admin must change password on first login before accessing anything."
        )

    except Exception as e:
        logger.error("bootstrap failed: %s", e)
```

---

## 14. Dashboard Auth

### 14.1 Token Storage

```
Access token  → JavaScript memory (React context state)
               Lost on page refresh → triggers silent refresh
               NEVER in localStorage or sessionStorage (XSS risk)

Refresh token → httpOnly cookie
               JS cannot read — XSS cannot steal
               SameSite=Strict — CSRF protection
               Secure flag — HTTPS only in production
               Path=/v1/auth — browser only sends to /v1/auth/* endpoints
```

### 14.2 Cookie Settings

```python
# Set on login and refresh
response.set_cookie(
    key      = "refresh_token",
    value    = refresh_token_raw,
    httponly = True,
    secure   = (settings.environment == "production"),
    samesite = "strict",
    max_age  = settings.jwt_refresh_token_expire_days * 24 * 3600,
    path     = "/v1/auth",
    # IMPORTANT: browser only sends this cookie to requests matching Path=/v1/auth
    # POST /v1/auth/refresh must remain at this exact path.
    # If the API prefix changes, this path must change to match.
    # This constraint is documented in Convention 24 below.
)

# Clear on logout and password change
response.set_cookie(
    key      = "refresh_token",
    value    = "",
    httponly = True,
    secure   = (settings.environment == "production"),
    samesite = "strict",
    max_age  = 0,
    path     = "/v1/auth",
)
```

### 14.3 Auth Flow

```
Page load:
  AuthProvider.onMount()
  → no access token in memory
  → POST /v1/auth/refresh (cookie sent automatically by browser)
    → success: store access_token in memory, set currentUser
    → fail (no cookie/expired/invalidated): redirect to /login

Authenticated:
  All API calls: Authorization: Bearer {accessToken}
  15s before token expiry: silent auto-refresh
  Any 401: trigger refresh → if fails → redirect /login

force_password_change = true on login response:
  → store access token
  → redirect to /change-password
  → ProtectedRoute blocks all other routes until password changed
```

### 14.4 New Dashboard Files

```
dashboard/app/login/page.tsx
dashboard/app/change-password/page.tsx
dashboard/components/auth/AuthProvider.tsx
dashboard/components/auth/ProtectedRoute.tsx
dashboard/middleware.ts
dashboard/lib/auth.ts
```

---

## 15. Retention Worker — Refresh Token Cleanup

Add to `workers/tasks.py`:

```python
async def cleanup_refresh_tokens(db: AsyncSession) -> int:
    """
    Deletes refresh tokens WHERE expires_at < NOW() AND revoked_at IS NOT NULL.

    Both conditions required:
        - Expired only (not revoked): keep — fails validation naturally,
          preserves session audit trail
        - Revoked only (not expired): keep — recent termination,
          useful for security investigations
        - Both expired AND revoked: safe to delete — audit value exhausted

    Runs daily alongside audit_logs cleanup.

    Two cleanup clauses (R6 fix — prevents table growth):

    Clause 1 (primary — preserves audit trail):
        DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL
        Only deletes tokens that are BOTH expired AND explicitly revoked.
        Keeps expired-but-active tokens (failed naturally, audit value remains).

    Clause 2 (secondary — prevents unbounded table growth):
        DELETE WHERE expires_at < NOW() - INTERVAL 90 days
        Deletes ALL tokens older than 3x the refresh token lifetime (30 days).
        At 90 days, tokens are long past expiry — audit value is exhausted.
        Users who never explicitly logged out (browser closed etc.) accumulate
        tokens only cleaned by this clause.

    Combined: no token older than 90 days survives, recently expired tokens
    are kept for audit until they are also revoked or age out.
    """
    cutoff_primary   = datetime.utcnow()
    cutoff_secondary = datetime.utcnow() - timedelta(days=90)

    # Clause 1 — revoked AND expired
    result1 = await db.execute(
        delete(RefreshTokenModel).where(
            RefreshTokenModel.expires_at < cutoff_primary,
            RefreshTokenModel.revoked_at.is_not(None),
        )
    )

    # Clause 2 — anything older than 90 days regardless of revocation
    result2 = await db.execute(
        delete(RefreshTokenModel).where(
            RefreshTokenModel.expires_at < cutoff_secondary,
        )
    )

    await db.commit()
    total = result1.rowcount + result2.rowcount
    return total
```

---

## 16. Complete Test Plan

### 16.1 Unit Tests

**`tests/unit/services/test_password.py`**
```
test_hash_returns_bcrypt_hash
test_verify_correct_returns_true
test_verify_wrong_returns_false
test_verify_dummy_does_not_raise
test_dummy_hash_is_static_not_dynamic        ← R5 fix verification
test_normalize_lowercase
test_normalize_strips_whitespace
test_normalize_both
test_strength_too_short
test_strength_no_uppercase
test_strength_no_lowercase
test_strength_no_digit
test_strength_valid_passes
test_strength_lists_all_failures
```

**`tests/unit/services/test_token.py`**
```
test_access_token_has_sub
test_access_token_type_is_access
test_access_token_has_ver
test_access_token_has_audience
test_access_token_has_tenant_id
test_access_token_has_role
test_access_token_dept_null_for_admin
test_decode_valid_returns_payload
test_decode_expired_raises
test_decode_tampered_raises
test_decode_wrong_type_raises             ← refresh token used as access
test_decode_wrong_audience_raises
test_decode_missing_sub_raises
test_decode_missing_tenant_id_raises
test_decode_missing_ver_raises
test_decode_error_message_is_generic      ← no internal details to client
test_refresh_token_is_tuple
test_refresh_raw_differs_from_hash
test_hash_is_deterministic
```

**`tests/unit/services/test_lockout.py`**
```
test_not_locked_initially
test_record_increments_counter
test_first_failure_sets_ttl
test_at_max_sets_lock
test_beyond_max_extends_lock_ttl          ← attacker extends own lockout
test_is_locked_true_when_key_exists
test_clear_removes_counter
test_clear_removes_lock
test_remaining_positive_when_locked
test_remaining_zero_when_not_locked
```

**`tests/unit/services/test_auth_service.py`**
```
test_login_valid_returns_tokens
test_login_wrong_password_401
test_login_wrong_email_same_message       ← no enumeration
test_login_locked_429
test_login_inactive_401
test_login_clears_lockout_on_success
test_login_increments_failure_counter
test_login_triggers_lockout_at_max
test_login_not_found_calls_verify_dummy   ← timing equalisation
test_login_creates_token_with_token_version  ← R4 fix
test_login_single_commit                  ← R4 fix
test_refresh_returns_new_tokens
test_refresh_rotates_token
test_refresh_old_invalid_after_rotation
test_refresh_expired_401
test_refresh_revoked_401
test_refresh_version_mismatch_401
test_refresh_single_commit                ← R4 fix
test_refresh_select_for_update_used      ← R5 race fix
test_logout_revokes_token
test_logout_idempotent
test_logout_all_increments_version
test_logout_all_revokes_tokens
test_logout_all_single_commit
test_change_wrong_current_401
test_change_weak_new_400
test_change_updates_hash
test_change_force_false
test_change_calls_logout_all
```

**`tests/unit/test_principal.py`**
```
test_has_role_match
test_has_role_no_match
test_has_role_multiple
test_has_permission_exact
test_has_permission_wildcard_star
test_has_permission_wildcard_segment
test_admin_star_matches_all
test_denied
test_build_user_admin_dept_null
test_build_user_developer_has_dept
test_build_user_no_tenant_raises_value_error
test_build_api_key_no_tenant_raises_value_error
test_build_api_key_tenant_is_real_uuid        ← no "admin" string
test_key_id_uses_user_prefix                  ← R5 fix
test_admin_key_id_uses_key_prefix             ← R5 fix
```

### 16.2 Integration Tests

**`tests/integration/test_auth_endpoints.py`**
```
test_login_returns_access_token
test_login_sets_httponly_cookie
test_login_wrong_password_401_same_message
test_login_wrong_email_401_same_message       ← no enumeration
test_login_inactive_401_account_disabled
test_login_5_failures_429_with_retry_after
test_login_success_clears_lockout
test_login_force_change_true_in_response
test_refresh_returns_new_token
test_refresh_rotates_cookie
test_refresh_old_rejected_after_rotation
test_refresh_no_cookie_401
test_refresh_expired_401
test_refresh_version_mismatch_401
test_refresh_parallel_requests_only_one_succeeds  ← R5 race condition
test_logout_clears_cookie
test_logout_idempotent_200
test_me_returns_data
test_me_rejected_with_api_key_403
test_change_password_success
test_change_wrong_current_401
test_change_weak_new_400
test_change_old_tokens_rejected_after
test_force_change_blocks_other_endpoints_403  ← R5 middleware enforcement
test_force_change_allows_change_password
test_force_change_allows_logout
test_force_change_allows_me
```

**`tests/integration/test_rbac.py`**
```
test_admin_can_write_settings
test_developer_cannot_write_settings_403
test_developer_can_read_settings_200
test_viewer_cannot_access_settings_403
test_viewer_cannot_access_keys_403
test_api_key_cannot_access_admin_403
test_api_key_can_scan_200                    ← Option B
test_jwt_developer_can_scan_200              ← Option B
test_no_auth_401
test_both_headers_api_key_wins               ← header precedence
test_admin_sees_all_depts_in_audit
test_developer_sees_only_own_dept
test_developer_other_dept_trace_id_404       ← isolation
test_last_admin_cannot_be_deactivated_400
test_last_admin_cannot_be_demoted_400
test_session_invalidated_401
test_inactive_user_jwt_401
test_jwt_tenant_mismatch_401                 ← R4 fix
test_dept_id_must_belong_to_tenant_400         ← R5 fix
test_dept_different_tenant_rejected_400       ← R6 DB FK fix
test_key_id_prefixed_in_rate_limit            ← R5 fix (no collision)
test_all_auth_failures_logged                 ← R5 fix
test_session_invalidated_distinct_from_401      ← R6 — frontend 401 behavior
test_bootstrap_logs_error_for_default_password_in_production  ← R6 fix
test_bootstrap_prints_to_stderr_in_production    ← R7 fix
test_has_permission_raises_not_implemented_in_v1 ← R6 fix
test_cleanup_expired_runs_both_clauses           ← R7 fix
test_cleanup_expired_removes_90day_old_tokens    ← R7 fix
```

---

## 17. Complete File List

### New Files

```
domain/entities/principal.py
services/auth/__init__.py
services/auth/password.py
services/auth/token.py
services/auth/lockout.py
services/auth/service.py
db/repositories/user.py
db/repositories/refresh_token.py
db/migrations/add_users.sql
api/v1/endpoints/auth.py
api/v1/endpoints/admin/users.py
api/v1/dependencies/auth.py
dashboard/app/login/page.tsx
dashboard/app/change-password/page.tsx
dashboard/components/auth/AuthProvider.tsx
dashboard/components/auth/ProtectedRoute.tsx
dashboard/middleware.ts
dashboard/lib/auth.ts
tests/unit/services/test_password.py
tests/unit/services/test_token.py
tests/unit/services/test_lockout.py
tests/unit/services/test_auth_service.py
tests/unit/test_principal.py
tests/integration/test_auth_endpoints.py
tests/integration/test_rbac.py
```

### Modified Files

```
domain/enums.py                 ← PrincipalType, UserRole
db/models.py                    ← UserModel, RefreshTokenModel
config/settings.py              ← JWT + lockout + bootstrap env vars
api/v1/middleware/auth.py       ← JWT path, admin tenant fetch, prefixed key_id,
                                   tenant cross-validation, dept mismatch logging,
                                   force_password_change enforcement, _unauthorized logging
api/v1/router.py                ← register auth + users routes
api/main.py                     ← bootstrap_admin in lifespan
workers/tasks.py                ← cleanup_refresh_tokens()
dashboard/lib/api.ts            ← Authorization: Bearer header on all calls
```

---

## 18. Implementation Order

Each step independently testable. Do not proceed until current step passes.

```
Step 1  — domain/enums.py
Step 2  — domain/entities/principal.py
Step 3  — config/settings.py
Step 4  — db/models.py                      (UserModel with token_version, RefreshTokenModel)
Step 5  — db/migrations/add_users.sql       Run migration
Step 6  — db/repositories/user.py           (get_by_email uses LOWER(), tenant check)
Step 7  — db/repositories/refresh_token.py  (get_by_hash uses SELECT FOR UPDATE)
Step 8  — services/auth/password.py         (hardcoded _DUMMY_HASH)
Step 9  — services/auth/token.py
Step 10 — services/auth/lockout.py
Step 11 — services/auth/service.py          (single commit per flow)
Step 12 — api/v1/middleware/auth.py         (prefixed key_id, tenant+dept validation,
                                             force_password_change, _unauthorized logging)
Step 13 — api/v1/dependencies/auth.py
Step 14 — api/v1/endpoints/auth.py
Step 15 — api/v1/endpoints/admin/users.py   (dept tenant check, last admin protection)
Step 16 — api/v1/router.py
Step 17 — api/main.py                       (bootstrap_admin)
Step 18 — workers/tasks.py
Step 19 — Unit tests (Steps 1-11)           All must pass
Step 20 — Integration tests (Steps 12-18)   All must pass
Step 21 — dashboard/lib/auth.ts
Step 22 — dashboard/components/auth/
Step 23 — dashboard/app/login/
Step 24 — dashboard/app/change-password/
Step 25 — dashboard/middleware.ts
Step 26 — dashboard/lib/api.ts
Step 27 — End-to-end: login → scan → audit → change-password → logout
```

---

## 19. Non-Negotiable Conventions

Every file touching authentication must follow these. Reviewers: each convention
references where it is implemented — check the section before flagging.

```
 1. tenant_id ALWAYS from authenticated identity — never from request body/params.
    [§1.3, §8.2 step 5, §8.3]

 2. dept_id ALWAYS from authenticated identity — never from client input.
    [§1.3, §8.2 step 5]

 3. Admin dept query: conditional WHERE dept_id — never WHERE dept_id = NULL.
    [§1.4]

 4. Same error for wrong email AND wrong password: "Invalid email or password".
    Never reveal which was wrong — prevents user enumeration.
    [§6.4 steps 4 and 6, §9.1]

 5. verify_dummy() MUST be called when user not found before raising any error.
    Equalises timing to prevent email enumeration via response time.
    [§6.1, §6.4 step 4]

 6. _DUMMY_HASH is hardcoded, not computed at runtime.
    Prevents timing variation across process restarts.
    [§6.1]

 7. token_version checked on EVERY JWT request in middleware.
    Not only at refresh time — on every authenticated request.
    [§8.2 step 4]

 8. JWT tenant_id MUST be cross-validated against DB tenant_id.
    Detects token tampering or stale tenant claim.
    payload["tenant_id"] != str(user.tenant_id) → 401.
    [§8.2 step 3]

 9. JWT dept_id mismatch: log warning, use DB value, do NOT reject.
    Dept can change between login and token expiry — mismatch is expected.
    [§8.2 step 3b]

10. principal_type ALWAYS written to audit_logs on every request.
    [§8.1, audit log attribution in ai.py and proxy.py]

11. user_role ALWAYS set on request.state in JWT path.
    RBAC dependencies read from request.state.user_role.
    [§8.1, §8.2 step 5]

12. force_password_change enforced in middleware — not just frontend.
    Users calling API directly (curl, SDK) are also blocked.
    Allowed paths when True: /v1/auth/change-password, /v1/auth/logout, /v1/auth/me.
    [§8.2 step 6]

13. normalize_email() before EVERY email read or write.
    User creation, bootstrap, login lookup, password reset — all of them.
    [§6.1, §4.3, §13]

14. get_by_email() MUST use func.lower() — never WHERE email = :email.
    ux_users_email_lower index only used with LOWER() queries.
    [§4.3]

15. refresh_token raw value NEVER stored server-side.
    Only SHA-256(raw) in DB. Never log raw token.
    [§6.3, §4.2]

16. API key ALWAYS wins if x-api-key header present — JWT ignored.
    [§1.2, §8.2 first line]

17. require_role() ALWAYS implies require_jwt() — API keys get 403.
    [§12]

18. has_permission() NOT called in v1 guards. Use has_role() only.
    [§3.2]

19. dept_id = NULL for ADMIN: intentional, enforced by DB CHECK + API validation.
    [§4.1, §5]

20. Refresh cleanup: DELETE WHERE expires_at < NOW() AND revoked_at IS NOT NULL.
    Never delete tokens that are only expired but not revoked.
    [§15]

21. Principal builder raises ValueError — never assert.
    assert can be disabled with Python -O flag.
    [§3.3]

22. Last admin protection: count_active_admins() before every demotion/deactivation.
    [§10.4]

23. Single DB commit per auth flow operation.
    login: create_token + update_last_login → one commit.
    refresh: revoke_old + create_new → one commit.
    logout_all: increment_version + revoke_all → one commit.
    [§6.4]

24. Refresh token cookie path is /v1/auth — browser only sends to /v1/auth/* endpoints.
    If API prefix changes, cookie Path= must also change to match.
    POST /v1/auth/refresh must remain at this path or cookie handling breaks.
    [§9.2, §14.2]

25. key_id prefixed to prevent namespace collision between user IDs and API key IDs:
    JWT users:    request.state.key_id = f"user:{user.id}"
    API keys:     request.state.key_id = f"key:{key.key_id}"
    Admin key:    request.state.key_id = "key:admin"
    Rate limiter, metrics, and logs all use key_id — prefix is mandatory.
    [§8.1, §8.2, §8.3]

26. get_by_hash() in RefreshTokenRepository uses SELECT FOR UPDATE.
    Prevents race condition on parallel refresh requests with the same token.
    [§4.3, §6.4]

27. dept_id must belong to same tenant — validated in UserRepository.create() and update().
    Application-level check: SELECT FROM departments WHERE id=dept_id AND tenant_id=tenant_id.
    [§4.3]

28. _unauthorized() always logs reason and path — no silent 401s.
    [§8.4]

29. Admin key fetches real tenant_id from DB — never uses string "admin" or any placeholder.
    request.state.tenant_id is always a real UUID string.
    [§8.3]

30. Auth events MUST be logged for all of:
    login success/fail/lock, logout, token refresh, session invalidation,
    password change, JWT tenant mismatch, JWT dept mismatch, all 401 rejections.
    [§11, §8.4]

31. PostgreSQL READ COMMITTED isolation is assumed.
    SELECT FOR UPDATE in RefreshTokenRepository.get_by_hash() relies on this.
    Do NOT change isolation level without reviewing refresh token rotation flow.
    Document any isolation level change in a migration comment before applying.
    [§5 migration]

32. JWT dept_id mismatch warnings (auth_event=JWT_DEPT_MISMATCH) must be routed
    to the security monitoring pipeline — not just stored in logs.
    DEPLOYMENT REQUIREMENT (R7 — not optional):
        Configure log aggregation (Grafana/Loki or equivalent) to alert on this event.
        This MUST be verified before go-live — check that dept_mismatch events appear
        in your monitoring dashboard. A warning that nobody watches provides zero
        security value. Include in deployment checklist and sign-off.
    [§8.2 step 3b, §11]

33. 401 UNAUTHORIZED response is always generic — "Missing or invalid credentials".
    This is intentional: revealing which specific check failed (expired vs tampered
    vs missing) is an oracle attack. Frontend must treat ALL 401s as re-auth required.
    The only exception is SESSION_INVALIDATED which has its own error code.
    Never branch frontend logic on 401 sub-reason — always redirect to login.
    [§9 endpoints, §8.4 _unauthorized()]

34. UUID/string type boundary must be maintained at every layer (R7 fix):
    DB layer:      UUID objects  (SQLAlchemy columns, FK joins, repository args)
    API/state/JWT: string objects (request.state, JWT claims, audit logs, responses)
    Cast at DB→API boundary: str(user.tenant_id) — builders and middleware always cast.
    Cast at API→DB boundary: UUID(tenant_id_string) — repositories cast internally.
    Mixing types causes silent comparison failures (UUID("abc") != "abc").
    [§1.3, §3.3, §8.1, §8.2]

35. cleanup_expired() implements BOTH clauses — retention worker calls this one method (R7 fix):
    Clause 1: WHERE expires_at < NOW() AND revoked_at IS NOT NULL
    Clause 2: WHERE expires_at < NOW() - 90 days
    Both DELETE statements execute in cleanup_expired() — not separate calls.
    [§4.3, §15]
```

---

---

## 20. On-Prem Deployment Requirements

These are not code changes — they are operational requirements that must be
satisfied before any on-prem production deployment. Verify each before go-live.

### 20.1 Security

```
✔ TLS termination configured (HTTPS enforced — never HTTP in production)
✔ Network exposure restricted (WrapSec API not exposed to public internet directly)
✔ SECRET_KEY is random, ≥32 chars, not the default
✔ ADMIN_PASSWORD changed from default before first login
✔ .env file permissions restricted (chmod 600 or equivalent)
✔ Database not exposed to public network
✔ Redis not exposed to public network
```

### 20.2 Observability (Required, not optional)

```
✔ Log aggregation configured (Grafana/Loki, ELK, or equivalent)
✔ auth_event=JWT_DEPT_MISMATCH alerts configured (Convention 32)
✔ auth_event=LOGIN_LOCKED alerts configured
✔ auth_event=SESSION_INVALIDATED visible in dashboard
✔ /metrics endpoint reachable by Prometheus
✔ Grafana dashboards imported (overview, latency, threats)
```

### 20.3 Data

```
✔ PostgreSQL backups scheduled and tested
✔ Backup includes: users, refresh_tokens, audit_logs, api_keys, settings tables
✔ Retention worker running (cleanup_refresh_tokens + cleanup_audit_logs daily)
✔ redis_url points to persistent Redis (not in-memory only)
```

### 20.4 SDK & Integration

```
✔ SDK integration tested: scan() works in <5 minutes from a fresh install
✔ Python SDK tested with at least one real application
✔ Node SDK tested with at least one real TypeScript application
✔ Dashboard login works end-to-end (login → scan → audit → logout)
✔ API version stability: /v1 prefix maintained, no breaking changes
```

### 20.5 Security Test Checklist (Run Manually Before Launch)

```
✔ JWT with wrong tenant_id → 401 (not 200)
✔ JWT with wrong dept_id → 200 but logged mismatch (verify in logs)
✔ API key + JWT together → API key wins
✔ Expired refresh token reuse → 401
✔ Parallel refresh with same token → only one succeeds
✔ force_password_change=True → all non-allowed endpoints return 403
✔ Invalid dept_id (different tenant) → 400
✔ Missing tenant_id → 401
✔ Last admin deactivation attempt → 400
✔ Lockout after 5 failures → 429 with retry_after
✔ Default admin password in production → error visible in console/logs
```

---

*Version 8.0 — Final. All seven review cycles incorporated and closed.*
*All 60 review items resolved — see table at top.*
*Implementation starts at Step 1.*
*No further changes without team sign-off.*
