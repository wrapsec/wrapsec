# WrapSec plugin contract

WrapSec is open-core: the OSS core is complete and self-hostable, and optional
features ship as **plugins** discovered through a Python entry point. This
document is the stable contract between a plugin and the core -- the seams a
plugin may use, the rules it must follow, and the guarantees the core makes in
return.

It is derived from the reference plugin (`plugins/refplugin`), which exercises
every seam listed here. The reference plugin is a permanent test instrument, not
a product feature; its tests (`tests/integration/test_refplugin.py`,
`tests/integration/test_plugin_migrations.py`) are the living proof that this
contract holds.

## Dependency discipline

- **A plugin imports core; core never imports a plugin.** The core has no
  knowledge of any plugin package name. Discovery is by entry point only.
- **`register(app)` is additive.** It mounts new routers and registers into the
  core's extension registries. It never patches, monkeypatches, or replaces a
  core component.
- **No paid/license code lives in core.** License checks live entirely in the
  plugin.

## Registration and lifecycle

A plugin declares one entry point in its own packaging metadata:

```toml
[project.entry-points."wrapsec.plugins"]
<name> = "<module>:register"
```

At startup `services.capabilities.load_plugins(app)` discovers every entry point
under the `wrapsec.plugins` group and calls each `register(app)`. Rules:

- A plugin that raises in `register()` is logged and skipped; the app still
  boots and the remaining plugins still load. Never assume your `register()`
  aborts startup.
- In the OSS edition nothing is installed under the group, so the process
  contains no plugin code at all.

### PEP 563 gotcha (required)

Do **not** put `from __future__ import annotations` in a module that defines
FastAPI route handlers inside `register()`. String annotations would leave
`get_type_hints` unable to resolve `Request`/`Principal` against the local scope,
and FastAPI would treat `request` as a required query parameter (HTTP 422). Use
real annotations resolved at def-time from the enclosing scope.

## The seams

Each seam is a public import. The `register_*` calls are informational routing,
never authorization (see Cardinal rules).

| Purpose | Import |
|---|---|
| Capability flag (UI/feature discovery) | `from services.capabilities import register_capability, capability_available` |
| HTTP route (authenticated) | `from fastapi import APIRouter, Depends, Request` / `from api.v1.dependencies.auth import get_current_principal` / `from domain.entities.principal import Principal` |
| Identity backend (SSO/OIDC/SAML) | `from services.auth.providers import register_auth_provider, AuthProvider, AuthenticationOutcome` |
| Policy layer (plan/entitlement ceiling) | `from services.policy_layers import register_policy_layer, PolicyContext` |
| SIEM connector | `from services.webhooks.connectors.registry import register_connector, ConnectorSpec, AuthKind` |
| Per-tenant config / entitlements | `from db.repositories.settings import TenantSettingsRepository, plugin_settings_key` |
| Owned-table migrations | `from db.plugin_migrations import run_plugin_migrations, plugin_version_table` |

### Capability + route

```python
def register(app):
    from fastapi import APIRouter, Depends, Request
    from fastapi.responses import JSONResponse
    from api.v1.dependencies.auth import get_current_principal
    from domain.entities.principal import Principal
    from services.capabilities import capability_available, register_capability

    register_capability("acme.feature")
    router = APIRouter()

    @router.get("/v1/acme/thing")
    async def thing(request: Request, _p: Principal = Depends(get_current_principal)):
        # Self-gate at request time; in SaaS also check the caller's entitlement.
        if not capability_available("acme.feature"):
            return JSONResponse(status_code=404, content={"error": {"code": "NOT_FOUND"}})
        return JSONResponse(content={"tenant_id": getattr(request.state, "tenant_id", None)})

    app.include_router(router)
```

### Identity backend

`register_auth_provider(provider)` registers an `AuthProvider` (see
`services/auth/providers/base.py`) under a new `method` name. `AuthService.login`
resolves the backend by method. The registry is **non-shadowing**: you cannot
overwrite the built-in `"password"` backend. A future SSO login endpoint passes
`method=<your name>`.

### Policy layer

`register_policy_layer(layer)` appends an async `layer(policy, PolicyContext) ->
policy` that runs as a **final ceiling** after all core resolution, so a plan
layer can clamp even an application override. The core never interprets
`tenants.plan`; your layer does, reading `PolicyContext.{db, tenant_id, dept_id,
app_id}`. A layer that raises is logged and skipped (fail-open) -- never rely on
it to *deny*; use it to shape.

### Per-tenant config and entitlements

Plugin config and per-tenant entitlements are `tenant_settings` rows under the
reserved prefix `plugin:<name>:<key>`. Build keys with `plugin_settings_key(name,
key)` and write them with the explicit opt-in:

```python
await TenantSettingsRepository(db).set(tenant_id, key, value, allow_plugin_namespace=True)
```

The core settings write path refuses the `plugin:` prefix, so a tenant admin can
never reach the namespace and core config can never collide with it. There is no
separate entitlement table in core.

### Owned-table migrations

A plugin owning tables ships its own Alembic chain and runs it with
`run_plugin_migrations(name, script_location)`, which isolates history in
`alembic_version_<name>` so it never touches the core chain. See
[plugin_migrations.md](plugin_migrations.md) for the env.py wiring.

## Cardinal rules

1. **Capability registration is informational, never authorization.** A route
   self-gates on `capability_available(...)` at request time, and in SaaS also
   checks the caller's per-tenant entitlement there. Registering a capability
   grants nothing.
2. **Every mounted route is tenant-isolated by classification.** Any route a
   plugin adds appears in the route-isolation guard
   (`tests/integration/test_route_isolation_guard.py`) and must be placed in a
   bucket. A route returning or mutating tenant data belongs in `TENANT_SCOPED`,
   carries `tenant_id` filtering, and needs a cross-tenant test. This makes the
   isolation contract structural, not a promise.
3. **Tenant data follows I8.** A plugin table holding tenant data has `tenant_id
   NOT NULL` and every read is tenant-filtered -- the same contract as core
   tables.
4. **Registries are non-shadowing where a built-in exists** (auth providers,
   connectors): you add a new name; you cannot silently replace core.

## What the core guarantees

- The entry-point group name (`wrapsec.plugins`), the `register(app)` signature,
  and every import in the seam table above are stable API; they change only with
  a deliberate, versioned break.
- Plugin load failures are isolated: one bad plugin never takes down the app or
  the other plugins.
- `GET /v1/capabilities` reports the effective (registered AND ceiling-permitted)
  capability set, so a dashboard can show or hide plugin UI.
