# Plugin database migrations

WrapSec is open-core: the OSS core is complete and self-hostable, and optional
features ship as plugins discovered through the `wrapsec.plugins` entry-point
group. A plugin that owns database tables manages their schema itself. This
document is the convention; it is fixed before any plugin ships tables because
retrofitting migration ownership onto a shared version table is painful.

## Ownership: one Alembic chain per owner, one version table per chain

Core startup runs `alembic upgrade head` against the **core** migration chain
only (`db/migrations`, version table `alembic_version`). A plugin ships its
**own** Alembic chain and runs it separately.

The two chains never touch because each records its history in its own version
table:

| Owner            | Migrations dir                        | Version table               |
|------------------|---------------------------------------|-----------------------------|
| Core             | `db/migrations`                       | `alembic_version`           |
| Plugin `<name>`  | `<plugin_pkg>/migrations`             | `alembic_version_<name>`    |

So `alembic upgrade head` on the core chain never sees a plugin revision (it
cannot mark it applied or pending), and a plugin upgrade never rewrites the core
history.

## Running a plugin's migrations

Use the core helper; it enforces the isolated version table:

```python
from db.plugin_migrations import run_plugin_migrations

run_plugin_migrations(
    "billing",                       # plugin name -> alembic_version_billing
    "wrapsec_billing/migrations",    # the plugin's own migrations dir
    database_url=None,               # None -> resolved from settings, like core
)
```

Call it from the plugin's `register(app)` (or a management CLI), never from core
startup. `command.upgrade` is synchronous and the env below calls `asyncio.run`,
so call it from a worker thread when inside an event loop
(`await asyncio.to_thread(run_plugin_migrations, ...)`).

## The plugin's `env.py`

A plugin's `env.py` mirrors the core `env.py`, with one required difference: it
reads the version table from `config.attributes["version_table"]` (set by
`run_plugin_migrations`) and passes it to `context.configure(...)`:

```python
config = context.config
_VERSION_TABLE = config.attributes.get("version_table", "alembic_version_<name>")

def _do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=<your Base.metadata or None>,
        version_table=_VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()
```

The complete, runnable reference lives in
`plugins/refplugin/wrapsec_refplugin/migrations/` and is exercised by
`tests/integration/test_plugin_migrations.py`.

## Tenant data in plugin tables (I8)

A plugin table that holds tenant data carries `tenant_id NOT NULL`, and every
read is tenant-filtered -- the same isolation contract as core tables. Any HTTP
route a plugin mounts is classified by the route-isolation guard
(`tests/integration/test_route_isolation_guard.py`), so tenant-scoped plugin
routes get a cross-tenant test by construction, not by promise.
