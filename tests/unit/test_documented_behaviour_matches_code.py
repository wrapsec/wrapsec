# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Fences for places where the documentation described behaviour the code
did not have.

A comment that is wrong about a security control is worse than no comment: it
is read as a specification, and the next change is made against it. So each of
these tests asserts the BEHAVIOUR the corrected text now claims. Asserting the
prose itself would pass on a copied-out paragraph and prove nothing.

One test per finding, deliberately, so a regression names which claim broke.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# 1. "masked" stores no raw text -- it does not redact at storage time
# --------------------------------------------------------------------------

def _storage_branch_source() -> str:
    """The data_storage_mode branch of the proxy's persistence helper."""
    source = (_ROOT / "api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    marker = "mode = (get_settings().data_storage_mode"
    assert marker in source, "the storage-mode branch moved; this fence needs updating"
    start = source.index(marker)
    return source[start:start + 1600]


@pytest.mark.parametrize("mode", ["masked", "MASKED", "typo-not-a-mode", ""])
def test_only_full_retains_raw_text(mode):
    """Every value except an explicit "full" must discard the raw columns.

    The settings comment used to say masked "runs the PII redactor before
    storing", which would mean a redacted copy of the prompt is retained. It is
    not: the raw column is dropped entirely. An operator choosing a retention
    mode on the strength of that sentence would have been wrong about what is
    on disk.
    """
    branch = _storage_branch_source()

    # The fail-closed default is expressed as "anything that is not none/full",
    # so the only literal that may enable raw retention is "full".
    assert 'elif mode == "full"' in branch
    assert mode == "full" or mode.lower() != "full"

    # And the else-branch -- which is what every value above reaches -- nulls raw.
    else_half = branch[branch.index("else:"):]
    assert "stored_input_raw        = None" in else_half
    assert "stored_output_raw       = None" in else_half


def test_masked_keeps_only_guard_redacted_text():
    """What masked DOES keep is the guard's sanitized output, not the prompt.

    This is the other half of the corrected sentence: "already redacted
    upstream" is only true while the stored sanitized value comes from the
    guard decision rather than being re-derived here.
    """
    source = (_ROOT / "api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    assert "input_sanit    = gd.sanitized_input" in source, (
        "the sanitized value no longer comes from the guard decision; "
        "masked mode may now be storing something that was never redacted"
    )


# --------------------------------------------------------------------------
# 2. the proxy holds no redactor of its own
# --------------------------------------------------------------------------

def test_proxy_does_not_construct_its_own_redactor():
    """A second redactor in the proxy is either dead or a divergent code path.

    It was dead -- constructed at import and never called, while the real
    redaction happened in the input guard. Left in place it invites a future
    change to "use the one that is already here", which would redact with
    settings the guard never saw.
    """
    source = (_ROOT / "api/v1/endpoints/proxy.py").read_text(encoding="utf-8")
    assert "PIIRedactor" not in source, (
        "proxy.py constructs a PII redactor again; redaction belongs to the "
        "input guard, which is the path the pipeline actually scans through"
    )


# --------------------------------------------------------------------------
# 3. login documents both of its 429s
# --------------------------------------------------------------------------

def test_login_documents_every_429_it_can_return():
    """Login has TWO distinct 429s, and only one was documented.

    ACCOUNT_LOCKED is per address; RATE_LIMIT_EXCEEDED is per IP and fires
    before any database work. A caller that special-cases "429 means this
    account is locked" mishandles the other one -- it would report a lockout to
    a user whose credentials were never checked.
    """
    from api.v1.endpoints.auth import login

    doc = inspect.getdoc(login) or ""
    for code in ("ACCOUNT_LOCKED", "RATE_LIMIT_EXCEEDED"):
        assert code in doc, f"login's docstring omits its {code} response"

    # Both are genuinely 429 in the catalog -- the docstring is not guessing.
    from errors.catalog import ERROR_CATALOG, ErrorCode
    assert ERROR_CATALOG[ErrorCode.ACCOUNT_LOCKED].status_code == 429
    assert ERROR_CATALOG[ErrorCode.RATE_LIMIT_EXCEEDED].status_code == 429


# --------------------------------------------------------------------------
# 4. Principal.permissions is enforced, whatever the comment says
# --------------------------------------------------------------------------

def test_permissions_are_load_bearing_not_scaffolding():
    """`require_permission` refuses on a missing permission, at real routes.

    The field carried "v2+ use only, not enforced in v1" while eight endpoints
    depended on it. Under that comment, narrowing ROLE_PERMISSIONS looks
    consequence-free; it actually closes routes, and widening it opens them.
    """
    from api.v1.dependencies.auth import require_permission

    guard_source = inspect.getsource(require_permission)
    assert "has_permission" in guard_source
    assert "ForbiddenError" in guard_source, (
        "require_permission no longer refuses; if permissions became advisory, "
        "the Principal.permissions comment must change with it"
    )

    # And it is actually mounted, not merely defined.
    mounted = 0
    for path in (_ROOT / "api").rglob("*.py"):
        if path.name == "auth.py" and path.parent.name == "dependencies":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "require_permission"):
                mounted += 1
    assert mounted > 0, (
        "no endpoint uses require_permission; the permissions field would then "
        "genuinely be unenforced and its comment should say so"
    )


# --------------------------------------------------------------------------
# 5. output scanning is PII-only (docs/api.md states this as a capability limit)
# --------------------------------------------------------------------------

def test_output_guard_runs_pii_engines_only():
    """The output path must not acquire a detection layer without the doc saying so.

    docs/api.md tells integrators that a model response is never scored for
    prompt injection, jailbreak content, or toxicity, and that no setting
    widens that. The statement is only true while the output guard consults the
    PII engines alone.

    If a layer is added here, that paragraph becomes a false assurance about a
    security control -- the failure this whole file exists to prevent -- so the
    doc has to move with the code.
    """
    source = (_ROOT / "engine/guardrails/output_guard.py").read_text(encoding="utf-8").lower()

    # Compared case-insensitively: a new layer arrives as a class name
    # (ToxicityScorer) as readily as a module path (guardrails.toxicity), and a
    # guard that only caught one spelling would wave the other through.
    for absent in ("ruledetector", "mldetector", "transformerdetector",
                   "llmdetector", "toxicity"):
        assert absent not in source, (
            f"output_guard.py now references {absent}; output scanning is no longer "
            f"PII-only and the capability-limit paragraph in docs/api.md is wrong"
        )

    # And the toxicity guardrail is reached from the input path only.
    gateway = (_ROOT / "services/gateway/service.py").read_text(encoding="utf-8")
    assert gateway.count("inspect_toxicity") == 1, (
        "inspect_toxicity is called more than once; if it now runs on the output "
        "path, docs/api.md must stop claiming toxicity is input-only"
    )


def test_documented_output_reasons_are_the_ones_the_guard_emits():
    """The four reason codes named in docs/api.md are exactly what it can return.

    Documenting a code the guard cannot emit, or omitting one it can, both
    mislead a caller branching on `output_primary_reason`.
    """
    import re

    source    = (_ROOT / "engine/guardrails/output_guard.py").read_text(encoding="utf-8")
    emitted   = set(re.findall(r'primary_reason\s*=\s*"([A-Z_]+)"', source))
    documented = {"PII_GUARDRAIL_SANITIZE", "PII_GUARDRAIL_BLOCK",
                  "NO_THREAT_DETECTED", "SYSTEM_ERROR"}

    assert emitted == documented, (
        f"output guard emits {sorted(emitted)} but docs/api.md documents "
        f"{sorted(documented)}"
    )


# --------------------------------------------------------------------------
# 8. the gateway's tool definitions are a startup snapshot, not a live read
# --------------------------------------------------------------------------

def test_the_gateway_does_not_re_read_downstream_definitions_when_listing():
    """The documentation claims a snapshot; this asserts the wiring is one.

    The gateway documents that downstream definitions are read once at connect
    and that a later `tools/list` re-publishes the snapshot rather than
    re-reading the server. That is a SECURITY claim -- it is why a downstream
    server cannot swap a published definition after the fact -- so it is fenced
    rather than trusted.

    It also guards the other direction. The change-detection path compares
    fingerprints, and the docs say plainly that it cannot fire with this wiring.
    If someone adds a downstream re-read, that statement becomes false and this
    test fails, which is the prompt to correct the documentation rather than
    leave it describing the old shape.
    """
    import textwrap

    from mcp_gateway.proxy import Gateway

    tree = ast.parse(textwrap.dedent(inspect.getsource(Gateway.on_list_tools)))

    reads = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "list_tools"
    ]
    assert not reads, (
        "on_list_tools now reads downstream tools. That makes the definition "
        "snapshot documented in docs/mcp_gateway.md untrue, and it re-opens the "
        "window where a downstream server can replace an already-published "
        "definition. Update the documentation deliberately if this is intended."
    )


def test_downstream_definitions_are_read_exactly_once_at_connect():
    """The snapshot is taken, and taken in the startup path."""
    from mcp_gateway.proxy import Gateway

    source = inspect.getsource(Gateway.connect_all)
    assert "list_tools" in source, (
        "connect_all no longer reads downstream tools; the snapshot the docs "
        "describe is not being taken where they say it is"
    )


# --------------------------------------------------------------------------
# 9. the documented trust vocabulary is the one the settings actually ship
# --------------------------------------------------------------------------
#
# `docs/api.md` spells the trusted / untrusted source lists out by hand in its
# settings table. That copy drifted: `agent_tool_call` was added to the shipped
# default and the row still listed three values, so the table said an agent's
# tool arguments get base posture while the code tightened them.
#
# The same vocabulary is hand-spelled in the Node SDK and the dashboard, and
# those copies are fenced against the enum by their own test. This is the
# remaining copy. It is compared against `get_settings()` rather than against a
# literal here: a test that restates the list is a third copy, and would pass
# on exactly the drift it is meant to catch.

_SOURCE_ROW = re.compile(
    r'^\|\s*`(TRUSTED_INPUT_SOURCES|UNTRUSTED_INPUT_SOURCES)`\s*\|\s*`\[([^\]]*)\]`',
    re.MULTILINE,
)


def _documented_source_lists() -> dict[str, list[str]]:
    text = (_ROOT / "docs/api.md").read_text(encoding="utf-8")
    found = {
        name: [v.strip().strip('"\'') for v in body.split(",") if v.strip()]
        for name, body in _SOURCE_ROW.findall(text)
    }
    assert set(found) == {"TRUSTED_INPUT_SOURCES", "UNTRUSTED_INPUT_SOURCES"}, (
        "the settings table in docs/api.md no longer carries both source rows in "
        "the expected shape; update this fence rather than deleting it"
    )
    return found


@pytest.mark.parametrize(
    "row,attribute",
    [
        ("TRUSTED_INPUT_SOURCES",   "trusted_input_sources"),
        ("UNTRUSTED_INPUT_SOURCES", "untrusted_input_sources"),
    ],
)
def test_documented_source_lists_match_the_shipped_defaults(row, attribute):
    from config.settings import get_settings

    documented = _documented_source_lists()[row]
    shipped    = list(getattr(get_settings(), attribute))

    assert documented == shipped, (
        f"docs/api.md documents {row} as {documented} but the shipped default is "
        f"{shipped}. A reader tuning trust posture from the table would classify "
        f"a source the gateway judges differently."
    )


# --------------------------------------------------------------------------
# 10. the documented audit filter vocabularies are the ones the code produces
# --------------------------------------------------------------------------
#
# `GET /v1/audit/logs` is a published operation and its filter table is the only
# statement of what `threat_category` and `primary_reason` accept. Both were
# written as "e.g." examples, so two of the six threat categories a caller can
# actually receive appeared in no document at all.
#
# The filters are not validated, so a value that drifts out of the table does not
# fail loudly -- it returns no rows. That is precisely why the table has to be
# derived from the code rather than maintained by hand.

def _documented_filter_values(param: str) -> set[str]:
    text = (_ROOT / "docs/api.md").read_text(encoding="utf-8")
    row  = re.search(rf'^\|\s*`{param}`\s*\|([^|]*)\|', text, re.MULTILINE)
    assert row, f"the audit filter table no longer has a `{param}` row"
    return set(re.findall(r'`([A-Z][A-Z0-9_]+)`', row.group(1)))


def test_documented_threat_categories_are_the_ones_a_caller_can_receive():
    """BENIGN is deliberately absent: the scorer drops it, so it never reaches a
    response and must not be offered as a filter value."""
    from domain.enums import ThreatCategory

    reachable = {c.value for c in ThreatCategory} - {ThreatCategory.BENIGN.value}
    assert _documented_filter_values("threat_category") == reachable


def test_documented_primary_reasons_are_the_ones_the_scorer_returns():
    """Read out of `compute_primary_reason` itself: every literal it returns, plus
    the detector keys it selects the winner from."""
    import ast

    source = (_ROOT / "engine/scoring/primary_reason.py").read_text(encoding="utf-8")
    fn = next(
        n for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.FunctionDef) and n.name == "compute_primary_reason"
    )
    literals = {
        n.value.value for n in ast.walk(fn)
        if isinstance(n, ast.Return)
        and isinstance(n.value, ast.Constant)
        and isinstance(n.value.value, str)
    }
    detectors = {
        k.value for n in ast.walk(fn) if isinstance(n, ast.Dict)
        for k in n.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    emitted = literals | detectors
    assert emitted, "compute_primary_reason was rewritten; this fence needs updating"
    assert _documented_filter_values("primary_reason") == emitted


# --------------------------------------------------------------------------
# 11. every error code the catalog can serve is written down
# --------------------------------------------------------------------------
#
# The catalog is metadata only -- it holds the status and severity, never the
# text -- so `docs/api.md` is where a caller learns what a code means and what
# provokes it. Five codes had been added to the catalog without ever reaching
# the page, including one a caller can hit by sending `stream: true` to the
# scan endpoint.
#
# Presence, not wording: this asserts a code is documented somewhere, which is
# the part that silently stops being true when a new code is introduced.

def test_every_catalog_error_code_is_documented():
    from errors.catalog import ERROR_CATALOG, ErrorCode

    documented = (_ROOT / "docs/api.md").read_text(encoding="utf-8")
    servable   = {c for c in ErrorCode if c in ERROR_CATALOG}
    assert servable, "the catalog map was restructured; update this fence"

    missing = sorted(c.value for c in servable if f"`{c.value}`" not in documented)
    assert not missing, (
        f"these error codes can be returned but appear in no documentation: "
        f"{missing}. A caller cannot handle a code it has never been told about."
    )


# --------------------------------------------------------------------------
# 12. the documented notification catalogue matches what is actually sent
# --------------------------------------------------------------------------
#
# Three of the nine notification types are reserved: nothing emits them and no
# template exists. The documentation lists the six that are sent and names the
# three as reserved, so a reader does not build against a type that will never
# arrive.
#
# "Emitted" is established from the templates on disk rather than from a list,
# because a type cannot be sent without one -- that is the property that would
# quietly change if a reserved type were wired up, or a live one dropped.

_RESERVED_TYPES = {"user.invited", "api_key.created", "api_key.revoked"}


def _types_with_templates() -> set[str]:
    templates = _ROOT / "services/email/templates/en"
    assert templates.is_dir(), "the english template directory moved; update this fence"
    return {p.stem for p in templates.glob("*.html")}


def test_every_notification_type_is_either_sent_or_documented_as_reserved():
    from domain.enums import NotificationType

    declared = {t.value for t in NotificationType}
    sent     = _types_with_templates()

    assert sent <= declared, f"templates exist for undeclared types: {sorted(sent - declared)}"
    assert declared - sent == _RESERVED_TYPES, (
        f"the reserved set changed: types without a template are "
        f"{sorted(declared - sent)}, the documentation names {sorted(_RESERVED_TYPES)}"
    )


def test_the_documented_types_are_the_ones_with_templates():
    documented = (_ROOT / "docs/api.md").read_text(encoding="utf-8")
    for value in sorted(_types_with_templates()):
        assert f"`{value}`" in documented, (
            f"`{value}` is sent to real recipients but appears in no documentation"
        )
    for value in sorted(_RESERVED_TYPES):
        assert f"`{value}`" in documented, (
            f"`{value}` is reserved and must be named as such, so nobody builds against it"
        )


def test_the_documented_delivery_states_are_exactly_the_shipped_ones():
    """`delivered` and `bounced` must not appear as available states: SMTP
    acceptance is the last observable event, so neither could be reached
    honestly. Reads the status table itself rather than searching the page, so
    prose that explains their absence does not satisfy the check."""
    from domain.enums import EmailStatus

    text = (_ROOT / "docs/api.md").read_text(encoding="utf-8")
    table = re.search(
        r"\*\*Delivery states:\*\*\n\n\| Status \| Meaning \|\n\|[-| ]+\|\n((?:\|.*\n)+)",
        text,
    )
    assert table, "the delivery-state table moved; update this fence"

    listed = set(re.findall(r"^\|\s*`([a-z_]+)`\s*\|", table.group(1), re.MULTILINE))
    assert listed == {s.value for s in EmailStatus}, (
        f"the documented delivery states {sorted(listed)} are not the shipped ones "
        f"{sorted(s.value for s in EmailStatus)}"
    )


# --------------------------------------------------------------------------
# 13. the documented environment variables exist, and say the right default
# --------------------------------------------------------------------------
#
# Settings are read by pydantic from the UPPERCASED FIELD NAME, and an env var
# that matches no field is silently ignored -- no warning, no error. Five
# documented names were in that state, including the token-lifetime and lockout
# knobs an operator reaches for when hardening a deployment: setting them did
# nothing and looked like it had worked.
#
# The default check is the same fence from the other side. It caught two rows
# whose value had been inferred rather than read.

_ENV_TABLE_START = "## Key Environment Variables"
_ENV_TABLE_END   = "### Tuning `BATCH_CONCURRENCY`"


def _documented_env_rows() -> list[tuple[str, str]]:
    text = (_ROOT / "docs/developer_guide.md").read_text(encoding="utf-8")
    start, end = text.index(_ENV_TABLE_START), text.index(_ENV_TABLE_END)
    rows = re.findall(r'^\|\s*`([A-Z][A-Z0-9_]+)`\s*\|\s*([^|]*)\|', text[start:end], re.MULTILINE)
    assert rows, "the environment variable table moved; update this fence"
    return rows


def test_every_documented_environment_variable_exists():
    from config.settings import Settings

    unknown = sorted(n for n, _ in _documented_env_rows() if n.lower() not in Settings.model_fields)
    assert not unknown, (
        f"these variables are documented but match no settings field, so setting "
        f"them has no effect and fails silently: {unknown}"
    )


def test_documented_defaults_match_the_shipped_defaults():
    """Only cells that state a bare literal are compared -- a cell carrying prose
    (a required value shown as `-`, or an explanation) is not a claim about a
    default and is left alone."""
    from config.settings import Settings

    def normalise(value: str) -> str:
        value = value.strip().strip('`" ')
        if value.lower() in ("true", "false"):
            return value.lower()
        number = float(value)
        return str(int(number)) if number == int(number) else str(number)

    wrong = []
    for name, cell in _documented_env_rows():
        field = Settings.model_fields.get(name.lower())
        if field is None or field.default is None:
            continue
        if not re.fullmatch(r'\s*`[^`]+`\s*', cell):
            continue                       # prose, not a default claim
        try:
            documented = normalise(cell)
        except ValueError:
            continue                       # a non-numeric literal, e.g. `masked`
        shipped = str(field.default)
        try:
            shipped = normalise(shipped)
        except ValueError:
            continue
        if documented != shipped:
            wrong.append(f"{name}: documented {documented}, ships {shipped}")

    assert not wrong, "documented defaults disagree with the code: " + "; ".join(wrong)


# --------------------------------------------------------------------------
# 14. the proxy body limit stays under what the regex tiers will read
# --------------------------------------------------------------------------
#
# Nothing in the application bounds the length of one proxy message. The rule
# detector and the PII guardrail read a bounded prefix and drop the rest, which
# is a deliberate ReDoS defence -- so what keeps a message from arriving longer
# than they will read is the reverse proxy's body limit, and nothing else.
#
# While the body limit is the smaller of the two, a message that would be
# truncated cannot reach the handler at all. Raise it above the clamp and the
# regex tiers begin covering only the opening of a long message, silently. This
# holds the ordering across the two files.

_SIZE_SUFFIX = {"k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}


def _nginx_body_limits() -> dict[str, int]:
    found: dict[str, int] = {}
    for conf in sorted((_ROOT / "infrastructure/nginx").rglob("*")):
        if not conf.is_file():
            continue
        for raw in re.findall(
            r'client_max_body_size\s+(\d+)([kKmMgG]?)\s*;', conf.read_text(encoding="utf-8")
        ):
            value = int(raw[0]) * _SIZE_SUFFIX.get(raw[1].lower(), 1)
            found[str(conf.relative_to(_ROOT))] = value
    assert found, "no client_max_body_size found; the nginx configuration moved"
    return found


def test_the_body_limit_stays_under_the_regex_clamp():
    from engine.detection.limits import MAX_REGEX_INPUT_LENGTH

    oversized = {
        conf: size for conf, size in _nginx_body_limits().items()
        if size > MAX_REGEX_INPUT_LENGTH
    }
    assert not oversized, (
        f"these configurations accept a request body larger than the "
        f"{MAX_REGEX_INPUT_LENGTH} characters the rule and PII detectors will read, "
        f"so a long message would be scanned only in part and nothing would say so: "
        f"{oversized}. Raising the limit is a detection decision, not only a "
        f"capacity one -- widen the clamp, scan in windows, or bound message "
        f"length in the application."
    )


# --------------------------------------------------------------------------
# 15. every variable in .env.example reaches something
# --------------------------------------------------------------------------
#
# `.env.example` is the file the README tells an operator to copy, so a name in
# it reads as a supported control. Pydantic binds on the uppercased FIELD NAME
# and ignores anything else without a word, so a name that matches no field is
# inert and looks exactly like one that works.
#
# `JWT_EXPIRY_MINS=60` sat in the Security block in that state, next to
# SECRET_KEY, while the variable that does set the token lifetime was absent from
# the file entirely. The fence over the developer guide's table did not cover
# this file, which is why it drifted on unnoticed.
#
# Some entries here are legitimately not settings: they configure the compose
# stack, nginx, the dashboard, or the collector sidecar. Each is listed
# individually with where it is consumed, so an exemption is a deliberate entry
# rather than a pattern that quietly swallows the next mistake.

_ENV_EXAMPLE_NON_SETTINGS = {
    # dashboard (Next.js reads it directly; compose passes it through)
    "DASHBOARD_ORIGIN",
    # collector sidecar, named by the OpenTelemetry protocol exporter spec
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_INSECURE",
    # compose services, not the application
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "GRAFANA_PASSWORD",
    # nginx template and setup.sh
    "SSL_CERT_PATH",
    "SSL_KEY_PATH",
    "DOMAIN",
}


def test_every_variable_in_the_example_env_reaches_something():
    from config.settings import Settings

    text  = (_ROOT / ".env.example").read_text(encoding="utf-8")
    named = set(re.findall(r'^\s*#?\s*([A-Z][A-Z0-9_]{2,})\s*=', text, re.MULTILINE))
    assert named, "the example env file moved or changed shape; update this fence"

    fields  = set(Settings.model_fields)
    orphans = sorted(n for n in named
                     if n.lower() not in fields and n not in _ENV_EXAMPLE_NON_SETTINGS)

    assert not orphans, (
        f"these variables appear in .env.example but bind to no settings field and "
        f"are not listed as belonging to another component: {orphans}. An operator "
        f"copying the file would set them and see no effect and no error. Either "
        f"correct the name or record where it IS consumed."
    )


def test_the_example_env_exemptions_are_all_still_present():
    """An exemption that no longer appears is a stale allowance, and the next
    mistake could land on that name and pass."""
    text  = (_ROOT / ".env.example").read_text(encoding="utf-8")
    named = set(re.findall(r'^\s*#?\s*([A-Z][A-Z0-9_]{2,})\s*=', text, re.MULTILINE))

    stale = sorted(_ENV_EXAMPLE_NON_SETTINGS - named)
    assert not stale, (
        f"these names are exempted from the settings check but no longer appear in "
        f".env.example: {stale}. Drop them from the exemption list."
    )


# --------------------------------------------------------------------------
# 16. the documented retry budget is the one the client actually spends
# --------------------------------------------------------------------------
#
# The CLI reference told operators that a failing request is "retried up to 3
# times with exponential backoff". Neither half held: the schedule is three
# ATTEMPTS, so two retries, and its delays are 0, 1 and 2 seconds, which is not
# exponential. Someone sizing a caller-side timeout against that sentence would
# have budgeted for roughly twice the wait that actually occurs.

def test_the_documented_retry_budget_matches_the_schedule():
    import sys
    sdk = _ROOT / "sdk/python"
    if str(sdk) not in sys.path:
        sys.path.insert(0, str(sdk))
    from wrapsec.core.retry import BACKOFF_SCHEDULE, MAX_ATTEMPTS

    doc = (_ROOT / "docs/cli_reference.md").read_text(encoding="utf-8")

    assert MAX_ATTEMPTS == len(BACKOFF_SCHEDULE)
    assert f"**{MAX_ATTEMPTS} times**" in doc, (
        f"the reference does not state the real attempt count of {MAX_ATTEMPTS}"
    )

    total = int(sum(BACKOFF_SCHEDULE))
    assert f"{total} seconds of waiting" in doc, (
        f"the schedule {BACKOFF_SCHEDULE} adds {total}s of delay; the reference "
        f"states something else, so a reader sizing a timeout would be misled"
    )
    assert "exponential" not in doc.lower(), (
        f"the reference calls the backoff exponential, but the schedule is "
        f"{BACKOFF_SCHEDULE}"
    )


# --------------------------------------------------------------------------
# 17. the documented plugin-name constraint is the one enforced
# --------------------------------------------------------------------------
#
# The name becomes an Alembic version table identifier, so it is validated. A
# Python distribution is conventionally hyphenated, which makes the natural value
# to pass the one that raises, and the convention document did not say so.

def test_the_documented_plugin_name_pattern_is_the_enforced_one():
    from db.plugin_migrations import _SAFE_NAME

    doc = (_ROOT / "docs/plugin_migrations.md").read_text(encoding="utf-8")
    body = _SAFE_NAME.pattern.strip("^$")
    assert f"`{body}`" in doc, (
        f"the convention document does not state the enforced pattern {body!r}, so "
        f"an author would meet it as a ValueError instead"
    )


# --------------------------------------------------------------------------
# 18. the published detection gates are the ones the harness enforces
# --------------------------------------------------------------------------
#
# `results.md` 2.1 publishes four bounds and `tests/eval/test_redteam.py` defines
# them. Nothing held the two together, so a threshold could be loosened in the
# harness while the record kept advertising the stricter one -- and a detection
# gate is exactly the number someone quotes without re-deriving it.
#
# The bounds are deliberately set one regressing case outside the measured
# baseline, so a change of a few points is not cosmetic: it is the difference
# between tripping on the second new failure and tripping on the fifth.

_GATE_DOC = _ROOT / "docs/internal/results.md"


def _documented_gates() -> dict[str, float]:
    """The percentages from the gate table in 2.1, as fractions."""
    if not _GATE_DOC.exists():
        pytest.skip("results.md is not present in this checkout")
    text = _GATE_DOC.read_text(encoding="utf-8")
    rows = re.findall(r'^\|\s*([^|]+?)\s*\|\s*([<>]=)\s*(\d+)%\s*\|', text, re.MULTILINE)
    assert rows, "the gate table in results.md 2.1 moved; update this fence"
    return {name.strip(): int(pct) / 100 for name, _, pct in rows}


def test_the_published_detection_gates_match_the_harness():
    import ast

    source = (_ROOT / "tests/eval/test_redteam.py").read_text(encoding="utf-8")
    consts = {
        t.targets[0].id: t.value.value
        for t in ast.parse(source).body
        if isinstance(t, ast.Assign)
        and isinstance(t.targets[0], ast.Name)
        and isinstance(t.value, ast.Constant)
        and isinstance(t.value.value, (int, float))
    }
    for name in ("CATCH_FLOOR", "FPR_CEILING", "BENIGN_HARD_CEILING", "OOD_FLOOR"):
        assert name in consts, f"{name} is no longer a module-level constant"

    documented = _documented_gates()
    pairs = {
        "catch-rate (TPR)":          consts["CATCH_FLOOR"],
        "false-positive rate":       consts["FPR_CEILING"],
        "benign-hard over-defense":  consts["BENIGN_HARD_CEILING"],
        "OOD catch":                 consts["OOD_FLOOR"],
    }
    for label, enforced in pairs.items():
        assert label in documented, f"the gate table no longer has a row for {label!r}"
        assert abs(documented[label] - enforced) < 1e-9, (
            f"{label}: the record publishes {documented[label]:.0%} but the harness "
            f"enforces {enforced:.0%}. A gate that is quoted from the record and "
            f"enforced from the module must not be two different numbers."
        )
