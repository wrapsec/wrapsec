# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
The audit read-back routes' response models are applied by the runtime.

`GET /v1/audit/logs` and `GET /v1/audit/stats` both used to answer with a
constructed `JSONResponse`, which OpenAPI cannot detect and which skips the model
entirely. These tests run over real HTTP and fail if either goes back.

The instrument differs per route, because their bodies are built differently:

  * logs -- `_format_item` is wrapped to emit a field no model declares. The
    model drops it; a `JSONResponse` serves it;
  * stats (populated) -- an undeclared field is injected INSIDE a `top_threats`
    entry, so the proof covers nested filtering, which is where an aggregate is
    most likely to leak an internal key;
  * stats (empty) -- that branch builds a literal dict, so there is nothing to
    inject into. `to_iso_z` is made to return a non-string instead: the model
    refuses to serve it, a `JSONResponse` would hand the caller an integer where
    the contract says timestamp. Each of the three success returns therefore has
    its own detector, which is what makes a per-return mutation meaningful.

ON SCORES. This projection has none. `_format_item` carries no
`detection_scores`, no `guardrail_scores` and no `assessment`, so unlike the scan
response there is nothing here to restrict and the authorized and restricted
callers receive identical field sets. That is asserted rather than assumed, since
"no restriction" is only safe while there is nothing to restrict.
"""

import uuid

import pytest

_LEAK = "undeclared_internal_field"

_NO_DIGITS = str.maketrans("0123456789", "ghijklmnop")


def _unique() -> str:
    return uuid.uuid4().hex.translate(_NO_DIGITS)


@pytest.fixture
def leaky_format_item(monkeypatch):
    """Emit a field no model declares, from the helper that builds each item.

    Patched on the audit module itself -- that is where `get_audit_logs` resolves
    the name at call time.
    """
    from api.v1.endpoints import audit

    original = audit._format_item

    def _leaky(*args, **kwargs):
        item = original(*args, **kwargs)
        item[_LEAK] = "must not reach the caller"
        return item

    monkeypatch.setattr(audit, "_format_item", _leaky)
    return _leaky


async def _record(client, headers, count: int = 2):
    for _ in range(count):
        r = await client.post("/v1/ai/request", headers=headers,
                              json={"input": f"audit contract probe {_unique()}"})
        assert r.status_code == 200, r.text


# ── GET /v1/audit/logs ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_logs_drops_an_undeclared_field(client, scored_key_pair, leaky_format_item):
    live, _ = scored_key_pair
    await _record(client, live)

    r = await client.get("/v1/audit/logs?limit=5", headers=live)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["items"], "no rows came back, so nothing was filtered"
    for item in body["items"]:
        assert _LEAK not in item, (
            "an undeclared field reached the caller: the response model is not "
            "being applied, so the success path is returning a Response object"
        )
    assert set(body) == {"total", "items"}, f"unexpected envelope keys: {sorted(body)}"


@pytest.mark.asyncio
async def test_logs_empty_result_keeps_the_same_envelope(client, scored_key_pair):
    """No match is `total: 0` with an empty list, never a 404, and the envelope
    is the one a populated page uses."""
    live, _ = scored_key_pair

    r = await client.get(f"/v1/audit/logs?trace_id=req_{_unique()}", headers=live)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"total", "items"}
    assert body["total"] == 0 and body["items"] == []


@pytest.mark.asyncio
async def test_logs_serves_the_same_fields_to_both_caller_classes(client, scored_key_pair):
    """There is no caller-dependent field in this projection. Asserted, because
    "nothing to restrict" is a claim about the projection, not a permission."""
    live, trial = scored_key_pair
    await _record(client, live)

    authorized = await client.get("/v1/audit/logs?limit=5", headers=live)
    restricted = await client.get("/v1/audit/logs?limit=5", headers=trial)
    assert authorized.status_code == 200 and restricted.status_code == 200

    a_items, r_items = authorized.json()["items"], restricted.json()["items"]
    assert a_items and r_items, "both callers need rows for this comparison"
    assert set(a_items[0]) == set(r_items[0]), (
        "the two caller classes received different field sets from a projection "
        "that carries no restricted field"
    )
    for item in a_items + r_items:
        for field in ("detection_scores", "guardrail_scores", "assessment"):
            assert field not in item, (
                f"{field} appeared in an audit item; this projection is not "
                "supposed to carry per-layer scores at all"
            )


@pytest.mark.asyncio
async def test_logs_keeps_null_fields_present(client, scored_key_pair):
    """`exclude_unset` must not drop a key the writer set to None."""
    live, _ = scored_key_pair
    await _record(client, live, count=1)

    r = await client.get("/v1/audit/logs?limit=1", headers=live)
    assert r.status_code == 200, r.text
    item = r.json()["items"][0]

    for field in ("app_id", "app_name", "user_id", "output_decision", "provider", "model"):
        assert field in item, f"{field} was dropped instead of being null"
        assert item[field] is None, f"{field} was expected null, got {item[field]!r}"
    for field in ("trace_id", "decision", "risk_score", "severity", "input_source"):
        assert field in item and item[field] is not None


@pytest.mark.asyncio
async def test_logs_item_matches_the_declared_projection(client, scored_key_pair):
    from api.v1.schemas.response import AuditItem

    live, _ = scored_key_pair
    await _record(client, live, count=1)

    r = await client.get("/v1/audit/logs?limit=1", headers=live)
    assert r.status_code == 200, r.text
    assert set(r.json()["items"][0]) == set(AuditItem.model_fields), (
        "the served item and the declared model disagree about the field set"
    )


@pytest.mark.asyncio
async def test_logs_rejects_an_out_of_range_limit_with_the_catalog_envelope(
    client, scored_key_pair,
):
    live, _ = scored_key_pair

    r = await client.get("/v1/audit/logs?limit=0", headers=live)

    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert r.json()["error"]["invalid_params"][0]["field"] == "limit"


# ── GET /v1/audit/stats ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_drops_an_undeclared_field_inside_top_threats(
    client, scored_key_pair, monkeypatch,
):
    """The populated branch, proven through a nested object."""
    from db.repositories.audit import AuditRepository

    live, _ = scored_key_pair
    await _record(client, live)

    original = AuditRepository.get_stats

    async def _leaky(self, **kwargs):
        stats = await original(self, **kwargs)
        stats["top_threats"] = [{"category": "PROMPT_INJECTION", "count": 1, _LEAK: "leak"}]
        return stats

    monkeypatch.setattr(AuditRepository, "get_stats", _leaky)

    r = await client.get("/v1/audit/stats", headers=live)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["top_threats"], "the injected threat entry did not survive to the response"
    assert _LEAK not in body["top_threats"][0], (
        "an undeclared field reached the caller inside top_threats; the stats "
        "success path is not passing through the response model"
    )
    assert body["top_threats"][0]["category"] == "PROMPT_INJECTION"


@pytest.mark.asyncio
async def test_stats_empty_branch_will_not_serve_a_wrong_type(
    client, scored_key_pair, monkeypatch,
):
    """The zero branch builds a literal dict, so there is nothing to inject. Its
    timestamps come from `to_iso_z`; make that return an integer and the model
    must refuse rather than serve it."""
    from fastapi.exceptions import ResponseValidationError

    from api.v1.endpoints import audit
    from db.repositories.audit import AuditRepository

    live, _ = scored_key_pair

    original = AuditRepository.get_stats

    async def _empty(self, **kwargs):
        stats = await original(self, **kwargs)
        stats["total"] = 0
        return stats

    monkeypatch.setattr(AuditRepository, "get_stats", _empty)
    monkeypatch.setattr(audit, "to_iso_z", lambda *_a, **_k: 12345)

    try:
        r = await client.get("/v1/audit/stats", headers=live)
    except ResponseValidationError as rejected:
        assert "period_from" in str(rejected) or "period_to" in str(rejected)
        return

    assert r.status_code != 200 or "12345" not in r.text, (
        "the zero branch served a value that violates its declared type, so the "
        "response model is not applied to it"
    )


@pytest.mark.asyncio
async def test_stats_empty_branch_keeps_the_full_shape(client, scored_key_pair, monkeypatch):
    """Zeroed, not truncated: every count, rate and severity key is still there,
    so a dashboard renders the same body when nothing matched."""
    from api.v1.schemas.response import AuditStatsResponse
    from db.repositories.audit import AuditRepository

    live, _ = scored_key_pair
    original = AuditRepository.get_stats

    async def _empty(self, **kwargs):
        stats = await original(self, **kwargs)
        stats["total"] = 0
        return stats

    monkeypatch.setattr(AuditRepository, "get_stats", _empty)

    r = await client.get("/v1/audit/stats", headers=live)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == set(AuditStatsResponse.model_fields)
    assert body["total_requests"] == 0 and body["top_threats"] == []
    assert set(body["severity_counts"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert all(v == 0 for v in body["severity_counts"].values())


@pytest.mark.asyncio
async def test_stats_populated_branch_keeps_counts_and_rates(client, scored_key_pair):
    """Counts sit alongside rates deliberately -- deriving one from the other
    drifts against the logs count once the rate is rounded."""
    from api.v1.schemas.response import AuditStatsResponse

    live, _ = scored_key_pair
    await _record(client, live, count=2)

    r = await client.get("/v1/audit/stats", headers=live)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == set(AuditStatsResponse.model_fields)
    assert body["total_requests"] >= 2
    assert isinstance(body["block_rate"], float)
    assert body["block_count"] + body["sanitize_count"] + body["allow_count"] == body["total_requests"]


# ── the writer fallbacks behind the stats model ──────────────────────────────

@pytest.mark.asyncio
async def test_the_stats_writer_never_returns_null_numerics(test_db):
    """Every numeric the stats model declares non-nullable comes from an SQL
    aggregate, and an aggregate over no rows is NULL. The repository's `or 0`
    and `float(... or 0)` fallbacks are what stand between that and a response
    the model would reject, so they are exercised directly against a range that
    matches nothing."""
    from db.repositories.audit import AuditRepository
    from services.time import utc_now

    far_future = utc_now().replace(year=utc_now().year + 5)
    stats = await AuditRepository(test_db).get_stats(
        tenant_id=None, dept_id=None, from_dt=far_future, to_dt=far_future,
        decision=None, threat_category=None, execution_mode=None, trace_id=None,
    )

    assert stats["total"] == 0, "the range was supposed to match nothing"
    for field in ("block_count", "sanitize_count", "allow_count"):
        assert isinstance(stats[field], int), f"{field} came back {stats[field]!r}"
    for field in ("avg_latency_ms", "p95_latency_ms", "avg_risk"):
        assert isinstance(stats[field], float), f"{field} came back {stats[field]!r}"
    assert stats["top_threats"] == [] and stats["severities_map"] == {}


# ── GET /v1/audit/export ─────────────────────────────────────────────────────
#
# This route is NOT converted to a response model: it answers with CSV, and a
# response model describes a JSON body. What was corrected is the ADVERTISEMENT
# -- the published 200 said `application/json` with an empty schema. These tests
# pin the runtime side of that contract, so the declaration and the response
# cannot drift apart: the schema change was made because of what the route
# already did, and these fail if what it does changes.

@pytest.mark.asyncio
async def test_export_still_answers_csv_with_its_attachment_headers(
    client, scored_key_pair,
):
    """The success contract the `text/csv` declaration describes.

    Content type, disposition and the header row are asserted together because
    they are what a caller actually consumes: a downloader keys off the
    disposition, a parser off the media type, and a spreadsheet off the columns.
    """
    live, _ = scored_key_pair
    await _record(client, live, count=1)

    r = await client.get("/v1/audit/export", headers=live)

    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv"), (
        f"export answered {r.headers['content-type']!r}; the published contract says text/csv"
    )
    assert r.headers["content-disposition"] == (
        "attachment; filename=wrapsec_audit_export.csv"
    )

    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert lines[0].split(",")[:4] == ["trace_id", "timestamp", "decision", "risk_score"]
    assert len(lines) >= 2, "no data row was exported, so the body proves nothing"
    assert not r.text.lstrip().startswith("{"), "export returned JSON, not CSV"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("query", "field", "code"),
    [
        ("?limit=0",     "limit",  "OUT_OF_RANGE"),
        ("?limit=99999", "limit",  "OUT_OF_RANGE"),
        ("?offset=-1",   "offset", "OUT_OF_RANGE"),
        ("?limit=abc",   "limit",  "INVALID_TYPE"),
    ],
)
async def test_export_validation_failures_return_the_catalog_envelope(
    client, scored_key_pair, query, field, code,
):
    """A 422 IS reachable here, unlike on the read-back route, so it is measured.

    `limit` and `offset` both carry bounds, and both a bound violation and a type
    violation are covered because they take different paths through the handler's
    classifier and were declared as one entry. The response is JSON even though
    the success body is CSV -- the error comes from the global handler, not from
    this route's writer, which is exactly why the 200 and the 422 advertise
    different media types.
    """
    live, _ = scored_key_pair

    r = await client.get("/v1/audit/export" + query, headers=live)

    assert r.status_code == 422, r.text
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert "detail" not in body, "the generated HTTPValidationError shape is back"
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["invalid_params"][0] == {
        "field": field, "code": code,
        "key": f"forms.errors.{code}", "params": {},
    }


@pytest.mark.asyncio
async def test_export_declares_no_response_model_at_runtime(client, scored_key_pair):
    """The CSV exception is a runtime property, not only a recorded intention.

    `test_non_model_routes_still_declare_no_model` asserts the same thing off the
    route table. This asserts the consequence a caller would see: the body is
    streamed bytes that no model filtered, so a column added to the writer reaches
    the caller rather than being silently dropped. Declaring the response class
    changed the advertised media type and nothing else.
    """
    from fastapi.routing import APIRoute
    from starlette.responses import StreamingResponse

    from api.main import app

    route = next(
        r for r in app.routes
        if isinstance(r, APIRoute) and r.path == "/v1/audit/export"
    )
    assert route.response_model is None, "the CSV route gained a response model"
    assert route.response_class is StreamingResponse, (
        "the response class is what derives the advertised media type; changing it "
        "puts application/json back on the 200"
    )

    live, _ = scored_key_pair
    r = await client.get("/v1/audit/export", headers=live)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
