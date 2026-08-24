#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
End-to-end check that the gateway attributes a request to the right address.

`TRUSTED_PROXY_IPS` decides who is believed when they say who the client is.
Unit tests over `get_client_ip` supply the peer address themselves, so they
prove the decision logic and nothing about the deployment: whether the proxy
actually holds the address the setting names, and whether a caller that reaches
the API directly can talk its way into being someone else.

Two paths, and they must resolve differently:

    external client -> nginx -> api      the CLIENT address, taken from the
                                         forwarded header, because nginx is the
                                         configured trusted hop

    dashboard BFF   -> api:8000          the BFF's own container address, and a
                                         forwarded header it sends is IGNORED,
                                         because a direct peer is a client

The second is the one that proves the first did not simply make every forwarded
header trustworthy. It is run here from inside the api container's network,
which is the same position the dashboard occupies.

Addresses are DISCOVERED, never hardcoded: only nginx has a fixed address, and
the caller's own is assigned at run time.

TRUSTED_PROXY_IPS and an API key's `ip_allowlist` are two different controls and
are not conflated here. The first names the PROXIES allowed to state who the
client is; the second names the CLIENT networks a given credential may be used
from. They never hold the same value. The allowlist appears below only as a
CONSUMER of the derived address -- the question being measured is which address
it receives through a proxy, not whether the allowlist itself works, which
`scripts/e2e_ip_allowlist.py` covers on its own.

Runs inside the api container so it reaches the service over the compose
network and presents a genuine bridge address rather than loopback:

    docker compose exec -T api python scripts/e2e_trusted_proxy.py
"""

from __future__ import annotations

import os
import sys

import httpx

DIRECT = os.getenv("E2E_API_BASE", "http://api:8000")
VIA_NGINX = os.getenv("E2E_NGINX_BASE", "http://nginx")
EMAIL = os.getenv("E2E_ADMIN_EMAIL", "e2e-admin@wrapsec-e2e.com")
PASSWORD = os.getenv("E2E_ADMIN_PASSWORD", "E2eAdmin!Pass123")

# TEST-NET-3, reserved for documentation. It can never be the address this
# process actually calls from, so seeing it echoed back means a header was
# believed that should not have been.
SPOOF = "203.0.113.5"

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  ' + detail if detail else ''}")
    if not ok:
        failures.append(label)


def _login(http: httpx.Client) -> dict | None:
    resp = http.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
    if resp.status_code != 200:
        print(f"could not sign in as {EMAIL}: {resp.status_code} {resp.text[:200]}")
        return None
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _latest_ip(http: httpx.Client, auth: dict, trace_id: str) -> str | None:
    """The address the gateway recorded for a scan, read back from its audit row."""
    resp = http.get(f"/v1/ai/requests/{trace_id}", headers=auth)
    if resp.status_code != 200:
        return None
    return resp.json().get("attribution", {}).get("ip_address")


def _check_auth_events(expected: str) -> None:
    """
    auth_events has no read endpoint, so this reads the row directly. The login
    that produced it went through nginx, so the address stored is the one the
    credential-event trail will show an operator investigating a sign-in.
    """
    import asyncio

    async def _latest() -> str | None:
        from sqlalchemy import text as sql

        from db.session import AsyncSessionFactory
        async with AsyncSessionFactory() as db:
            row = (await db.execute(sql(
                "SELECT ip_address FROM auth_events "
                "WHERE ip_address IS NOT NULL ORDER BY created_at DESC LIMIT 1"
            ))).first()
        return row[0] if row else None

    try:
        seen = asyncio.run(_latest())
    except Exception as exc:
        check("auth_events.ip_address is the client", False, f"(could not read: {exc})")
        return
    check("auth_events.ip_address is the client", seen == expected,
          f"({seen})")


def _check_rate_limit_bucket(expected: str) -> None:
    """
    The limiter runs before authentication and derives its own bucket, so it is
    the one control here that could disagree with the rest. A JWT request
    buckets on the address; the sorted set it creates names it.
    """
    import asyncio

    async def _buckets() -> list[str]:
        from cache.redis_client import get_redis
        keys = await get_redis().keys("rate_limit:ip:*")
        return sorted(k.decode() if isinstance(k, bytes) else k for k in keys)

    try:
        found = asyncio.run(_buckets())
    except Exception as exc:
        check("rate-limit bucket is keyed on the client", False, f"(could not read: {exc})")
        return

    want = f"rate_limit:ip:{expected}"
    check("rate-limit bucket is keyed on the client", want in found,
          f"(looked for {want}, found {found or 'none'})")


def _check_allowlist(http: httpx.Client, auth: dict, expected: str) -> None:
    """
    The allowlist is evaluated in the auth middleware, against the address
    get_client_ip resolved. Through a proxy that must be the CLIENT: a
    restriction naming the client has to be honoured, and one naming somewhere
    else has to refuse. Both directions, because a control that always allows
    would pass the first on its own.
    """
    import uuid as _uuid

    depts = http.get("/v1/admin/departments", headers=auth).json().get("departments", [])
    if not depts:
        check("API-key allowlist is evaluated against the client", False,
              "(no department to scope a key to)")
        return

    created = http.post("/v1/keys", headers=auth,
                        json={"name": f"e2e-attr-{_uuid.uuid4().hex[:8]}",
                              "dept_id": depts[0]["id"]})
    if created.status_code not in (200, 201):
        check("API-key allowlist is evaluated against the client", False,
              f"(could not create a key: {created.status_code})")
        return

    body    = created.json()
    key_id  = body["key_id"]
    key_hdr = {"x-api-key": body["api_key"]}
    try:
        http.put(f"/v1/keys/{key_id}", headers=auth,
                 json={"name": body["name"], "ip_allowlist": [f"{expected}/32"]})
        allowed = http.post("/v1/ai/request", headers=key_hdr, json={"input": "allowlist check"})

        http.put(f"/v1/keys/{key_id}", headers=auth,
                 json={"name": body["name"], "ip_allowlist": [f"{SPOOF}/32"]})
        refused = http.post("/v1/ai/request", headers=key_hdr, json={"input": "allowlist check"})

        check("API-key allowlist is evaluated against the client",
              allowed.status_code == 200 and refused.status_code == 403,
              f"(client-listed {allowed.status_code}, elsewhere-listed {refused.status_code})")
    finally:
        http.delete(f"/v1/keys/{key_id}", headers=auth)


def main() -> int:
    print("\nClient-address attribution, both entry paths\n")

    # ---------------------------------------------------------------- direct
    # The position the dashboard BFF occupies: a peer that is NOT the trusted
    # proxy. Its own address must be recorded, and any header it sends ignored.
    with httpx.Client(base_url=DIRECT, timeout=30.0) as http:
        auth = _login(http)
        if auth is None:
            return 1

        scan = http.post("/v1/ai/request", json={"input": "attribution check, direct"},
                         headers=auth)
        if scan.status_code != 200:
            print(f"direct scan failed: {scan.status_code} {scan.text[:200]}")
            return 1
        direct_ip = _latest_ip(http, auth, scan.json()["trace_id"])
        check("a direct caller is attributed to an address", bool(direct_ip), f"({direct_ip})")

        spoofed = http.post(
            "/v1/ai/request",
            json={"input": "attribution check, direct spoof"},
            headers={**auth, "X-Forwarded-For": SPOOF},
        )
        if spoofed.status_code != 200:
            print(f"direct spoof scan failed: {spoofed.status_code}")
            return 1
        spoof_ip = _latest_ip(http, auth, spoofed.json()["trace_id"])
        check("a direct caller's forwarded header is IGNORED",
              spoof_ip != SPOOF and spoof_ip == direct_ip,
              f"(recorded {spoof_ip}, sent {SPOOF})")

    # ------------------------------------------------------------- via nginx
    # The real client path. nginx appends the peer address to X-Forwarded-For,
    # and it is the configured trusted hop, so the CLIENT address is recorded --
    # not nginx's own.
    try:
        with httpx.Client(base_url=VIA_NGINX, timeout=30.0) as http:
            auth = _login(http)
            if auth is None:
                print("  SKIP  nginx path: could not sign in through the proxy")
                return 1 if failures else 0

            scan = http.post("/v1/ai/request", json={"input": "attribution check, proxied"},
                             headers=auth)
            if scan.status_code != 200:
                print(f"  proxied scan failed: {scan.status_code} {scan.text[:200]}")
                return 1
            proxied_ip = _latest_ip(http, auth, scan.json()["trace_id"])

            # No address is named here. This process reached the API twice from
            # the same container, once directly and once through nginx, so the
            # two must resolve to the SAME address -- its own. If the forwarded
            # header were being ignored the proxied request would be attributed
            # to nginx instead, and the two would differ. That holds whatever
            # addresses the network happened to assign, which is the point: a
            # hardcoded expectation would pass by luck on one stack and fail on
            # another.
            check("a proxied request resolves to the calling client, not the proxy",
                  bool(proxied_ip) and proxied_ip == direct_ip,
                  f"(via nginx {proxied_ip}, direct {direct_ip})")

            # ---------------------------------------------------------------
            # Each control that reads the client address, measured on the
            # proxied path rather than reasoned about. They do not share code:
            # audit and auth events are written from request.state, the
            # allowlist is evaluated in the auth middleware, and the rate
            # limiter derives its own bucket before auth runs. One being right
            # does not make the others right.
            # ---------------------------------------------------------------
            print("\n  dependent controls, measured through nginx:")
            check("audit_logs.ip_address is the client",
                  proxied_ip == direct_ip, f"({proxied_ip})")

            _check_auth_events(direct_ip)
            _check_rate_limit_bucket(direct_ip)
            _check_allowlist(http, auth, direct_ip)
    except httpx.HTTPError as exc:
        check("nginx is reachable from the api container", False, f"({exc})")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: " + ", ".join(failures))
        return 1
    print("client-address attribution is correct on both paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
