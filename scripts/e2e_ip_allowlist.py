#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
End-to-end round trip for the source-network restriction.

The unit and integration tests drive this through the app object, where the
client address is whatever the test says it is. That proves the decision logic
and nothing about the plumbing: how the address is derived from a real socket,
whether a real proxy header can override it, and whether a real credential is
actually turned away. This runs the whole thing over HTTP against a running
stack, so a mistake anywhere in that chain fails here.

The address is DISCOVERED, never hardcoded. Container addresses are assigned by
the network at run time, so a fixed value would either pass by luck or fail on
a machine whose subnet differs. The credential is used once with no restriction
and the address it was seen from is read back from the API, which also exercises
the view an operator uses when setting a restriction for real.

Runs inside the api container so it reaches the service over the compose network
and presents a genuine bridge address rather than loopback:

    docker compose exec -T api python scripts/e2e_ip_allowlist.py
"""

from __future__ import annotations

import os
import sys
import uuid

import httpx

BASE     = os.getenv("E2E_API_BASE", "http://api:8000")
EMAIL    = os.getenv("E2E_ADMIN_EMAIL", "e2e-admin@wrapsec-e2e.com")
PASSWORD = os.getenv("E2E_ADMIN_PASSWORD", "E2eAdmin!Pass123")

# TEST-NET-3, reserved for documentation and guaranteed not to be the address
# this process is calling from. Using it as the "wrong" list means the denial
# cannot be an accident of whatever subnet the stack came up on.
NOT_US = "203.0.113.5/32"

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{'  ' + detail if detail else ''}")
    if not ok:
        failures.append(label)


def main() -> int:
    print(f"\nSource-network round trip against {BASE}\n")

    with httpx.Client(base_url=BASE, timeout=30.0) as http:
        # -- sign in -------------------------------------------------------
        resp = http.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
        if resp.status_code != 200:
            print(f"could not sign in as {EMAIL}: {resp.status_code} {resp.text[:200]}")
            return 1
        auth = {"Authorization": f"Bearer {resp.json()['access_token']}"}

        depts = http.get("/v1/admin/departments", headers=auth).json().get("departments", [])
        if not depts:
            print("no department to scope a key to")
            return 1
        dept_id = depts[0]["id"]

        # -- a credential with no restriction ------------------------------
        created = http.post(
            "/v1/keys", headers=auth,
            json={"name": f"e2e-allowlist-{uuid.uuid4().hex[:8]}", "dept_id": dept_id},
        )
        if created.status_code not in (200, 201):
            print(f"could not create a key: {created.status_code} {created.text[:200]}")
            return 1
        key_id  = created.json()["key_id"]
        raw_key = created.json()["api_key"]
        key_hdr = {"x-api-key": raw_key}

        try:
            scan = http.post("/v1/ai/request", headers=key_hdr, json={"input": "hello"})
            check("an unrestricted credential is accepted", scan.status_code == 200,
                  f"({scan.status_code})")

            # -- discover the address the server actually saw ---------------
            seen = http.get(f"/v1/keys/{key_id}/addresses", headers=auth)
            check("the address it was used from is reported",
                  seen.status_code == 200 and bool(seen.json().get("observed")),
                  f"({seen.status_code})")
            if seen.status_code != 200 or not seen.json().get("observed"):
                return 1
            address = seen.json()["observed"][0]["ip_address"]
            print(f"        discovered source address: {address}")

            # -- allow exactly that address ---------------------------------
            http.put(f"/v1/keys/{key_id}", headers=auth,
                     json={"name": created.json()["name"], "ip_allowlist": [f"{address}/32"]})
            allowed = http.post("/v1/ai/request", headers=key_hdr, json={"input": "hello"})
            check("a listed address still proceeds", allowed.status_code == 200,
                  f"({allowed.status_code})")

            # -- allow only somewhere else ----------------------------------
            http.put(f"/v1/keys/{key_id}", headers=auth,
                     json={"name": created.json()["name"], "ip_allowlist": [NOT_US]})
            denied = http.post("/v1/ai/request", headers=key_hdr, json={"input": "hello"})
            check("an unlisted address is refused", denied.status_code == 403,
                  f"({denied.status_code})")

            # -- a header must not talk its way in --------------------------
            spoofed = http.post(
                "/v1/ai/request",
                headers={**key_hdr, "X-Forwarded-For": NOT_US.split("/")[0]},
                json={"input": "hello"},
            )
            check("a forwarded header cannot present a listed address",
                  spoofed.status_code == 403, f"({spoofed.status_code})")

            # -- the refusal is attributable --------------------------------
            trail = http.get(f"/v1/keys/{key_id}/addresses", headers=auth)
            refusals = trail.json().get("denied", []) if trail.status_code == 200 else []
            check("the refusal is recorded against this credential", bool(refusals),
                  f"({len(refusals)} address(es))")

            # -- removing the restriction restores access -------------------
            http.put(f"/v1/keys/{key_id}", headers=auth,
                     json={"name": created.json()["name"], "ip_allowlist": []})
            reopened = http.post("/v1/ai/request", headers=key_hdr, json={"input": "hello"})
            check("clearing the list restores access", reopened.status_code == 200,
                  f"({reopened.status_code})")

        finally:
            http.delete(f"/v1/keys/{key_id}", headers=auth)

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}\n")
        return 1
    print("source-network round trip passed\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
