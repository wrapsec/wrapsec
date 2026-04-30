# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import pytest


@pytest.mark.asyncio
async def test_create_key(client, admin_headers):
    response = await client.post(
        "/v1/keys",
        json={"name": "test-system"},
        headers=admin_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-system"
    assert data["api_key"].startswith("wsk_live_")
    assert "key_id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_api_key_not_in_list(client, admin_headers):
    await client.post(
        "/v1/keys",
        json={"name": "test-system"},
        headers=admin_headers,
    )
    response = await client.get("/v1/keys", headers=admin_headers)
    data = response.json()
    for key in data["keys"]:
        assert "api_key" not in key


@pytest.mark.asyncio
async def test_list_keys(client, admin_headers):
    await client.post("/v1/keys", json={"name": "key-1"}, headers=admin_headers)
    await client.post("/v1/keys", json={"name": "key-2"}, headers=admin_headers)

    response = await client.get("/v1/keys", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["keys"]) == 2


@pytest.mark.asyncio
async def test_revoke_key(client, admin_headers):
    create = await client.post(
        "/v1/keys",
        json={"name": "to-revoke"},
        headers=admin_headers,
    )
    key_id = create.json()["key_id"]

    response = await client.delete(
        f"/v1/keys/{key_id}",
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["revoked"] is True
    assert "revoked_at" in data


@pytest.mark.asyncio
async def test_revoked_key_excluded_from_list(client, admin_headers):
    create = await client.post(
        "/v1/keys",
        json={"name": "to-revoke"},
        headers=admin_headers,
    )
    key_id = create.json()["key_id"]
    await client.delete(f"/v1/keys/{key_id}", headers=admin_headers)

    response = await client.get("/v1/keys", headers=admin_headers)
    data = response.json()
    assert all(k["key_id"] != key_id for k in data["keys"])


@pytest.mark.asyncio
async def test_revoke_nonexistent_key_returns_404(client, admin_headers):
    response = await client.delete(
        "/v1/keys/key_nonexistent",
        headers=admin_headers,
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"