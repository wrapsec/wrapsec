import pytest


@pytest.mark.asyncio
async def test_get_thresholds_returns_defaults(client, admin_headers):
    response = await client.get("/v1/settings/thresholds", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "block_threshold" in data
    assert "sanitize_threshold" in data
    assert data["block_threshold"] > data["sanitize_threshold"]


@pytest.mark.asyncio
async def test_update_thresholds(client, admin_headers):
    response = await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.75, "sanitize_threshold": 0.45},
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["block_threshold"] == 0.75
    assert data["sanitize_threshold"] == 0.45
    assert "updated_at" in data


@pytest.mark.asyncio
async def test_invalid_thresholds_rejected(client, admin_headers):
    response = await client.put(
        "/v1/settings/thresholds",
        json={"block_threshold": 0.3, "sanitize_threshold": 0.5},
        headers=admin_headers,
    )
    assert response.status_code in (400, 422)


@pytest.mark.asyncio
async def test_get_layers_returns_defaults(client, admin_headers):
    response = await client.get("/v1/settings/layers", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "rule_enabled" in data
    assert "ml_enabled" in data
    assert "llm_enabled" in data


@pytest.mark.asyncio
async def test_update_layers(client, admin_headers):
    response = await client.put(
        "/v1/settings/layers",
        json={"llm_enabled": False},
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["llm_enabled"] is False
    assert data["rule_enabled"] is True
    assert "updated_at" in data