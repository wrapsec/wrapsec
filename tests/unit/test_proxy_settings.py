"""
Phase 1 unit tests -- proxy settings endpoints and encryption utility.

Run:
    $env:TESTING = "true"
    pytest tests/unit/test_proxy_settings.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

from security.encryption import encrypt, decrypt, mask
from config.settings import get_settings

settings = get_settings()


# ===========================================================================
# Encryption utility tests
# ===========================================================================

class TestEncryption:

    def test_encrypt_produces_non_empty_string(self):
        result = encrypt("sk-my-secret-key", settings.secret_key)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "sk-openai-mysecretkey1234567890"
        encrypted = encrypt(plaintext, settings.secret_key)
        decrypted = decrypt(encrypted, settings.secret_key)
        assert decrypted == plaintext

    def test_encrypted_value_is_not_plaintext(self):
        plaintext = "sk-openai-mysecretkey1234567890"
        encrypted = encrypt(plaintext, settings.secret_key)
        assert plaintext not in encrypted

    def test_different_calls_produce_different_ciphertext(self):
        # Each call uses a random nonce -- ciphertext must differ
        plaintext  = "sk-openai-mysecretkey1234567890"
        encrypted1 = encrypt(plaintext, settings.secret_key)
        encrypted2 = encrypt(plaintext, settings.secret_key)
        assert encrypted1 != encrypted2

    def test_decrypt_with_wrong_key_raises(self):
        encrypted = encrypt("sk-my-secret", settings.secret_key)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(encrypted, "wrong-key-that-is-long-enough-to-be-valid")

    def test_decrypt_tampered_data_raises(self):
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt("this-is-not-valid-encrypted-data", settings.secret_key)

    def test_mask_long_string(self):
        result = mask("sk-abcdefghijklmnop")
        assert result == "sk-a...mnop"
        assert "abcdefghij" not in result

    def test_mask_short_string(self):
        result = mask("short")
        assert result == "****"

    def test_mask_exactly_8_chars(self):
        result = mask("12345678")
        assert result == "****"

    def test_mask_9_chars_shows_partial(self):
        result = mask("123456789")
        assert result == "1234...6789"


# ===========================================================================
# Proxy settings endpoint tests
# ===========================================================================

@pytest.fixture
def mock_config():
    """A mock ProxyProviderConfigModel instance."""
    from datetime import datetime
    config = MagicMock()
    config.key_id               = "wsk_live_testkey"
    config.provider             = "openai"
    config.base_url             = "https://api.openai.com/v1"
    config.provider_api_key_enc = encrypt("sk-openai-test1234567890", settings.secret_key)
    config.default_model        = "gpt-4o"
    config.timeout_seconds      = 60
    config.created_at           = datetime(2025, 1, 1, 0, 0, 0)
    config.updated_at           = datetime(2025, 1, 1, 0, 0, 0)
    return config


class TestProxySettingsEndpoints:
    """
    These tests use the FastAPI test client with mocked DB and auth.
    Each test patches the DB query and request.state.key_id directly.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import app inside each test to respect TESTING env var."""
        from api.main import app
        self.app = app

    # -----------------------------------------------------------------------
    # GET /v1/settings/proxy
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_proxy_settings_read(self, mock_config):
        """GET returns existing config with masked api key."""
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            with patch(
                "api.v1.endpoints.proxy_settings._get_config",
                new_callable=AsyncMock,
                return_value=mock_config,
            ):
                resp = await client.get(
                    "/v1/settings/proxy",
                    headers={"x-api-key": settings.admin_api_key},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"]       == "openai"
        assert data["base_url"]       == "https://api.openai.com/v1"
        assert data["default_model"]  == "gpt-4o"
        assert data["timeout_seconds"] == 60
        # api key must be masked -- never the plaintext
        assert "api_key_masked" in data
        assert data["api_key_masked"] is not None
        assert "openai-test" not in (data["api_key_masked"] or "")

    @pytest.mark.asyncio
    async def test_proxy_settings_read_not_found(self):
        """GET returns 404 when no config exists for this key."""
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            with patch(
                "api.v1.endpoints.proxy_settings._get_config",
                new_callable=AsyncMock,
                return_value=None,
            ):
                resp = await client.get(
                    "/v1/settings/proxy",
                    headers={"x-api-key": settings.admin_api_key},
                )

        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"

    # -----------------------------------------------------------------------
    # PUT /v1/settings/proxy
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_proxy_settings_create(self):
        """PUT creates a new config and returns masked key."""
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_db.commit  = AsyncMock()
        mock_db.refresh = AsyncMock()

        async def fake_get_db():
            yield mock_db

        self.app.dependency_overrides[
            __import__(
                "api.v1.dependencies.db", fromlist=["get_db"]
            ).get_db
        ] = fake_get_db

        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            resp = await client.put(
                "/v1/settings/proxy",
                headers={"x-api-key": settings.admin_api_key},
                json={
                    "provider":      "openai",
                    "base_url":      "https://api.openai.com/v1",
                    "api_key":       "sk-openai-testkeylong1234567890",
                    "default_model": "gpt-4o",
                    "timeout":       60,
                },
            )

        self.app.dependency_overrides = {}

        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"]      == "openai"
        assert data["default_model"] == "gpt-4o"
        assert "api_key_masked" in data

    @pytest.mark.asyncio
    async def test_proxy_settings_api_key_never_plaintext_in_response(self):
        """PUT response must never contain the plaintext api key."""
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_db.commit  = AsyncMock()
        mock_db.refresh = AsyncMock()

        plaintext_key = "sk-openai-supersecretlongkey12345"

        from api.v1.dependencies.db import get_db

        async def fake_get_db():
            yield mock_db

        self.app.dependency_overrides[get_db] = fake_get_db

        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            resp = await client.put(
                "/v1/settings/proxy",
                headers={"x-api-key": settings.admin_api_key},
                json={
                    "provider":      "openai",
                    "base_url":      "https://api.openai.com/v1",
                    "api_key":       plaintext_key,
                    "default_model": "gpt-4o",
                },
            )

        self.app.dependency_overrides = {}

        assert plaintext_key not in resp.text

    @pytest.mark.asyncio
    async def test_proxy_settings_openai_requires_api_key(self):
        """PUT with provider=openai and no api_key returns 422."""
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            resp = await client.put(
                "/v1/settings/proxy",
                headers={"x-api-key": settings.admin_api_key},
                json={
                    "provider":      "openai",
                    "base_url":      "https://api.openai.com/v1",
                    "default_model": "gpt-4o",
                    # api_key intentionally omitted
                },
            )

        assert resp.status_code == 422

    # -----------------------------------------------------------------------
    # DELETE /v1/settings/proxy
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_proxy_settings_delete(self):
        """DELETE removes existing config and returns 204."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit  = AsyncMock()

        from api.v1.dependencies.db import get_db

        async def fake_get_db():
            yield mock_db

        self.app.dependency_overrides[get_db] = fake_get_db

        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            resp = await client.delete(
                "/v1/settings/proxy",
                headers={"x-api-key": settings.admin_api_key},
            )

        self.app.dependency_overrides = {}
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_proxy_settings_delete_not_found(self):
        """DELETE returns 404 when no config exists."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit  = AsyncMock()

        from api.v1.dependencies.db import get_db

        async def fake_get_db():
            yield mock_db

        self.app.dependency_overrides[get_db] = fake_get_db

        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            resp = await client.delete(
                "/v1/settings/proxy",
                headers={"x-api-key": settings.admin_api_key},
            )

        self.app.dependency_overrides = {}
        assert resp.status_code == 404

    # -----------------------------------------------------------------------
    # GET /v1/settings/proxy/health
    # -----------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_proxy_health_reachable(self, mock_config):
        """Health endpoint returns reachable=true when provider responds 200."""
        import httpx

        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            with (
                patch(
                    "api.v1.endpoints.proxy_settings._get_config",
                    new_callable=AsyncMock,
                    return_value=mock_config,
                ),
                patch("httpx.AsyncClient") as mock_http,
            ):
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.raise_for_status = MagicMock()
                mock_http.return_value.__aenter__ = AsyncMock(
                    return_value=MagicMock(
                        get=AsyncMock(return_value=mock_response)
                    )
                )
                mock_http.return_value.__aexit__ = AsyncMock(return_value=False)

                resp = await client.get(
                    "/v1/settings/proxy/health",
                    headers={"x-api-key": settings.admin_api_key},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["reachable"]  is True
        assert data["provider"]   == "openai"
        assert "latency_ms" in data

    @pytest.mark.asyncio
    async def test_proxy_health_unreachable(self, mock_config):
        """Health endpoint returns reachable=false when provider is unreachable."""
        import httpx

        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            with (
                patch(
                    "api.v1.endpoints.proxy_settings._get_config",
                    new_callable=AsyncMock,
                    return_value=mock_config,
                ),
                patch("httpx.AsyncClient") as mock_http,
            ):
                mock_http.return_value.__aenter__ = AsyncMock(
                    return_value=MagicMock(
                        get=AsyncMock(
                            side_effect=httpx.ConnectError("Connection refused")
                        )
                    )
                )
                mock_http.return_value.__aexit__ = AsyncMock(return_value=False)

                resp = await client.get(
                    "/v1/settings/proxy/health",
                    headers={"x-api-key": settings.admin_api_key},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["reachable"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_proxy_health_not_found(self):
        """Health endpoint returns 404 when no config exists."""
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        ) as client:
            with patch(
                "api.v1.endpoints.proxy_settings._get_config",
                new_callable=AsyncMock,
                return_value=None,
            ):
                resp = await client.get(
                    "/v1/settings/proxy/health",
                    headers={"x-api-key": settings.admin_api_key},
                )

        assert resp.status_code == 404