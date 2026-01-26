"""Tests for Hydra client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from bindu.auth.hydra_client import HydraClient


class TestHydraClient:
    """Test Hydra client operations."""

    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test client initialization."""
        client = HydraClient(
            admin_url="https://hydra-admin.example.com",
            public_url="https://hydra.example.com",
            timeout=10,
            verify_ssl=True,
        )

        assert client.admin_url == "https://hydra-admin.example.com"
        assert client.public_url == "https://hydra.example.com"
        assert client.timeout == 10
        assert client.verify_ssl is True

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        """Test successful health check."""
        async with HydraClient(
            admin_url="https://hydra-admin.example.com",
            public_url="https://hydra.example.com",
        ) as client:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"status": "ok"})

            with patch.object(client, '_request_with_retry', return_value=mock_response):
                is_healthy = await client.health_check()

                assert is_healthy is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        """Test health check failure."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 500

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_get_context = MagicMock()
            mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.get = MagicMock(return_value=mock_get_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                is_healthy = await client.health_check()

                assert is_healthy is False

    @pytest.mark.asyncio
    async def test_get_oauth_client_success(self):
        """Test getting OAuth client."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "client_id": "test-client",
                    "client_name": "Test Client",
                }
            )

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_get_context = MagicMock()
            mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.get = MagicMock(return_value=mock_get_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                result = await client.get_oauth_client("test-client")

                assert result is not None
                assert result["client_id"] == "test-client"

    @pytest.mark.asyncio
    async def test_get_oauth_client_not_found(self):
        """Test getting non-existent OAuth client."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 404

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_get_context = MagicMock()
            mock_get_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.get = MagicMock(return_value=mock_get_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                result = await client.get_oauth_client("nonexistent")

                assert result is None

    @pytest.mark.asyncio
    async def test_create_oauth_client_success(self):
        """Test creating OAuth client."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 201
            mock_response.json = AsyncMock(
                return_value={
                    "client_id": "new-client",
                    "client_name": "New Client",
                }
            )

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                client_data = {
                    "client_id": "new-client",
                    "client_name": "New Client",
                    "grant_types": ["client_credentials"],
                }

                result = await client.create_oauth_client(client_data)

                assert result is not None
                assert result["client_id"] == "new-client"

    @pytest.mark.asyncio
    async def test_create_oauth_client_failure(self):
        """Test creating OAuth client failure."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 400
            mock_response.text = AsyncMock(return_value="Bad request")

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                client_data = {
                    "client_id": "invalid",
                }

                result = await client.create_oauth_client(client_data)

                assert result is None

    @pytest.mark.asyncio
    async def test_delete_oauth_client_success(self):
        """Test deleting OAuth client."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 204

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_delete_context = MagicMock()
            mock_delete_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_delete_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.delete = MagicMock(return_value=mock_delete_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                result = await client.delete_oauth_client("test-client")

                assert result is True

    @pytest.mark.asyncio
    async def test_delete_oauth_client_failure(self):
        """Test deleting OAuth client failure."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 404

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_delete_context = MagicMock()
            mock_delete_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_delete_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.delete = MagicMock(return_value=mock_delete_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                result = await client.delete_oauth_client("nonexistent")

                assert result is False

    @pytest.mark.asyncio
    async def test_introspect_token_active(self):
        """Test introspecting active token."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"active": True, "sub": "user-123"}
            )

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                result = await client.introspect_token("test_token")  # pragma: allowlist secret

                assert result is not None
                assert result["active"] is True

    @pytest.mark.asyncio
    async def test_revoke_token_success(self):
        """Test revoking token."""
        with patch("bindu.auth.hydra_client.aiohttp.ClientSession") as mock_session_class:
            mock_response = MagicMock()
            mock_response.status = 200

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_post_context = MagicMock()
            mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post_context.__aexit__ = AsyncMock(return_value=None)
            mock_session.post = MagicMock(return_value=mock_post_context)

            mock_session_class.return_value = mock_session

            async with HydraClient(
                admin_url="https://hydra-admin.example.com",
                public_url="https://hydra.example.com",
            ) as client:
                result = await client.revoke_token("test_token")  # pragma: allowlist secret

                assert result is True
