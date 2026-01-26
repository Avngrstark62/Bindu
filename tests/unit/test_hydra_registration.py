"""Tests for Hydra registration utilities."""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from bindu.auth.hydra_registration import (
    save_agent_credentials,
    load_agent_credentials,
    AgentCredentials,
)


class TestSaveAgentCredentials:
    """Test saving agent credentials."""

    def test_save_credentials_new_file(self):
        """Test saving credentials to a new file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)

            credentials = AgentCredentials(
                agent_id="test-agent-123",
                client_id="did:key:test123",
                client_secret="test-secret-456",  # pragma: allowlist secret
                created_at="2026-01-01T00:00:00Z",
                scopes=["agent:read", "agent:write"],
            )

            save_agent_credentials(credentials, credentials_dir)

            # Verify file was created
            creds_file = credentials_dir / "oauth_credentials.json"
            assert creds_file.exists()

            # Verify content
            with open(creds_file, "r") as f:
                saved_data = json.load(f)

            assert "did:key:test123" in saved_data
            assert saved_data["did:key:test123"]["agent_id"] == "test-agent-123"
            assert saved_data["did:key:test123"]["client_id"] == "did:key:test123"

    def test_save_credentials_append_to_existing(self):
        """Test appending credentials to existing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)

            # Create first credential
            cred1 = AgentCredentials(
                agent_id="agent-1",
                client_id="did:key:first",
                client_secret="secret-1",  # pragma: allowlist secret
                created_at="2026-01-01T00:00:00Z",
                scopes=["agent:read"],
            )
            save_agent_credentials(cred1, credentials_dir)

            # Add second credential
            cred2 = AgentCredentials(
                agent_id="agent-2",
                client_id="did:key:second",
                client_secret="secret-2",  # pragma: allowlist secret
                created_at="2026-01-02T00:00:00Z",
                scopes=["agent:write"],
            )
            save_agent_credentials(cred2, credentials_dir)

            # Verify both exist
            creds_file = credentials_dir / "oauth_credentials.json"
            with open(creds_file, "r") as f:
                saved_data = json.load(f)

            assert len(saved_data) == 2
            assert "did:key:first" in saved_data
            assert "did:key:second" in saved_data

    def test_save_credentials_corrupted_file(self):
        """Test handling corrupted credentials file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)
            creds_file = credentials_dir / "oauth_credentials.json"

            # Create corrupted file
            with open(creds_file, "w") as f:
                f.write("invalid json{{{")

            # Should still save successfully
            credentials = AgentCredentials(
                agent_id="test-agent",
                client_id="did:key:test",
                client_secret="test-secret",  # pragma: allowlist secret
                created_at="2026-01-01T00:00:00Z",
                scopes=["agent:read"],
            )
            save_agent_credentials(credentials, credentials_dir)

            # Verify new valid file was created
            with open(creds_file, "r") as f:
                saved_data = json.load(f)

            assert "did:key:test" in saved_data


class TestLoadAgentCredentials:
    """Test loading agent credentials."""

    def test_load_credentials_success(self):
        """Test successfully loading credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)

            # Save credentials first
            credentials = AgentCredentials(
                agent_id="test-agent",
                client_id="did:key:test123",
                client_secret="test-secret",  # pragma: allowlist secret
                created_at="2026-01-01T00:00:00Z",
                scopes=["agent:read", "agent:write"],
            )
            save_agent_credentials(credentials, credentials_dir)

            # Load by DID
            loaded = load_agent_credentials("did:key:test123", credentials_dir)

            assert loaded is not None
            assert loaded.agent_id == "test-agent"
            assert loaded.client_id == "did:key:test123"
            assert loaded.client_secret == "test-secret"  # pragma: allowlist secret
            assert loaded.scopes == ["agent:read", "agent:write"]

    def test_load_credentials_not_found(self):
        """Test loading when DID not found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)

            # Save one credential
            credentials = AgentCredentials(
                agent_id="test-agent",
                client_id="did:key:exists",
                client_secret="test-secret",  # pragma: allowlist secret
                created_at="2026-01-01T00:00:00Z",
                scopes=["agent:read"],
            )
            save_agent_credentials(credentials, credentials_dir)

            # Try to load different DID
            loaded = load_agent_credentials("did:key:notfound", credentials_dir)

            assert loaded is None

    def test_load_credentials_no_file(self):
        """Test loading when credentials file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)

            loaded = load_agent_credentials("did:key:test", credentials_dir)

            assert loaded is None

    def test_load_credentials_corrupted_file(self):
        """Test loading from corrupted file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)
            creds_file = credentials_dir / "oauth_credentials.json"

            # Create corrupted file
            with open(creds_file, "w") as f:
                f.write("invalid json{{{")

            loaded = load_agent_credentials("did:key:test", credentials_dir)

            assert loaded is None

    def test_load_credentials_invalid_data(self):
        """Test loading when credential data is invalid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            credentials_dir = Path(tmpdir)
            creds_file = credentials_dir / "oauth_credentials.json"

            # Create file with invalid credential data
            with open(creds_file, "w") as f:
                json.dump(
                    {
                        "did:key:test": {
                            "agent_id": "test",
                            # Missing required fields
                        }
                    },
                    f,
                )

            loaded = load_agent_credentials("did:key:test", credentials_dir)

            assert loaded is None


class TestAgentCredentials:
    """Test AgentCredentials model."""

    def test_credentials_to_dict(self):
        """Test converting credentials to dict."""
        credentials = AgentCredentials(
            agent_id="test-agent",
            client_id="did:key:test",
            client_secret="test-secret",  # pragma: allowlist secret
            created_at="2026-01-01T00:00:00Z",
            scopes=["agent:read", "agent:write"],
        )

        data = credentials.to_dict()

        assert data["agent_id"] == "test-agent"
        assert data["client_id"] == "did:key:test"
        assert data["client_secret"] == "test-secret"  # pragma: allowlist secret
        assert data["created_at"] == "2026-01-01T00:00:00Z"
        assert data["scopes"] == ["agent:read", "agent:write"]

    def test_credentials_from_dict(self):
        """Test creating credentials from dict."""
        data = {
            "agent_id": "test-agent",
            "client_id": "did:key:test",
            "client_secret": "test-secret",  # pragma: allowlist secret
            "created_at": "2026-01-01T00:00:00Z",
            "scopes": ["agent:read", "agent:write"],
        }

        credentials = AgentCredentials.from_dict(data)

        assert credentials.agent_id == "test-agent"
        assert credentials.client_id == "did:key:test"
        assert credentials.client_secret == "test-secret"  # pragma: allowlist secret
        assert credentials.created_at == "2026-01-01T00:00:00Z"
        assert credentials.scopes == ["agent:read", "agent:write"]


class TestRegisterAgentInHydra:
    """Test agent registration in Hydra."""

    @pytest.mark.asyncio
    async def test_registration_disabled(self):
        """Test when auto-registration is disabled."""
        from bindu.auth.hydra_registration import register_agent_in_hydra

        with patch("bindu.auth.hydra_registration.app_settings") as mock_settings:
            mock_settings.hydra.auto_register_agents = False

            result = await register_agent_in_hydra(
                agent_id="test-agent",
                agent_name="Test Agent",
                agent_url="http://localhost:3773",
                did="did:key:test",
                credentials_dir=Path("/tmp/.bindu"),
            )

            assert result is None

    @pytest.mark.asyncio
    async def test_registration_with_existing_credentials(self):
        """Test when credentials already exist."""
        from bindu.auth.hydra_registration import register_agent_in_hydra

        mock_creds = AgentCredentials(
            agent_id="test-agent",
            client_id="did:key:test",
            client_secret="existing-secret",  # pragma: allowlist secret
            created_at="2026-01-01T00:00:00Z",
            scopes=["agent:read"],
        )

        with patch("bindu.auth.hydra_registration.app_settings") as mock_settings:
            mock_settings.hydra.auto_register_agents = True

            with patch(
                "bindu.auth.hydra_registration.load_agent_credentials",
                return_value=mock_creds,
            ):
                result = await register_agent_in_hydra(
                    agent_id="test-agent",
                    agent_name="Test Agent",
                    agent_url="http://localhost:3773",
                    did="did:key:test",
                    credentials_dir=Path("/tmp/.bindu"),
                )

                assert result == mock_creds

    @pytest.mark.asyncio
    async def test_registration_client_exists_in_hydra(self):
        """Test when client already exists in Hydra but not locally."""
        from bindu.auth.hydra_registration import register_agent_in_hydra

        with patch("bindu.auth.hydra_registration.app_settings") as mock_settings:
            mock_settings.hydra.auto_register_agents = True
            mock_settings.hydra.admin_url = "https://hydra-admin.example.com"
            mock_settings.hydra.public_url = "https://hydra.example.com"
            mock_settings.hydra.timeout = 10
            mock_settings.hydra.verify_ssl = True
            mock_settings.hydra.max_retries = 3

            with patch(
                "bindu.auth.hydra_registration.load_agent_credentials",
                return_value=None,
            ):
                with patch(
                    "bindu.auth.hydra_registration.HydraClient"
                ) as mock_hydra_class:
                    mock_hydra = AsyncMock()
                    mock_hydra.get_oauth_client.return_value = {
                        "client_id": "did:key:test",
                        "client_name": "Existing Client",
                    }
                    mock_hydra_class.return_value.__aenter__.return_value = mock_hydra
                    mock_hydra_class.return_value.__aexit__.return_value = None

                    result = await register_agent_in_hydra(
                        agent_id="test-agent",
                        agent_name="Test Agent",
                        agent_url="http://localhost:3773",
                        did="did:key:test",
                        credentials_dir=Path("/tmp/.bindu"),
                    )

                    assert result is None
