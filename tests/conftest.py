"""Shared test fixtures for aumos-auth-gateway.

Provides:
    - Fixed agent and tenant UUIDs for test isolation
    - InternalCA instance pre-bootstrapped with a test CA
    - AgentTokenService with test secret key
    - AgentIdentityManager with in-memory mock repository
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_auth_gateway.agent_identity.certificate_authority import InternalCA
from aumos_auth_gateway.agent_identity.identity_manager import AgentIdentityManager
from aumos_auth_gateway.agent_identity.token_service import AgentTokenService


@pytest.fixture
def tenant_id() -> uuid.UUID:
    """Fixed tenant UUID for test isolation."""
    return uuid.UUID("10000000-0000-0000-0000-000000000001")


@pytest.fixture
def agent_id() -> uuid.UUID:
    """Fixed agent UUID for test isolation."""
    return uuid.UUID("20000000-0000-0000-0000-000000000002")


@pytest.fixture
def ca() -> InternalCA:
    """InternalCA bootstrapped with a fresh ephemeral Ed25519 CA."""
    return InternalCA()


@pytest.fixture
def token_service(ca: InternalCA) -> AgentTokenService:
    """AgentTokenService with a deterministic test secret key."""
    return AgentTokenService(
        ca=ca,
        jwt_signing_secret="test-secret-key-for-unit-tests-minimum-32-chars",
        token_ttl_seconds=300,
    )


@pytest.fixture
def mock_identity_repo() -> AsyncMock:
    """Mock AgentIdentityRepository for identity manager tests."""
    repo = AsyncMock()
    repo.create.return_value = None
    repo.get_by_id.return_value = None
    repo.update_status.return_value = None
    repo.get_behavioral_profile.return_value = {}
    repo.list_anomalies.return_value = []
    return repo


@pytest.fixture
def identity_manager(
    ca: InternalCA,
    token_service: AgentTokenService,
    mock_identity_repo: AsyncMock,
) -> AgentIdentityManager:
    """AgentIdentityManager with mock repository and real CA/token service."""
    return AgentIdentityManager(
        ca=ca,
        repository=mock_identity_repo,
    )
