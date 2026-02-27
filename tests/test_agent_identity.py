"""Tests for aumos-auth-gateway agent identity components.

Covers:
    - InternalCA: certificate issuance, SAN fields, fingerprint, verification
    - AgentTokenService: token exchange, validation, expiry, tamper detection
    - AgentIdentityManager: register, suspend, revoke, agent_class validation

At least 20 meaningful test cases across all three modules.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from aumos_auth_gateway.agent_identity.certificate_authority import InternalCA
from aumos_auth_gateway.agent_identity.identity_manager import (
    AgentIdentityManager,
    AgentIdentityRecord,
    _VALID_AGENT_CLASSES,
)
from aumos_auth_gateway.agent_identity.token_service import (
    AgentTokenExchangeResult,
    AgentTokenService,
)


# ===========================================================================
# InternalCA tests
# ===========================================================================


def test_ca_bootstraps_ephemeral_ca() -> None:
    """InternalCA with no arguments should bootstrap a fresh ephemeral CA."""
    ca = InternalCA()
    ca_pem = ca.get_ca_certificate_pem()
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert "-----END CERTIFICATE-----" in ca_pem


def test_ca_issue_certificate_returns_cert_and_key(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """issue_agent_certificate should return a certificate and a private key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    cert, private_key = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    assert cert is not None
    assert isinstance(private_key, Ed25519PrivateKey)


def test_ca_certificate_san_contains_agent_uri(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """Issued certificate should contain urn:aumos:agent:{agent_id} in SAN."""
    from cryptography import x509 as cx509

    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="orchestrator",
    )
    san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    uris = {v.value for v in san_ext.value.get_values_for_type(cx509.UniformResourceIdentifier)}
    assert f"urn:aumos:agent:{agent_id}" in uris


def test_ca_certificate_san_contains_tenant_uri(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """Issued certificate should contain urn:aumos:tenant:{tenant_id} in SAN."""
    from cryptography import x509 as cx509

    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    uris = {v.value for v in san_ext.value.get_values_for_type(cx509.UniformResourceIdentifier)}
    assert f"urn:aumos:tenant:{tenant_id}" in uris


def test_ca_certificate_san_contains_class_uri(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """Issued certificate should contain urn:aumos:class:{agent_class} in SAN."""
    from cryptography import x509 as cx509

    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="evaluator",
    )
    san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    uris = {v.value for v in san_ext.value.get_values_for_type(cx509.UniformResourceIdentifier)}
    assert "urn:aumos:class:evaluator" in uris


def test_ca_get_certificate_pem_format(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """get_certificate_pem should return a valid PEM string."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="retriever",
    )
    pem = ca.get_certificate_pem(cert)
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    assert "-----END CERTIFICATE-----" in pem


def test_ca_get_private_key_pem_format(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """get_private_key_pem should return a valid PKCS8 PEM string."""
    _, private_key = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="executor",
    )
    pem = ca.get_private_key_pem(private_key)
    assert pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert "-----END PRIVATE KEY-----" in pem


def test_ca_fingerprint_is_64_hex_chars(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """SHA-256 fingerprint should be a 64-character hex string."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    fp = ca.get_certificate_fingerprint(cert)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_ca_verify_certificate_succeeds_for_valid_cert(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """verify_agent_certificate should return True for a certificate issued by this CA."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    pem = ca.get_certificate_pem(cert)
    assert ca.verify_agent_certificate(
        certificate_pem=pem,
        expected_agent_id=agent_id,
        expected_tenant_id=tenant_id,
    ) is True


def test_ca_verify_certificate_fails_wrong_agent_id(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """verify_agent_certificate should return False if agent_id does not match SAN."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    pem = ca.get_certificate_pem(cert)
    wrong_agent_id = uuid.uuid4()
    assert ca.verify_agent_certificate(
        certificate_pem=pem,
        expected_agent_id=wrong_agent_id,
        expected_tenant_id=tenant_id,
    ) is False


def test_ca_verify_certificate_fails_wrong_tenant_id(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """verify_agent_certificate should return False if tenant_id does not match SAN."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    pem = ca.get_certificate_pem(cert)
    wrong_tenant_id = uuid.uuid4()
    assert ca.verify_agent_certificate(
        certificate_pem=pem,
        expected_agent_id=agent_id,
        expected_tenant_id=wrong_tenant_id,
    ) is False


def test_ca_verify_certificate_fails_for_different_ca(
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """verify_agent_certificate should return False for cert issued by a different CA."""
    issuing_ca = InternalCA()
    verifying_ca = InternalCA()  # Different ephemeral CA

    cert, _ = issuing_ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    pem = issuing_ca.get_certificate_pem(cert)

    # Verifying with a different CA should fail
    assert verifying_ca.verify_agent_certificate(
        certificate_pem=pem,
        expected_agent_id=agent_id,
        expected_tenant_id=tenant_id,
    ) is False


# ===========================================================================
# AgentTokenService tests
# ===========================================================================


@pytest.mark.asyncio
async def test_token_exchange_returns_bearer_token(
    ca: InternalCA,
    token_service: AgentTokenService,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """Token exchange should return a valid Bearer JWT with correct metadata."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    cert_pem = ca.get_certificate_pem(cert)

    result = await token_service.exchange_certificate_for_token(
        certificate_pem=cert_pem,
        agent_id=agent_id,
        tenant_id=tenant_id,
    )

    assert isinstance(result, AgentTokenExchangeResult)
    assert result.token_type == "Bearer"
    assert result.expires_in == 300
    assert result.agent_id == agent_id
    assert result.tenant_id == tenant_id
    assert result.access_token != ""
    # JWT has 3 parts
    assert len(result.access_token.split(".")) == 3


@pytest.mark.asyncio
async def test_token_exchange_fails_wrong_agent_id(
    ca: InternalCA,
    token_service: AgentTokenService,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """Token exchange with wrong agent_id claim should raise ValueError."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    cert_pem = ca.get_certificate_pem(cert)
    wrong_agent_id = uuid.uuid4()

    with pytest.raises(ValueError, match="Certificate verification failed"):
        await token_service.exchange_certificate_for_token(
            certificate_pem=cert_pem,
            agent_id=wrong_agent_id,
            tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_token_validate_succeeds_for_fresh_token(
    ca: InternalCA,
    token_service: AgentTokenService,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """validate_agent_token should return claims for a freshly issued token."""
    cert, _ = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    cert_pem = ca.get_certificate_pem(cert)
    result = await token_service.exchange_certificate_for_token(
        certificate_pem=cert_pem,
        agent_id=agent_id,
        tenant_id=tenant_id,
    )

    claims = token_service.validate_agent_token(result.access_token)
    assert claims["agent_id"] == str(agent_id)
    assert claims["tenant_id"] == str(tenant_id)
    assert claims["is_agent"] is True
    assert claims["iss"] == "aumos-auth-gateway"


def test_token_validate_fails_tampered_payload(
    token_service: AgentTokenService,
) -> None:
    """validate_agent_token should raise ValueError if signature is tampered."""
    # Build a valid-looking JWT with wrong signature
    import base64
    import json

    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload_data = {
        "sub": "agent:fake",
        "iss": "aumos-auth-gateway",
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()
    fake_sig = base64.urlsafe_b64encode(b"fakesignature" * 3).rstrip(b"=").decode()
    tampered_token = f"{header}.{payload}.{fake_sig}"

    with pytest.raises(ValueError):
        token_service.validate_agent_token(tampered_token)


def test_token_validate_fails_wrong_secret() -> None:
    """Token signed with one secret should fail validation against a different secret."""
    ca = InternalCA()
    service_a = AgentTokenService(ca=ca, jwt_signing_secret="secret-a" * 5)
    service_b = AgentTokenService(ca=ca, jwt_signing_secret="secret-b" * 5)

    token = service_a._sign_jwt({
        "sub": "test",
        "iss": "aumos-auth-gateway",
        "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
    })

    with pytest.raises(ValueError):
        service_b.validate_agent_token(token)


def test_token_validate_fails_expired_token(token_service: AgentTokenService) -> None:
    """Expired token should raise ValueError."""
    expired_claims = {
        "sub": "agent:test",
        "iss": "aumos-auth-gateway",
        "exp": int((datetime.now(UTC) - timedelta(hours=1)).timestamp()),
        "iat": int((datetime.now(UTC) - timedelta(hours=2)).timestamp()),
    }
    expired_token = token_service._sign_jwt(expired_claims)

    with pytest.raises(ValueError, match="expired"):
        token_service.validate_agent_token(expired_token)


# ===========================================================================
# AgentIdentityManager tests
# ===========================================================================


@pytest.mark.asyncio
async def test_register_agent_returns_record_and_private_key(
    identity_manager: AgentIdentityManager,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """register_agent should return a record and private key PEM string."""
    # Set up mock to return the record passed in
    mock_identity_repo.save.side_effect = lambda record: record

    record, private_key_pem = await identity_manager.register_agent(
        tenant_id=tenant_id,
        agent_class="tool",
        display_name="Test Tool Agent",
    )

    assert isinstance(record, AgentIdentityRecord)
    assert record.tenant_id == tenant_id
    assert record.agent_class == "tool"
    assert record.display_name == "Test Tool Agent"
    assert record.status == "active"
    assert private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")


@pytest.mark.asyncio
async def test_register_agent_invalid_class_raises(
    identity_manager: AgentIdentityManager,
    tenant_id: uuid.UUID,
) -> None:
    """Registering with an invalid agent_class should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid agent_class"):
        await identity_manager.register_agent(
            tenant_id=tenant_id,
            agent_class="super_hacker",
            display_name="Rogue Agent",
        )


@pytest.mark.asyncio
async def test_register_agent_all_valid_classes(
    ca: InternalCA,
    tenant_id: uuid.UUID,
) -> None:
    """All 5 valid agent classes should be accepted."""
    repo = AsyncMock()
    repo.save.side_effect = lambda record: record

    manager = AgentIdentityManager(ca=ca, repository=repo)

    for agent_class in _VALID_AGENT_CLASSES:
        record, _ = await manager.register_agent(
            tenant_id=tenant_id,
            agent_class=agent_class,
            display_name=f"Test {agent_class}",
        )
        assert record.agent_class == agent_class


@pytest.mark.asyncio
async def test_suspend_agent_calls_update_status(
    identity_manager: AgentIdentityManager,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """suspend_agent should call update_status with status='suspended'."""
    mock_identity_repo.update_status.return_value = True

    await identity_manager.suspend_agent(
        agent_id=agent_id,
        tenant_id=tenant_id,
        reason="Anomaly detected",
    )

    mock_identity_repo.update_status.assert_called_once_with(
        agent_id=agent_id,
        tenant_id=tenant_id,
        status="suspended",
    )


@pytest.mark.asyncio
async def test_revoke_agent_calls_update_status(
    identity_manager: AgentIdentityManager,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """revoke_agent should call update_status with status='revoked'."""
    mock_identity_repo.update_status.return_value = True

    await identity_manager.revoke_agent(
        agent_id=agent_id,
        tenant_id=tenant_id,
        reason="Compromised",
    )

    mock_identity_repo.update_status.assert_called_once_with(
        agent_id=agent_id,
        tenant_id=tenant_id,
        status="revoked",
    )


@pytest.mark.asyncio
async def test_suspend_agent_not_found_raises(
    identity_manager: AgentIdentityManager,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """Suspending a non-existent agent should raise NotFoundError."""
    from aumos_common.errors import NotFoundError

    mock_identity_repo.update_status.return_value = False

    with pytest.raises(NotFoundError):
        await identity_manager.suspend_agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_revoke_agent_not_found_raises(
    identity_manager: AgentIdentityManager,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """Revoking a non-existent agent should raise NotFoundError."""
    from aumos_common.errors import NotFoundError

    mock_identity_repo.update_status.return_value = False

    with pytest.raises(NotFoundError):
        await identity_manager.revoke_agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_get_agent_not_found_raises(
    identity_manager: AgentIdentityManager,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """get_agent for a non-existent agent should raise NotFoundError."""
    from aumos_common.errors import NotFoundError

    mock_identity_repo.get_by_id.return_value = None

    with pytest.raises(NotFoundError):
        await identity_manager.get_agent(
            agent_id=agent_id,
            tenant_id=tenant_id,
        )


@pytest.mark.asyncio
async def test_get_behavioral_profile_returns_dict(
    ca: InternalCA,
    agent_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> None:
    """get_behavioral_profile should return a structured dict with required keys."""
    repo = AsyncMock()

    # Create a real record for the mock to return
    cert, private_key = ca.issue_agent_certificate(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
    )
    record = AgentIdentityRecord(
        agent_id=agent_id,
        tenant_id=tenant_id,
        agent_class="tool",
        display_name="Profile Test Agent",
        certificate_serial=hex(cert.serial_number),
        certificate_fingerprint=ca.get_certificate_fingerprint(cert),
        certificate_pem=ca.get_certificate_pem(cert),
        permitted_operations=["read", "write"],
    )
    repo.get_by_id.return_value = record
    repo.save.side_effect = lambda r: r

    manager = AgentIdentityManager(ca=ca, repository=repo)
    profile = await manager.get_behavioral_profile(
        agent_id=agent_id,
        tenant_id=tenant_id,
    )

    assert profile["agent_id"] == str(agent_id)
    assert profile["tenant_id"] == str(tenant_id)
    assert profile["agent_class"] == "tool"
    assert profile["status"] == "active"
    assert "permitted_operations" in profile
    assert "certificate_fingerprint" in profile


@pytest.mark.asyncio
async def test_list_anomalies_delegates_to_repo(
    identity_manager: AgentIdentityManager,
    tenant_id: uuid.UUID,
    mock_identity_repo: AsyncMock,
) -> None:
    """list_anomalies should pass through to the repository."""
    mock_identity_repo.list_anomalies.return_value = [
        {"anomaly_type": "call_rate", "score": 0.92}
    ]

    anomalies = await identity_manager.list_anomalies(
        tenant_id=tenant_id,
        limit=10,
        offset=0,
    )

    assert len(anomalies) == 1
    mock_identity_repo.list_anomalies.assert_called_once_with(
        tenant_id=tenant_id,
        limit=10,
        offset=0,
    )
