"""FastAPI routes for zero-trust agent identity management.

Provides endpoints for:
- Agent registration (issues X.509 certificate + private key)
- Certificate-based token exchange (5-min TTL JWT)
- Agent suspend/revoke lifecycle management
- Behavioral profile and anomaly retrieval

All endpoints require a valid Bearer JWT from the auth middleware.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from aumos_common.auth import TenantContext, get_current_tenant
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

logger = get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------


class AgentRegisterRequest(BaseModel):
    """Request to register a new zero-trust agent identity."""

    agent_class: str = Field(
        description="Agent class: orchestrator, tool, evaluator, retriever, executor"
    )
    display_name: str = Field(
        min_length=1,
        max_length=255,
        description="Human-readable name for this agent",
    )
    permitted_operations: list[str] = Field(
        default_factory=list,
        description="Allowed operation identifiers. Empty list defaults to ['*']",
    )


class AgentRegisterResponse(BaseModel):
    """Response from agent registration — includes the one-time private key."""

    agent_id: uuid.UUID = Field(description="Assigned agent UUID")
    certificate_pem: str = Field(description="PEM-encoded X.509 certificate for this agent")
    private_key_pem: str = Field(
        description="PEM-encoded Ed25519 private key — returned ONCE, store securely"
    )
    certificate_fingerprint: str = Field(description="SHA-256 fingerprint of the certificate")
    certificate_serial: str = Field(description="Hex serial number of the certificate")
    agent_class: str
    display_name: str
    status: str = Field(default="active")


class TokenExchangeRequest(BaseModel):
    """Request to exchange a certificate for a short-lived access token."""

    certificate_pem: str = Field(description="PEM-encoded agent certificate")


class TokenExchangeResponse(BaseModel):
    """Response from certificate-to-token exchange."""

    access_token: str = Field(description="Short-lived JWT access token (5-min TTL)")
    expires_in: int = Field(default=300, description="Token validity in seconds")
    token_type: str = Field(default="Bearer")


class AgentStatusUpdateRequest(BaseModel):
    """Request to suspend or revoke an agent."""

    reason: str | None = Field(default=None, max_length=500, description="Audit reason")


class AgentBehavioralProfileResponse(BaseModel):
    """Behavioral profile summary for an agent."""

    agent_id: str
    tenant_id: str
    agent_class: str
    display_name: str
    status: str
    permitted_operations: list[str]
    certificate_fingerprint: str
    registered_at: str


class AnomalyRecord(BaseModel):
    """A single behavioral anomaly record."""

    id: str
    agent_id: str
    tenant_id: str
    detected_at: str
    anomaly_type: str
    anomaly_score: float
    description: str
    actions_taken: list[Any]


class AnomalyListResponse(BaseModel):
    """Paginated list of behavioral anomalies."""

    items: list[AnomalyRecord]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Dependency factories
# ---------------------------------------------------------------------------


def _get_identity_manager(request: Request) -> Any:
    """Get AgentIdentityManager from app state.

    Args:
        request: FastAPI request.

    Returns:
        Configured AgentIdentityManager instance.
    """
    return request.app.state.agent_identity_manager


def _get_token_service(request: Request) -> Any:
    """Get AgentTokenService from app state.

    Args:
        request: FastAPI request.

    Returns:
        Configured AgentTokenService instance.
    """
    return request.app.state.agent_token_service


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


@router.post(
    "/agents/register",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new zero-trust agent with X.509 certificate",
    tags=["Zero-Trust Agent Identity"],
)
async def register_agent(
    body: AgentRegisterRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    identity_manager: Any = Depends(_get_identity_manager),
) -> AgentRegisterResponse:
    """Register a new AI agent and issue its X.509 certificate.

    Returns the agent's certificate and Ed25519 private key. The private key
    is returned ONCE and cannot be recovered — store it securely in a secrets
    manager before discarding this response.

    Args:
        body: Agent registration parameters.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        identity_manager: Injected AgentIdentityManager.

    Returns:
        AgentRegisterResponse with certificate, private key, and agent metadata.

    Raises:
        HTTPException: 400 if agent_class is invalid.
    """
    correlation_id = request.headers.get("X-Request-ID")
    try:
        record, private_key_pem = await identity_manager.register_agent(
            tenant_id=uuid.UUID(tenant.tenant_id),
            agent_class=body.agent_class,
            display_name=body.display_name,
            permitted_operations=body.permitted_operations or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    logger.info(
        "Agent registration complete",
        agent_id=str(record.agent_id),
        tenant_id=str(tenant.tenant_id),
        correlation_id=correlation_id,
    )

    return AgentRegisterResponse(
        agent_id=record.agent_id,
        certificate_pem=record.certificate_pem,
        private_key_pem=private_key_pem,
        certificate_fingerprint=record.certificate_fingerprint,
        certificate_serial=record.certificate_serial,
        agent_class=record.agent_class,
        display_name=record.display_name,
        status=record.status,
    )


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}/token/exchange",
    response_model=TokenExchangeResponse,
    summary="Exchange agent certificate for a 5-minute access token",
    tags=["Zero-Trust Agent Identity"],
)
async def exchange_token(
    agent_id: uuid.UUID,
    body: TokenExchangeRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    identity_manager: Any = Depends(_get_identity_manager),
    token_service: Any = Depends(_get_token_service),
) -> TokenExchangeResponse:
    """Exchange a valid agent X.509 certificate for a short-lived JWT.

    The certificate must be valid, not expired, and issued by the AumOS internal
    CA for the specified agent_id and tenant. The returned token has a 5-minute
    (300 second) TTL.

    Args:
        agent_id: Agent UUID in the path.
        body: Certificate to exchange.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        identity_manager: Injected AgentIdentityManager.
        token_service: Injected AgentTokenService.

    Returns:
        TokenExchangeResponse with access_token and expires_in=300.

    Raises:
        HTTPException: 403 if certificate verification fails.
        HTTPException: 404 if the agent does not exist.
        HTTPException: 409 if agent is suspended or revoked.
    """
    try:
        record = await identity_manager.get_agent(
            agent_id=agent_id,
            tenant_id=uuid.UUID(tenant.tenant_id),
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    if record.status in ("suspended", "revoked", "expired"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent {agent_id} is {record.status} — token exchange denied",
        )

    try:
        result = await token_service.exchange_certificate_for_token(
            certificate_pem=body.certificate_pem,
            agent_id=agent_id,
            tenant_id=uuid.UUID(tenant.tenant_id),
            permitted_operations=record.permitted_operations,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )

    return TokenExchangeResponse(
        access_token=result.access_token,
        expires_in=result.expires_in,
        token_type=result.token_type,
    )


# ---------------------------------------------------------------------------
# Lifecycle management
# ---------------------------------------------------------------------------


@router.post(
    "/agents/{agent_id}/suspend",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Suspend an agent identity",
    tags=["Zero-Trust Agent Identity"],
)
async def suspend_agent(
    agent_id: uuid.UUID,
    body: AgentStatusUpdateRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    identity_manager: Any = Depends(_get_identity_manager),
) -> None:
    """Suspend an agent identity, preventing further token exchanges.

    Suspension is reversible. Use revoke for permanent decommissioning.

    Args:
        agent_id: Agent UUID to suspend.
        body: Optional suspension reason for audit log.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        identity_manager: Injected AgentIdentityManager.

    Raises:
        HTTPException: 404 if the agent does not exist.
    """
    try:
        await identity_manager.suspend_agent(
            agent_id=agent_id,
            tenant_id=uuid.UUID(tenant.tenant_id),
            reason=body.reason,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


@router.post(
    "/agents/{agent_id}/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Permanently revoke an agent identity",
    tags=["Zero-Trust Agent Identity"],
)
async def revoke_agent(
    agent_id: uuid.UUID,
    body: AgentStatusUpdateRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    identity_manager: Any = Depends(_get_identity_manager),
) -> None:
    """Permanently revoke an agent identity.

    Revocation is irreversible. The agent's certificate is considered invalid
    and should be added to the platform CRL.

    Args:
        agent_id: Agent UUID to revoke.
        body: Optional revocation reason for audit log.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        identity_manager: Injected AgentIdentityManager.

    Raises:
        HTTPException: 404 if the agent does not exist.
    """
    try:
        await identity_manager.revoke_agent(
            agent_id=agent_id,
            tenant_id=uuid.UUID(tenant.tenant_id),
            reason=body.reason,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


# ---------------------------------------------------------------------------
# Behavioral profile and anomalies
# ---------------------------------------------------------------------------


@router.get(
    "/agents/{agent_id}/behavioral-profile",
    response_model=AgentBehavioralProfileResponse,
    summary="Retrieve behavioral profile for an agent",
    tags=["Zero-Trust Agent Identity"],
)
async def get_behavioral_profile(
    agent_id: uuid.UUID,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    identity_manager: Any = Depends(_get_identity_manager),
) -> AgentBehavioralProfileResponse:
    """Retrieve the behavioral profile summary for an agent.

    Returns the agent's identity metadata and any behavioral baseline stats.

    Args:
        agent_id: Agent UUID.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        identity_manager: Injected AgentIdentityManager.

    Returns:
        AgentBehavioralProfileResponse with profile data.

    Raises:
        HTTPException: 404 if the agent does not exist.
    """
    try:
        profile = await identity_manager.get_behavioral_profile(
            agent_id=agent_id,
            tenant_id=uuid.UUID(tenant.tenant_id),
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    return AgentBehavioralProfileResponse(**profile)


@router.get(
    "/agents/anomalies",
    response_model=AnomalyListResponse,
    summary="List detected agent behavioral anomalies",
    tags=["Zero-Trust Agent Identity"],
)
async def list_anomalies(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    identity_manager: Any = Depends(_get_identity_manager),
) -> AnomalyListResponse:
    """List behavioral anomalies detected for agents in the tenant.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.
        page: Page number (1-based).
        page_size: Results per page.
        identity_manager: Injected AgentIdentityManager.

    Returns:
        Paginated AnomalyListResponse.
    """
    offset = (page - 1) * page_size
    anomalies = await identity_manager.list_anomalies(
        tenant_id=uuid.UUID(tenant.tenant_id),
        limit=page_size,
        offset=offset,
    )

    records = [
        AnomalyRecord(
            id=str(a.get("id", "")),
            agent_id=str(a.get("agent_id", "")),
            tenant_id=str(a.get("tenant_id", "")),
            detected_at=str(a.get("detected_at", "")),
            anomaly_type=str(a.get("anomaly_type", "")),
            anomaly_score=float(a.get("anomaly_score", 0.0)),
            description=str(a.get("description", "")),
            actions_taken=list(a.get("actions_taken", [])),
        )
        for a in anomalies
    ]

    return AnomalyListResponse(
        items=records,
        total=len(records),
        page=page,
        page_size=page_size,
    )
