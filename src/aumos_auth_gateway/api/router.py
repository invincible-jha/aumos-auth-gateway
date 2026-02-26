"""API v1 router for AumOS Auth Gateway.

Provides endpoints for agent identity management, OPA policy evaluation,
Keycloak realm management, and tenant IAM operations. All endpoints are
mounted under /api/v1 and require a valid Bearer JWT token.

Routes delegate immediately to service layer — no business logic here.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from aumos_common.auth import TenantContext, get_current_tenant
from aumos_common.observability import get_logger
from aumos_common.pagination import PageRequest

from aumos_auth_gateway.api.schemas import (
    AgentCreateRequest,
    AgentCreateResponse,
    AgentListResponse,
    AgentPrivilegeUpdateRequest,
    AgentResponse,
    AgentSecretRotateResponse,
    AgentUpdateRequest,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyListResponse,
    RealmCreateRequest,
    RealmListResponse,
    RealmResponse,
    TenantRoleAssignRequest,
    TenantUserListResponse,
)
from aumos_auth_gateway.adapters.repositories import AgentRepository, PolicyEvaluationRepository
from aumos_auth_gateway.core.services import AgentService, PolicyService, TenantIAMService

logger = get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency factories
# ---------------------------------------------------------------------------


def _get_agent_service(request: Request) -> AgentService:
    """Build AgentService from app state.

    Args:
        request: FastAPI request with app state.

    Returns:
        Configured AgentService.
    """
    from aumos_common.database import get_db_session

    session = request.state.db_session if hasattr(request.state, "db_session") else None
    settings = request.app.state.settings
    return AgentService(
        agent_repo=AgentRepository(session) if session else _noop_repo(),  # type: ignore[arg-type]
        event_publisher=request.app.state.event_publisher,
        kong_client=request.app.state.kong_client,
        max_privilege_level=settings.agent_max_privilege_level,
        hitl_required_level=settings.hitl_required_privilege_level,
    )


def _get_policy_service(request: Request) -> PolicyService:
    """Build PolicyService from app state.

    Args:
        request: FastAPI request with app state.

    Returns:
        Configured PolicyService.
    """
    session = request.state.db_session if hasattr(request.state, "db_session") else None
    return PolicyService(
        opa_client=request.app.state.opa_client,
        evaluation_repo=PolicyEvaluationRepository(session) if session else _noop_eval_repo(),  # type: ignore[arg-type]
        event_publisher=request.app.state.event_publisher,
    )


def _get_iam_service(request: Request) -> TenantIAMService:
    """Build TenantIAMService from app state.

    Args:
        request: FastAPI request with app state.

    Returns:
        Configured TenantIAMService.
    """
    return TenantIAMService(keycloak=request.app.state.keycloak_client)


def _noop_repo() -> "AgentRepository":  # type: ignore[empty-body]
    """Placeholder — in production, session is always injected via middleware."""
    ...


def _noop_eval_repo() -> "PolicyEvaluationRepository":  # type: ignore[empty-body]
    """Placeholder — in production, session is always injected via middleware."""
    ...


# ---------------------------------------------------------------------------
# Agent identity endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/agents",
    response_model=AgentListResponse,
    summary="List agent identities for the current tenant",
    tags=["Agents"],
)
async def list_agents(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    agent_service: AgentService = Depends(_get_agent_service),
) -> AgentListResponse:
    """List all agent identities belonging to the authenticated tenant.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context (injected).
        page: Page number for pagination.
        page_size: Results per page.
        agent_service: Injected agent service.

    Returns:
        Paginated AgentListResponse.
    """
    page_request = PageRequest(page=page, page_size=page_size)
    page_response = await agent_service.list_agents(tenant=tenant, page_request=page_request)
    return AgentListResponse(
        items=page_response.items,
        total=page_response.total,
        page=page_response.page,
        page_size=page_response.page_size,
    )


@router.post(
    "/agents",
    response_model=AgentCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new agent identity",
    tags=["Agents"],
)
async def create_agent(
    request: Request,
    body: AgentCreateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: AgentService = Depends(_get_agent_service),
) -> AgentCreateResponse:
    """Register a new AI-agent identity with privilege level and capability constraints.

    Returns a one-time plaintext secret that cannot be recovered after this call.

    Args:
        request: FastAPI request.
        body: Agent creation parameters.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Returns:
        AgentCreateResponse with agent details and one-time plaintext secret.

    Raises:
        HTTPException: 400 if privilege level exceeds maximum.
    """
    from aumos_common.errors import AumOSError

    correlation_id = request.headers.get("X-Request-ID")
    try:
        agent, plaintext_secret = await agent_service.create_agent(
            tenant=tenant,
            request=body,
            correlation_id=correlation_id,
        )
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc.message))

    return AgentCreateResponse(agent=agent, plaintext_secret=plaintext_secret)


@router.get(
    "/agents/{agent_id}",
    response_model=AgentResponse,
    summary="Get agent identity details",
    tags=["Agents"],
)
async def get_agent(
    agent_id: uuid.UUID,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: AgentService = Depends(_get_agent_service),
) -> AgentResponse:
    """Retrieve detailed information about a specific agent identity.

    Args:
        agent_id: Agent UUID.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Returns:
        AgentResponse with full agent details.

    Raises:
        HTTPException: 404 if the agent does not exist within the tenant.
    """
    from aumos_common.errors import NotFoundError

    try:
        return await agent_service.get_agent(tenant=tenant, agent_id=agent_id)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )


@router.put(
    "/agents/{agent_id}/privilege",
    response_model=AgentResponse,
    summary="Update agent privilege level",
    tags=["Agents"],
)
async def update_agent_privilege(
    agent_id: uuid.UUID,
    body: AgentPrivilegeUpdateRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: AgentService = Depends(_get_agent_service),
) -> AgentResponse:
    """Update an agent's privilege level.

    Privilege escalation to level 4+ automatically enables HITL gates.
    Only tenant admins can elevate agents to PRIVILEGED or SUPER_ADMIN.

    Args:
        agent_id: Agent UUID.
        body: New privilege level and optional reason.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Returns:
        Updated AgentResponse.

    Raises:
        HTTPException: 400 if privilege level is invalid, 404 if agent not found.
    """
    from aumos_common.errors import AumOSError, NotFoundError

    update_request = AgentUpdateRequest(privilege_level=body.privilege_level)
    try:
        return await agent_service.update_agent(
            tenant=tenant,
            agent_id=agent_id,
            request=update_request,
        )
    except NotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {agent_id} not found")
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc.message))


@router.delete(
    "/agents/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke and delete an agent identity",
    tags=["Agents"],
)
async def delete_agent(
    agent_id: uuid.UUID,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: AgentService = Depends(_get_agent_service),
) -> None:
    """Revoke an agent identity and remove its Kong consumer.

    The agent's secret is invalidated immediately. The record is soft-deleted
    (status=revoked) for audit trail preservation.

    Args:
        agent_id: Agent UUID to revoke.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Raises:
        HTTPException: 404 if the agent does not exist.
    """
    from aumos_common.errors import NotFoundError

    try:
        await agent_service.delete_agent(tenant=tenant, agent_id=agent_id)
    except NotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {agent_id} not found")


@router.post(
    "/agents/{agent_id}/rotate-secret",
    response_model=AgentSecretRotateResponse,
    summary="Rotate agent service account secret",
    tags=["Agents"],
)
async def rotate_agent_secret(
    agent_id: uuid.UUID,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: AgentService = Depends(_get_agent_service),
) -> AgentSecretRotateResponse:
    """Rotate an agent's service account secret.

    The old secret is immediately invalidated. The new plaintext secret is
    returned only in this response and cannot be recovered afterward.

    Args:
        agent_id: Agent UUID.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Returns:
        AgentSecretRotateResponse with updated agent and new plaintext secret.

    Raises:
        HTTPException: 404 if the agent does not exist.
    """
    from aumos_common.errors import NotFoundError

    try:
        agent, plaintext_secret = await agent_service.rotate_secret(tenant=tenant, agent_id=agent_id)
    except NotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {agent_id} not found")

    return AgentSecretRotateResponse(agent=agent, plaintext_secret=plaintext_secret)


# ---------------------------------------------------------------------------
# Policy evaluation endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/policies/evaluate",
    response_model=PolicyEvaluateResponse,
    summary="Evaluate an OPA authorization policy",
    tags=["Policies"],
)
async def evaluate_policy(
    body: PolicyEvaluateRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    policy_service: PolicyService = Depends(_get_policy_service),
) -> PolicyEvaluateResponse:
    """Evaluate an OPA policy for the given subject, resource, and action.

    The policy engine is queried and the result is recorded in the audit log.
    On OPA failure, the system fails closed (denies access).

    Args:
        body: Policy evaluation request with resource, action, and optional context.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        policy_service: Injected policy service.

    Returns:
        PolicyEvaluateResponse with allow/deny decision and explanation.
    """
    from aumos_common.auth import get_current_user

    subject = body.subject or request.headers.get("X-User-ID", "unknown")
    correlation_id = request.headers.get("X-Request-ID")

    return await policy_service.evaluate(
        tenant_id=tenant.tenant_id,
        request=body,
        subject=subject,
        correlation_id=correlation_id,
    )


@router.get(
    "/policies/evaluations",
    response_model=PolicyListResponse,
    summary="List policy evaluation audit history",
    tags=["Policies"],
)
async def list_policy_evaluations(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    policy_service: PolicyService = Depends(_get_policy_service),
) -> PolicyListResponse:
    """List the OPA policy evaluation audit history for the current tenant.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.
        page: Page number for pagination.
        page_size: Results per page.
        policy_service: Injected policy service.

    Returns:
        Paginated PolicyListResponse with evaluation records.
    """
    records, total = await policy_service.evaluation_repo.list_by_tenant(
        tenant_id=tenant.tenant_id,
        page=page,
        page_size=page_size,
    )
    return PolicyListResponse(
        items=records,  # type: ignore[arg-type]
        total=total,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Keycloak realm endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/realms",
    response_model=RealmListResponse,
    summary="List Keycloak realms",
    tags=["Realms"],
)
async def list_realms(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> RealmListResponse:
    """List all Keycloak realms visible to the admin account.

    Requires SUPER_ADMIN privilege. Realms map to AumOS tenants.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Returns:
        RealmListResponse with all visible realms.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    try:
        realms = await keycloak.list_realms()
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    realm_responses = [
        RealmResponse(
            id=r.get("id", r.get("realm", "")),
            realm=r.get("realm", ""),
            display_name=r.get("displayName"),
            enabled=r.get("enabled", True),
        )
        for r in realms
    ]
    return RealmListResponse(items=realm_responses, total=len(realm_responses))


@router.post(
    "/realms",
    response_model=RealmResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new Keycloak realm",
    tags=["Realms"],
)
async def create_realm(
    body: RealmCreateRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> RealmResponse:
    """Create a new Keycloak realm for a tenant.

    Requires SUPER_ADMIN privilege. Each enterprise tenant typically maps
    to a dedicated Keycloak realm for complete identity isolation.

    Args:
        body: Realm creation parameters.
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Returns:
        RealmResponse with new realm details.

    Raises:
        HTTPException: 503 if Keycloak is unavailable, 409 if realm already exists.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    try:
        realm_data = await keycloak.create_realm(
            realm_name=body.realm_name,
            display_name=body.display_name,
        )
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    return RealmResponse(
        id=realm_data.get("id", body.realm_name),
        realm=realm_data.get("realm", body.realm_name),
        display_name=realm_data.get("display_name", body.display_name),
        enabled=realm_data.get("enabled", True),
    )


# ---------------------------------------------------------------------------
# Tenant IAM endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/tenants/{tenant_id}/users",
    response_model=TenantUserListResponse,
    summary="List users in a tenant",
    tags=["Tenant IAM"],
)
async def list_tenant_users(
    tenant_id: uuid.UUID,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    iam_service: TenantIAMService = Depends(_get_iam_service),
) -> TenantUserListResponse:
    """List users belonging to a specific tenant's Keycloak group.

    Args:
        tenant_id: Target tenant UUID.
        request: FastAPI request.
        tenant: Authenticated tenant context (must match tenant_id or be SUPER_ADMIN).
        page: Page number.
        page_size: Results per page.
        iam_service: Injected IAM service.

    Returns:
        TenantUserListResponse with user list and pagination metadata.
    """
    page_request = PageRequest(page=page, page_size=page_size)

    from aumos_common.auth import TenantContext as TC

    scoped_tenant = TC(tenant_id=tenant_id, roles=tenant.roles)
    return await iam_service.list_users(tenant=scoped_tenant, page_request=page_request)


@router.post(
    "/tenants/{tenant_id}/users/{user_id}/roles",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Assign a role to a tenant user",
    tags=["Tenant IAM"],
)
async def assign_tenant_user_role(
    tenant_id: uuid.UUID,
    user_id: str,
    body: TenantRoleAssignRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    iam_service: TenantIAMService = Depends(_get_iam_service),
) -> None:
    """Assign a role to a user within a tenant.

    Roles: admin, developer, viewer, auditor.

    Args:
        tenant_id: Target tenant UUID.
        user_id: Keycloak user UUID string.
        body: Role assignment request.
        request: FastAPI request.
        tenant: Authenticated tenant context.
        iam_service: Injected IAM service.

    Raises:
        HTTPException: 400 if the role is invalid, 503 if Keycloak is unavailable.
    """
    from aumos_common.auth import TenantContext as TC
    from aumos_common.errors import AumOSError

    scoped_tenant = TC(tenant_id=tenant_id, roles=tenant.roles)
    try:
        await iam_service.assign_role(tenant=scoped_tenant, user_id=user_id, request=body)
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc.message))
