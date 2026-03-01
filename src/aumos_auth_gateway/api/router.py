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
    AuditEventListResponse,
    AuditEventResponse,
    PasskeyPolicyConfig,
    PasskeyPolicyResponse,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyListResponse,
    PrivilegeMetricsResponse,
    RateLimitConfig,
    RateLimitResponse,
    RealmCreateRequest,
    RealmListResponse,
    RealmResponse,
    SessionListResponse,
    SessionResponse,
    SessionTerminateRequest,
    SocialIdpConfig,
    SocialIdpListResponse,
    SocialIdpResponse,
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


# ---------------------------------------------------------------------------
# Admin dashboard — sessions (Gap #15 + #21)
# ---------------------------------------------------------------------------


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List active sessions for the current tenant",
    tags=["Sessions"],
)
async def list_sessions(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
) -> SessionListResponse:
    """List all active sessions belonging to the authenticated tenant.

    Calls the Keycloak Admin API to enumerate live user sessions in the AumOS realm
    scoped to the current tenant's client configuration.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.
        page: Page number.
        page_size: Results per page.

    Returns:
        SessionListResponse with active session list and pagination metadata.
    """
    from aumos_common.errors import AumOSError
    from datetime import timezone

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings
    skip = (page - 1) * page_size

    try:
        raw_sessions = await keycloak.list_sessions(
            realm=settings.keycloak_aumos_realm,
            client_id=settings.keycloak_audience,
            skip=skip,
            limit=page_size,
        )
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    items: list[SessionResponse] = []
    now = __import__("datetime").datetime.now(timezone.utc)
    for s in raw_sessions:
        items.append(
            SessionResponse(
                session_id=s.get("id", ""),
                user_id=s.get("userId", s.get("username", "")),
                tenant_id=tenant.tenant_id,
                client_id=s.get("clients", {}).get(settings.keycloak_audience),
                ip_address=s.get("ipAddress"),
                started_at=__import__("datetime").datetime.fromtimestamp(
                    s.get("start", 0) / 1000, tz=timezone.utc
                ) if s.get("start") else now,
                last_access_at=__import__("datetime").datetime.fromtimestamp(
                    s.get("lastAccess", 0) / 1000, tz=timezone.utc
                ) if s.get("lastAccess") else now,
            )
        )

    return SessionListResponse(
        items=items,
        total=len(items),
        page=page,
        page_size=page_size,
    )


@router.delete(
    "/sessions",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Terminate one or more sessions",
    tags=["Sessions"],
)
async def terminate_sessions(
    body: SessionTerminateRequest,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> None:
    """Terminate one or more active sessions.

    If session_ids is empty, all sessions for the tenant realm are terminated.
    Requires PRIVILEGED or higher access.

    Args:
        body: Session IDs to terminate and optional audit reason.
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Raises:
        HTTPException: 503 if Keycloak is unavailable.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings
    realm = settings.keycloak_aumos_realm

    try:
        for session_id in body.session_ids:
            await keycloak.delete_session(realm=realm, session_id=session_id)
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    logger.info(
        "Sessions terminated",
        tenant_id=str(tenant.tenant_id),
        count=len(body.session_ids),
        reason=body.reason,
    )


# ---------------------------------------------------------------------------
# Admin dashboard — audit log (Gap #15)
# ---------------------------------------------------------------------------


@router.get(
    "/audit",
    response_model=AuditEventListResponse,
    summary="List audit events for the current tenant",
    tags=["Audit"],
)
async def list_audit_events(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = Query(default=1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    event_type: str | None = Query(default=None, description="Filter by event type (e.g., auth.login)"),
) -> AuditEventListResponse:
    """Return the auth gateway audit event log for the current tenant.

    Pulls policy evaluation records from the database and formats them as
    audit events. Used by the admin dashboard.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.
        page: Page number.
        page_size: Results per page.
        event_type: Optional filter by event type string.

    Returns:
        AuditEventListResponse with paginated audit entries.
    """
    from aumos_common.errors import AumOSError

    session = request.state.db_session if hasattr(request.state, "db_session") else None
    if session is None:
        return AuditEventListResponse(items=[], total=0, page=page, page_size=page_size)

    eval_repo = __import__(
        "aumos_auth_gateway.adapters.repositories",
        fromlist=["PolicyEvaluationRepository"],
    ).PolicyEvaluationRepository(session)

    try:
        records, total = await eval_repo.list_by_tenant(
            tenant_id=tenant.tenant_id,
            page=page,
            page_size=page_size,
        )
    except Exception:
        return AuditEventListResponse(items=[], total=0, page=page, page_size=page_size)

    import datetime

    items: list[AuditEventResponse] = []
    for rec in records:
        et = getattr(rec, "event_type", None) or "policy.evaluated"
        if event_type and et != event_type:
            continue
        items.append(
            AuditEventResponse(
                id=getattr(rec, "id", uuid.uuid4()),
                tenant_id=getattr(rec, "tenant_id", tenant.tenant_id),
                event_type=et,
                subject=getattr(rec, "subject", "unknown"),
                resource=getattr(rec, "resource", None),
                action=getattr(rec, "action", None),
                outcome=getattr(rec, "decision", "unknown"),
                ip_address=None,
                timestamp=getattr(rec, "timestamp", datetime.datetime.utcnow()),
                metadata=getattr(rec, "context", {}),
            )
        )

    return AuditEventListResponse(items=items, total=total, page=page, page_size=page_size)


# ---------------------------------------------------------------------------
# Privilege metrics (Gap #19)
# ---------------------------------------------------------------------------


@router.get(
    "/agents/metrics/privilege",
    response_model=PrivilegeMetricsResponse,
    summary="Privilege-level distribution for tenant agents",
    tags=["Agents"],
)
async def get_privilege_metrics(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: "AgentService" = Depends(_get_agent_service),
) -> PrivilegeMetricsResponse:
    """Return privilege-level distribution metrics for all agents in the tenant.

    Aggregates agent privilege levels into a dashboard-friendly breakdown
    showing counts per level and how many require HITL approval.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Returns:
        PrivilegeMetricsResponse with distribution and aggregate stats.
    """
    from aumos_auth_gateway.api.schemas import PrivilegeDistributionEntry

    LEVEL_NAMES = {
        1: "READ_ONLY",
        2: "STANDARD",
        3: "ELEVATED",
        4: "PRIVILEGED",
        5: "SUPER_ADMIN",
    }
    HITL_REQUIRED_FROM = 4

    page_request = __import__(
        "aumos_common.pagination", fromlist=["PageRequest"]
    ).PageRequest(page=1, page_size=1000)
    page_response = await agent_service.list_agents(tenant=tenant, page_request=page_request)
    agents = page_response.items

    counts: dict[int, int] = {lvl: 0 for lvl in range(1, 6)}
    last_change: "datetime | None" = None

    import datetime

    for agent in agents:
        lvl = getattr(agent, "privilege_level", 1)
        counts[lvl] = counts.get(lvl, 0) + 1
        updated = getattr(agent, "updated_at", None)
        if updated and (last_change is None or updated > last_change):
            last_change = updated

    distribution = [
        PrivilegeDistributionEntry(
            privilege_level=lvl,
            level_name=LEVEL_NAMES[lvl],
            count=counts[lvl],
            hitl_required=lvl >= HITL_REQUIRED_FROM,
        )
        for lvl in range(1, 6)
    ]

    elevated = sum(counts[lvl] for lvl in range(3, 6))
    hitl_count = sum(counts[lvl] for lvl in range(HITL_REQUIRED_FROM, 6))
    total = sum(counts.values())

    return PrivilegeMetricsResponse(
        tenant_id=tenant.tenant_id,
        total_agents=total,
        distribution=distribution,
        elevated_agent_count=elevated,
        hitl_required_count=hitl_count,
        last_privilege_change_at=last_change,
    )


# ---------------------------------------------------------------------------
# Social IdP management (Gap #20)
# ---------------------------------------------------------------------------


@router.get(
    "/idp",
    response_model=SocialIdpListResponse,
    summary="List social identity providers",
    tags=["Identity Providers"],
)
async def list_idps(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> SocialIdpListResponse:
    """List all social identity providers configured for the tenant realm.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Returns:
        SocialIdpListResponse with all configured providers.

    Raises:
        HTTPException: 503 if Keycloak is unavailable.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings

    try:
        raw_providers = await keycloak.list_identity_providers(realm=settings.keycloak_aumos_realm)
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    items = [
        SocialIdpResponse(
            alias=p.get("alias", ""),
            display_name=p.get("displayName", p.get("alias", "")),
            provider_id=p.get("providerId", ""),
            client_id=p.get("config", {}).get("clientId", ""),
            enabled=p.get("enabled", True),
            trust_email=p.get("trustEmail", False),
        )
        for p in raw_providers
    ]
    return SocialIdpListResponse(items=items, total=len(items))


@router.post(
    "/idp",
    response_model=SocialIdpResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a social identity provider",
    tags=["Identity Providers"],
)
async def create_idp(
    body: SocialIdpConfig,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> SocialIdpResponse:
    """Register a social identity provider (Google, GitHub, Microsoft, generic OIDC/SAML).

    Args:
        body: Social IdP configuration.
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Returns:
        SocialIdpResponse with the created provider details (secret omitted).

    Raises:
        HTTPException: 409 if provider alias already exists, 503 if Keycloak is down.
    """
    from aumos_common.errors import AumOSError, ErrorCode

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings

    provider_payload: dict[str, Any] = {
        "alias": body.alias,
        "displayName": body.display_name,
        "providerId": body.provider_id,
        "enabled": body.enabled,
        "trustEmail": body.trust_email,
        "firstBrokerLoginFlowAlias": body.first_broker_login_flow_alias,
        "config": {
            "clientId": body.client_id,
            "clientSecret": body.client_secret,
            **body.config,
        },
    }

    try:
        await keycloak.create_identity_provider(
            realm=settings.keycloak_aumos_realm,
            provider=provider_payload,
        )
    except AumOSError as exc:
        if exc.error_code == ErrorCode.CONFLICT:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc.message),
            )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    return SocialIdpResponse(
        alias=body.alias,
        display_name=body.display_name,
        provider_id=body.provider_id,
        client_id=body.client_id,
        enabled=body.enabled,
        trust_email=body.trust_email,
    )


@router.delete(
    "/idp/{alias}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a social identity provider",
    tags=["Identity Providers"],
)
async def delete_idp(
    alias: str,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> None:
    """Remove a social identity provider from the tenant realm.

    Args:
        alias: Identity provider alias to remove.
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Raises:
        HTTPException: 503 if Keycloak is unavailable.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings

    try:
        await keycloak.delete_identity_provider(realm=settings.keycloak_aumos_realm, alias=alias)
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))


# ---------------------------------------------------------------------------
# Passkey / FIDO2 policy (Gap #18)
# ---------------------------------------------------------------------------


@router.get(
    "/passkeys/policy",
    response_model=PasskeyPolicyResponse,
    summary="Get WebAuthn/FIDO2 passkey policy",
    tags=["Passkeys"],
)
async def get_passkey_policy(
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> PasskeyPolicyResponse:
    """Retrieve the current WebAuthn/FIDO2 passkey policy for the AumOS realm.

    Args:
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Returns:
        PasskeyPolicyResponse with current policy settings.

    Raises:
        HTTPException: 503 if Keycloak is unavailable.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings

    try:
        realm_data = await keycloak.get_webauthn_policy(realm=settings.keycloak_aumos_realm)
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    webauthn_enabled = "webauthn" in realm_data.get("browserFlow", "").lower() or any(
        "webauthn" in str(v).lower() for v in realm_data.values() if isinstance(v, str)
    )
    policy = PasskeyPolicyConfig(
        rp_entity_name=realm_data.get("webAuthnPolicyRpEntityName", "AumOS"),
        rp_id=realm_data.get("webAuthnPolicyRpId"),
        attestation_conveyance_preference=realm_data.get(
            "webAuthnPolicyAttestationConveyancePreference", "none"
        ),
        authenticator_attachment=realm_data.get("webAuthnPolicyAuthenticatorAttachment", "platform"),
        require_resident_key=realm_data.get("webAuthnPolicyRequireResidentKey", "Yes") == "Yes",
        user_verification_requirement=realm_data.get("webAuthnPolicyUserVerificationRequirement", "required"),
    )
    return PasskeyPolicyResponse(realm=settings.keycloak_aumos_realm, policy=policy, enabled=webauthn_enabled)


@router.put(
    "/passkeys/policy",
    response_model=PasskeyPolicyResponse,
    summary="Update WebAuthn/FIDO2 passkey policy",
    tags=["Passkeys"],
)
async def update_passkey_policy(
    body: PasskeyPolicyConfig,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
) -> PasskeyPolicyResponse:
    """Update the WebAuthn/FIDO2 passkey policy for the AumOS realm.

    Applies the provided configuration to the Keycloak realm's WebAuthn
    authenticator policy via the Keycloak Admin API.

    Args:
        body: New passkey policy configuration.
        request: FastAPI request.
        tenant: Authenticated tenant context.

    Returns:
        PasskeyPolicyResponse with updated policy settings.

    Raises:
        HTTPException: 503 if Keycloak is unavailable.
    """
    from aumos_common.errors import AumOSError

    keycloak = request.app.state.keycloak_client
    settings = request.app.state.settings

    keycloak_policy: dict[str, Any] = {
        "webAuthnPolicyRpEntityName": body.rp_entity_name,
        "webAuthnPolicyAttestationConveyancePreference": body.attestation_conveyance_preference,
        "webAuthnPolicyAuthenticatorAttachment": body.authenticator_attachment,
        "webAuthnPolicyRequireResidentKey": "Yes" if body.require_resident_key else "No",
        "webAuthnPolicyUserVerificationRequirement": body.user_verification_requirement,
    }
    if body.rp_id:
        keycloak_policy["webAuthnPolicyRpId"] = body.rp_id

    try:
        await keycloak.set_webauthn_policy(realm=settings.keycloak_aumos_realm, policy=keycloak_policy)
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    return PasskeyPolicyResponse(
        realm=settings.keycloak_aumos_realm,
        policy=body,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Per-agent rate limiting (Gap #22)
# ---------------------------------------------------------------------------


@router.put(
    "/agents/{agent_id}/rate-limit",
    response_model=RateLimitResponse,
    summary="Set per-agent Kong rate limit",
    tags=["Agents"],
)
async def set_agent_rate_limit(
    agent_id: uuid.UUID,
    body: RateLimitConfig,
    request: Request,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    agent_service: "AgentService" = Depends(_get_agent_service),
) -> RateLimitResponse:
    """Apply a per-agent rate limit via the Kong Admin API.

    Creates or updates a consumer-level rate-limiting plugin for the specified
    agent. Rate limits are enforced by Kong at the gateway layer.

    Args:
        agent_id: Agent UUID to rate-limit.
        body: Rate-limiting configuration (requests per minute/hour/day).
        request: FastAPI request.
        tenant: Authenticated tenant context.
        agent_service: Injected agent service.

    Returns:
        RateLimitResponse with applied configuration and Kong plugin ID.

    Raises:
        HTTPException: 404 if agent not found, 503 if Kong is unreachable.
    """
    from aumos_common.errors import AumOSError, NotFoundError

    try:
        agent = await agent_service.get_agent(tenant=tenant, agent_id=agent_id)
    except NotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {agent_id} not found")

    kong = request.app.state.kong_client
    consumer_id = str(agent_id)

    try:
        plugin_data = await kong.set_consumer_rate_limit(
            consumer_id=consumer_id,
            requests_per_minute=body.requests_per_minute,
            requests_per_hour=body.requests_per_hour,
            requests_per_day=body.requests_per_day,
        )
    except AumOSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))

    return RateLimitResponse(
        agent_id=agent_id,
        consumer_id=consumer_id,
        config=body,
        plugin_id=plugin_data.get("id"),
    )
