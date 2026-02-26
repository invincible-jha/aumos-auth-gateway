"""Auth Gateway business logic services.

Contains three services:
- AuthService: Token issuance, refresh, logout, userinfo via Keycloak
- AgentService: AI-agent identity CRUD with privilege enforcement
- PolicyService: OPA-backed policy evaluation with audit trail
"""

import secrets
import time
import uuid
from typing import Any

import bcrypt

from aumos_common.auth import TenantContext, UserContext
from aumos_common.errors import AumOSError, ErrorCode, NotFoundError
from aumos_common.observability import get_logger
from aumos_common.pagination import PageRequest, PageResponse

from aumos_auth_gateway.api.schemas import (
    AgentCreateRequest,
    AgentListResponse,
    AgentResponse,
    AgentUpdateRequest,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyListResponse,
    PolicyUpdateRequest,
    TenantRoleAssignRequest,
    TenantUserListResponse,
    TokenRequest,
    TokenResponse,
    UserInfoResponse,
)
from aumos_auth_gateway.core.interfaces import (
    IAgentRepository,
    IAuthEventPublisher,
    IKeycloakClient,
    IOPAClient,
    IPolicyEvaluationRepository,
)
from aumos_auth_gateway.core.models import AgentStatus, PrivilegeLevel

logger = get_logger(__name__)

_AGENT_SECRET_LENGTH = 48  # bytes → 64-char hex string


class AuthService:
    """Handles token issuance, refresh, logout, and userinfo via Keycloak.

    Delegates all token operations to Keycloak and publishes audit events
    to Kafka for downstream security monitoring.

    Args:
        keycloak: Keycloak admin client implementing IKeycloakClient.
        event_publisher: Kafka publisher for auth domain events.
        client_id: Default Keycloak client ID for token operations.
    """

    def __init__(
        self,
        keycloak: IKeycloakClient,
        event_publisher: IAuthEventPublisher,
        client_id: str = "aumos-platform",
    ) -> None:
        self._keycloak = keycloak
        self._publisher = event_publisher
        self._client_id = client_id

    async def issue_token(
        self,
        request: TokenRequest,
        ip_address: str | None = None,
        correlation_id: str | None = None,
    ) -> TokenResponse:
        """Authenticate a user/agent and return a JWT token pair.

        Args:
            request: Credentials (username+password or client_credentials).
            ip_address: Caller IP for audit logging.
            correlation_id: Request correlation ID.

        Returns:
            TokenResponse containing access_token and refresh_token.

        Raises:
            AumOSError: If credentials are invalid or Keycloak is unreachable.
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        client_id = request.client_id or self._client_id

        logger.info(
            "Token issuance requested",
            grant_type=request.grant_type,
            username=request.username,
            correlation_id=correlation_id,
        )

        token_response = await self._keycloak.get_token(
            username=request.username or "",
            password=request.password or "",
            client_id=client_id,
        )

        # Publish login audit event
        await self._publisher.publish_login(
            tenant_id=str(token_response.tenant_id or ""),
            user_id=str(token_response.user_id or ""),
            username=request.username or "",
            ip_address=ip_address,
            correlation_id=correlation_id,
        )

        logger.info(
            "Token issued",
            grant_type=request.grant_type,
            username=request.username,
            correlation_id=correlation_id,
        )
        return token_response

    async def refresh(
        self,
        refresh_token_value: str,
        correlation_id: str | None = None,
    ) -> TokenResponse:
        """Issue a new access token from a valid refresh token.

        Args:
            refresh_token_value: The refresh token string.
            correlation_id: Request correlation ID.

        Returns:
            New TokenResponse with fresh access token.
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        logger.info("Token refresh requested", correlation_id=correlation_id)

        token_response = await self._keycloak.refresh_token(
            refresh_token_value=refresh_token_value,
            client_id=self._client_id,
        )
        return token_response

    async def logout(
        self,
        refresh_token_value: str,
        user_id: str | None = None,
        tenant_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """Invalidate a session in Keycloak.

        Args:
            refresh_token_value: The refresh token to revoke.
            user_id: User ID for audit logging.
            tenant_id: Tenant ID for audit logging.
            correlation_id: Request correlation ID.
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        await self._keycloak.logout(
            refresh_token_value=refresh_token_value,
            client_id=self._client_id,
        )

        if user_id and tenant_id:
            await self._publisher.publish_logout(
                tenant_id=tenant_id,
                user_id=user_id,
                correlation_id=correlation_id,
            )

        logger.info("User logged out", user_id=user_id, correlation_id=correlation_id)

    async def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """Retrieve user profile from Keycloak userinfo endpoint.

        Args:
            access_token: Valid JWT access token.

        Returns:
            UserInfoResponse with standard OIDC claims.
        """
        return await self._keycloak.get_userinfo(access_token=access_token)


class AgentService:
    """Manages AI-agent identities with 5-level privilege enforcement.

    Handles creation, updates, deletion, and secret rotation for agent
    service accounts. Enforces privilege constraints and publishes
    lifecycle events to Kafka.

    Args:
        agent_repo: Repository for agent identity persistence.
        event_publisher: Kafka publisher for agent lifecycle events.
        kong_client: Kong admin client for consumer management.
        max_privilege_level: Maximum privilege level to allow (default 5).
        hitl_required_level: Privilege level at which HITL is auto-enabled.
    """

    def __init__(
        self,
        agent_repo: IAgentRepository,
        event_publisher: IAuthEventPublisher,
        kong_client: Any,
        max_privilege_level: int = 5,
        hitl_required_level: int = 4,
    ) -> None:
        self._repo = agent_repo
        self._publisher = event_publisher
        self._kong = kong_client
        self._max_privilege = max_privilege_level
        self._hitl_level = hitl_required_level

    async def create_agent(
        self,
        tenant: TenantContext,
        request: AgentCreateRequest,
        correlation_id: str | None = None,
    ) -> tuple[AgentResponse, str]:
        """Create a new agent identity and return (agent, plaintext_secret).

        The plaintext secret is returned ONCE at creation. After this call
        it is not recoverable — only the bcrypt hash is stored.

        Args:
            tenant: Authenticated tenant context.
            request: Agent creation parameters.
            correlation_id: Request correlation ID.

        Returns:
            Tuple of (AgentResponse, plaintext_secret_string).

        Raises:
            AumOSError: If privilege level exceeds maximum or request is invalid.
        """
        correlation_id = correlation_id or str(uuid.uuid4())

        if request.privilege_level > self._max_privilege:
            raise AumOSError(
                message=f"Privilege level {request.privilege_level} exceeds maximum {self._max_privilege}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        # Auto-enable HITL for high-privilege agents
        if request.privilege_level >= self._hitl_level and not request.requires_hitl:
            logger.info(
                "Auto-enabling HITL for privileged agent",
                privilege_level=request.privilege_level,
                agent_name=request.name,
            )
            request = request.model_copy(update={"requires_hitl": True})

        agent, plaintext_secret = await self._repo.create(
            tenant_id=tenant.tenant_id,
            request=request,
        )

        # Register consumer in Kong for JWT validation
        try:
            await self._kong.upsert_consumer(
                consumer_id=str(agent.id),
                custom_id=agent.service_account,
            )
        except Exception as exc:
            logger.warning(
                "Failed to register agent consumer in Kong",
                agent_id=str(agent.id),
                error=str(exc),
            )

        # Publish agent created event
        await self._publisher.publish_agent_created(
            tenant_id=str(tenant.tenant_id),
            agent_id=str(agent.id),
            agent_name=agent.name,
            privilege_level=agent.privilege_level,
            correlation_id=correlation_id,
        )

        logger.info(
            "Agent identity created",
            agent_id=str(agent.id),
            agent_name=agent.name,
            privilege_level=agent.privilege_level,
            tenant_id=str(tenant.tenant_id),
        )
        return agent, plaintext_secret

    async def get_agent(
        self,
        tenant: TenantContext,
        agent_id: uuid.UUID,
    ) -> AgentResponse:
        """Retrieve a single agent by ID.

        Args:
            tenant: Authenticated tenant context.
            agent_id: Agent UUID.

        Returns:
            AgentResponse if found.

        Raises:
            NotFoundError: If agent does not exist within tenant.
        """
        agent = await self._repo.get_by_id(tenant_id=tenant.tenant_id, agent_id=agent_id)
        if agent is None:
            raise NotFoundError(resource="agent", resource_id=str(agent_id))
        return agent

    async def list_agents(
        self,
        tenant: TenantContext,
        page_request: PageRequest,
    ) -> PageResponse[AgentResponse]:
        """List agents for a tenant with pagination.

        Args:
            tenant: Authenticated tenant context.
            page_request: Pagination parameters.

        Returns:
            Paginated page of AgentResponse objects.
        """
        agents, total = await self._repo.list_by_tenant(
            tenant_id=tenant.tenant_id,
            page=page_request.page,
            page_size=page_request.page_size,
        )
        return PageResponse(
            items=agents,
            total=total,
            page=page_request.page,
            page_size=page_request.page_size,
        )

    async def update_agent(
        self,
        tenant: TenantContext,
        agent_id: uuid.UUID,
        request: AgentUpdateRequest,
    ) -> AgentResponse:
        """Update agent configuration.

        Args:
            tenant: Authenticated tenant context.
            agent_id: Agent UUID.
            request: Fields to update (only non-None fields are applied).

        Returns:
            Updated AgentResponse.

        Raises:
            NotFoundError: If agent does not exist.
            AumOSError: If privilege escalation attempt detected.
        """
        if request.privilege_level is not None and request.privilege_level > self._max_privilege:
            raise AumOSError(
                message=f"Privilege level {request.privilege_level} exceeds maximum",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        agent = await self._repo.update(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            request=request,
        )
        if agent is None:
            raise NotFoundError(resource="agent", resource_id=str(agent_id))
        return agent

    async def delete_agent(
        self,
        tenant: TenantContext,
        agent_id: uuid.UUID,
    ) -> None:
        """Revoke and delete an agent identity.

        Also removes the Kong consumer to prevent further token usage.

        Args:
            tenant: Authenticated tenant context.
            agent_id: Agent UUID.

        Raises:
            NotFoundError: If agent does not exist.
        """
        found = await self._repo.delete(tenant_id=tenant.tenant_id, agent_id=agent_id)
        if not found:
            raise NotFoundError(resource="agent", resource_id=str(agent_id))

        try:
            await self._kong.delete_consumer(consumer_id=str(agent_id))
        except Exception as exc:
            logger.warning(
                "Failed to remove agent consumer from Kong",
                agent_id=str(agent_id),
                error=str(exc),
            )

        logger.info("Agent revoked", agent_id=str(agent_id), tenant_id=str(tenant.tenant_id))

    async def rotate_secret(
        self,
        tenant: TenantContext,
        agent_id: uuid.UUID,
    ) -> tuple[AgentResponse, str]:
        """Rotate an agent's service account secret.

        Generates a new cryptographically secure secret, updates the hash,
        and resets last_rotated_at. The old secret is immediately invalidated.

        Args:
            tenant: Authenticated tenant context.
            agent_id: Agent UUID.

        Returns:
            Tuple of (updated_AgentResponse, new_plaintext_secret).

        Raises:
            NotFoundError: If agent does not exist.
        """
        result = await self._repo.rotate_secret(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
        )
        if result is None:
            raise NotFoundError(resource="agent", resource_id=str(agent_id))

        agent, plaintext_secret = result
        logger.info(
            "Agent secret rotated",
            agent_id=str(agent_id),
            tenant_id=str(tenant.tenant_id),
        )
        return agent, plaintext_secret


class PolicyService:
    """OPA-backed authorization policy evaluation with full audit trail.

    Evaluates RBAC, ABAC, and agent privilege policies via OPA and records
    every decision to the policy_evaluations audit table.

    Args:
        opa_client: OPA REST API client.
        evaluation_repo: Repository for persisting evaluation records.
        event_publisher: Kafka publisher for policy evaluation events.
    """

    def __init__(
        self,
        opa_client: IOPAClient,
        evaluation_repo: IPolicyEvaluationRepository,
        event_publisher: IAuthEventPublisher,
    ) -> None:
        self._opa = opa_client
        self._repo = evaluation_repo
        self._publisher = event_publisher

    async def evaluate(
        self,
        tenant_id: uuid.UUID,
        request: PolicyEvaluateRequest,
        subject: str,
        correlation_id: str | None = None,
    ) -> PolicyEvaluateResponse:
        """Evaluate a policy decision and record the audit entry.

        Selects the appropriate OPA policy path based on the resource type,
        then queries OPA and persists the result.

        Args:
            tenant_id: Tenant context for the evaluation.
            request: Evaluation request with subject, resource, action.
            subject: The authenticated principal (user/agent ID).
            correlation_id: Request correlation ID.

        Returns:
            PolicyEvaluateResponse with allow/deny decision and explanation.
        """
        correlation_id = correlation_id or str(uuid.uuid4())
        start_ms = time.monotonic() * 1000

        # Build OPA input from request
        opa_input: dict[str, Any] = {
            "tenant_id": str(tenant_id),
            "subject": subject,
            "resource": request.resource,
            "action": request.action,
            "context": request.context or {},
        }

        # Determine which policy to evaluate
        policy_path = self._select_policy_path(request.resource, request.policy_name)

        try:
            result = await self._opa.evaluate(policy_path=policy_path, input_data=opa_input)
            elapsed_ms = time.monotonic() * 1000 - start_ms

            allow = bool(result.get("allow", False))
            decision = "allow" if allow else "deny"
            reason = result.get("reason", "")

        except AumOSError:
            # OPA unavailable — fail-closed (deny)
            logger.error("OPA unavailable, failing closed", correlation_id=correlation_id)
            elapsed_ms = time.monotonic() * 1000 - start_ms
            decision = "deny"
            allow = False
            reason = "Policy engine unavailable — access denied (fail-closed)"
            policy_path = "unavailable"

        # Record audit trail (fire-and-forget, don't fail the request)
        try:
            await self._repo.record(
                tenant_id=tenant_id,
                subject=subject,
                resource=request.resource,
                action=request.action,
                decision=decision,
                policy_name=policy_path,
                evaluation_ms=round(elapsed_ms, 2),
                context=opa_input,
            )
        except Exception as exc:
            logger.warning("Failed to record policy evaluation", error=str(exc))

        # Publish audit event
        await self._publisher.publish_policy_evaluated(
            tenant_id=str(tenant_id),
            subject=subject,
            resource=request.resource,
            action=request.action,
            decision=decision,
            correlation_id=correlation_id,
        )

        logger.info(
            "Policy evaluated",
            subject=subject,
            resource=request.resource,
            action=request.action,
            decision=decision,
            policy_path=policy_path,
            elapsed_ms=round(elapsed_ms, 2),
        )

        return PolicyEvaluateResponse(
            allow=allow,
            decision=decision,
            policy_name=policy_path,
            evaluation_ms=round(elapsed_ms, 2),
            reason=reason,
        )

    def _select_policy_path(self, resource: str, explicit_policy: str | None) -> str:
        """Select appropriate OPA policy path based on resource type.

        Args:
            resource: Resource identifier (e.g., "/api/v1/agents", "urn:agent:...")
            explicit_policy: Explicitly requested policy name (overrides auto-select).

        Returns:
            OPA policy path string.
        """
        if explicit_policy:
            return explicit_policy

        # Auto-select based on resource prefix
        if resource.startswith("urn:agent:"):
            return "agent/privilege_levels"
        if resource.startswith("urn:hitl:"):
            return "agent/hitl_gates"
        if "tenant" in resource.lower():
            return "rbac/tenant_isolation"
        if resource.startswith("/api/"):
            return "rbac/roles"
        return "abac/resource_access"

    async def get_policy(self, policy_path: str) -> dict[str, Any]:
        """Retrieve current policy Rego from OPA.

        Args:
            policy_path: Policy identifier path.

        Returns:
            Dictionary with policy content and metadata.
        """
        rego_content = await self._opa.get_policy(policy_path=policy_path)
        return {"policy_path": policy_path, "content": rego_content}

    async def update_policy(self, policy_path: str, request: PolicyUpdateRequest) -> None:
        """Upload new Rego policy to OPA.

        Args:
            policy_path: Policy identifier path.
            request: New policy content.
        """
        await self._opa.update_policy(policy_path=policy_path, rego_content=request.rego_content)
        logger.info("Policy updated", policy_path=policy_path)


class TenantIAMService:
    """Manages tenant user assignments and role management via Keycloak.

    Wraps Keycloak user/group/role operations for tenant-scoped IAM.

    Args:
        keycloak: Keycloak admin client.
    """

    def __init__(self, keycloak: IKeycloakClient) -> None:
        self._keycloak = keycloak

    async def list_users(
        self,
        tenant: TenantContext,
        page_request: PageRequest,
    ) -> TenantUserListResponse:
        """List users in a tenant's Keycloak group.

        Args:
            tenant: Authenticated tenant context.
            page_request: Pagination parameters.

        Returns:
            TenantUserListResponse with users and pagination metadata.
        """
        users = await self._keycloak.list_users(
            tenant_id=tenant.tenant_id,
            page=page_request.page,
            page_size=page_request.page_size,
        )
        return TenantUserListResponse(
            users=users,
            total=len(users),
            page=page_request.page,
            page_size=page_request.page_size,
        )

    async def assign_role(
        self,
        tenant: TenantContext,
        user_id: str,
        request: TenantRoleAssignRequest,
    ) -> None:
        """Assign a role to a user within the tenant's Keycloak group.

        Args:
            tenant: Authenticated tenant context.
            user_id: Keycloak user UUID string.
            request: Role assignment request.
        """
        valid_roles = {"admin", "developer", "viewer", "auditor"}
        if request.role not in valid_roles:
            raise AumOSError(
                message=f"Invalid role '{request.role}'. Must be one of: {sorted(valid_roles)}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )
        await self._keycloak.assign_role(
            tenant_id=tenant.tenant_id,
            user_id=user_id,
            role=request.role,
        )
        logger.info(
            "Role assigned",
            tenant_id=str(tenant.tenant_id),
            user_id=user_id,
            role=request.role,
        )
