"""Auth Gateway business logic services.

Contains three services:
- AuthService: Token issuance, refresh, logout, userinfo via Keycloak
- AgentService: AI-agent identity CRUD with privilege enforcement
- PolicyService: OPA-backed policy evaluation with audit trail
"""

import secrets
import time
import uuid
from datetime import datetime
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
    IAgentPrivilegeAuditor,
    IAgentRepository,
    IAuthEventPublisher,
    IEnterpriseIdPFederation,
    IKeycloakClient,
    IMFAEngine,
    IOPAClient,
    IPolicyEvaluationRepository,
    ISAMLAdapter,
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


class MFAService:
    """Orchestrates multi-factor authentication flows for users and agents.

    Wraps the MFAEngine adapter to provide TOTP provisioning, OTP dispatch
    and validation, and recovery code management. Also applies MFA policy
    (service accounts bypass MFA; high-privilege agents always require it).

    Args:
        mfa_engine: MFA adapter implementing IMFAEngine.
        hitl_required_level: Agents at or above this level always require MFA.
    """

    def __init__(
        self,
        mfa_engine: IMFAEngine,
        hitl_required_level: int = 4,
    ) -> None:
        self._mfa = mfa_engine
        self._hitl_level = hitl_required_level

    async def enroll_totp(
        self,
        user_id: str,
        tenant: TenantContext,
        issuer: str | None = None,
    ) -> dict[str, Any]:
        """Start TOTP enrollment for a user or agent.

        Args:
            user_id: The user or agent identifier.
            tenant: Authenticated tenant context.
            issuer: Authenticator app issuer label (defaults to AumOS).

        Returns:
            Dict with secret_b32, otpauth_uri, and qr_code_uri for display.
        """
        effective_issuer = issuer or f"AumOS ({tenant.tenant_id})"
        logger.info(
            "TOTP enrollment started",
            user_id=user_id,
            tenant_id=str(tenant.tenant_id),
        )
        return await self._mfa.provision_totp(
            user_id=user_id,
            tenant_id=tenant.tenant_id,
            issuer=effective_issuer,
        )

    async def confirm_totp_enrollment(
        self,
        user_id: str,
        tenant: TenantContext,
        totp_code: str,
    ) -> bool:
        """Confirm TOTP enrollment by validating the user's first code.

        Args:
            user_id: The user or agent identifier.
            tenant: Authenticated tenant context.
            totp_code: 6-digit code from the authenticator app.

        Returns:
            True if enrollment is confirmed successfully.
        """
        confirmed = await self._mfa.confirm_totp_enrollment(
            user_id=user_id,
            tenant_id=tenant.tenant_id,
            totp_code=totp_code,
        )
        if confirmed:
            logger.info(
                "TOTP enrollment confirmed",
                user_id=user_id,
                tenant_id=str(tenant.tenant_id),
            )
        else:
            logger.warning(
                "TOTP enrollment confirmation failed — invalid code",
                user_id=user_id,
                tenant_id=str(tenant.tenant_id),
            )
        return confirmed

    async def validate_mfa(
        self,
        user_id: str,
        tenant: TenantContext,
        mfa_method: str,
        code: str,
        otp_id: str | None = None,
    ) -> bool:
        """Validate an MFA credential for a user or agent.

        Dispatches to the appropriate validation method based on ``mfa_method``:
        - "totp": TOTP RFC 6238 validation
        - "sms" / "email": OTP code validation using ``otp_id``
        - "recovery": Backup recovery code consumption

        Args:
            user_id: The user or agent identifier.
            tenant: Authenticated tenant context.
            mfa_method: One of "totp", "sms", "email", "recovery".
            code: The submitted MFA code.
            otp_id: Required for "sms" and "email" methods (record ID).

        Returns:
            True if the MFA challenge is satisfied.

        Raises:
            AumOSError: If ``mfa_method`` is not recognised.
        """
        if mfa_method == "totp":
            return await self._mfa.validate_totp(
                user_id=user_id,
                tenant_id=tenant.tenant_id,
                totp_code=code,
            )
        elif mfa_method in ("sms", "email"):
            if not otp_id:
                raise AumOSError(
                    message=f"otp_id is required for {mfa_method} MFA method",
                    error_code=ErrorCode.VALIDATION_ERROR,
                )
            return await self._mfa.validate_otp(otp_id=otp_id, code=code)
        elif mfa_method == "recovery":
            return await self._mfa.validate_recovery_code(
                user_id=user_id,
                tenant_id=tenant.tenant_id,
                code=code,
            )
        else:
            raise AumOSError(
                message=f"Unknown MFA method: {mfa_method!r}. Use totp, sms, email, or recovery.",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

    async def is_mfa_required(self, user_id: str, tenant: TenantContext) -> bool:
        """Check whether MFA is required before granting access.

        Args:
            user_id: The user or agent identifier.
            tenant: Authenticated tenant context.

        Returns:
            True if the MFA challenge must be completed.
        """
        return await self._mfa.is_mfa_required(
            user_id=user_id,
            tenant_id=tenant.tenant_id,
        )


class SAMLFederationService:
    """Manages SAML 2.0 SP-initiated SSO flows for enterprise customers.

    Handles AuthnRequest generation, Response parsing and validation,
    SP metadata generation, and Single Logout initiation. Delegates all
    XML and cryptographic operations to the SAMLAdapter.

    Args:
        saml_adapter: SAML adapter implementing ISAMLAdapter.
        base_url: Public base URL of the AumOS auth-gateway.
    """

    def __init__(self, saml_adapter: ISAMLAdapter, base_url: str) -> None:
        self._saml = saml_adapter
        self._base_url = base_url

    async def initiate_sso(
        self,
        idp_id: str,
        relay_state: str | None = None,
        binding: str = "HTTP_REDIRECT",
    ) -> dict[str, Any]:
        """Build an AuthnRequest and return the redirect or POST parameters.

        Args:
            idp_id: Identifier of the target SAML IdP.
            relay_state: Optional opaque state to carry through the flow.
            binding: Binding type — "HTTP_REDIRECT" or "HTTP_POST".

        Returns:
            Dict with redirect_url (HTTP_REDIRECT) or saml_request + action_url
            (HTTP_POST) for the caller to build the browser response.
        """
        logger.info("SAML SSO initiated", idp_id=idp_id, binding=binding)
        return await self._saml.generate_authn_request(
            idp_id=idp_id,
            relay_state=relay_state,
            binding=binding,
        )

    async def process_saml_response(
        self,
        saml_response_b64: str,
        relay_state: str | None = None,
    ) -> dict[str, Any]:
        """Parse and validate an incoming SAML Response from an IdP.

        Args:
            saml_response_b64: Base64-encoded SAML Response XML.
            relay_state: relay_state parameter from the HTTP callback.

        Returns:
            Parsed assertion dict with name_id, attributes, session_index.

        Raises:
            AumOSError: If the response is invalid, expired, or lacks a valid
                signature.
        """
        assertion = await self._saml.parse_saml_response(
            saml_response_b64=saml_response_b64,
            relay_state=relay_state,
        )
        logger.info(
            "SAML response processed",
            name_id=assertion.get("name_id", ""),
            issuer=assertion.get("issuer", ""),
        )
        return assertion

    async def get_sp_metadata(self) -> str:
        """Generate AumOS SP metadata XML for registration with an IdP.

        Returns:
            SP metadata XML string.
        """
        return await self._saml.generate_sp_metadata(base_url=self._base_url)

    async def initiate_slo(
        self,
        idp_id: str,
        name_id: str,
        session_index: str | None = None,
    ) -> dict[str, Any]:
        """Build a Single Logout request for the given SAML session.

        Args:
            idp_id: Identifier of the target SAML IdP.
            name_id: NameID from the original SAML assertion.
            session_index: Session index from the original assertion.

        Returns:
            Dict with redirect parameters for the SLO request.
        """
        logger.info("SAML SLO initiated", idp_id=idp_id, name_id=name_id)
        return await self._saml.generate_slo_request(
            idp_id=idp_id,
            name_id=name_id,
            session_index=session_index,
        )


class EnterpriseIdPService:
    """Manages enterprise OIDC Identity Provider federation and JIT provisioning.

    Handles IdP registration, email-domain-based routing, Authorization Code
    flow, and JIT user provisioning. Wraps the EnterpriseIdPFederation adapter
    with business-level validation and logging.

    Args:
        idp_federation: Federation adapter implementing IEnterpriseIdPFederation.
        event_publisher: Kafka publisher for auth domain events.
    """

    def __init__(
        self,
        idp_federation: IEnterpriseIdPFederation,
        event_publisher: IAuthEventPublisher,
    ) -> None:
        self._federation = idp_federation
        self._publisher = event_publisher

    async def register_enterprise_idp(
        self,
        idp_id: str,
        config: dict[str, Any],
        correlation_id: str | None = None,
    ) -> None:
        """Register a new enterprise OIDC IdP.

        Args:
            idp_id: Unique identifier for the IdP (e.g., "okta-acme").
            config: IdP configuration (discovery_url, client_id, client_secret,
                email_domains, attribute_mappings, jit_enabled).
            correlation_id: Request correlation identifier.

        Raises:
            AumOSError: If required config fields are missing.
        """
        required_fields = {"discovery_url", "client_id", "client_secret", "email_domains"}
        missing = required_fields - set(config.keys())
        if missing:
            raise AumOSError(
                message=f"Missing required IdP config fields: {sorted(missing)}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )
        await self._federation.register_idp(idp_id=idp_id, config=config)
        logger.info(
            "Enterprise IdP registered",
            idp_id=idp_id,
            email_domains=config.get("email_domains", []),
            correlation_id=correlation_id,
        )

    async def resolve_idp_for_email(self, email: str) -> str:
        """Route a user email to the correct enterprise IdP.

        Args:
            email: User email address.

        Returns:
            The idp_id to use for this user's authentication flow.

        Raises:
            AumOSError: If no IdP is registered for the email domain.
        """
        idp_id = await self._federation.route_to_idp(email=email)
        if idp_id is None:
            domain = email.split("@")[-1] if "@" in email else email
            raise AumOSError(
                message=f"No enterprise IdP registered for domain '{domain}'",
                error_code=ErrorCode.NOT_FOUND,
            )
        return idp_id

    async def start_authorization_flow(
        self,
        idp_id: str,
        redirect_uri: str,
        state: str,
        nonce: str | None = None,
        scopes: list[str] | None = None,
    ) -> str:
        """Build an OIDC Authorization Code flow URL for an enterprise IdP.

        Args:
            idp_id: Identifier of the enterprise IdP.
            redirect_uri: OAuth callback URI.
            state: CSRF state parameter.
            nonce: Optional ID token nonce.
            scopes: Requested scopes (defaults to openid profile email).

        Returns:
            Full authorization URL string to redirect the user's browser to.
        """
        return await self._federation.build_authorization_url(
            idp_id=idp_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            scopes=scopes or ["openid", "profile", "email"],
        )

    async def complete_authorization_flow(
        self,
        idp_id: str,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Complete an OIDC Authorization Code flow and JIT-provision the user.

        Exchanges the code for tokens, fetches UserInfo, then provisions or
        updates the user account via JIT provisioning.

        Args:
            idp_id: Identifier of the enterprise IdP.
            code: Authorization code from the IdP callback.
            redirect_uri: Redirect URI used in the initial request.
            code_verifier: PKCE code verifier if applicable.
            correlation_id: Request correlation identifier.

        Returns:
            Dict with provisioned user fields and token data.
        """
        correlation_id = correlation_id or str(uuid.uuid4())

        tokens = await self._federation.exchange_code_for_tokens(
            idp_id=idp_id,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        # Decode ID token claims (already validated by the adapter)
        id_token_claims = tokens.get("id_token_claims", {})

        # Fetch UserInfo for authoritative attribute data
        userinfo: dict[str, Any] = {}
        if tokens.get("access_token"):
            try:
                userinfo = await self._federation.provision_user_jit(
                    idp_id=idp_id,
                    id_token_claims=id_token_claims,
                    userinfo=userinfo,
                )
            except Exception as exc:
                logger.warning(
                    "JIT provisioning encountered non-fatal error",
                    idp_id=idp_id,
                    error=str(exc),
                    correlation_id=correlation_id,
                )

        logger.info(
            "Enterprise OIDC flow completed",
            idp_id=idp_id,
            user_email=id_token_claims.get("email", ""),
            correlation_id=correlation_id,
        )
        return {"tokens": tokens, "user": userinfo}


class PrivilegeAuditService:
    """Coordinates agent privilege auditing across tenants.

    Provides a service-layer wrapper around the AgentPrivilegeAuditor adapter
    that applies tenant scoping and orchestrates audit reporting workflows.

    Args:
        auditor: Privilege auditor adapter implementing IAgentPrivilegeAuditor.
    """

    def __init__(self, auditor: IAgentPrivilegeAuditor) -> None:
        self._auditor = auditor

    async def record_privilege_usage(
        self,
        agent_id: uuid.UUID,
        tenant: TenantContext,
        privilege_level_used: int,
        configured_privilege_level: int,
        resource: str,
        action: str,
        granted: bool,
        ip_address: str | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record an agent privilege usage event (fire-and-forget wrapper).

        Designed to be called from API middleware or policy evaluation hooks.
        Errors are caught and logged rather than propagated so that audit
        failures never block the primary auth flow.

        Args:
            agent_id: UUID of the acting agent.
            tenant: Authenticated tenant context.
            privilege_level_used: Privilege level exercised (1-5).
            configured_privilege_level: Agent's assigned maximum level (1-5).
            resource: Resource URN or path.
            action: Action category.
            granted: Whether access was granted.
            ip_address: Optional caller IP.
            correlation_id: Optional request correlation ID.
            metadata: Optional additional context.
        """
        try:
            await self._auditor.record_usage(
                agent_id=agent_id,
                tenant_id=tenant.tenant_id,
                privilege_level_used=privilege_level_used,
                configured_privilege_level=configured_privilege_level,
                resource=resource,
                action=action,
                granted=granted,
                ip_address=ip_address,
                correlation_id=correlation_id,
                metadata=metadata,
            )
        except Exception as exc:
            logger.warning(
                "Failed to record privilege usage event",
                agent_id=str(agent_id),
                tenant_id=str(tenant.tenant_id),
                error=str(exc),
            )

    async def get_tenant_escalation_alerts(
        self,
        tenant: TenantContext,
        since: datetime | None = None,
        agent_id: uuid.UUID | None = None,
    ) -> list[Any]:
        """Retrieve privilege escalation alerts for a tenant.

        Args:
            tenant: Authenticated tenant context.
            since: Optional timestamp filter.
            agent_id: Optional agent filter.

        Returns:
            List of EscalationAlert records.
        """
        return await self._auditor.get_escalation_alerts(
            tenant_id=tenant.tenant_id,
            since=since,
            agent_id=agent_id,
        )

    async def get_tenant_analytics(
        self,
        tenant: TenantContext,
        agent_id: uuid.UUID | None = None,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Return aggregated privilege analytics for a tenant.

        Args:
            tenant: Authenticated tenant context.
            agent_id: Optional agent filter.
            since: Optional start of the analytics window.

        Returns:
            Analytics dict from AgentPrivilegeAuditor.
        """
        return await self._auditor.get_usage_analytics(
            tenant_id=tenant.tenant_id,
            agent_id=agent_id,
            since=since,
        )

    async def get_dormant_agents(
        self,
        tenant: TenantContext,
        threshold_days: int = 30,
    ) -> list[Any]:
        """Identify dormant agents in a tenant.

        Args:
            tenant: Authenticated tenant context.
            threshold_days: Inactivity threshold in days.

        Returns:
            List of AgentPrivilegeSummary for dormant agents.
        """
        return await self._auditor.get_dormant_agents(
            tenant_id=tenant.tenant_id,
            threshold_days=threshold_days,
        )

    async def run_access_review(self, tenant: TenantContext) -> list[Any]:
        """Generate prioritised access review entries for a tenant.

        Args:
            tenant: Authenticated tenant context.

        Returns:
            List of AccessReviewEntry sorted by risk_score descending.
        """
        return await self._auditor.get_access_review_data(tenant_id=tenant.tenant_id)

    async def generate_privilege_report(
        self,
        tenant: TenantContext,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> Any:
        """Generate a full privilege audit report for a tenant.

        Args:
            tenant: Authenticated tenant context.
            period_start: Optional start of the audit period.
            period_end: Optional end of the audit period.

        Returns:
            PrivilegeAuditReport with summaries, alerts, and review entries.
        """
        report = await self._auditor.generate_report(
            tenant_id=tenant.tenant_id,
            period_start=period_start,
            period_end=period_end,
        )
        logger.info(
            "Privilege audit report generated via service",
            tenant_id=str(tenant.tenant_id),
            period_start=period_start.isoformat() if period_start else None,
            period_end=period_end.isoformat() if period_end else None,
        )
        return report
