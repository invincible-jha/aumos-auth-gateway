"""Protocol interfaces for Auth Gateway services and adapters.

Using Protocol classes (structural typing) to keep core logic decoupled
from specific implementations and enable easy testing with mocks.

New interfaces added for auth-gateway domain adapters:
  - IMFAEngine         — TOTP/OTP multi-factor authentication
  - ISAMLAdapter       — SAML 2.0 SP-initiated SSO flows
  - IEnterpriseIdPFederation — OIDC discovery and JIT provisioning
  - IAgentPrivilegeAuditor   — per-agent privilege tracking and reporting
"""

import uuid
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from aumos_auth_gateway.api.schemas import (
    AgentCreateRequest,
    AgentResponse,
    AgentUpdateRequest,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    TokenRequest,
    TokenResponse,
    UserInfoResponse,
)


@runtime_checkable
class IAgentRepository(Protocol):
    """Data access protocol for agent identities."""

    async def create(self, tenant_id: uuid.UUID, request: AgentCreateRequest) -> AgentResponse:
        """Persist a new agent identity and return the response with hashed secret."""
        ...

    async def get_by_id(self, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> AgentResponse | None:
        """Retrieve a single agent by ID within a tenant."""
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[AgentResponse], int]:
        """List agents for a tenant with pagination."""
        ...

    async def update(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        request: AgentUpdateRequest,
    ) -> AgentResponse | None:
        """Update agent attributes. Returns None if not found."""
        ...

    async def delete(self, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> bool:
        """Soft-delete (revoke) an agent. Returns True if found and deleted."""
        ...

    async def rotate_secret(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> tuple[AgentResponse, str] | None:
        """Rotate agent secret. Returns (updated_agent, new_plaintext_secret) or None."""
        ...

    async def get_by_service_account(self, service_account: str) -> AgentResponse | None:
        """Look up an agent by its service account name (for auth flows)."""
        ...


@runtime_checkable
class IPolicyEvaluationRepository(Protocol):
    """Data access protocol for policy evaluation audit records."""

    async def record(
        self,
        tenant_id: uuid.UUID,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        policy_name: str | None,
        evaluation_ms: float | None,
        context: dict[str, Any],
    ) -> None:
        """Persist a policy evaluation result for audit purposes."""
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], int]:
        """List evaluation records for a tenant with pagination."""
        ...


@runtime_checkable
class IOPAClient(Protocol):
    """Protocol for Open Policy Agent evaluation client."""

    async def evaluate(
        self,
        policy_path: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a policy and return the full decision result."""
        ...

    async def ping(self) -> bool:
        """Check OPA server liveness."""
        ...

    async def close(self) -> None:
        """Release underlying HTTP client resources."""
        ...


@runtime_checkable
class IKeycloakClient(Protocol):
    """Protocol for Keycloak admin API client."""

    async def get_token(self, username: str, password: str, client_id: str) -> TokenResponse:
        """Exchange credentials for a JWT token pair."""
        ...

    async def refresh_token(self, refresh_token_value: str, client_id: str) -> TokenResponse:
        """Refresh an access token using a refresh token."""
        ...

    async def logout(self, refresh_token_value: str, client_id: str) -> None:
        """Invalidate a user session in Keycloak."""
        ...

    async def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """Fetch user profile from Keycloak userinfo endpoint."""
        ...

    async def list_users(self, tenant_id: uuid.UUID, page: int, page_size: int) -> list[dict[str, Any]]:
        """List users belonging to a tenant group."""
        ...

    async def assign_role(self, tenant_id: uuid.UUID, user_id: str, role: str) -> None:
        """Assign a role to a user within a tenant."""
        ...

    async def ping(self) -> bool:
        """Check Keycloak server liveness."""
        ...

    async def close(self) -> None:
        """Release underlying HTTP client resources."""
        ...


@runtime_checkable
class IKongClient(Protocol):
    """Protocol for Kong admin API client."""

    async def upsert_consumer(self, consumer_id: str, custom_id: str) -> None:
        """Create or update a Kong consumer for an agent service account."""
        ...

    async def set_jwt_credential(self, consumer_id: str, key: str, secret: str) -> None:
        """Set JWT credentials on a Kong consumer."""
        ...

    async def delete_consumer(self, consumer_id: str) -> None:
        """Remove a Kong consumer."""
        ...

    async def get_rate_limit_config(self, service_name: str) -> dict[str, Any]:
        """Retrieve rate limit configuration for a service."""
        ...

    async def close(self) -> None:
        """Release underlying HTTP client resources."""
        ...


@runtime_checkable
class IAuthEventPublisher(Protocol):
    """Protocol for publishing auth domain events to Kafka."""

    async def publish_login(
        self,
        tenant_id: str,
        user_id: str,
        username: str,
        ip_address: str | None,
        correlation_id: str,
    ) -> None:
        """Publish a user login event."""
        ...

    async def publish_logout(
        self,
        tenant_id: str,
        user_id: str,
        correlation_id: str,
    ) -> None:
        """Publish a user logout event."""
        ...

    async def publish_agent_created(
        self,
        tenant_id: str,
        agent_id: str,
        agent_name: str,
        privilege_level: int,
        correlation_id: str,
    ) -> None:
        """Publish an agent identity creation event."""
        ...

    async def publish_policy_evaluated(
        self,
        tenant_id: str,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        correlation_id: str,
    ) -> None:
        """Publish a policy evaluation audit event."""
        ...


@runtime_checkable
class IAuthService(Protocol):
    """Protocol for the authentication and token management service."""

    async def issue_token(self, request: TokenRequest) -> TokenResponse:
        """Validate credentials and issue a JWT token pair."""
        ...

    async def refresh(self, refresh_token_value: str) -> TokenResponse:
        """Issue new access token from a valid refresh token."""
        ...

    async def logout(self, refresh_token_value: str) -> None:
        """Invalidate a session by revoking the refresh token."""
        ...

    async def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """Introspect a token and return user profile information."""
        ...


@runtime_checkable
class IPolicyService(Protocol):
    """Protocol for OPA-backed policy evaluation service."""

    async def evaluate(
        self,
        tenant_id: uuid.UUID,
        request: PolicyEvaluateRequest,
        subject: str,
    ) -> PolicyEvaluateResponse:
        """Evaluate a policy decision and record the audit trail."""
        ...

    async def get_policy(self, policy_path: str) -> dict[str, Any]:
        """Retrieve current policy content from OPA."""
        ...

    async def update_policy(self, policy_path: str, rego_content: str) -> None:
        """Upload new policy Rego to OPA."""
        ...


# ---------------------------------------------------------------------------
# MFA Engine
# ---------------------------------------------------------------------------


@runtime_checkable
class IMFAEngine(Protocol):
    """Protocol for multi-factor authentication operations.

    Supports TOTP (RFC 6238), SMS OTP, Email OTP, and recovery codes.
    """

    async def provision_totp(
        self,
        user_id: str,
        tenant_id: uuid.UUID,
        issuer: str,
    ) -> dict[str, Any]:
        """Provision a new TOTP secret and return provisioning data.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.
            issuer: Issuer label shown in authenticator apps.

        Returns:
            Dict with keys: secret_b32, otpauth_uri, qr_code_uri.
        """
        ...

    async def confirm_totp_enrollment(
        self,
        user_id: str,
        tenant_id: uuid.UUID,
        totp_code: str,
    ) -> bool:
        """Confirm TOTP enrollment by validating the first code.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.
            totp_code: 6-digit code from the authenticator app.

        Returns:
            True if the code is valid and enrollment is confirmed.
        """
        ...

    async def validate_totp(
        self,
        user_id: str,
        tenant_id: uuid.UUID,
        totp_code: str,
    ) -> bool:
        """Validate a TOTP code for an enrolled user.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.
            totp_code: 6-digit TOTP code to validate.

        Returns:
            True if the code is valid within the drift window.
        """
        ...

    async def send_sms_otp(self, user_id: str, tenant_id: uuid.UUID, phone_number: str) -> str:
        """Generate and dispatch a one-time passcode via SMS.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.
            phone_number: E.164-formatted destination phone number.

        Returns:
            The OTP record ID (for subsequent validation).
        """
        ...

    async def send_email_otp(self, user_id: str, tenant_id: uuid.UUID, email: str) -> str:
        """Generate and dispatch a one-time passcode via email.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.
            email: Destination email address.

        Returns:
            The OTP record ID (for subsequent validation).
        """
        ...

    async def validate_otp(self, otp_id: str, code: str) -> bool:
        """Validate a previously dispatched SMS or email OTP.

        Args:
            otp_id: Record ID returned from send_sms_otp / send_email_otp.
            code: The code entered by the user.

        Returns:
            True if the code matches and has not expired.
        """
        ...

    async def validate_recovery_code(
        self,
        user_id: str,
        tenant_id: uuid.UUID,
        code: str,
    ) -> bool:
        """Consume a backup recovery code for MFA bypass.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.
            code: One of the 8-character recovery codes.

        Returns:
            True if the code is valid (consumed atomically).
        """
        ...

    async def is_mfa_required(self, user_id: str, tenant_id: uuid.UUID) -> bool:
        """Check whether MFA is required for a given user or agent.

        Args:
            user_id: The user or agent identifier.
            tenant_id: UUID of the owning tenant.

        Returns:
            True if MFA must be completed before access is granted.
        """
        ...


# ---------------------------------------------------------------------------
# SAML Adapter
# ---------------------------------------------------------------------------


@runtime_checkable
class ISAMLAdapter(Protocol):
    """Protocol for SAML 2.0 SP-initiated SSO operations."""

    async def generate_authn_request(
        self,
        idp_id: str,
        relay_state: str | None,
        binding: str,
    ) -> dict[str, Any]:
        """Build a SAML AuthnRequest and return redirect/POST parameters.

        Args:
            idp_id: Identifier of the SAML Identity Provider.
            relay_state: Opaque value to include in the AuthnRequest.
            binding: SAMLBinding constant (HTTP_REDIRECT or HTTP_POST).

        Returns:
            Dict with keys appropriate for the binding (e.g., redirect_url,
            or saml_request + action_url for POST).
        """
        ...

    async def parse_saml_response(
        self,
        saml_response_b64: str,
        relay_state: str | None,
    ) -> dict[str, Any]:
        """Parse and validate a base64-encoded SAML Response.

        Args:
            saml_response_b64: Base64-encoded SAML Response XML.
            relay_state: Relay state from the HTTP response parameter.

        Returns:
            Dict with keys: name_id, attributes, session_index, issuer.

        Raises:
            AumOSError: If the response is invalid, expired, or unsigned.
        """
        ...

    async def fetch_idp_metadata(self, metadata_url: str) -> dict[str, Any]:
        """Fetch and parse IdP metadata from a URL.

        Args:
            metadata_url: URL of the IdP SAML metadata XML document.

        Returns:
            Dict with parsed metadata fields (entity_id, sso_url, etc.).
        """
        ...

    async def generate_sp_metadata(self, base_url: str) -> str:
        """Generate SP metadata XML for registration with an IdP.

        Args:
            base_url: Base URL of the AumOS auth-gateway service.

        Returns:
            SP metadata XML string.
        """
        ...

    async def generate_slo_request(
        self,
        idp_id: str,
        name_id: str,
        session_index: str | None,
    ) -> dict[str, Any]:
        """Build a SAML Single Logout Request.

        Args:
            idp_id: Identifier of the target Identity Provider.
            name_id: NameID from the original SAML assertion.
            session_index: Session index from the original assertion.

        Returns:
            Dict with redirect parameters for the SLO request.
        """
        ...


# ---------------------------------------------------------------------------
# Enterprise IdP Federation
# ---------------------------------------------------------------------------


@runtime_checkable
class IEnterpriseIdPFederation(Protocol):
    """Protocol for enterprise OIDC Identity Provider federation."""

    async def register_idp(self, idp_id: str, config: dict[str, Any]) -> None:
        """Register an enterprise OIDC IdP configuration.

        Args:
            idp_id: Unique identifier for the IdP.
            config: IdP configuration dict (discovery_url, client_id,
                client_secret, email_domains, attribute_mappings).
        """
        ...

    async def deregister_idp(self, idp_id: str) -> bool:
        """Remove an enterprise IdP registration.

        Args:
            idp_id: Unique identifier of the IdP to remove.

        Returns:
            True if the IdP was found and removed.
        """
        ...

    async def get_registered_idps(self) -> list[dict[str, Any]]:
        """Return a list of all registered enterprise IdP configurations.

        Returns:
            List of dicts with idp_id and non-sensitive config fields.
        """
        ...

    async def route_to_idp(self, email: str) -> str | None:
        """Determine which IdP to use for a given email address.

        Args:
            email: User email address to route.

        Returns:
            The idp_id that handles this email domain, or None if unknown.
        """
        ...

    async def build_authorization_url(
        self,
        idp_id: str,
        redirect_uri: str,
        state: str,
        nonce: str | None,
        scopes: list[str] | None,
    ) -> str:
        """Build an OIDC Authorization Code flow URL for a registered IdP.

        Args:
            idp_id: Unique identifier of the target IdP.
            redirect_uri: Callback URI for the authorization code.
            state: CSRF protection state parameter.
            nonce: Optional nonce for ID token validation.
            scopes: OAuth scopes to request (defaults to openid profile email).

        Returns:
            Full authorization URL string.
        """
        ...

    async def exchange_code_for_tokens(
        self,
        idp_id: str,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> dict[str, Any]:
        """Exchange an authorization code for tokens from an enterprise IdP.

        Args:
            idp_id: Unique identifier of the IdP.
            code: Authorization code received from the IdP callback.
            redirect_uri: Redirect URI used in the authorization request.
            code_verifier: PKCE code verifier if PKCE was used.

        Returns:
            Dict with access_token, id_token, refresh_token, expires_in.
        """
        ...

    async def provision_user_jit(
        self,
        idp_id: str,
        id_token_claims: dict[str, Any],
        userinfo: dict[str, Any],
    ) -> dict[str, Any]:
        """JIT-provision a user from enterprise IdP claims.

        Args:
            idp_id: Unique identifier of the source IdP.
            id_token_claims: Decoded claims from the OIDC ID token.
            userinfo: Claims from the OIDC UserInfo endpoint.

        Returns:
            Dict with provisioned user fields (user_id, email, roles, etc.).
        """
        ...


# ---------------------------------------------------------------------------
# Agent Privilege Auditor
# ---------------------------------------------------------------------------


@runtime_checkable
class IAgentPrivilegeAuditor(Protocol):
    """Protocol for per-agent privilege usage tracking and audit reporting."""

    async def record_usage(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        privilege_level_used: int,
        configured_privilege_level: int,
        resource: str,
        action: str,
        granted: bool,
        ip_address: str | None,
        correlation_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> Any:
        """Record a privilege usage event for an agent.

        Args:
            agent_id: UUID of the acting agent.
            tenant_id: UUID of the tenant context.
            privilege_level_used: Privilege level exercised (1-5).
            configured_privilege_level: Agent's assigned maximum level (1-5).
            resource: Resource URN or path that was accessed.
            action: Action category (read, write, execute, admin, cross_tenant).
            granted: Whether access was granted.
            ip_address: Optional caller IP.
            correlation_id: Optional request correlation ID.
            metadata: Optional additional context dict.

        Returns:
            PrivilegeUsageEvent record.
        """
        ...

    async def get_escalation_alerts(
        self,
        tenant_id: uuid.UUID,
        since: datetime | None,
        agent_id: uuid.UUID | None,
    ) -> list[Any]:
        """Return privilege escalation alerts for a tenant.

        Args:
            tenant_id: UUID of the tenant.
            since: Filter to alerts after this timestamp.
            agent_id: Optional agent filter.

        Returns:
            List of EscalationAlert records.
        """
        ...

    async def get_least_privilege_violations(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID | None,
    ) -> list[Any]:
        """Return events flagged as least-privilege violations.

        Args:
            tenant_id: UUID of the tenant.
            agent_id: Optional agent filter.

        Returns:
            List of PrivilegeUsageEvent records.
        """
        ...

    async def get_usage_analytics(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID | None,
        since: datetime | None,
    ) -> dict[str, Any]:
        """Return aggregated privilege usage analytics.

        Args:
            tenant_id: UUID of the tenant.
            agent_id: Optional agent filter.
            since: Optional start of the analytics window.

        Returns:
            Dict with counts and breakdowns.
        """
        ...

    async def get_dormant_agents(
        self,
        tenant_id: uuid.UUID,
        threshold_days: int,
    ) -> list[Any]:
        """Return agents with no activity in the past threshold_days days.

        Args:
            tenant_id: UUID of the tenant.
            threshold_days: Inactivity threshold in days.

        Returns:
            List of AgentPrivilegeSummary records.
        """
        ...

    async def get_access_review_data(
        self,
        tenant_id: uuid.UUID,
    ) -> list[Any]:
        """Return prioritised access review entries for all tenant agents.

        Args:
            tenant_id: UUID of the tenant.

        Returns:
            List of AccessReviewEntry records sorted by risk_score descending.
        """
        ...

    async def generate_report(
        self,
        tenant_id: uuid.UUID,
        period_start: datetime | None,
        period_end: datetime | None,
    ) -> Any:
        """Generate a comprehensive privilege audit report.

        Args:
            tenant_id: UUID of the tenant.
            period_start: Start of the reporting period.
            period_end: End of the reporting period.

        Returns:
            PrivilegeAuditReport with summaries, alerts, and review entries.
        """
        ...
