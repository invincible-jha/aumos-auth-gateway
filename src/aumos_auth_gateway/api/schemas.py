"""Pydantic request/response schemas for the Auth Gateway API.

All API inputs and outputs are validated through these models. Never return
raw dicts from endpoints — always use a typed schema defined here.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Token / Auth schemas
# ---------------------------------------------------------------------------


class TokenRequest(BaseModel):
    """OAuth2-compatible token request body.

    Supports password and client_credentials grant types.
    """

    grant_type: str = Field(default="password", description="OAuth2 grant type")
    username: str | None = Field(default=None, description="Username (password grant)")
    password: str | None = Field(default=None, description="Password (password grant)")
    client_id: str | None = Field(default=None, description="Client ID override")
    client_secret: str | None = Field(default=None, description="Client secret (client_credentials grant)")
    scope: str | None = Field(default=None, description="Requested OAuth2 scopes")


class TokenResponse(BaseModel):
    """JWT token pair response.

    Returned after successful authentication or token refresh.
    """

    access_token: str = Field(description="JWT access token")
    refresh_token: str | None = Field(default=None, description="Refresh token for obtaining new access tokens")
    token_type: str = Field(default="Bearer", description="Token type — always Bearer")
    expires_in: int = Field(description="Access token validity in seconds")
    refresh_expires_in: int | None = Field(default=None, description="Refresh token validity in seconds")
    scope: str | None = Field(default=None, description="Granted OAuth2 scopes")
    tenant_id: uuid.UUID | None = Field(default=None, description="Authenticated tenant UUID")
    user_id: str | None = Field(default=None, description="Authenticated user or agent ID")


class RefreshTokenRequest(BaseModel):
    """Request to refresh an access token."""

    refresh_token: str = Field(description="Valid refresh token")


class RevokeTokenRequest(BaseModel):
    """Request to revoke a token (logout)."""

    refresh_token: str = Field(description="Refresh token to revoke")
    user_id: str | None = Field(default=None, description="User ID for audit logging")
    tenant_id: str | None = Field(default=None, description="Tenant ID for audit logging")


class UserInfoResponse(BaseModel):
    """OIDC-compatible userinfo response.

    Returns standard claims about the authenticated user or agent.
    """

    sub: str = Field(description="Subject identifier (user/agent ID)")
    preferred_username: str | None = Field(default=None, description="Human-readable username")
    email: str | None = Field(default=None, description="Email address")
    email_verified: bool | None = Field(default=None, description="Whether email has been verified")
    given_name: str | None = Field(default=None, description="First name")
    family_name: str | None = Field(default=None, description="Last name")
    name: str | None = Field(default=None, description="Full display name")
    tenant_id: str | None = Field(default=None, description="Associated tenant ID")
    roles: list[str] = Field(default_factory=list, description="Assigned roles")


class OIDCDiscoveryResponse(BaseModel):
    """OpenID Connect discovery document (/.well-known/openid-configuration)."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    response_types_supported: list[str]
    grant_types_supported: list[str]
    subject_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]


# ---------------------------------------------------------------------------
# Agent Identity schemas
# ---------------------------------------------------------------------------


class AgentCreateRequest(BaseModel):
    """Request to register a new AI-agent identity.

    The agent receives a service account + secret pair. The plaintext secret
    is returned ONCE at creation and cannot be recovered afterward.
    """

    name: str = Field(min_length=1, max_length=255, description="Human-readable agent name")
    agent_type: str = Field(
        description="Agent category: synthesis, governance, security, orchestrator, analytics"
    )
    privilege_level: int = Field(
        default=1,
        ge=1,
        le=5,
        description="Privilege level 1-5 (1=READ_ONLY, 5=SUPER_ADMIN)",
    )
    allowed_tools: list[str] = Field(default_factory=list, description="Allowlisted tool names")
    allowed_models: list[str] = Field(default_factory=list, description="Allowlisted model IDs")
    max_tokens_per_hr: int = Field(default=100000, ge=1000, description="Token rate limit per hour")
    requires_hitl: bool = Field(default=False, description="Whether human approval is required before actions")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")


class AgentUpdateRequest(BaseModel):
    """Request to update an existing agent identity.

    Only non-None fields are applied. This is a partial update (PATCH semantics).
    """

    privilege_level: int | None = Field(default=None, ge=1, le=5, description="New privilege level")
    allowed_tools: list[str] | None = Field(default=None, description="Replacement tool allowlist")
    allowed_models: list[str] | None = Field(default=None, description="Replacement model allowlist")
    max_tokens_per_hr: int | None = Field(default=None, ge=1000, description="New token rate limit per hour")
    requires_hitl: bool | None = Field(default=None, description="Override HITL requirement")
    status: str | None = Field(default=None, description="New status: active, suspended, revoked")
    metadata: dict[str, Any] | None = Field(default=None, description="Replacement metadata")


class AgentPrivilegeUpdateRequest(BaseModel):
    """Targeted request to update only an agent's privilege level.

    Used by the PUT /agents/{agent_id}/privilege endpoint.
    """

    privilege_level: int = Field(ge=1, le=5, description="New privilege level 1-5")
    reason: str | None = Field(default=None, max_length=500, description="Reason for privilege change (audit)")


class AgentResponse(BaseModel):
    """Full agent identity response.

    The secret_hash field is never exposed. The plaintext secret is only
    available at creation time via AgentCreateResponse.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    agent_type: str
    privilege_level: int
    allowed_tools: list[str]
    allowed_models: list[str]
    max_tokens_per_hr: int
    requires_hitl: bool
    service_account: str
    status: str
    last_rotated_at: datetime
    metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class AgentCreateResponse(BaseModel):
    """Response returned only at agent creation — includes the plaintext secret.

    After this response, the plaintext secret cannot be recovered. Store it securely.
    """

    agent: AgentResponse
    plaintext_secret: str = Field(description="One-time plaintext secret — store securely, cannot be recovered")


class AgentSecretRotateResponse(BaseModel):
    """Response after secret rotation — includes new plaintext secret."""

    agent: AgentResponse
    plaintext_secret: str = Field(description="New plaintext secret — store securely, cannot be recovered")


class AgentListResponse(BaseModel):
    """Paginated list of agent identities."""

    items: list[AgentResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Policy evaluation schemas
# ---------------------------------------------------------------------------


class PolicyEvaluateRequest(BaseModel):
    """Request to evaluate an OPA authorization policy.

    The evaluator selects the appropriate policy based on resource type,
    or uses the explicitly provided policy_name.
    """

    subject: str | None = Field(default=None, description="Subject override (defaults to authenticated user/agent)")
    resource: str = Field(description="Resource being accessed (path or URN, e.g., /api/v1/agents or urn:agent:123)")
    action: str = Field(description="Action requested: read, write, delete, execute")
    policy_name: str | None = Field(default=None, description="Explicit OPA policy path override")
    context: dict[str, Any] | None = Field(default=None, description="Additional evaluation context")


class PolicyEvaluateResponse(BaseModel):
    """Result of an OPA policy evaluation."""

    allow: bool = Field(description="True if access is granted, False if denied")
    decision: str = Field(description="allow or deny")
    policy_name: str | None = Field(default=None, description="OPA policy path that produced the decision")
    evaluation_ms: float | None = Field(default=None, description="OPA evaluation latency in milliseconds")
    reason: str | None = Field(default=None, description="Human-readable explanation of the decision")


class PolicyEvaluationRecord(BaseModel):
    """A single policy evaluation audit record."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    subject: str
    resource: str
    action: str
    decision: str
    policy_name: str | None
    evaluation_ms: float | None
    timestamp: datetime
    context: dict[str, Any]


class PolicyListResponse(BaseModel):
    """Paginated list of policy evaluation records."""

    items: list[PolicyEvaluationRecord]
    total: int
    page: int
    page_size: int


class PolicyUpdateRequest(BaseModel):
    """Request to upload new Rego policy content to OPA."""

    rego_content: str = Field(min_length=1, description="Raw Rego policy text")


# ---------------------------------------------------------------------------
# Keycloak realm schemas
# ---------------------------------------------------------------------------


class RealmCreateRequest(BaseModel):
    """Request to create a new Keycloak realm."""

    realm_name: str = Field(min_length=1, max_length=255, description="Realm name (URL-safe identifier)")
    display_name: str | None = Field(default=None, description="Human-readable display name")
    enabled: bool = Field(default=True, description="Whether the realm is enabled")


class RealmResponse(BaseModel):
    """Keycloak realm details."""

    id: str
    realm: str
    display_name: str | None
    enabled: bool


class RealmListResponse(BaseModel):
    """List of Keycloak realms."""

    items: list[RealmResponse]
    total: int


# ---------------------------------------------------------------------------
# Tenant IAM schemas
# ---------------------------------------------------------------------------


class TenantRoleAssignRequest(BaseModel):
    """Request to assign a role to a user within a tenant."""

    role: str = Field(description="Role name: admin, developer, viewer, auditor")


class TenantUserResponse(BaseModel):
    """A user entry within a tenant's Keycloak group."""

    id: str
    username: str
    email: str | None
    enabled: bool
    roles: list[str]


class TenantUserListResponse(BaseModel):
    """Paginated list of tenant users."""

    users: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Session management schemas (Gap #21)
# ---------------------------------------------------------------------------


class SessionResponse(BaseModel):
    """An active Keycloak session for an authenticated user or agent.

    Attributes:
        session_id: Unique session identifier.
        user_id: User or agent ID owning this session.
        tenant_id: Tenant UUID the session belongs to.
        client_id: Keycloak client ID for the session.
        ip_address: Source IP address that initiated the session.
        started_at: Session start timestamp (UTC ISO 8601).
        last_access_at: Most recent activity timestamp (UTC ISO 8601).
        expires_at: Session expiry timestamp (UTC ISO 8601).
    """

    session_id: str
    user_id: str
    tenant_id: uuid.UUID | None = None
    client_id: str | None = None
    ip_address: str | None = None
    started_at: datetime
    last_access_at: datetime
    expires_at: datetime | None = None


class SessionListResponse(BaseModel):
    """Paginated list of active sessions.

    Attributes:
        items: List of SessionResponse objects.
        total: Total number of matching sessions.
        page: Current page number (1-based).
        page_size: Results per page.
    """

    items: list[SessionResponse]
    total: int
    page: int
    page_size: int


class SessionTerminateRequest(BaseModel):
    """Request to terminate one or more sessions.

    Attributes:
        session_ids: List of session IDs to terminate. Terminates all active
            sessions for the tenant if empty.
        reason: Optional audit reason for the termination.
    """

    session_ids: list[str] = []
    reason: str | None = Field(default=None, max_length=500)


# ---------------------------------------------------------------------------
# Admin audit schemas (Gap #15)
# ---------------------------------------------------------------------------


class AuditEventResponse(BaseModel):
    """A single audit log entry from the auth gateway.

    Attributes:
        id: Unique audit event UUID.
        tenant_id: Tenant this event belongs to.
        event_type: Type of event (e.g., auth.login, agent.created).
        subject: User or agent that triggered the event.
        resource: Target resource path or URN.
        action: Action performed (read, write, delete).
        outcome: Result of the action (success, failure, denied).
        ip_address: Source IP address.
        timestamp: Event timestamp (UTC ISO 8601).
        metadata: Additional structured event metadata.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    event_type: str
    subject: str
    resource: str | None = None
    action: str | None = None
    outcome: str
    ip_address: str | None = None
    timestamp: datetime
    metadata: dict[str, Any] = {}


class AuditEventListResponse(BaseModel):
    """Paginated list of audit events.

    Attributes:
        items: List of AuditEventResponse objects.
        total: Total number of matching events.
        page: Current page number (1-based).
        page_size: Results per page.
    """

    items: list[AuditEventResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Token exchange schemas (Gap #17)
# ---------------------------------------------------------------------------


class TokenExchangeRequest(BaseModel):
    """RFC 8693 token exchange request.

    Exchanges a Kubernetes ServiceAccount token (or other subject token)
    for an AumOS JWT issued by Keycloak.

    Attributes:
        subject_token: The token to be exchanged (e.g., K8s SA JWT).
        subject_token_type: Token type URN per RFC 8693.
        requested_token_type: Desired output token type URN.
        audience: Target service audience for the issued token.
        scope: Requested OAuth2 scopes for the issued token.
    """

    subject_token: str = Field(description="Token to exchange (K8s SA JWT or other subject token)")
    subject_token_type: str = Field(
        default="urn:ietf:params:oauth:token-type:jwt",
        description="Type of the subject_token per RFC 8693",
    )
    requested_token_type: str = Field(
        default="urn:ietf:params:oauth:token-type:access_token",
        description="Type of token to issue",
    )
    audience: str | None = Field(default=None, description="Target audience for the issued token")
    scope: str | None = Field(default=None, description="Requested scopes for the issued token")


class TokenExchangeResponse(BaseModel):
    """RFC 8693 token exchange response.

    Attributes:
        access_token: Issued AumOS JWT access token.
        issued_token_type: URN identifying the type of issued token.
        token_type: Token scheme (always Bearer).
        expires_in: Token validity in seconds.
        scope: Granted OAuth2 scopes.
        tenant_id: AumOS tenant UUID the token is scoped to.
    """

    access_token: str
    issued_token_type: str = "urn:ietf:params:oauth:token-type:access_token"
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None
    tenant_id: uuid.UUID | None = None


# ---------------------------------------------------------------------------
# Passkey / FIDO2 schemas (Gap #18)
# ---------------------------------------------------------------------------


class PasskeyPolicyConfig(BaseModel):
    """WebAuthn/FIDO2 passkey policy configuration for a realm.

    Attributes:
        rp_entity_name: Relying party display name shown in browser dialogs.
        rp_id: Relying party domain (must match the browser origin).
        attestation_conveyance_preference: Attestation preference (none/indirect/direct/enterprise).
        authenticator_attachment: Platform-specific authenticator binding (platform/cross-platform).
        require_resident_key: Whether to require a discoverable credential.
        user_verification_requirement: User verification policy (required/preferred/discouraged).
        passkey_registration_required: Whether passkey registration is enforced for all users.
    """

    rp_entity_name: str = Field(default="AumOS", description="Relying party display name")
    rp_id: str | None = Field(default=None, description="Relying party domain (e.g., aumos.ai)")
    attestation_conveyance_preference: str = Field(
        default="none",
        description="Attestation preference: none | indirect | direct | enterprise",
    )
    authenticator_attachment: str = Field(
        default="platform",
        description="Authenticator attachment: platform | cross-platform",
    )
    require_resident_key: bool = Field(default=True, description="Require discoverable credential")
    user_verification_requirement: str = Field(
        default="required",
        description="User verification: required | preferred | discouraged",
    )
    passkey_registration_required: bool = Field(
        default=False,
        description="Enforce passkey registration for all tenant users",
    )


class PasskeyPolicyResponse(BaseModel):
    """Current passkey policy for a Keycloak realm.

    Attributes:
        realm: Realm name the policy applies to.
        policy: PasskeyPolicyConfig containing the current policy settings.
        enabled: Whether the WebAuthn authenticator is enabled for this realm.
    """

    realm: str
    policy: PasskeyPolicyConfig
    enabled: bool


# ---------------------------------------------------------------------------
# Social IdP schemas (Gap #20)
# ---------------------------------------------------------------------------


class SocialIdpConfig(BaseModel):
    """Configuration for a social identity provider in Keycloak.

    Attributes:
        alias: Unique identifier for the IdP within the realm.
        display_name: Human-readable display name shown on the login page.
        provider_id: Keycloak provider type (google, github, microsoft, oidc, saml).
        client_id: OAuth2 client ID registered with the social provider.
        client_secret: OAuth2 client secret (write-only, never returned in responses).
        enabled: Whether the IdP is enabled.
        trust_email: Whether to trust email claims from this provider without verification.
        first_broker_login_flow_alias: Auth flow for first-time broker logins.
        config: Additional provider-specific configuration.
    """

    alias: str = Field(min_length=1, max_length=64, description="Unique IdP identifier in the realm")
    display_name: str = Field(default="", description="Display name on login page")
    provider_id: str = Field(description="Provider type: google | github | microsoft | oidc | saml")
    client_id: str = Field(description="OAuth2 client ID from the social provider")
    client_secret: str = Field(description="OAuth2 client secret (write-only)")
    enabled: bool = Field(default=True)
    trust_email: bool = Field(default=False, description="Trust email claims without verification")
    first_broker_login_flow_alias: str = Field(
        default="first broker login",
        description="Auth flow used on first-time broker login",
    )
    config: dict[str, Any] = Field(default_factory=dict, description="Provider-specific extra config")


class SocialIdpResponse(BaseModel):
    """Social identity provider details (without secret).

    Attributes:
        alias: Unique IdP identifier.
        display_name: Human-readable display name.
        provider_id: Keycloak provider type.
        client_id: OAuth2 client ID.
        enabled: Whether the IdP is active.
        trust_email: Whether email is trusted.
    """

    alias: str
    display_name: str
    provider_id: str
    client_id: str
    enabled: bool
    trust_email: bool


class SocialIdpListResponse(BaseModel):
    """List of social identity providers configured for a realm.

    Attributes:
        items: List of SocialIdpResponse objects.
        total: Total number of configured providers.
    """

    items: list[SocialIdpResponse]
    total: int


# ---------------------------------------------------------------------------
# Privilege metrics schemas (Gap #19)
# ---------------------------------------------------------------------------


class PrivilegeDistributionEntry(BaseModel):
    """Count of agents at a specific privilege level.

    Attributes:
        privilege_level: Agent privilege level (1-5).
        level_name: Human-readable name for the privilege level.
        count: Number of active agents at this privilege level.
        hitl_required: Whether HITL gates are required at this level.
    """

    privilege_level: int
    level_name: str
    count: int
    hitl_required: bool


class PrivilegeMetricsResponse(BaseModel):
    """Privilege-level distribution and audit metrics for a tenant.

    Attributes:
        tenant_id: Tenant UUID.
        total_agents: Total active agent count across all levels.
        distribution: Per-level breakdown of agent counts.
        elevated_agent_count: Agents at privilege level >= 3.
        hitl_required_count: Agents requiring human-in-the-loop approval.
        last_privilege_change_at: Timestamp of the most recent privilege update.
    """

    tenant_id: uuid.UUID
    total_agents: int
    distribution: list[PrivilegeDistributionEntry]
    elevated_agent_count: int
    hitl_required_count: int
    last_privilege_change_at: datetime | None = None


# ---------------------------------------------------------------------------
# Rate-limiting schemas (Gap #22)
# ---------------------------------------------------------------------------


class RateLimitConfig(BaseModel):
    """Per-agent Kong rate-limiting configuration.

    Attributes:
        requests_per_minute: Maximum API requests per minute.
        requests_per_hour: Optional maximum API requests per hour.
        requests_per_day: Optional maximum API requests per day.
    """

    requests_per_minute: int = Field(ge=1, description="Maximum requests per minute")
    requests_per_hour: int | None = Field(default=None, ge=1, description="Maximum requests per hour")
    requests_per_day: int | None = Field(default=None, ge=1, description="Maximum requests per day")


class RateLimitResponse(BaseModel):
    """Response after applying a per-agent rate limit.

    Attributes:
        agent_id: Agent UUID the rate limit was applied to.
        consumer_id: Kong consumer ID.
        config: Applied rate-limiting configuration.
        plugin_id: Kong plugin UUID for the created/updated rate-limit rule.
    """

    agent_id: uuid.UUID
    consumer_id: str
    config: RateLimitConfig
    plugin_id: str | None = None
