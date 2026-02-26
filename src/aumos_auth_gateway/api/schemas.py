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
