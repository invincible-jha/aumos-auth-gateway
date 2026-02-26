"""Protocol interfaces for Auth Gateway services and adapters.

Using Protocol classes (structural typing) to keep core logic decoupled
from specific implementations and enable easy testing with mocks.
"""

import uuid
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
