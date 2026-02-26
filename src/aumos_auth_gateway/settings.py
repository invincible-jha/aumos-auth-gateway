"""Auth Gateway service settings extending AumOS base configuration."""

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Auth Gateway service settings.

    Extends the base AumOS settings with auth-gateway-specific configuration
    for Keycloak, OPA, Kong, and AI-agent privilege management.
    """

    service_name: str = "aumos-auth-gateway"

    # Keycloak configuration
    keycloak_base_url: str = Field(default="http://keycloak:8080", description="Keycloak server base URL")
    keycloak_admin_realm: str = Field(default="master", description="Keycloak admin realm name")
    keycloak_admin_client_id: str = Field(default="admin-cli", description="Keycloak admin client ID")
    keycloak_admin_username: str = Field(default="admin", description="Keycloak admin username")
    keycloak_admin_password: str = Field(default="", description="Keycloak admin password")
    keycloak_aumos_realm: str = Field(default="aumos", description="AumOS Keycloak realm name")
    keycloak_token_issuer: str = Field(
        default="http://keycloak:8080/realms/aumos",
        description="Expected JWT issuer (Keycloak realm URL)",
    )
    keycloak_audience: str = Field(default="aumos-platform", description="Expected JWT audience")
    keycloak_admin_timeout_seconds: int = Field(default=30, description="Keycloak admin API request timeout")

    # OPA configuration
    opa_base_url: str = Field(default="http://opa:8181", description="OPA REST API base URL")
    opa_timeout_seconds: int = Field(default=5, description="OPA policy evaluation timeout")
    opa_policy_prefix: str = Field(default="aumos", description="Root namespace for OPA policies")

    # Kong configuration
    kong_admin_url: str = Field(default="http://kong:8001", description="Kong admin API base URL")
    kong_timeout_seconds: int = Field(default=10, description="Kong admin API request timeout")

    # Agent identity settings
    agent_secret_min_length: int = Field(default=32, description="Minimum length for agent service account secrets")
    agent_secret_rotation_days: int = Field(default=90, description="Days before agent secret should be rotated")
    agent_max_privilege_level: int = Field(default=5, description="Maximum privilege level (SUPER_ADMIN)")

    # JWT settings for agent tokens
    agent_token_expiry_minutes: int = Field(default=60, description="Agent JWT token validity in minutes")
    user_token_expiry_minutes: int = Field(default=30, description="User JWT token validity in minutes")
    refresh_token_expiry_days: int = Field(default=7, description="Refresh token validity in days")

    # HITL (Human-in-the-loop) gate configuration
    hitl_required_privilege_level: int = Field(
        default=4,
        description="Privilege level at or above which HITL approval is required",
    )

    # Redis for token blacklisting
    token_blacklist_ttl_seconds: int = Field(default=86400, description="TTL for blacklisted tokens in Redis")

    model_config = SettingsConfigDict(env_prefix="AUMOS_AUTH_")
