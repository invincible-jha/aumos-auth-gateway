"""Enterprise IdP Federation adapter for AumOS Auth Gateway.

Implements OIDC-based enterprise IdP integration: Discovery via .well-known
endpoint, Authorization Code flow, token exchange and validation, UserInfo
endpoint integration, IdP-to-tenant mapping, JIT user provisioning, and
multi-IdP routing.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)

_DISCOVERY_PATH = "/.well-known/openid-configuration"
_METADATA_CACHE_TTL_SECONDS = 3600  # Re-fetch IdP metadata every hour


@dataclass
class OIDCProviderMetadata:
    """Cached OIDC provider metadata from .well-known/openid-configuration.

    Attributes:
        issuer: IdP issuer URL.
        authorization_endpoint: Authorization URL.
        token_endpoint: Token exchange URL.
        userinfo_endpoint: UserInfo URL.
        jwks_uri: JWKS endpoint for token signature verification.
        scopes_supported: Supported OAuth scopes.
        response_types_supported: Supported response_type values.
        fetched_at: Unix timestamp when metadata was last fetched.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    scopes_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    fetched_at: float = field(default_factory=time.time)

    @property
    def is_stale(self) -> bool:
        """True if metadata should be re-fetched."""
        return time.time() - self.fetched_at > _METADATA_CACHE_TTL_SECONDS


@dataclass
class EnterpriseIdPConfig:
    """Configuration for a registered enterprise IdP.

    Attributes:
        idp_id: Unique identifier for this IdP registration.
        tenant_id: AumOS tenant this IdP is mapped to.
        display_name: Human-readable IdP name.
        issuer_url: OIDC issuer URL (used for discovery).
        client_id: OAuth client ID registered with this IdP.
        client_secret: OAuth client secret.
        scopes: OAuth scopes to request.
        email_domain: Email domain pattern for routing (e.g. "@acme.com").
        jit_provisioning_enabled: Auto-create users on first login.
        attribute_mappings: Map from IdP claim names to AumOS user attributes.
    """

    idp_id: str
    tenant_id: str
    display_name: str
    issuer_url: str
    client_id: str
    client_secret: str
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    email_domain: str = ""
    jit_provisioning_enabled: bool = True
    attribute_mappings: dict[str, str] = field(default_factory=dict)


@dataclass
class OIDCTokenResponse:
    """Token response from an enterprise IdP token exchange.

    Attributes:
        access_token: IdP-issued access token.
        id_token: OIDC ID token JWT.
        refresh_token: Optional refresh token.
        token_type: Token type (usually "Bearer").
        expires_in: Access token lifetime in seconds.
        scope: Granted scopes.
    """

    access_token: str
    id_token: str
    refresh_token: str | None
    token_type: str
    expires_in: int
    scope: str | None = None


@dataclass
class JITProvisioningResult:
    """Result of a JIT user provisioning operation.

    Attributes:
        user_id: AumOS user ID (newly created or existing).
        tenant_id: Tenant this user was provisioned into.
        email: User's email address.
        display_name: User's display name.
        was_created: True if a new user record was created.
        claims: Raw IdP claims used for provisioning.
    """

    user_id: str
    tenant_id: str
    email: str
    display_name: str
    was_created: bool
    claims: dict[str, Any]


class EnterpriseIdPFederation:
    """Enterprise OIDC IdP federation for AumOS Auth Gateway.

    Manages registrations for enterprise identity providers, performs OIDC
    Discovery, handles the Authorization Code flow, validates tokens, queries
    UserInfo endpoints, routes authentication requests to the correct IdP based
    on email domain, and provisions users on first login (JIT).

    Args:
        acs_callback_url: AumOS OAuth callback URL (redirect_uri for IdPs).
        http_timeout_seconds: Timeout for HTTP calls to IdP endpoints.
    """

    def __init__(
        self,
        acs_callback_url: str,
        http_timeout_seconds: int = 15,
    ) -> None:
        self._callback_url = acs_callback_url
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(http_timeout_seconds))

        # IdP registry
        self._idp_configs: dict[str, EnterpriseIdPConfig] = {}   # idp_id -> config
        self._domain_map: dict[str, str] = {}                     # email_domain -> idp_id
        self._metadata_cache: dict[str, OIDCProviderMetadata] = {}  # idp_id -> metadata
        self._pending_states: dict[str, str] = {}                  # state -> idp_id

    # ------------------------------------------------------------------
    # IdP registration
    # ------------------------------------------------------------------

    def register_idp(self, config: EnterpriseIdPConfig) -> None:
        """Register an enterprise IdP configuration.

        Args:
            config: IdP configuration including client credentials and domain mapping.
        """
        self._idp_configs[config.idp_id] = config
        if config.email_domain:
            self._domain_map[config.email_domain.lstrip("@").lower()] = config.idp_id
        logger.info("Enterprise IdP registered", idp_id=config.idp_id, tenant_id=config.tenant_id)

    def deregister_idp(self, idp_id: str) -> bool:
        """Remove an enterprise IdP registration.

        Args:
            idp_id: IdP to remove.

        Returns:
            True if removed, False if not found.
        """
        config = self._idp_configs.pop(idp_id, None)
        if config and config.email_domain:
            domain = config.email_domain.lstrip("@").lower()
            self._domain_map.pop(domain, None)
        self._metadata_cache.pop(idp_id, None)
        logger.info("Enterprise IdP deregistered", idp_id=idp_id)
        return config is not None

    def get_registered_idps(self) -> list[dict[str, Any]]:
        """List all registered enterprise IdP configurations.

        Returns:
            List of IdP summary dicts (excludes secrets).
        """
        return [
            {
                "idp_id": c.idp_id,
                "tenant_id": c.tenant_id,
                "display_name": c.display_name,
                "issuer_url": c.issuer_url,
                "email_domain": c.email_domain,
                "jit_enabled": c.jit_provisioning_enabled,
            }
            for c in self._idp_configs.values()
        ]

    # ------------------------------------------------------------------
    # Multi-IdP routing
    # ------------------------------------------------------------------

    def route_to_idp(self, email_or_domain: str) -> EnterpriseIdPConfig | None:
        """Determine which registered IdP should handle an authentication.

        Matches the email domain against registered IdP domain patterns.

        Args:
            email_or_domain: Email address or domain string to route.

        Returns:
            Matching EnterpriseIdPConfig or None if no match.
        """
        # Extract domain from email if full address given
        if "@" in email_or_domain:
            domain = email_or_domain.split("@", 1)[1].lower()
        else:
            domain = email_or_domain.lower().lstrip("@")

        idp_id = self._domain_map.get(domain)
        if not idp_id:
            logger.debug("No IdP registered for domain", domain=domain)
            return None

        return self._idp_configs.get(idp_id)

    # ------------------------------------------------------------------
    # OIDC Discovery
    # ------------------------------------------------------------------

    async def discover_metadata(self, idp_id: str) -> OIDCProviderMetadata:
        """Fetch and cache OIDC provider metadata from the .well-known endpoint.

        Args:
            idp_id: Registered IdP identifier.

        Returns:
            OIDCProviderMetadata with endpoints and capabilities.

        Raises:
            AumOSError: If the IdP is unknown or discovery fails.
        """
        config = self._idp_configs.get(idp_id)
        if not config:
            raise AumOSError(
                message=f"Unknown IdP: {idp_id}",
                error_code=ErrorCode.NOT_FOUND,
            )

        cached = self._metadata_cache.get(idp_id)
        if cached and not cached.is_stale:
            return cached

        discovery_url = f"{config.issuer_url.rstrip('/')}{_DISCOVERY_PATH}"
        try:
            response = await self._http.get(discovery_url)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"Cannot reach IdP discovery endpoint: {discovery_url}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 200:
            raise AumOSError(
                message=f"IdP discovery returned {response.status_code}: {discovery_url}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        data: dict[str, Any] = response.json()
        metadata = OIDCProviderMetadata(
            issuer=data.get("issuer", ""),
            authorization_endpoint=data.get("authorization_endpoint", ""),
            token_endpoint=data.get("token_endpoint", ""),
            userinfo_endpoint=data.get("userinfo_endpoint", ""),
            jwks_uri=data.get("jwks_uri", ""),
            scopes_supported=data.get("scopes_supported", []),
            response_types_supported=data.get("response_types_supported", []),
        )
        self._metadata_cache[idp_id] = metadata
        logger.info("OIDC metadata discovered and cached", idp_id=idp_id, issuer=metadata.issuer)
        return metadata

    # ------------------------------------------------------------------
    # Authorization Code flow
    # ------------------------------------------------------------------

    async def build_authorization_url(
        self,
        idp_id: str,
        additional_scopes: list[str] | None = None,
    ) -> tuple[str, str]:
        """Build an OIDC Authorization URL for the given IdP.

        Args:
            idp_id: Registered IdP identifier.
            additional_scopes: Extra scopes to request beyond the configured defaults.

        Returns:
            Tuple of (authorization_url, state_value) for the session.

        Raises:
            AumOSError: If IdP is unknown or metadata cannot be fetched.
        """
        config = self._idp_configs.get(idp_id)
        if not config:
            raise AumOSError(message=f"Unknown IdP: {idp_id}", error_code=ErrorCode.NOT_FOUND)

        metadata = await self.discover_metadata(idp_id)
        state = str(uuid.uuid4())
        self._pending_states[state] = idp_id

        scopes = list(config.scopes)
        if additional_scopes:
            for s in additional_scopes:
                if s not in scopes:
                    scopes.append(s)

        from urllib.parse import urlencode
        params = {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": self._callback_url,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": uuid.uuid4().hex,
        }
        url = f"{metadata.authorization_endpoint}?{urlencode(params)}"
        logger.info("Authorization URL built", idp_id=idp_id, state=state)
        return url, state

    async def exchange_code_for_tokens(
        self,
        code: str,
        state: str,
    ) -> tuple[OIDCTokenResponse, str]:
        """Exchange an authorization code for IdP tokens.

        Args:
            code: Authorization code from the IdP callback.
            state: State parameter from the authorization request.

        Returns:
            Tuple of (OIDCTokenResponse, idp_id).

        Raises:
            AumOSError: If state is unknown, code exchange fails, or IdP is unreachable.
        """
        idp_id = self._pending_states.pop(state, None)
        if not idp_id:
            raise AumOSError(
                message="Unknown or expired OIDC state parameter",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        config = self._idp_configs.get(idp_id)
        if not config:
            raise AumOSError(message=f"IdP {idp_id} was deregistered", error_code=ErrorCode.NOT_FOUND)

        metadata = await self.discover_metadata(idp_id)

        try:
            response = await self._http.post(
                metadata.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._callback_url,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                },
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"Cannot reach IdP token endpoint: {metadata.token_endpoint}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 200:
            raise AumOSError(
                message=f"Token exchange failed: {response.status_code} {response.text[:200]}",
                error_code=ErrorCode.UNAUTHORIZED,
            )

        data: dict[str, Any] = response.json()
        token_response = OIDCTokenResponse(
            access_token=data.get("access_token", ""),
            id_token=data.get("id_token", ""),
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 3600),
            scope=data.get("scope"),
        )
        logger.info("Authorization code exchanged for tokens", idp_id=idp_id)
        return token_response, idp_id

    # ------------------------------------------------------------------
    # UserInfo
    # ------------------------------------------------------------------

    async def get_user_info(self, idp_id: str, access_token: str) -> dict[str, Any]:
        """Fetch user profile claims from the IdP UserInfo endpoint.

        Args:
            idp_id: Registered IdP identifier.
            access_token: IdP-issued access token.

        Returns:
            UserInfo claims dict (OpenID Connect standard + provider extensions).

        Raises:
            AumOSError: If the UserInfo endpoint returns an error.
        """
        metadata = await self.discover_metadata(idp_id)

        try:
            response = await self._http.get(
                metadata.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Cannot reach IdP UserInfo endpoint",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code == 401:
            raise AumOSError(message="Access token rejected by IdP UserInfo endpoint", error_code=ErrorCode.UNAUTHORIZED)

        if response.status_code != 200:
            raise AumOSError(
                message=f"UserInfo endpoint returned {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        claims: dict[str, Any] = response.json()
        logger.info("UserInfo retrieved", idp_id=idp_id, sub=claims.get("sub", "")[:20])
        return claims

    # ------------------------------------------------------------------
    # JIT user provisioning
    # ------------------------------------------------------------------

    async def provision_user_jit(
        self,
        idp_id: str,
        claims: dict[str, Any],
        existing_user_lookup: Any | None = None,
    ) -> JITProvisioningResult:
        """Provision an AumOS user from IdP claims on first login.

        Applies attribute mappings from the IdP configuration to convert
        OIDC claims into AumOS user attributes. Skips provisioning and
        returns existing user data if the user already exists.

        Args:
            idp_id: Registered IdP identifier.
            claims: UserInfo claims from the IdP.
            existing_user_lookup: Optional callable (email) -> user_id | None
                for checking existing users. None assumes new user always.

        Returns:
            JITProvisioningResult with user ID and creation flag.

        Raises:
            AumOSError: If JIT provisioning is disabled for this IdP.
        """
        config = self._idp_configs.get(idp_id)
        if not config:
            raise AumOSError(message=f"Unknown IdP: {idp_id}", error_code=ErrorCode.NOT_FOUND)

        if not config.jit_provisioning_enabled:
            raise AumOSError(
                message=f"JIT provisioning is disabled for IdP '{idp_id}'",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        # Apply attribute mappings
        mapped_attrs = self._apply_attribute_mappings(claims, config.attribute_mappings)
        email: str = mapped_attrs.get("email") or claims.get("email", "")
        display_name: str = mapped_attrs.get("display_name") or claims.get("name", email)

        # Check for existing user
        was_created = True
        user_id: str = str(uuid.uuid4())

        if existing_user_lookup and email:
            existing_id = existing_user_lookup(email)
            if existing_id:
                user_id = existing_id
                was_created = False

        if was_created:
            logger.info("JIT user provisioned", idp_id=idp_id, email=email[:30], tenant_id=config.tenant_id)
        else:
            logger.info("Existing user found via JIT lookup", idp_id=idp_id, user_id=user_id)

        return JITProvisioningResult(
            user_id=user_id,
            tenant_id=config.tenant_id,
            email=email,
            display_name=display_name,
            was_created=was_created,
            claims=claims,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_attribute_mappings(
        self,
        claims: dict[str, Any],
        mappings: dict[str, str],
    ) -> dict[str, Any]:
        """Map IdP claims to AumOS user attributes.

        Args:
            claims: Raw IdP claims dict.
            mappings: Dict of {idp_claim_name: aumos_attribute_name}.

        Returns:
            Dict of {aumos_attribute_name: claim_value}.
        """
        result: dict[str, Any] = {}
        for idp_key, aumos_key in mappings.items():
            if idp_key in claims:
                result[aumos_key] = claims[idp_key]
        return result

    async def close(self) -> None:
        """Release the HTTP client resources."""
        await self._http.aclose()
