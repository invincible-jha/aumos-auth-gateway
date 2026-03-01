"""Keycloak Admin REST API client for AumOS Auth Gateway.

Provides typed wrappers around Keycloak's Admin REST API for realm management,
user operations, role assignments, and token issuance. Also implements the
IKeycloakClient protocol for token/userinfo operations used by AuthService.

Keycloak Admin API docs: https://www.keycloak.org/docs-api/latest/rest-api/
"""

import uuid
from typing import Any

import httpx

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

from aumos_auth_gateway.api.schemas import TokenResponse, UserInfoResponse

logger = get_logger(__name__)


class KeycloakAdminClient:
    """HTTP client for the Keycloak Admin REST API.

    Handles authentication against the master realm admin endpoint and provides
    typed methods for realm/user/role/token operations used throughout Auth Gateway.

    Args:
        base_url: Keycloak server base URL (e.g., http://keycloak:8080)
        admin_realm: Admin realm name (default "master")
        client_id: Admin client ID (default "admin-cli")
        username: Admin username
        password: Admin password
        aumos_realm: Primary AumOS realm for user/token operations
        timeout_seconds: HTTP request timeout in seconds
    """

    def __init__(
        self,
        base_url: str,
        admin_realm: str = "master",
        client_id: str = "admin-cli",
        username: str = "admin",
        password: str = "",
        aumos_realm: str = "aumos",
        timeout_seconds: int = 30,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._admin_realm = admin_realm
        self._client_id = client_id
        self._username = username
        self._password = password
        self._aumos_realm = aumos_realm
        self._timeout = httpx.Timeout(timeout_seconds)
        self._http = httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout)
        self._admin_token: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_admin_token(self) -> str:
        """Obtain a short-lived admin access token from the master realm.

        Returns:
            Bearer token string for use in Admin API calls.

        Raises:
            AumOSError: If Keycloak is unreachable or credentials are invalid.
        """
        token_url = f"/realms/{self._admin_realm}/protocol/openid-connect/token"
        try:
            response = await self._http.post(
                token_url,
                data={
                    "grant_type": "password",
                    "client_id": self._client_id,
                    "username": self._username,
                    "password": self._password,
                },
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"Keycloak unreachable at {self._base_url}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 200:
            raise AumOSError(
                message=f"Keycloak admin authentication failed: {response.status_code}",
                error_code=ErrorCode.UNAUTHORIZED,
            )
        data: dict[str, Any] = response.json()
        token: str = data["access_token"]
        self._admin_token = token
        return token

    async def _admin_headers(self) -> dict[str, str]:
        """Build authorization headers for Admin API calls.

        Returns:
            Dict with Authorization and Content-Type headers.
        """
        token = await self._get_admin_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def _admin_request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Execute an authenticated Admin API request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            path: URL path relative to Keycloak base URL.
            json: Optional JSON request body.

        Returns:
            httpx.Response object.

        Raises:
            AumOSError: On connection errors.
        """
        headers = await self._admin_headers()
        try:
            response = await self._http.request(method, path, headers=headers, json=json)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"Keycloak Admin API unreachable: {path}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc
        return response

    # ------------------------------------------------------------------
    # Liveness
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """Check Keycloak server liveness.

        Returns:
            True if Keycloak responds to the health endpoint, False otherwise.
        """
        try:
            response = await self._http.get("/health/ready")
            return response.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Realm management
    # ------------------------------------------------------------------

    async def create_realm(self, realm_name: str, display_name: str | None = None) -> dict[str, Any]:
        """Create a new Keycloak realm.

        Args:
            realm_name: URL-safe realm identifier.
            display_name: Optional human-readable name.

        Returns:
            Created realm representation as a dict.

        Raises:
            AumOSError: If creation fails.
        """
        payload: dict[str, Any] = {
            "realm": realm_name,
            "displayName": display_name or realm_name,
            "enabled": True,
        }
        response = await self._admin_request("POST", "/admin/realms", json=payload)
        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to create realm '{realm_name}': {response.status_code} {response.text[:200]}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Keycloak realm created", realm_name=realm_name)
        return {"realm": realm_name, "display_name": display_name, "enabled": True}

    async def list_realms(self) -> list[dict[str, Any]]:
        """List all Keycloak realms visible to the admin account.

        Returns:
            List of realm representation dicts.

        Raises:
            AumOSError: If the request fails.
        """
        response = await self._admin_request("GET", "/admin/realms")
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to list realms: {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: list[dict[str, Any]] = response.json()
        return result

    async def create_client(self, realm: str, client_id: str, client_secret: str) -> dict[str, Any]:
        """Register a confidential client in a Keycloak realm.

        Args:
            realm: Target realm name.
            client_id: Client identifier string.
            client_secret: Client secret for confidential client.

        Returns:
            Created client representation as a dict.

        Raises:
            AumOSError: If the request fails.
        """
        payload: dict[str, Any] = {
            "clientId": client_id,
            "secret": client_secret,
            "enabled": True,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": True,
        }
        response = await self._admin_request("POST", f"/admin/realms/{realm}/clients", json=payload)
        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to create client '{client_id}' in realm '{realm}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Keycloak client created", realm=realm, client_id=client_id)
        result: dict[str, Any] = response.json() if response.content else {"clientId": client_id}
        return result

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    async def get_user(self, realm: str, user_id: str) -> dict[str, Any]:
        """Retrieve a single user by ID from a Keycloak realm.

        Args:
            realm: Realm name.
            user_id: Keycloak user UUID string.

        Returns:
            User representation dict.

        Raises:
            AumOSError: If user is not found or request fails.
        """
        response = await self._admin_request("GET", f"/admin/realms/{realm}/users/{user_id}")
        if response.status_code == 404:
            raise AumOSError(
                message=f"User '{user_id}' not found in realm '{realm}'",
                error_code=ErrorCode.NOT_FOUND,
            )
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to get user '{user_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: dict[str, Any] = response.json()
        return result

    async def list_users(
        self,
        realm: str,
        skip: int = 0,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List users in a Keycloak realm with pagination.

        Args:
            realm: Realm name.
            skip: Number of users to skip (offset).
            limit: Maximum number of users to return.

        Returns:
            List of user representation dicts.

        Raises:
            AumOSError: If the request fails.
        """
        response = await self._admin_request(
            "GET",
            f"/admin/realms/{realm}/users?first={skip}&max={limit}",
        )
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to list users in realm '{realm}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: list[dict[str, Any]] = response.json()
        return result

    async def assign_role(self, realm: str, user_id: str, role_name: str) -> None:
        """Assign a realm role to a user.

        First looks up the role representation, then assigns it to the user.

        Args:
            realm: Realm name.
            user_id: Keycloak user UUID string.
            role_name: Role name to assign.

        Raises:
            AumOSError: If the role or user is not found or assignment fails.
        """
        # Look up role representation
        role_response = await self._admin_request("GET", f"/admin/realms/{realm}/roles/{role_name}")
        if role_response.status_code == 404:
            raise AumOSError(
                message=f"Role '{role_name}' not found in realm '{realm}'",
                error_code=ErrorCode.NOT_FOUND,
            )
        if role_response.status_code != 200:
            raise AumOSError(
                message=f"Failed to look up role '{role_name}': {role_response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        role_repr: dict[str, Any] = role_response.json()

        # Assign role to user
        assign_response = await self._admin_request(
            "POST",
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            json=[role_repr],
        )
        if assign_response.status_code not in (200, 204):
            raise AumOSError(
                message=f"Failed to assign role '{role_name}' to user '{user_id}': {assign_response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Role assigned", realm=realm, user_id=user_id, role_name=role_name)

    # ------------------------------------------------------------------
    # IKeycloakClient protocol methods (used by AuthService)
    # ------------------------------------------------------------------

    async def get_token(
        self,
        username: str,
        password: str,
        client_id: str,
    ) -> TokenResponse:
        """Exchange username/password credentials for a JWT token pair.

        Args:
            username: User's username.
            password: User's password.
            client_id: Client ID to authenticate against.

        Returns:
            TokenResponse with access_token and refresh_token.

        Raises:
            AumOSError: If credentials are invalid or Keycloak is unreachable.
        """
        token_url = f"/realms/{self._aumos_realm}/protocol/openid-connect/token"
        try:
            response = await self._http.post(
                token_url,
                data={
                    "grant_type": "password",
                    "client_id": client_id,
                    "username": username,
                    "password": password,
                },
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Keycloak unreachable during token issuance",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code == 401:
            raise AumOSError(
                message="Invalid credentials",
                error_code=ErrorCode.UNAUTHORIZED,
            )
        if response.status_code != 200:
            raise AumOSError(
                message=f"Token issuance failed: {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        data: dict[str, Any] = response.json()
        return TokenResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 300),
            refresh_expires_in=data.get("refresh_expires_in"),
            scope=data.get("scope"),
        )

    async def refresh_token(self, refresh_token_value: str, client_id: str) -> TokenResponse:
        """Exchange a refresh token for a new access token.

        Args:
            refresh_token_value: Valid refresh token string.
            client_id: Client ID the refresh token was issued for.

        Returns:
            New TokenResponse with fresh access token.

        Raises:
            AumOSError: If the refresh token is invalid or expired.
        """
        token_url = f"/realms/{self._aumos_realm}/protocol/openid-connect/token"
        try:
            response = await self._http.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refresh_token_value,
                },
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Keycloak unreachable during token refresh",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code == 400:
            raise AumOSError(
                message="Refresh token is invalid or expired",
                error_code=ErrorCode.UNAUTHORIZED,
            )
        if response.status_code != 200:
            raise AumOSError(
                message=f"Token refresh failed: {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        data: dict[str, Any] = response.json()
        return TokenResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 300),
            refresh_expires_in=data.get("refresh_expires_in"),
            scope=data.get("scope"),
        )

    async def logout(self, refresh_token_value: str, client_id: str) -> None:
        """Invalidate a session by revoking the refresh token in Keycloak.

        Args:
            refresh_token_value: The refresh token to revoke.
            client_id: Client ID associated with the session.

        Raises:
            AumOSError: If Keycloak is unreachable.
        """
        logout_url = f"/realms/{self._aumos_realm}/protocol/openid-connect/logout"
        try:
            await self._http.post(
                logout_url,
                data={
                    "client_id": client_id,
                    "refresh_token": refresh_token_value,
                },
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Keycloak unreachable during logout",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc
        # Logout endpoint returns 204 on success; we don't fail if already expired.

    async def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """Fetch OIDC userinfo claims for an access token.

        Args:
            access_token: Valid JWT access token.

        Returns:
            UserInfoResponse with standard OIDC claims.

        Raises:
            AumOSError: If the token is invalid or Keycloak is unreachable.
        """
        userinfo_url = f"/realms/{self._aumos_realm}/protocol/openid-connect/userinfo"
        try:
            response = await self._http.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Keycloak unreachable during userinfo lookup",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code == 401:
            raise AumOSError(
                message="Access token is invalid or expired",
                error_code=ErrorCode.UNAUTHORIZED,
            )
        if response.status_code != 200:
            raise AumOSError(
                message=f"Userinfo request failed: {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        data: dict[str, Any] = response.json()
        realm_access: dict[str, Any] = data.get("realm_access", {})
        roles: list[str] = realm_access.get("roles", [])

        return UserInfoResponse(
            sub=data.get("sub", ""),
            preferred_username=data.get("preferred_username"),
            email=data.get("email"),
            email_verified=data.get("email_verified"),
            given_name=data.get("given_name"),
            family_name=data.get("family_name"),
            name=data.get("name"),
            tenant_id=data.get("tenant_id"),
            roles=roles,
        )

    # IKeycloakClient protocol method used by TenantIAMService
    async def list_users_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> list[dict[str, Any]]:
        """List users belonging to a tenant group in the AumOS realm.

        Args:
            tenant_id: Tenant UUID (maps to a Keycloak group).
            page: 1-based page number.
            page_size: Number of results per page.

        Returns:
            List of user representation dicts.
        """
        skip = (page - 1) * page_size
        group_id = str(tenant_id)
        response = await self._admin_request(
            "GET",
            f"/admin/realms/{self._aumos_realm}/groups/{group_id}/members?first={skip}&max={page_size}",
        )
        if response.status_code == 404:
            return []
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to list tenant users: {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: list[dict[str, Any]] = response.json()
        return result

    async def assign_role_to_tenant_user(
        self,
        tenant_id: uuid.UUID,
        user_id: str,
        role: str,
    ) -> None:
        """Assign a role to a user within the AumOS tenant realm.

        Args:
            tenant_id: Tenant UUID (for audit logging).
            user_id: Keycloak user UUID string.
            role: Role name to assign.
        """
        await self.assign_role(realm=self._aumos_realm, user_id=user_id, role_name=role)
        logger.info("Tenant role assigned", tenant_id=str(tenant_id), user_id=user_id, role=role)

    # ------------------------------------------------------------------
    # Token exchange (Gap #17 — RFC 8693 K8s OIDC token exchange)
    # ------------------------------------------------------------------

    async def exchange_token(
        self,
        subject_token: str,
        subject_token_type: str,
        requested_token_type: str,
        client_id: str,
        client_secret: str,
        audience: str | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Exchange a subject token for an AumOS JWT via Keycloak Token Exchange (RFC 8693).

        Used by the K8s OIDC integration to convert validated Kubernetes ServiceAccount
        tokens into AumOS JWTs without storing long-lived credentials.

        Args:
            subject_token: The token to be exchanged (e.g., a K8s SA JWT).
            subject_token_type: Token type URN per RFC 8693 (e.g., urn:ietf:params:oauth:token-type:jwt).
            requested_token_type: Desired output type URN (e.g., urn:ietf:params:oauth:token-type:access_token).
            client_id: Keycloak client authorized to perform token exchange.
            client_secret: Client secret for the exchange client.
            audience: Optional target audience for the issued token.
            scope: Optional OAuth2 scopes to request on the issued token.

        Returns:
            Token exchange response dict with access_token, expires_in, and scope.

        Raises:
            AumOSError: If Keycloak is unreachable or the exchange fails.
        """
        token_url = f"/realms/{self._aumos_realm}/protocol/openid-connect/token"
        form_data: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": client_id,
            "client_secret": client_secret,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "requested_token_type": requested_token_type,
        }
        if audience:
            form_data["audience"] = audience
        if scope:
            form_data["scope"] = scope

        try:
            response = await self._http.post(token_url, data=form_data)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Keycloak unreachable during token exchange",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code == 401:
            raise AumOSError(
                message="Token exchange rejected — invalid subject token or unauthorized client",
                error_code=ErrorCode.UNAUTHORIZED,
            )
        if response.status_code == 403:
            raise AumOSError(
                message="Token exchange forbidden — client not authorized for token exchange",
                error_code=ErrorCode.FORBIDDEN,
            )
        if response.status_code != 200:
            raise AumOSError(
                message=f"Token exchange failed: {response.status_code} {response.text[:200]}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        result: dict[str, Any] = response.json()
        logger.info("Token exchange successful", client_id=client_id, audience=audience)
        return result

    # ------------------------------------------------------------------
    # WebAuthn / FIDO2 passkey policy (Gap #18)
    # ------------------------------------------------------------------

    async def get_webauthn_policy(self, realm: str) -> dict[str, Any]:
        """Retrieve the WebAuthn authenticator policy for a Keycloak realm.

        Args:
            realm: Realm name to fetch the policy for.

        Returns:
            Dict containing webAuthnPolicyRpEntityName, webAuthnPolicyRpId,
            webAuthnPolicyAttestationConveyancePreference, and related fields.

        Raises:
            AumOSError: If the request fails.
        """
        response = await self._admin_request("GET", f"/admin/realms/{realm}")
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to get realm config for passkey policy: {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: dict[str, Any] = response.json()
        return result

    async def set_webauthn_policy(self, realm: str, policy: dict[str, Any]) -> None:
        """Update the WebAuthn authenticator policy for a Keycloak realm.

        Args:
            realm: Realm name to update.
            policy: Partial realm representation with WebAuthn policy fields.
                    Keycloak uses the top-level realm PUT to update webAuthnPolicy*.

        Raises:
            AumOSError: If the update fails.
        """
        response = await self._admin_request("PUT", f"/admin/realms/{realm}", json=policy)
        if response.status_code not in (200, 204):
            raise AumOSError(
                message=f"Failed to update WebAuthn policy for realm '{realm}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("WebAuthn policy updated", realm=realm)

    # ------------------------------------------------------------------
    # Social IdP management (Gap #20)
    # ------------------------------------------------------------------

    async def list_identity_providers(self, realm: str) -> list[dict[str, Any]]:
        """List all identity providers configured in a Keycloak realm.

        Args:
            realm: Realm name to list IdPs from.

        Returns:
            List of identity provider representation dicts.

        Raises:
            AumOSError: If the request fails.
        """
        response = await self._admin_request("GET", f"/admin/realms/{realm}/identity-provider/instances")
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to list identity providers for realm '{realm}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: list[dict[str, Any]] = response.json()
        return result

    async def create_identity_provider(self, realm: str, provider: dict[str, Any]) -> dict[str, Any]:
        """Register a new social identity provider in a Keycloak realm.

        Args:
            realm: Realm name.
            provider: Identity provider representation dict with alias, providerId, config, etc.

        Returns:
            Created identity provider representation dict.

        Raises:
            AumOSError: If creation fails or a provider with the same alias already exists.
        """
        response = await self._admin_request(
            "POST",
            f"/admin/realms/{realm}/identity-provider/instances",
            json=provider,
        )
        if response.status_code == 409:
            raise AumOSError(
                message=f"Identity provider '{provider.get('alias')}' already exists in realm '{realm}'",
                error_code=ErrorCode.CONFLICT,
            )
        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to create identity provider: {response.status_code} {response.text[:200]}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Identity provider created", realm=realm, alias=provider.get("alias"))
        created: dict[str, Any] = response.json() if response.content else provider
        return created

    async def delete_identity_provider(self, realm: str, alias: str) -> None:
        """Remove a social identity provider from a Keycloak realm.

        Args:
            realm: Realm name.
            alias: Identity provider alias to delete.

        Raises:
            AumOSError: If deletion fails (404 is silently ignored).
        """
        response = await self._admin_request(
            "DELETE",
            f"/admin/realms/{realm}/identity-provider/instances/{alias}",
        )
        if response.status_code not in (204, 404):
            raise AumOSError(
                message=f"Failed to delete identity provider '{alias}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Identity provider deleted", realm=realm, alias=alias)

    # ------------------------------------------------------------------
    # Session management (Gap #21)
    # ------------------------------------------------------------------

    async def list_sessions(
        self,
        realm: str,
        client_id: str | None = None,
        skip: int = 0,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List active user sessions in a Keycloak realm.

        Args:
            realm: Realm name to query sessions from.
            client_id: Optional client ID to filter sessions by.
            skip: Offset for pagination.
            limit: Maximum number of sessions to return.

        Returns:
            List of user session representation dicts.

        Raises:
            AumOSError: If the request fails.
        """
        if client_id:
            path = f"/admin/realms/{realm}/clients/{client_id}/user-sessions?first={skip}&max={limit}"
        else:
            path = f"/admin/realms/{realm}/sessions/stats"

        response = await self._admin_request("GET", path)
        if response.status_code != 200:
            raise AumOSError(
                message=f"Failed to list sessions for realm '{realm}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result: list[dict[str, Any]] = response.json() if isinstance(response.json(), list) else []
        return result

    async def delete_session(self, realm: str, session_id: str) -> None:
        """Terminate a specific user session in Keycloak.

        Args:
            realm: Realm name.
            session_id: Keycloak session UUID to terminate.

        Raises:
            AumOSError: If deletion fails (404 is silently ignored).
        """
        response = await self._admin_request(
            "DELETE",
            f"/admin/realms/{realm}/sessions/{session_id}",
        )
        if response.status_code not in (204, 404):
            raise AumOSError(
                message=f"Failed to terminate session '{session_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Session terminated", realm=realm, session_id=session_id)

    async def delete_all_sessions_for_user(self, realm: str, user_id: str) -> None:
        """Terminate all active sessions for a specific user.

        Args:
            realm: Realm name.
            user_id: Keycloak user UUID whose sessions should be terminated.

        Raises:
            AumOSError: If deletion fails.
        """
        response = await self._admin_request(
            "DELETE",
            f"/admin/realms/{realm}/users/{user_id}/sessions",
        )
        if response.status_code not in (200, 204, 404):
            raise AumOSError(
                message=f"Failed to terminate sessions for user '{user_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("All user sessions terminated", realm=realm, user_id=user_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release the underlying HTTP client resources."""
        await self._http.aclose()
