"""Kong Admin REST API client for AumOS Auth Gateway.

Provides typed wrappers around Kong's Admin API for managing services, routes,
plugins, and consumers. Used to register AI-agent service accounts as Kong
consumers and configure JWT validation and rate limiting.

Kong Admin API docs: https://docs.konghq.com/gateway/latest/admin-api/
"""

from typing import Any

import httpx

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class KongAdminClient:
    """HTTP client for the Kong Admin REST API.

    Manages Kong services, routes, plugins, and consumers. Agent identities
    are registered as Kong consumers so Kong can enforce JWT validation and
    per-agent rate limiting.

    Args:
        admin_url: Kong Admin API base URL (e.g., http://kong:8001)
        timeout_seconds: HTTP request timeout in seconds
    """

    def __init__(
        self,
        admin_url: str,
        timeout_seconds: int = 10,
    ) -> None:
        self._admin_url = admin_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds)
        self._http = httpx.AsyncClient(base_url=self._admin_url, timeout=self._timeout)

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    async def create_service(self, name: str, url: str) -> dict[str, Any]:
        """Register a backend service in Kong.

        Args:
            name: Unique service name identifier.
            url: Upstream URL Kong should proxy to (e.g., http://aumos-model-registry:8000).

        Returns:
            Created service object dict.

        Raises:
            AumOSError: If Kong is unreachable or creation fails.
        """
        payload: dict[str, Any] = {"name": name, "url": url}
        try:
            response = await self._http.post("/services", json=payload)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"Kong Admin API unreachable at {self._admin_url}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code in (200, 201):
            result: dict[str, Any] = response.json()
            logger.info("Kong service created", service_name=name, url=url)
            return result

        if response.status_code == 409:
            # Already exists — fetch and return existing
            existing = await self._http.get(f"/services/{name}")
            if existing.status_code == 200:
                existing_result: dict[str, Any] = existing.json()
                return existing_result

        raise AumOSError(
            message=f"Failed to create Kong service '{name}': {response.status_code} {response.text[:200]}",
            error_code=ErrorCode.INTERNAL_ERROR,
        )

    async def create_route(
        self,
        service_id: str,
        paths: list[str],
        methods: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a route attached to an existing service.

        Args:
            service_id: Kong service UUID or name.
            paths: List of path prefixes to match (e.g., ["/api/v1/agents"]).
            methods: Optional list of HTTP methods to match (e.g., ["GET", "POST"]).

        Returns:
            Created route object dict.

        Raises:
            AumOSError: If the service does not exist or creation fails.
        """
        payload: dict[str, Any] = {"paths": paths}
        if methods:
            payload["methods"] = methods

        try:
            response = await self._http.post(f"/services/{service_id}/routes", json=payload)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during route creation",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to create Kong route for service '{service_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        result: dict[str, Any] = response.json()
        logger.info("Kong route created", service_id=service_id, paths=paths)
        return result

    async def add_plugin(
        self,
        service_id: str,
        plugin_name: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Attach a plugin to a service.

        Used to add JWT validation, rate limiting, or CORS plugins to services.

        Args:
            service_id: Kong service UUID or name.
            plugin_name: Kong plugin name (e.g., "jwt", "rate-limiting").
            config: Plugin configuration dict.

        Returns:
            Created plugin object dict.

        Raises:
            AumOSError: If the service does not exist or plugin creation fails.
        """
        payload: dict[str, Any] = {"name": plugin_name, "config": config}
        try:
            response = await self._http.post(f"/services/{service_id}/plugins", json=payload)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during plugin creation",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to add plugin '{plugin_name}' to service '{service_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        result: dict[str, Any] = response.json()
        logger.info("Kong plugin added", service_id=service_id, plugin_name=plugin_name)
        return result

    # ------------------------------------------------------------------
    # Consumers
    # ------------------------------------------------------------------

    async def create_consumer(self, username: str, custom_id: str) -> dict[str, Any]:
        """Register a new consumer in Kong.

        Args:
            username: Consumer username (typically the agent service_account name).
            custom_id: External custom identifier (typically the agent UUID).

        Returns:
            Created consumer object dict.

        Raises:
            AumOSError: If creation fails.
        """
        payload: dict[str, Any] = {"username": username, "custom_id": custom_id}
        try:
            response = await self._http.post("/consumers", json=payload)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during consumer creation",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code in (200, 201):
            result: dict[str, Any] = response.json()
            logger.info("Kong consumer created", username=username, custom_id=custom_id)
            return result

        if response.status_code == 409:
            # Already exists — return existing
            existing = await self._http.get(f"/consumers/{username}")
            if existing.status_code == 200:
                existing_result: dict[str, Any] = existing.json()
                return existing_result

        raise AumOSError(
            message=f"Failed to create Kong consumer '{username}': {response.status_code}",
            error_code=ErrorCode.INTERNAL_ERROR,
        )

    async def upsert_consumer(self, consumer_id: str, custom_id: str) -> None:
        """Create or update a Kong consumer for an agent service account.

        Args:
            consumer_id: Kong consumer username (typically agent UUID string).
            custom_id: External custom identifier for the consumer.
        """
        payload: dict[str, Any] = {"username": consumer_id, "custom_id": custom_id}
        try:
            response = await self._http.put(f"/consumers/{consumer_id}", json=payload)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during consumer upsert",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to upsert Kong consumer '{consumer_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Kong consumer upserted", consumer_id=consumer_id, custom_id=custom_id)

    async def set_jwt_credential(self, consumer_id: str, key: str, secret: str) -> None:
        """Set JWT credentials on a Kong consumer.

        Args:
            consumer_id: Kong consumer username or ID.
            key: JWT credential key (iss claim value).
            secret: JWT signing secret.

        Raises:
            AumOSError: If the consumer does not exist or credential creation fails.
        """
        payload: dict[str, Any] = {"key": key, "secret": secret}
        try:
            response = await self._http.post(f"/consumers/{consumer_id}/jwt", json=payload)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during JWT credential creation",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code not in (200, 201):
            raise AumOSError(
                message=f"Failed to set JWT credential for consumer '{consumer_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Kong JWT credential set", consumer_id=consumer_id, key=key)

    async def delete_consumer(self, consumer_id: str) -> None:
        """Remove a Kong consumer and all associated credentials.

        Args:
            consumer_id: Kong consumer username or ID.

        Raises:
            AumOSError: If deletion fails (404 is silently ignored).
        """
        try:
            response = await self._http.delete(f"/consumers/{consumer_id}")
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during consumer deletion",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code not in (204, 404):
            raise AumOSError(
                message=f"Failed to delete Kong consumer '{consumer_id}': {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("Kong consumer deleted", consumer_id=consumer_id)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def get_rate_limit_config(self, service_name: str) -> dict[str, Any]:
        """Retrieve rate-limiting plugin configuration for a service.

        Args:
            service_name: Kong service name or UUID.

        Returns:
            Rate-limiting plugin config dict, or empty dict if not configured.

        Raises:
            AumOSError: If the request fails.
        """
        try:
            response = await self._http.get(f"/services/{service_name}/plugins")
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kong Admin API unreachable during rate-limit config fetch",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 200:
            return {}

        plugins: dict[str, Any] = response.json()
        plugin_list: list[dict[str, Any]] = plugins.get("data", [])
        for plugin in plugin_list:
            if plugin.get("name") == "rate-limiting":
                config: dict[str, Any] = plugin.get("config", {})
                return config
        return {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release the underlying HTTP client resources."""
        await self._http.aclose()
