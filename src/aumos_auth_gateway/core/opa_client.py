"""OPA (Open Policy Agent) REST API client.

Communicates with OPA's REST API to evaluate Rego policies for RBAC,
ABAC, agent privilege enforcement, and HITL gate decisions.

OPA REST API docs: https://www.openpolicyagent.org/docs/latest/rest-api/
"""

import time
from typing import Any

import httpx

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)

_OPA_ALLOW_PATHS = frozenset({"allow", "result", "decision"})


class OPAClient:
    """HTTP client for the Open Policy Agent REST API.

    Wraps OPA's /v1/data/{policy_path} POST endpoint to evaluate policies
    and return structured decisions. Designed for sub-10ms evaluation latency
    on warm OPA instances.

    Args:
        base_url: OPA server base URL (e.g., http://opa:8181)
        timeout_seconds: HTTP request timeout
        policy_prefix: Root Rego namespace prefix (e.g., "aumos")
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 5,
        policy_prefix: str = "aumos",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds)
        self._policy_prefix = policy_prefix
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            headers={"Content-Type": "application/json"},
        )

    async def evaluate(
        self,
        policy_path: str,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a policy against input data.

        Args:
            policy_path: Rego policy path relative to the policy_prefix.
                         e.g., "rbac/roles" resolves to /v1/data/aumos/rbac/roles
            input_data: The policy input document (context for evaluation)

        Returns:
            Full OPA result document, typically containing an "allow" or "result" key.

        Raises:
            AumOSError: If OPA is unreachable or returns an error response.
        """
        full_path = f"{self._policy_prefix}/{policy_path.lstrip('/')}"
        url = f"/v1/data/{full_path}"

        start_ms = time.monotonic() * 1000
        try:
            response = await self._client.post(url, json={"input": input_data})
            elapsed_ms = time.monotonic() * 1000 - start_ms
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"OPA server unreachable at {self._base_url}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc
        except httpx.TimeoutException as exc:
            raise AumOSError(
                message="OPA policy evaluation timed out",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 200:
            logger.error(
                "OPA returned error response",
                status_code=response.status_code,
                policy_path=policy_path,
                response_body=response.text[:500],
            )
            raise AumOSError(
                message=f"OPA evaluation failed with status {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        result = response.json()
        logger.debug(
            "OPA policy evaluated",
            policy_path=policy_path,
            elapsed_ms=round(elapsed_ms, 2),
            decision=result.get("result", {}).get("allow"),
        )
        return result.get("result", {})

    async def evaluate_allow(
        self,
        policy_path: str,
        input_data: dict[str, Any],
    ) -> bool:
        """Convenience method — evaluate a policy and return the boolean allow decision.

        Args:
            policy_path: Rego policy path relative to the policy_prefix.
            input_data: The policy input document.

        Returns:
            True if the policy grants access, False if it denies.
        """
        result = await self.evaluate(policy_path, input_data)
        return bool(result.get("allow", False))

    async def update_policy(self, policy_path: str, rego_content: str) -> None:
        """Upload or replace a policy in OPA.

        Args:
            policy_path: The policy identifier path (without /v1/policies/ prefix).
            rego_content: Raw Rego policy text.

        Raises:
            AumOSError: If the upload fails.
        """
        url = f"/v1/policies/{policy_path}"
        try:
            response = await self._client.put(
                url,
                content=rego_content,
                headers={"Content-Type": "text/plain"},
            )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="OPA server unreachable",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code not in (200, 204):
            raise AumOSError(
                message=f"OPA policy upload failed: {response.text[:200]}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        logger.info("OPA policy updated", policy_path=policy_path)

    async def get_policy(self, policy_path: str) -> str:
        """Retrieve current Rego content for a policy.

        Args:
            policy_path: The policy identifier path.

        Returns:
            Raw Rego policy text.

        Raises:
            AumOSError: If the policy is not found or OPA is unreachable.
        """
        url = f"/v1/policies/{policy_path}"
        try:
            response = await self._client.get(url)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="OPA server unreachable",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code == 404:
            raise AumOSError(
                message=f"Policy '{policy_path}' not found in OPA",
                error_code=ErrorCode.NOT_FOUND,
            )
        if response.status_code != 200:
            raise AumOSError(
                message=f"OPA get_policy failed with status {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )
        result = response.json()
        return result.get("result", {}).get("raw", "")

    async def ping(self) -> bool:
        """Check OPA server liveness via /health endpoint.

        Returns:
            True if OPA is healthy, False otherwise.
        """
        try:
            response = await self._client.get("/health")
            return response.status_code == 200
        except Exception:
            return False

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
