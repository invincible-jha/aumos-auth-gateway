"""Kubernetes OIDC token validator for AumOS Auth Gateway.

Gap #17: Kubernetes OIDC integration — validates Kubernetes ServiceAccount tokens
via the TokenReview API and exchanges them for AumOS JWTs via Keycloak Token Exchange
(RFC 8693). This enables pods running in AumOS tenant namespaces to authenticate
to the platform without storing long-lived credentials.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
from pydantic import BaseModel

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class K8sTokenReviewResult(BaseModel):
    """Result of a Kubernetes TokenReview API call.

    Attributes:
        authenticated: Whether the token is valid.
        username: ServiceAccount username (e.g., system:serviceaccount:ns:sa-name).
        namespace: ServiceAccount namespace.
        service_account_name: ServiceAccount name.
        uid: ServiceAccount UID.
    """

    authenticated: bool
    username: str = ""
    namespace: str = ""
    service_account_name: str = ""
    uid: str = ""


class K8sTokenValidator:
    """Validates Kubernetes ServiceAccount tokens via the Kubernetes TokenReview API.

    Uses the in-cluster service account credentials to call the Kubernetes API
    server's TokenReview endpoint, then exchanges the validated identity for an
    AumOS JWT via Keycloak Token Exchange (RFC 8693).
    """

    def __init__(
        self,
        k8s_api_url: str,
        k8s_service_account_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token",
        k8s_ca_cert_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        namespace_prefix: str = "aumos-tenant-",
        timeout_seconds: int = 10,
    ) -> None:
        """Initialize the K8sTokenValidator.

        Args:
            k8s_api_url: Kubernetes API server URL.
            k8s_service_account_token_path: Path to the mounted service account token.
            k8s_ca_cert_path: Path to the Kubernetes CA certificate.
            namespace_prefix: Prefix used by AumOS tenant namespaces.
            timeout_seconds: HTTP request timeout in seconds.
        """
        self._k8s_api_url = k8s_api_url.rstrip("/")
        self._sa_token_path = k8s_service_account_token_path
        self._ca_cert_path = k8s_ca_cert_path
        self._namespace_prefix = namespace_prefix
        self._timeout = httpx.Timeout(timeout_seconds)

    async def validate_token(self, token: str) -> K8sTokenReviewResult:
        """Validate a Kubernetes ServiceAccount token via the TokenReview API.

        Args:
            token: Raw Kubernetes ServiceAccount JWT token string.

        Returns:
            K8sTokenReviewResult with authentication status and identity details.

        Raises:
            AumOSError: If the Kubernetes API is unreachable or returns an error.
        """
        try:
            sa_token = open(self._sa_token_path).read().strip()
        except FileNotFoundError:
            logger.warning("k8s_sa_token_not_found", path=self._sa_token_path)
            sa_token = ""

        review_payload: dict[str, Any] = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token},
        }

        headers = {
            "Authorization": f"Bearer {sa_token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._ca_cert_path) as client:
                response = await client.post(
                    f"{self._k8s_api_url}/apis/authentication.k8s.io/v1/tokenreviews",
                    json=review_payload,
                    headers=headers,
                )
        except httpx.ConnectError as exc:
            raise AumOSError(
                message="Kubernetes API unreachable for TokenReview",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 201:
            raise AumOSError(
                message=f"TokenReview API returned {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        review_data: dict[str, Any] = response.json()
        status_data: dict[str, Any] = review_data.get("status", {})
        authenticated: bool = status_data.get("authenticated", False)

        if not authenticated:
            return K8sTokenReviewResult(authenticated=False)

        user_info: dict[str, Any] = status_data.get("user", {})
        username: str = user_info.get("username", "")
        uid: str = user_info.get("uid", "")

        # Parse system:serviceaccount:{namespace}:{name}
        namespace = ""
        sa_name = ""
        if username.startswith("system:serviceaccount:"):
            parts = username.split(":")
            if len(parts) >= 4:
                namespace = parts[2]
                sa_name = parts[3]

        return K8sTokenReviewResult(
            authenticated=True,
            username=username,
            namespace=namespace,
            service_account_name=sa_name,
            uid=uid,
        )

    def extract_tenant_name(self, namespace: str) -> str | None:
        """Extract the AumOS tenant name from a Kubernetes namespace.

        Args:
            namespace: Kubernetes namespace string.

        Returns:
            Tenant name string if this is an AumOS tenant namespace, else None.
        """
        if namespace.startswith(self._namespace_prefix):
            return namespace[len(self._namespace_prefix):]
        return None
