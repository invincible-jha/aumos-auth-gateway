"""Certificate-based short-lived token exchange for AI agents.

Agents present their X.509 certificate to obtain a 5-minute JWT access token.
This implements the mTLS -> JWT bridge pattern used throughout the AumOS platform.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from cryptography import x509

from aumos_common.observability import get_logger

from aumos_auth_gateway.agent_identity.certificate_authority import InternalCA

logger = get_logger(__name__)

# Short-lived token TTL — 5 minutes (300 seconds)
_TOKEN_TTL_SECONDS: Final[int] = 300
# Token issuer claim
_TOKEN_ISSUER: Final[str] = "aumos-auth-gateway"


class AgentTokenExchangeResult:
    """Result of a successful certificate-to-token exchange.

    Attributes:
        access_token: Signed JWT token string.
        expires_in: Token validity in seconds (always 300).
        token_type: Always "Bearer".
        agent_id: UUID of the agent the token was issued for.
        tenant_id: UUID of the owning tenant.
        issued_at: UTC timestamp when the token was issued.
        jti: JWT ID — unique identifier for this token instance.
    """

    def __init__(
        self,
        access_token: str,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        issued_at: datetime,
        jti: str,
        expires_in: int = _TOKEN_TTL_SECONDS,
    ) -> None:
        self.access_token = access_token
        self.expires_in = expires_in
        self.token_type = "Bearer"
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.issued_at = issued_at
        self.jti = jti


class AgentTokenService:
    """Certificate-based token exchange service for AI agents.

    Agents present their X.509 certificate (issued by InternalCA). This service
    validates the certificate, verifies the agent identity matches what is on file,
    and returns a short-lived JWT (5-min TTL) for use against AumOS APIs.

    Args:
        ca: InternalCA instance used to verify agent certificates.
        jwt_signing_secret: Secret for signing JWTs (HS256). In production,
            this should be a long random bytes value from a secrets manager.
        token_ttl_seconds: Override for token TTL (default 300 seconds).
    """

    def __init__(
        self,
        ca: InternalCA,
        jwt_signing_secret: str,
        token_ttl_seconds: int = _TOKEN_TTL_SECONDS,
    ) -> None:
        self._ca = ca
        self._signing_secret = jwt_signing_secret
        self._ttl = token_ttl_seconds

    async def exchange_certificate_for_token(
        self,
        certificate_pem: str,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        permitted_operations: list[str] | None = None,
    ) -> AgentTokenExchangeResult:
        """Exchange a valid agent certificate for a short-lived access token.

        Validates the certificate against the InternalCA, verifies the SAN fields
        match the claimed agent_id and tenant_id, then issues a signed JWT with
        a 5-minute TTL.

        Args:
            certificate_pem: PEM-encoded agent certificate.
            agent_id: Agent UUID claimed by the presenter.
            tenant_id: Tenant UUID claimed by the presenter.
            permitted_operations: Optional list of permitted operation scopes to
                embed in the token claims. If None, embeds ["*"] (unrestricted).

        Returns:
            AgentTokenExchangeResult with the access token and metadata.

        Raises:
            ValueError: If the certificate is invalid, expired, or SAN mismatch.
        """
        # Verify certificate against CA
        if not self._ca.verify_agent_certificate(
            certificate_pem=certificate_pem,
            expected_agent_id=agent_id,
            expected_tenant_id=tenant_id,
        ):
            logger.warning(
                "Certificate verification failed during token exchange",
                agent_id=str(agent_id),
                tenant_id=str(tenant_id),
            )
            raise ValueError(f"Certificate verification failed for agent {agent_id}")

        # Parse certificate to extract serial + fingerprint
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        cert_serial = hex(cert.serial_number)
        cert_fingerprint = self._ca.get_certificate_fingerprint(cert)

        # Build token claims
        now = datetime.now(UTC)
        expiry = now + timedelta(seconds=self._ttl)
        jti = str(uuid.uuid4())

        claims: dict[str, Any] = {
            "iss": _TOKEN_ISSUER,
            "sub": f"agent:{agent_id}",
            "tenant_id": str(tenant_id),
            "agent_id": str(agent_id),
            "cert_serial": cert_serial,
            "cert_fingerprint": cert_fingerprint,
            "permitted_operations": permitted_operations or ["*"],
            "is_agent": True,
            "iat": int(now.timestamp()),
            "exp": int(expiry.timestamp()),
            "jti": jti,
        }

        access_token = self._sign_jwt(claims)

        logger.info(
            "Agent token issued via certificate exchange",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            jti=jti,
            expires_at=expiry.isoformat(),
        )

        return AgentTokenExchangeResult(
            access_token=access_token,
            agent_id=agent_id,
            tenant_id=tenant_id,
            issued_at=now,
            jti=jti,
            expires_in=self._ttl,
        )

    def validate_agent_token(self, token: str) -> dict[str, Any]:
        """Validate an agent JWT token and return its claims.

        Args:
            token: JWT access token string.

        Returns:
            Decoded and validated claims dictionary.

        Raises:
            ValueError: If the token is invalid, expired, or tampered with.
        """
        try:
            import hmac
            import json
            from base64 import urlsafe_b64decode

            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWT structure")

            # Decode header and payload
            # Pad base64 as needed
            def _b64_decode(data: str) -> bytes:
                padding = 4 - len(data) % 4
                if padding < 4:
                    data += "=" * padding
                return urlsafe_b64decode(data)

            header = json.loads(_b64_decode(parts[0]))
            payload = json.loads(_b64_decode(parts[1]))

            # Verify algorithm
            if header.get("alg") != "HS256":
                raise ValueError(f"Unexpected algorithm: {header.get('alg')}")

            # Verify signature
            import hashlib

            signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
            expected_sig = hmac.new(
                self._signing_secret.encode("utf-8"),
                signing_input,
                hashlib.sha256,
            ).digest()

            import base64

            actual_sig = _b64_decode(parts[2])
            if not hmac.compare_digest(expected_sig, actual_sig):
                raise ValueError("Token signature verification failed")

            # Check expiry
            now_ts = int(datetime.now(UTC).timestamp())
            if payload.get("exp", 0) < now_ts:
                raise ValueError("Token has expired")

            # Check issuer
            if payload.get("iss") != _TOKEN_ISSUER:
                raise ValueError(f"Unexpected issuer: {payload.get('iss')}")

            return payload  # type: ignore[no-any-return]

        except (ValueError, KeyError, AttributeError) as exc:
            raise ValueError(f"Token validation failed: {exc}") from exc

    def _sign_jwt(self, claims: dict[str, Any]) -> str:
        """Sign a claims dictionary as a compact JWT (HS256).

        Args:
            claims: JWT claims dictionary.

        Returns:
            Signed JWT string in compact serialization format.
        """
        import hashlib
        import hmac
        import json
        from base64 import urlsafe_b64encode

        def _b64_encode(data: bytes) -> str:
            return urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

        header = {"alg": "HS256", "typ": "JWT"}
        header_encoded = _b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_encoded = _b64_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))

        signing_input = f"{header_encoded}.{payload_encoded}".encode("utf-8")
        signature = hmac.new(
            self._signing_secret.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        signature_encoded = _b64_encode(signature)

        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
