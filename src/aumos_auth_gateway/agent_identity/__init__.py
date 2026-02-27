"""Zero-trust agent identity management for AumOS Auth Gateway.

Provides X.509 certificate issuance, short-lived token exchange (5-min TTL),
and mTLS-ready agent cryptographic identities.

Modules:
    certificate_authority  — InternalCA: issues X.509 certs with agent SAN fields
    identity_manager       — AgentIdentityManager: register/lifecycle management
    token_service          — AgentTokenService: certificate-based token exchange
"""

from aumos_auth_gateway.agent_identity.certificate_authority import InternalCA
from aumos_auth_gateway.agent_identity.identity_manager import AgentIdentityManager
from aumos_auth_gateway.agent_identity.token_service import AgentTokenService

__all__ = [
    "InternalCA",
    "AgentIdentityManager",
    "AgentTokenService",
]
