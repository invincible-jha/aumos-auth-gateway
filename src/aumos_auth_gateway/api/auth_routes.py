"""Authentication routes — OIDC/token endpoints for AumOS Auth Gateway.

Serves the /auth prefix (not /api/v1) for token issuance, refresh, revocation,
userinfo, and OIDC discovery. These endpoints are consumed by all AumOS services
and client applications.

All token operations are delegated to AuthService which wraps Keycloak.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aumos_common.observability import get_logger

from aumos_auth_gateway.api.schemas import (
    OIDCDiscoveryResponse,
    RefreshTokenRequest,
    RevokeTokenRequest,
    TokenRequest,
    TokenResponse,
    UserInfoResponse,
)
from aumos_auth_gateway.core.services import AuthService

logger = get_logger(__name__)
router = APIRouter()
_bearer = HTTPBearer(auto_error=False)


def _get_auth_service(request: Request) -> AuthService:
    """Dependency: build AuthService from app state.

    Args:
        request: FastAPI request with app state injected during lifespan.

    Returns:
        Configured AuthService instance.
    """
    return AuthService(
        keycloak=request.app.state.keycloak_client,
        event_publisher=request.app.state.event_publisher,
        client_id=request.app.state.settings.keycloak_audience,
    )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange credentials for a JWT token pair",
    tags=["Authentication"],
)
async def issue_token(
    token_request: TokenRequest,
    request: Request,
    auth_service: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    """Exchange username/password or client credentials for a JWT token pair.

    Supports OAuth2 password grant (username + password) and client_credentials
    grant (client_id + client_secret). The resulting tokens are issued by Keycloak
    and validated by all downstream AumOS services.

    Args:
        token_request: OAuth2 grant request body.
        request: FastAPI request (for IP extraction).
        auth_service: Injected auth service.

    Returns:
        TokenResponse with access_token and optional refresh_token.

    Raises:
        HTTPException: 401 if credentials are invalid, 503 if Keycloak is down.
    """
    from aumos_common.errors import AumOSError, ErrorCode

    ip_address = request.client.host if request.client else None
    correlation_id = request.headers.get("X-Request-ID")

    try:
        return await auth_service.issue_token(
            request=token_request,
            ip_address=ip_address,
            correlation_id=correlation_id,
        )
    except AumOSError as exc:
        if exc.error_code == ErrorCode.UNAUTHORIZED:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc.message))
        if exc.error_code == ErrorCode.SERVICE_UNAVAILABLE:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc.message))


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh a JWT access token",
    tags=["Authentication"],
)
async def refresh_token(
    body: RefreshTokenRequest,
    request: Request,
    auth_service: AuthService = Depends(_get_auth_service),
) -> TokenResponse:
    """Exchange a refresh token for a new access token.

    Args:
        body: Request body containing the refresh token.
        request: FastAPI request.
        auth_service: Injected auth service.

    Returns:
        New TokenResponse with refreshed access token.

    Raises:
        HTTPException: 401 if the refresh token is invalid or expired.
    """
    from aumos_common.errors import AumOSError, ErrorCode

    correlation_id = request.headers.get("X-Request-ID")
    try:
        return await auth_service.refresh(
            refresh_token_value=body.refresh_token,
            correlation_id=correlation_id,
        )
    except AumOSError as exc:
        if exc.error_code == ErrorCode.UNAUTHORIZED:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc.message))
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))


@router.post(
    "/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a token (logout)",
    tags=["Authentication"],
)
async def revoke_token(
    body: RevokeTokenRequest,
    request: Request,
    auth_service: AuthService = Depends(_get_auth_service),
) -> None:
    """Revoke a refresh token and invalidate the session in Keycloak.

    Args:
        body: Request body with the refresh token to revoke.
        request: FastAPI request.
        auth_service: Injected auth service.
    """
    from aumos_common.errors import AumOSError

    correlation_id = request.headers.get("X-Request-ID")
    try:
        await auth_service.logout(
            refresh_token_value=body.refresh_token,
            user_id=body.user_id,
            tenant_id=body.tenant_id,
            correlation_id=correlation_id,
        )
    except AumOSError as exc:
        logger.warning("Token revocation failed", error=str(exc))
        # Silently absorb — best effort logout


@router.get(
    "/userinfo",
    response_model=UserInfoResponse,
    summary="Get authenticated user info",
    tags=["Authentication"],
)
async def get_userinfo(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    auth_service: AuthService = Depends(_get_auth_service),
) -> UserInfoResponse:
    """Return OIDC userinfo claims for the authenticated user.

    Requires a valid Bearer token in the Authorization header.

    Args:
        request: FastAPI request.
        credentials: Bearer token extracted from Authorization header.
        auth_service: Injected auth service.

    Returns:
        UserInfoResponse with OIDC standard claims.

    Raises:
        HTTPException: 401 if no valid Bearer token is provided.
    """
    from aumos_common.errors import AumOSError, ErrorCode

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return await auth_service.get_userinfo(access_token=credentials.credentials)
    except AumOSError as exc:
        if exc.error_code == ErrorCode.UNAUTHORIZED:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc.message),
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc.message))


@router.get(
    "/.well-known/openid-configuration",
    response_model=OIDCDiscoveryResponse,
    summary="OIDC discovery document",
    tags=["Authentication"],
)
async def oidc_discovery(request: Request) -> OIDCDiscoveryResponse:
    """Return the OpenID Connect discovery document.

    Allows clients to auto-discover Keycloak endpoints for this deployment.

    Args:
        request: FastAPI request (used to derive base URL).

    Returns:
        OIDCDiscoveryResponse with standard discovery fields.
    """
    settings = request.app.state.settings
    keycloak_realm_url = f"{settings.keycloak_base_url}/realms/{settings.keycloak_aumos_realm}"
    oidc_base = f"{keycloak_realm_url}/protocol/openid-connect"

    return OIDCDiscoveryResponse(
        issuer=keycloak_realm_url,
        authorization_endpoint=f"{oidc_base}/auth",
        token_endpoint=f"{oidc_base}/token",
        userinfo_endpoint=f"{oidc_base}/userinfo",
        jwks_uri=f"{oidc_base}/certs",
        response_types_supported=["code", "token", "id_token"],
        grant_types_supported=["authorization_code", "refresh_token", "client_credentials", "password"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )
