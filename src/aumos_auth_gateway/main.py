"""AumOS Auth Gateway service entry point."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from aumos_common.app import create_app
from aumos_common.database import init_database
from aumos_common.health import HealthCheck
from aumos_common.observability import get_logger

from aumos_auth_gateway.adapters.kafka import AuthEventPublisher
from aumos_auth_gateway.adapters.keycloak_client import KeycloakAdminClient
from aumos_auth_gateway.adapters.kong_client import KongAdminClient
from aumos_auth_gateway.adapters.repositories import AgentRepository, PolicyEvaluationRepository
from aumos_auth_gateway.core.opa_client import OPAClient
from aumos_auth_gateway.settings import Settings

logger = get_logger(__name__)
settings = Settings()

# Module-level singletons (injected via app.state)
_opa_client: OPAClient | None = None
_keycloak_client: KeycloakAdminClient | None = None
_kong_client: KongAdminClient | None = None
_event_publisher: AuthEventPublisher | None = None


async def _check_postgres() -> bool:
    """Health check for PostgreSQL connectivity."""
    try:
        from aumos_common.database import get_db_session_no_tenant

        async for session in get_db_session_no_tenant():
            from sqlalchemy import text

            await session.execute(text("SELECT 1"))
            return True
    except Exception as exc:
        logger.warning("Postgres health check failed", error=str(exc))
        return False
    return False


async def _check_keycloak() -> bool:
    """Health check for Keycloak connectivity."""
    if _keycloak_client is None:
        return False
    try:
        return await _keycloak_client.ping()
    except Exception as exc:
        logger.warning("Keycloak health check failed", error=str(exc))
        return False


async def _check_opa() -> bool:
    """Health check for OPA connectivity."""
    if _opa_client is None:
        return False
    try:
        return await _opa_client.ping()
    except Exception as exc:
        logger.warning("OPA health check failed", error=str(exc))
        return False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifecycle — startup and shutdown."""
    global _opa_client, _keycloak_client, _kong_client, _event_publisher

    logger.info("Starting AumOS Auth Gateway", version="0.1.0")

    # Initialize database
    init_database(settings.database)

    # Initialize OPA client
    _opa_client = OPAClient(
        base_url=settings.opa_base_url,
        timeout_seconds=settings.opa_timeout_seconds,
        policy_prefix=settings.opa_policy_prefix,
    )

    # Initialize Keycloak client
    _keycloak_client = KeycloakAdminClient(
        base_url=settings.keycloak_base_url,
        admin_realm=settings.keycloak_admin_realm,
        client_id=settings.keycloak_admin_client_id,
        username=settings.keycloak_admin_username,
        password=settings.keycloak_admin_password,
        aumos_realm=settings.keycloak_aumos_realm,
        timeout_seconds=settings.keycloak_admin_timeout_seconds,
    )

    # Initialize Kong client
    _kong_client = KongAdminClient(
        admin_url=settings.kong_admin_url,
        timeout_seconds=settings.kong_timeout_seconds,
    )

    # Initialize Kafka event publisher
    _event_publisher = AuthEventPublisher(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        service_name=settings.service_name,
    )
    await _event_publisher.start()

    # Store in app state for dependency injection
    app.state.opa_client = _opa_client
    app.state.keycloak_client = _keycloak_client
    app.state.kong_client = _kong_client
    app.state.event_publisher = _event_publisher
    app.state.settings = settings

    logger.info(
        "Auth Gateway started",
        keycloak_url=settings.keycloak_base_url,
        opa_url=settings.opa_base_url,
        kong_url=settings.kong_admin_url,
    )

    yield

    # Shutdown
    logger.info("Shutting down AumOS Auth Gateway")
    if _event_publisher is not None:
        await _event_publisher.stop()
    if _opa_client is not None:
        await _opa_client.close()
    if _keycloak_client is not None:
        await _keycloak_client.close()
    if _kong_client is not None:
        await _kong_client.close()


app = create_app(
    service_name="aumos-auth-gateway",
    version="0.1.0",
    settings=settings,
    lifespan=lifespan,
    health_checks=[
        HealthCheck(name="postgres", check_fn=_check_postgres),
        HealthCheck(name="keycloak", check_fn=_check_keycloak),
        HealthCheck(name="opa", check_fn=_check_opa),
    ],
)

# Auth routes (OIDC/token endpoints — no /api/v1 prefix)
from aumos_auth_gateway.api.auth_routes import router as auth_router

app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# API v1 routes
from aumos_auth_gateway.api.router import router as api_router

app.include_router(api_router, prefix="/api/v1")
