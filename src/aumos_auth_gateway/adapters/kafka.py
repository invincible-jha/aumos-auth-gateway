"""Kafka event publisher for AumOS Auth Gateway.

Publishes authentication and authorization domain events to Kafka topics
for downstream consumption by security monitoring, audit, and analytics services.

All events include tenant_id and correlation_id for distributed tracing.
"""

from typing import Any

from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class AuthEventPublisher:
    """Publisher for Auth Gateway domain events.

    Wraps EventPublisher with typed methods for each auth event type:
    login, logout, agent lifecycle, and policy evaluation results.

    Args:
        bootstrap_servers: Kafka broker connection string (e.g., "kafka:9092").
        service_name: Identifying service name for event metadata.
    """

    def __init__(self, bootstrap_servers: str, service_name: str = "aumos-auth-gateway") -> None:
        self._bootstrap_servers = bootstrap_servers
        self._service_name = service_name
        self._publisher: EventPublisher | None = None

    async def start(self) -> None:
        """Initialize the underlying Kafka producer.

        Must be called before any publish methods. Called during app lifespan startup.
        """
        self._publisher = EventPublisher(
            bootstrap_servers=self._bootstrap_servers,
            service_name=self._service_name,
        )
        await self._publisher.start()
        logger.info("AuthEventPublisher started", bootstrap_servers=self._bootstrap_servers)

    async def stop(self) -> None:
        """Flush and close the Kafka producer.

        Must be called during app lifespan shutdown to avoid message loss.
        """
        if self._publisher is not None:
            await self._publisher.stop()
            logger.info("AuthEventPublisher stopped")

    def _require_publisher(self) -> EventPublisher:
        """Return the publisher or raise if not started.

        Returns:
            The initialized EventPublisher.

        Raises:
            RuntimeError: If start() has not been called.
        """
        if self._publisher is None:
            raise RuntimeError("AuthEventPublisher.start() must be called before publishing events")
        return self._publisher

    # ------------------------------------------------------------------
    # Auth events
    # ------------------------------------------------------------------

    async def publish_login(
        self,
        tenant_id: str,
        user_id: str,
        username: str,
        ip_address: str | None,
        correlation_id: str,
    ) -> None:
        """Publish a user or agent login event.

        Args:
            tenant_id: Tenant UUID string.
            user_id: Authenticated user or agent ID.
            username: Username or service account name.
            ip_address: Source IP address (None if unavailable).
            correlation_id: Request correlation ID for distributed tracing.
        """
        publisher = self._require_publisher()
        event: dict[str, Any] = {
            "event_type": "auth.login",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "correlation_id": correlation_id,
            "service": self._service_name,
        }
        await publisher.publish(Topics.AUTH_EVENTS, event)
        logger.info(
            "Published auth.login event",
            tenant_id=tenant_id,
            user_id=user_id,
            correlation_id=correlation_id,
        )

    async def publish_logout(
        self,
        tenant_id: str,
        user_id: str,
        correlation_id: str,
    ) -> None:
        """Publish a user or agent logout event.

        Args:
            tenant_id: Tenant UUID string.
            user_id: Authenticated user or agent ID.
            correlation_id: Request correlation ID.
        """
        publisher = self._require_publisher()
        event: dict[str, Any] = {
            "event_type": "auth.logout",
            "tenant_id": tenant_id,
            "user_id": user_id,
            "correlation_id": correlation_id,
            "service": self._service_name,
        }
        await publisher.publish(Topics.AUTH_EVENTS, event)
        logger.info(
            "Published auth.logout event",
            tenant_id=tenant_id,
            user_id=user_id,
            correlation_id=correlation_id,
        )

    async def publish_agent_created(
        self,
        tenant_id: str,
        agent_id: str,
        agent_name: str,
        privilege_level: int,
        correlation_id: str,
    ) -> None:
        """Publish an agent identity creation event.

        Args:
            tenant_id: Tenant UUID string.
            agent_id: Newly created agent UUID string.
            agent_name: Human-readable agent name.
            privilege_level: Assigned privilege level (1-5).
            correlation_id: Request correlation ID.
        """
        publisher = self._require_publisher()
        event: dict[str, Any] = {
            "event_type": "agent.created",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "privilege_level": privilege_level,
            "correlation_id": correlation_id,
            "service": self._service_name,
        }
        await publisher.publish(Topics.AGENT_LIFECYCLE, event)
        logger.info(
            "Published agent.created event",
            tenant_id=tenant_id,
            agent_id=agent_id,
            privilege_level=privilege_level,
            correlation_id=correlation_id,
        )

    async def publish_agent_revoked(
        self,
        tenant_id: str,
        agent_id: str,
        correlation_id: str,
    ) -> None:
        """Publish an agent identity revocation event.

        Args:
            tenant_id: Tenant UUID string.
            agent_id: Revoked agent UUID string.
            correlation_id: Request correlation ID.
        """
        publisher = self._require_publisher()
        event: dict[str, Any] = {
            "event_type": "agent.revoked",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "correlation_id": correlation_id,
            "service": self._service_name,
        }
        await publisher.publish(Topics.AGENT_LIFECYCLE, event)
        logger.info(
            "Published agent.revoked event",
            tenant_id=tenant_id,
            agent_id=agent_id,
            correlation_id=correlation_id,
        )

    async def publish_policy_evaluated(
        self,
        tenant_id: str,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        correlation_id: str,
    ) -> None:
        """Publish an OPA policy evaluation audit event.

        Args:
            tenant_id: Tenant UUID string.
            subject: Who requested access (user/agent ID).
            resource: Resource being accessed.
            action: Action requested.
            decision: allow or deny.
            correlation_id: Request correlation ID.
        """
        publisher = self._require_publisher()
        event: dict[str, Any] = {
            "event_type": "policy.evaluated",
            "tenant_id": tenant_id,
            "subject": subject,
            "resource": resource,
            "action": action,
            "decision": decision,
            "correlation_id": correlation_id,
            "service": self._service_name,
        }
        await publisher.publish(Topics.POLICY_DECISIONS, event)
        logger.info(
            "Published policy.evaluated event",
            tenant_id=tenant_id,
            subject=subject,
            decision=decision,
            correlation_id=correlation_id,
        )

    async def publish_auth_event(
        self,
        tenant_id: str,
        event_type: str,
        actor: str,
        details: dict[str, Any],
    ) -> None:
        """Generic auth event publisher for custom event types.

        Args:
            tenant_id: Tenant UUID string.
            event_type: Dotted event type string (e.g., "auth.token_revoked").
            actor: User or agent ID performing the action.
            details: Additional event-specific details.
        """
        publisher = self._require_publisher()
        event: dict[str, Any] = {
            "event_type": event_type,
            "tenant_id": tenant_id,
            "actor": actor,
            "service": self._service_name,
            **details,
        }
        await publisher.publish(Topics.AUTH_EVENTS, event)
        logger.info(
            "Published auth event",
            event_type=event_type,
            tenant_id=tenant_id,
            actor=actor,
        )
