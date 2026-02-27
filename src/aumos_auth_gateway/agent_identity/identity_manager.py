"""Agent identity lifecycle manager — register agents, issue certs, manage status.

Coordinates between InternalCA for certificate issuance and the identity repository
for persistence. This is the primary entry point for agent identity operations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_auth_gateway.agent_identity.certificate_authority import InternalCA

logger = get_logger(__name__)

# Valid agent classes per spec
_VALID_AGENT_CLASSES: frozenset[str] = frozenset({
    "orchestrator",
    "tool",
    "evaluator",
    "retriever",
    "executor",
})


class AgentIdentityRecord:
    """In-memory representation of a registered agent identity.

    Attributes:
        agent_id: UUID of this agent.
        tenant_id: Owning tenant UUID.
        agent_class: Agent classification (orchestrator/tool/evaluator/retriever/executor).
        display_name: Human-readable name.
        certificate_serial: Hex serial number of the active certificate.
        certificate_fingerprint: SHA-256 fingerprint of the active certificate.
        certificate_pem: PEM-encoded active certificate.
        permitted_operations: List of permitted operation identifiers.
        status: Agent status (active/suspended/revoked/expired).
        registered_at: When this agent was registered.
    """

    def __init__(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        agent_class: str,
        display_name: str,
        certificate_serial: str,
        certificate_fingerprint: str,
        certificate_pem: str,
        permitted_operations: list[str],
        status: str = "active",
    ) -> None:
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.agent_class = agent_class
        self.display_name = display_name
        self.certificate_serial = certificate_serial
        self.certificate_fingerprint = certificate_fingerprint
        self.certificate_pem = certificate_pem
        self.permitted_operations = permitted_operations
        self.status = status
        self.registered_at: datetime = datetime.now(UTC)


class IAgentIdentityRepository(Protocol):
    """Repository protocol for agent identity persistence."""

    async def save(self, record: AgentIdentityRecord) -> AgentIdentityRecord:
        """Persist a new or updated agent identity record."""
        ...

    async def get_by_id(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> AgentIdentityRecord | None:
        """Retrieve an agent identity by ID within a tenant."""
        ...

    async def update_status(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: str,
    ) -> bool:
        """Update the status of an agent. Returns True if found."""
        ...

    async def list_anomalies(
        self,
        tenant_id: uuid.UUID | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        """List behavioral anomaly records, optionally filtered by tenant."""
        ...


class AgentIdentityManager:
    """Manages AI agent cryptographic identities — register, suspend, revoke.

    Orchestrates certificate issuance via InternalCA and persistence via
    the identity repository. Every registered agent receives:
    - A unique UUID agent_id
    - An X.509 certificate with agent_id + tenant_id in SAN fields
    - A private key (returned once, never stored)

    Args:
        ca: InternalCA for certificate operations.
        repository: Persistence layer for agent identity records.
        cert_validity_days: Days until issued certificates expire.
    """

    def __init__(
        self,
        ca: InternalCA,
        repository: IAgentIdentityRepository,
        cert_validity_days: int = 90,
    ) -> None:
        self._ca = ca
        self._repo = repository
        self._cert_validity_days = cert_validity_days

    async def register_agent(
        self,
        tenant_id: uuid.UUID,
        agent_class: str,
        display_name: str,
        permitted_operations: list[str] | None = None,
    ) -> tuple[AgentIdentityRecord, str]:
        """Register a new AI agent and issue its X.509 certificate.

        Generates a fresh key pair, issues a certificate via InternalCA with
        agent_id and tenant_id embedded in SAN URI fields, and persists the
        identity record (excluding the private key).

        Args:
            tenant_id: Owning tenant UUID.
            agent_class: Agent class (orchestrator/tool/evaluator/retriever/executor).
            display_name: Human-readable agent name.
            permitted_operations: List of operation identifiers this agent may
                perform. Defaults to ["*"] (all operations permitted).

        Returns:
            Tuple of (AgentIdentityRecord, private_key_pem_string). The private
            key is returned ONCE — it is not stored. Caller must deliver it
            securely to the agent.

        Raises:
            ValueError: If agent_class is not one of the valid values.
        """
        if agent_class not in _VALID_AGENT_CLASSES:
            raise ValueError(
                f"Invalid agent_class '{agent_class}'. "
                f"Must be one of: {sorted(_VALID_AGENT_CLASSES)}"
            )

        agent_id = uuid.uuid4()
        ops = permitted_operations or ["*"]

        # Issue certificate
        cert, private_key = self._ca.issue_agent_certificate(
            agent_id=agent_id,
            tenant_id=tenant_id,
            agent_class=agent_class,
            validity_days=self._cert_validity_days,
        )

        cert_pem = self._ca.get_certificate_pem(cert)
        private_key_pem = self._ca.get_private_key_pem(private_key)
        fingerprint = self._ca.get_certificate_fingerprint(cert)
        serial = hex(cert.serial_number)

        record = AgentIdentityRecord(
            agent_id=agent_id,
            tenant_id=tenant_id,
            agent_class=agent_class,
            display_name=display_name,
            certificate_serial=serial,
            certificate_fingerprint=fingerprint,
            certificate_pem=cert_pem,
            permitted_operations=ops,
            status="active",
        )

        saved_record = await self._repo.save(record)

        logger.info(
            "Agent identity registered",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            agent_class=agent_class,
            cert_serial=serial,
        )

        return saved_record, private_key_pem

    async def get_agent(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> AgentIdentityRecord:
        """Retrieve an agent identity record.

        Args:
            agent_id: Agent UUID.
            tenant_id: Owning tenant UUID (for isolation).

        Returns:
            AgentIdentityRecord if found.

        Raises:
            NotFoundError: If the agent does not exist within the tenant.
        """
        record = await self._repo.get_by_id(agent_id=agent_id, tenant_id=tenant_id)
        if record is None:
            raise NotFoundError(resource="agent_identity", resource_id=str(agent_id))
        return record

    async def suspend_agent(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        reason: str | None = None,
    ) -> None:
        """Suspend an active agent, preventing token exchange.

        A suspended agent can be re-activated. Use revoke() for permanent
        decommissioning.

        Args:
            agent_id: Agent UUID to suspend.
            tenant_id: Owning tenant UUID.
            reason: Optional audit reason for suspension.

        Raises:
            NotFoundError: If the agent does not exist.
        """
        found = await self._repo.update_status(
            agent_id=agent_id,
            tenant_id=tenant_id,
            status="suspended",
        )
        if not found:
            raise NotFoundError(resource="agent_identity", resource_id=str(agent_id))

        logger.info(
            "Agent suspended",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            reason=reason,
        )

    async def revoke_agent(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        reason: str | None = None,
    ) -> None:
        """Permanently revoke an agent identity.

        Revoked agents cannot be re-activated. Their certificates should be
        added to a CRL or OCSP responder in production deployments.

        Args:
            agent_id: Agent UUID to revoke.
            tenant_id: Owning tenant UUID.
            reason: Optional audit reason for revocation.

        Raises:
            NotFoundError: If the agent does not exist.
        """
        found = await self._repo.update_status(
            agent_id=agent_id,
            tenant_id=tenant_id,
            status="revoked",
        )
        if not found:
            raise NotFoundError(resource="agent_identity", resource_id=str(agent_id))

        logger.warning(
            "Agent revoked",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            reason=reason,
        )

    async def get_behavioral_profile(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Retrieve the behavioral profile summary for an agent.

        Returns the agent's identity record combined with any available
        behavioral baseline metrics. This is the data used by the anomaly
        detector to compute deviation scores.

        Args:
            agent_id: Agent UUID.
            tenant_id: Owning tenant UUID.

        Returns:
            Dictionary with identity details and behavioral summary.

        Raises:
            NotFoundError: If the agent does not exist.
        """
        record = await self.get_agent(agent_id=agent_id, tenant_id=tenant_id)

        return {
            "agent_id": str(record.agent_id),
            "tenant_id": str(record.tenant_id),
            "agent_class": record.agent_class,
            "display_name": record.display_name,
            "status": record.status,
            "permitted_operations": record.permitted_operations,
            "certificate_fingerprint": record.certificate_fingerprint,
            "registered_at": record.registered_at.isoformat(),
        }

    async def list_anomalies(
        self,
        tenant_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List detected behavioral anomalies.

        Args:
            tenant_id: Optional tenant filter. If None, returns all (admin).
            limit: Maximum number of records to return.
            offset: Pagination offset.

        Returns:
            List of anomaly record dictionaries.
        """
        return await self._repo.list_anomalies(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
        )
