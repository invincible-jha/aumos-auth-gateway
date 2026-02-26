"""SQLAlchemy repository implementations for Auth Gateway.

Provides CRUD access to agent identities and policy evaluation audit records.
Uses BaseRepository from aumos-common for automatic RLS tenant isolation and
standard CRUD operations.

Table prefix: ath_ (auth-gateway)
"""

import secrets
import uuid
from datetime import datetime
from typing import Any

import bcrypt
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.database import BaseRepository
from aumos_common.observability import get_logger

from aumos_auth_gateway.api.schemas import (
    AgentCreateRequest,
    AgentResponse,
    AgentUpdateRequest,
)
from aumos_auth_gateway.core.models import AgentIdentity, AgentStatus, PolicyEvaluation

logger = get_logger(__name__)

_SECRET_BYTES = 48  # 48 bytes → 96-char hex string
_BCRYPT_ROUNDS = 12


def _generate_secret() -> tuple[str, str]:
    """Generate a cryptographically secure secret and its bcrypt hash.

    Returns:
        Tuple of (plaintext_hex_secret, bcrypt_hash).
    """
    plaintext = secrets.token_hex(_SECRET_BYTES)
    hashed = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode()
    return plaintext, hashed


def _agent_to_response(agent: AgentIdentity) -> AgentResponse:
    """Convert a SQLAlchemy AgentIdentity ORM object to AgentResponse schema.

    Args:
        agent: The ORM model instance.

    Returns:
        Pydantic AgentResponse.
    """
    return AgentResponse(
        id=agent.id,
        tenant_id=agent.tenant_id,
        name=agent.name,
        agent_type=agent.agent_type,
        privilege_level=agent.privilege_level,
        allowed_tools=agent.allowed_tools or [],
        allowed_models=agent.allowed_models or [],
        max_tokens_per_hr=agent.max_tokens_per_hr,
        requires_hitl=agent.requires_hitl,
        service_account=agent.service_account,
        status=agent.status,
        last_rotated_at=agent.last_rotated_at,
        metadata=agent.metadata_ or {},
        created_at=agent.created_at,
        updated_at=agent.updated_at,
    )


class AgentRepository(BaseRepository[AgentIdentity]):  # type: ignore[type-arg]
    """Repository for AI-agent identity CRUD operations.

    Extends BaseRepository with agent-specific methods including secret hashing,
    service account generation, and soft-delete (revoke) support.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async SQLAlchemy session.

        Args:
            session: Async SQLAlchemy database session.
        """
        super().__init__(session)

    async def create(
        self,
        tenant_id: uuid.UUID,
        request: AgentCreateRequest,
    ) -> tuple[AgentResponse, str]:
        """Persist a new agent identity with a generated service account and hashed secret.

        Args:
            tenant_id: Tenant UUID that owns the agent.
            request: Agent creation parameters.

        Returns:
            Tuple of (AgentResponse, plaintext_secret). The plaintext secret
            is only available at creation time.
        """
        plaintext_secret, secret_hash = _generate_secret()
        service_account = f"agent-{uuid.uuid4().hex[:12]}"

        agent = AgentIdentity(
            tenant_id=tenant_id,
            name=request.name,
            agent_type=request.agent_type,
            privilege_level=request.privilege_level,
            allowed_tools=request.allowed_tools,
            allowed_models=request.allowed_models,
            max_tokens_per_hr=request.max_tokens_per_hr,
            requires_hitl=request.requires_hitl,
            service_account=service_account,
            secret_hash=secret_hash,
            last_rotated_at=datetime.utcnow(),
            status=AgentStatus.ACTIVE,
            metadata_=request.metadata,
        )
        self.session.add(agent)
        await self.session.flush()
        await self.session.refresh(agent)

        logger.info(
            "Agent identity persisted",
            agent_id=str(agent.id),
            tenant_id=str(tenant_id),
            service_account=service_account,
        )
        return _agent_to_response(agent), plaintext_secret

    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> AgentResponse | None:
        """Retrieve a single agent by ID within a tenant.

        Args:
            tenant_id: Tenant UUID for isolation.
            agent_id: Agent UUID.

        Returns:
            AgentResponse if found, None otherwise.
        """
        stmt = select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.status != AgentStatus.REVOKED,
        )
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()
        return _agent_to_response(agent) if agent is not None else None

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[AgentResponse], int]:
        """List agents for a tenant with offset pagination.

        Args:
            tenant_id: Tenant UUID.
            page: 1-based page number.
            page_size: Number of results per page.

        Returns:
            Tuple of (list of AgentResponse, total count).
        """
        base_filter = (
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.status != AgentStatus.REVOKED,
        )

        count_stmt = select(func.count()).select_from(AgentIdentity).where(*base_filter)
        count_result = await self.session.execute(count_stmt)
        total: int = count_result.scalar_one()

        offset = (page - 1) * page_size
        list_stmt = (
            select(AgentIdentity)
            .where(*base_filter)
            .order_by(AgentIdentity.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        list_result = await self.session.execute(list_stmt)
        agents = list_result.scalars().all()

        return [_agent_to_response(a) for a in agents], total

    async def update(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        request: AgentUpdateRequest,
    ) -> AgentResponse | None:
        """Apply a partial update to an agent identity.

        Only non-None fields in the request are applied (PATCH semantics).

        Args:
            tenant_id: Tenant UUID for isolation.
            agent_id: Agent UUID.
            request: Fields to update.

        Returns:
            Updated AgentResponse, or None if the agent was not found.
        """
        update_values: dict[str, Any] = {}
        if request.privilege_level is not None:
            update_values["privilege_level"] = request.privilege_level
        if request.allowed_tools is not None:
            update_values["allowed_tools"] = request.allowed_tools
        if request.allowed_models is not None:
            update_values["allowed_models"] = request.allowed_models
        if request.max_tokens_per_hr is not None:
            update_values["max_tokens_per_hr"] = request.max_tokens_per_hr
        if request.requires_hitl is not None:
            update_values["requires_hitl"] = request.requires_hitl
        if request.status is not None:
            update_values["status"] = request.status
        if request.metadata is not None:
            update_values["metadata_"] = request.metadata

        if not update_values:
            return await self.get_by_id(tenant_id=tenant_id, agent_id=agent_id)

        update_values["updated_at"] = datetime.utcnow()

        stmt = (
            update(AgentIdentity)
            .where(AgentIdentity.id == agent_id, AgentIdentity.tenant_id == tenant_id)
            .values(**update_values)
            .returning(AgentIdentity)
        )
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()
        return _agent_to_response(agent) if agent is not None else None

    async def delete(self, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> bool:
        """Soft-delete (revoke) an agent by setting status to REVOKED.

        Args:
            tenant_id: Tenant UUID for isolation.
            agent_id: Agent UUID.

        Returns:
            True if the agent was found and revoked, False if not found.
        """
        stmt = (
            update(AgentIdentity)
            .where(
                AgentIdentity.id == agent_id,
                AgentIdentity.tenant_id == tenant_id,
                AgentIdentity.status != AgentStatus.REVOKED,
            )
            .values(status=AgentStatus.REVOKED, updated_at=datetime.utcnow())
        )
        result = await self.session.execute(stmt)
        return result.rowcount > 0

    async def rotate_secret(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> tuple[AgentResponse, str] | None:
        """Generate a new secret hash and update last_rotated_at.

        Args:
            tenant_id: Tenant UUID for isolation.
            agent_id: Agent UUID.

        Returns:
            Tuple of (updated_AgentResponse, new_plaintext_secret) or None if not found.
        """
        plaintext_secret, new_hash = _generate_secret()
        now = datetime.utcnow()

        stmt = (
            update(AgentIdentity)
            .where(
                AgentIdentity.id == agent_id,
                AgentIdentity.tenant_id == tenant_id,
                AgentIdentity.status == AgentStatus.ACTIVE,
            )
            .values(secret_hash=new_hash, last_rotated_at=now, updated_at=now)
            .returning(AgentIdentity)
        )
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()
        if agent is None:
            return None

        logger.info("Agent secret rotated", agent_id=str(agent_id), tenant_id=str(tenant_id))
        return _agent_to_response(agent), plaintext_secret

    async def get_by_service_account(self, service_account: str) -> AgentResponse | None:
        """Look up an agent by its service account name.

        Used in auth flows where the service account is the JWT subject.

        Args:
            service_account: Service account identifier string.

        Returns:
            AgentResponse if found, None otherwise.
        """
        stmt = select(AgentIdentity).where(
            AgentIdentity.service_account == service_account,
            AgentIdentity.status == AgentStatus.ACTIVE,
        )
        result = await self.session.execute(stmt)
        agent = result.scalar_one_or_none()
        return _agent_to_response(agent) if agent is not None else None


class PolicyEvaluationRepository(BaseRepository[PolicyEvaluation]):  # type: ignore[type-arg]
    """Repository for OPA policy evaluation audit log records.

    Stores every policy evaluation result for compliance and forensics.
    Not tenant-isolated at the RLS level — access is controlled by RBAC
    at the API layer.

    Args:
        session: The async SQLAlchemy session (injected by FastAPI dependency).
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize with async SQLAlchemy session.

        Args:
            session: Async SQLAlchemy database session.
        """
        super().__init__(session)

    async def record(
        self,
        tenant_id: uuid.UUID,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        policy_name: str | None,
        evaluation_ms: float | None,
        context: dict[str, Any],
    ) -> None:
        """Persist a policy evaluation result to the audit table.

        Args:
            tenant_id: Tenant context for the evaluation.
            subject: Who requested access (user/agent ID).
            resource: Resource being accessed.
            action: Action requested.
            decision: allow or deny.
            policy_name: OPA policy path that produced the decision.
            evaluation_ms: OPA evaluation latency in milliseconds.
            context: Full evaluation context document for audit trail.
        """
        evaluation = PolicyEvaluation(
            tenant_id=tenant_id,
            subject=subject,
            resource=resource,
            action=action,
            decision=decision,
            policy_name=policy_name,
            evaluation_ms=evaluation_ms,
            timestamp=datetime.utcnow(),
            context=context,
        )
        self.session.add(evaluation)
        await self.session.flush()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], int]:
        """List policy evaluation records for a tenant with pagination.

        Args:
            tenant_id: Tenant UUID to filter by.
            page: 1-based page number.
            page_size: Number of results per page.

        Returns:
            Tuple of (list of evaluation dicts, total count).
        """
        count_stmt = (
            select(func.count())
            .select_from(PolicyEvaluation)
            .where(PolicyEvaluation.tenant_id == tenant_id)
        )
        count_result = await self.session.execute(count_stmt)
        total: int = count_result.scalar_one()

        offset = (page - 1) * page_size
        list_stmt = (
            select(PolicyEvaluation)
            .where(PolicyEvaluation.tenant_id == tenant_id)
            .order_by(PolicyEvaluation.timestamp.desc())
            .offset(offset)
            .limit(page_size)
        )
        list_result = await self.session.execute(list_stmt)
        evaluations = list_result.scalars().all()

        records: list[dict[str, Any]] = [
            {
                "id": str(e.id),
                "tenant_id": str(e.tenant_id),
                "subject": e.subject,
                "resource": e.resource,
                "action": e.action,
                "decision": e.decision,
                "policy_name": e.policy_name,
                "evaluation_ms": e.evaluation_ms,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "context": e.context,
            }
            for e in evaluations
        ]
        return records, total
