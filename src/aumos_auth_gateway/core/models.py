"""SQLAlchemy ORM models for Auth Gateway — agent identities and policy evaluations."""

import uuid
from datetime import datetime
from enum import IntEnum

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

from aumos_common.database import AumOSModel, Base


class AgentType(str):
    """Valid agent type values for ath_agent_identities."""

    SYNTHESIS = "synthesis"
    GOVERNANCE = "governance"
    SECURITY = "security"
    ORCHESTRATOR = "orchestrator"
    ANALYTICS = "analytics"


class PrivilegeLevel(IntEnum):
    """Five-level AI-agent privilege system.

    Each level grants progressively broader capabilities and requires
    stricter authorization controls. Levels 4+ require HITL approval by default.
    """

    READ_ONLY = 1
    """Can read data and call read-only tools. No state mutations."""

    STANDARD = 2
    """Can perform standard operations within own tenant context."""

    ELEVATED = 3
    """Can access advanced tools and models. Requires explicit allowlist."""

    PRIVILEGED = 4
    """Can perform cross-system operations. Requires HITL gate by default."""

    SUPER_ADMIN = 5
    """Full platform access. Reserved for orchestrator agents with explicit approval."""


class AgentStatus(str):
    """Valid status values for ath_agent_identities."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    ROTATING = "rotating"


class AgentIdentity(AumOSModel):
    """AI-agent service identity with privilege levels and capability constraints.

    Each agent receives a service_account + secret pair (like a service account)
    and is constrained to specific tools, models, and token budgets.

    Table prefix: ath_ (auth-gateway)
    """

    __tablename__ = "ath_agent_identities"

    # Override id and tenant_id from AumOSModel (already provided by parent)
    name = Column(String(255), nullable=False, index=True, comment="Human-readable agent name")
    agent_type = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Agent category: synthesis, governance, security, orchestrator, analytics",
    )
    privilege_level = Column(
        Integer,
        nullable=False,
        default=PrivilegeLevel.READ_ONLY,
        comment="1=READ_ONLY, 2=STANDARD, 3=ELEVATED, 4=PRIVILEGED, 5=SUPER_ADMIN",
    )
    allowed_tools = Column(
        ARRAY(Text),
        nullable=False,
        default=list,
        comment="Allowlisted tool names this agent may invoke",
    )
    allowed_models = Column(
        ARRAY(Text),
        nullable=False,
        default=list,
        comment="Allowlisted model IDs this agent may call",
    )
    max_tokens_per_hr = Column(
        Integer,
        nullable=False,
        default=100000,
        comment="Token rate limit per hour (enforced by Kong + OPA)",
    )
    requires_hitl = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether human approval is required before actions",
    )
    service_account = Column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique service account identifier (used as JWT subject)",
    )
    secret_hash = Column(
        String(255),
        nullable=False,
        comment="Bcrypt hash of the agent secret — plaintext never stored",
    )
    last_rotated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        comment="Timestamp of last secret rotation",
    )
    status = Column(
        String(20),
        nullable=False,
        default=AgentStatus.ACTIVE,
        index=True,
        comment="active, suspended, revoked, rotating",
    )
    metadata_ = Column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        comment="Arbitrary metadata — contact owner, purpose, deployment context",
    )


class PolicyEvaluation(Base):
    """Audit log of OPA policy evaluation results.

    Not tenant-isolated because policy evaluations may span tenants
    (super-admin operations). Access controlled by RBAC at the API layer.

    Table prefix: ath_ (auth-gateway)
    """

    __tablename__ = "ath_policy_evaluations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    subject = Column(String(255), nullable=False, index=True, comment="Who is requesting access (user/agent ID)")
    resource = Column(String(255), nullable=False, index=True, comment="Resource being accessed (path or URN)")
    action = Column(String(50), nullable=False, comment="Action requested: read, write, delete, execute")
    decision = Column(String(10), nullable=False, index=True, comment="allow or deny")
    policy_name = Column(String(255), nullable=True, comment="Policy that produced the decision")
    evaluation_ms = Column(Float, nullable=True, comment="OPA evaluation latency in milliseconds")
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )
    context = Column(JSONB, nullable=False, default=dict, comment="Full evaluation context for audit trail")
