"""SQLAlchemy ORM models for Auth Gateway — agent identities and policy evaluations."""

import uuid
from datetime import datetime
from enum import IntEnum

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

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


# ---------------------------------------------------------------------------
# Zero-Trust Agent Identity models (P2.1)
# ---------------------------------------------------------------------------


class ZeroTrustAgentIdentity(AumOSModel):
    """Cryptographic identity for a zero-trust AI agent with X.509 certificate.

    Every AI agent receives a short-lived X.509 certificate (Ed25519) with the
    agent_id and tenant_id embedded as URI Subject Alternative Names. Tokens
    are obtained via certificate-based exchange and have a 5-minute TTL.

    Table prefix: ath_ (auth-gateway)
    """

    __tablename__ = "ath_zt_agent_identities"

    agent_class: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Agent role class: orchestrator, tool, evaluator, retriever, executor",
    )
    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Human-readable display name for this agent",
    )
    certificate_serial: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
        comment="Hex serial number of the active X.509 certificate",
    )
    certificate_fingerprint: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
        comment="SHA-256 fingerprint of the active certificate for quick lookup",
    )
    certificate_pem: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="PEM-encoded X.509 certificate — public cert only, no private key",
    )
    permitted_operations: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of permitted operation identifiers (JSONB array)",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
        index=True,
        comment="Identity status: active | suspended | revoked | expired",
    )


class AgentBehavioralBaseline(AumOSModel):
    """Established behavioral baseline for an AI agent identity.

    Records the reference behavioral profile (operation rates, sequence patterns,
    time-of-day distributions) established during a baseline observation period.

    Table prefix: ath_ (auth-gateway)
    """

    __tablename__ = "ath_agent_behavioral_baselines"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Agent identity UUID this baseline belongs to",
    )
    baseline_period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Start of the baseline observation window (UTC)",
    )
    baseline_period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="End of the baseline observation window (UTC)",
    )
    operation_distribution: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="Frequency distribution of operation types: {operation: count}",
    )
    call_rate_p50: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Median (p50) call rate per minute over the baseline period",
    )
    call_rate_p99: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="99th percentile call rate per minute over the baseline period",
    )
    operation_sequence_model: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=dict,
        comment="Markov chain transition matrix for operation sequence modeling",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
        index=True,
        comment="Baseline status: active | superseded | archived",
    )


class AgentBehavioralAnomaly(AumOSModel):
    """Detected behavioral anomaly for an AI agent identity.

    Created by the AgentBehavioralAnomalyDetector when an agent's observed
    behavior deviates from its established baseline. High-score anomalies
    (composite >= 0.85) trigger automatic revocation.

    Table prefix: ath_ (auth-gateway)
    """

    __tablename__ = "ath_agent_behavioral_anomalies"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Agent identity UUID where the anomaly was detected",
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Timestamp when the anomaly was detected (UTC)",
    )
    anomaly_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Anomaly signal type: call_rate | operation_set | data_access | sequence | time_of_day",
    )
    anomaly_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="Composite anomaly score (0.0 = normal, 1.0 = maximum anomaly)",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Human-readable description of the detected anomaly",
    )
    actions_taken: Mapped[dict] = mapped_column(  # type: ignore[type-arg]
        JSONB,
        nullable=False,
        default=list,
        comment="List of automated actions taken in response to this anomaly",
    )
