"""Agent Privilege Auditor adapter for AumOS Auth Gateway.

Tracks per-agent privilege usage, detects escalations and least-privilege
violations, surfaces dormant privileges, and generates structured audit
reports for periodic access reviews.

License: Apache 2.0
"""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Privilege level names for reporting
PRIVILEGE_LEVEL_NAMES: dict[int, str] = {
    1: "READ_ONLY",
    2: "STANDARD",
    3: "ELEVATED",
    4: "PRIVILEGED",
    5: "SUPER_ADMIN",
}

# Privilege usage event action categories
ACTION_READ = "read"
ACTION_WRITE = "write"
ACTION_EXECUTE = "execute"
ACTION_ADMIN = "admin"
ACTION_CROSS_TENANT = "cross_tenant"

# Days of inactivity before a privilege is considered dormant
DORMANT_THRESHOLD_DAYS = 30

# Maximum usage events retained per agent (ring-buffer style)
MAX_USAGE_EVENTS_PER_AGENT = 500


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PrivilegeUsageEvent:
    """A single privilege usage record for an agent.

    Attributes:
        event_id: Unique identifier for this usage event.
        agent_id: UUID of the agent that used the privilege.
        tenant_id: UUID of the tenant context.
        privilege_level_used: Actual privilege level exercised (1-5).
        configured_privilege_level: Agent's assigned maximum privilege level.
        resource: Resource URN or path that was accessed.
        action: Action category (read, write, execute, admin, cross_tenant).
        granted: Whether the access was granted or denied.
        timestamp: UTC timestamp when the event occurred.
        ip_address: Optional caller IP address.
        correlation_id: Request correlation identifier.
        metadata: Arbitrary additional context.
    """

    event_id: uuid.UUID
    agent_id: uuid.UUID
    tenant_id: uuid.UUID
    privilege_level_used: int
    configured_privilege_level: int
    resource: str
    action: str
    granted: bool
    timestamp: datetime
    ip_address: str | None = None
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_escalation(self) -> bool:
        """Return True if the privilege used exceeded the configured level."""
        return self.privilege_level_used > self.configured_privilege_level

    @property
    def is_least_privilege_violation(self) -> bool:
        """Return True if the agent used a higher privilege than necessary.

        Defined as using privilege > 1 (READ_ONLY) when the action was read-only.
        """
        return self.action == ACTION_READ and self.privilege_level_used > 1


@dataclass
class AgentPrivilegeSummary:
    """Aggregated privilege usage summary for a single agent.

    Attributes:
        agent_id: UUID of the agent.
        tenant_id: UUID of the owning tenant.
        configured_privilege_level: Agent's assigned privilege ceiling.
        max_privilege_used: Highest privilege level actually exercised.
        total_events: Total number of usage events recorded.
        granted_events: Number of granted access events.
        denied_events: Number of denied access events.
        escalation_count: Number of events where used > configured privilege.
        least_privilege_violations: Number of over-privileged read operations.
        action_breakdown: Count of events per action category.
        first_seen: Timestamp of the earliest recorded event.
        last_seen: Timestamp of the most recent recorded event.
        is_dormant: True if no activity in the last DORMANT_THRESHOLD_DAYS days.
    """

    agent_id: uuid.UUID
    tenant_id: uuid.UUID
    configured_privilege_level: int
    max_privilege_used: int
    total_events: int
    granted_events: int
    denied_events: int
    escalation_count: int
    least_privilege_violations: int
    action_breakdown: dict[str, int]
    first_seen: datetime | None
    last_seen: datetime | None
    is_dormant: bool


@dataclass
class EscalationAlert:
    """Record of a detected privilege escalation event.

    Attributes:
        alert_id: Unique identifier for this alert.
        agent_id: UUID of the agent that escalated.
        tenant_id: UUID of the tenant context.
        configured_level: Agent's assigned privilege ceiling.
        used_level: Privilege level that was actually exercised.
        resource: Resource that was accessed.
        action: Action that was attempted.
        timestamp: When the escalation occurred.
        correlation_id: Request correlation identifier.
    """

    alert_id: uuid.UUID
    agent_id: uuid.UUID
    tenant_id: uuid.UUID
    configured_level: int
    used_level: int
    resource: str
    action: str
    timestamp: datetime
    correlation_id: str | None


@dataclass
class AccessReviewEntry:
    """Privilege access review record for periodic review workflows.

    Attributes:
        agent_id: UUID of the agent under review.
        tenant_id: UUID of the owning tenant.
        configured_privilege_level: Agent's assigned maximum privilege.
        recommended_privilege_level: System recommendation based on usage.
        justification: Human-readable recommendation rationale.
        last_activity: Most recent recorded usage timestamp.
        total_events_last_30d: Activity count in the past 30 days.
        escalation_count_last_30d: Escalation count in the past 30 days.
        is_dormant: True if no activity in DORMANT_THRESHOLD_DAYS days.
        risk_score: Integer risk score (0-100) for prioritising review.
    """

    agent_id: uuid.UUID
    tenant_id: uuid.UUID
    configured_privilege_level: int
    recommended_privilege_level: int
    justification: str
    last_activity: datetime | None
    total_events_last_30d: int
    escalation_count_last_30d: int
    is_dormant: bool
    risk_score: int


@dataclass
class PrivilegeAuditReport:
    """Full privilege audit report for a tenant.

    Attributes:
        report_id: Unique report identifier.
        tenant_id: UUID of the tenant being audited.
        generated_at: UTC timestamp when the report was generated.
        period_start: Start of the audit period.
        period_end: End of the audit period.
        total_agents: Number of agents in scope.
        dormant_agents: Agents with no activity in DORMANT_THRESHOLD_DAYS days.
        agents_with_escalations: Count of agents with any escalation events.
        total_escalation_events: Total privilege escalation events in period.
        total_least_privilege_violations: Total over-privileged read operations.
        agent_summaries: Per-agent aggregated summaries.
        escalation_alerts: All escalation alerts in the period.
        access_review_entries: Prioritised review list.
    """

    report_id: uuid.UUID
    tenant_id: uuid.UUID
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_agents: int
    dormant_agents: int
    agents_with_escalations: int
    total_escalation_events: int
    total_least_privilege_violations: int
    agent_summaries: list[AgentPrivilegeSummary]
    escalation_alerts: list[EscalationAlert]
    access_review_entries: list[AccessReviewEntry]


# ---------------------------------------------------------------------------
# Main adapter class
# ---------------------------------------------------------------------------


class AgentPrivilegeAuditor:
    """Tracks, analyses, and reports on per-agent privilege usage.

    Maintains an in-memory store of privilege usage events per (tenant, agent)
    pair. Provides real-time escalation detection, least-privilege violation
    flagging, dormancy analysis, and full audit report generation.

    In production, the in-memory store is complemented by a persistent
    audit sink (e.g., aumos-data-layer or a SIEM endpoint) via the
    optional ``audit_sink_url`` parameter.

    Args:
        audit_sink_url: Optional HTTP endpoint to forward audit events.
        http_client: Optional pre-configured httpx.AsyncClient. When provided,
            audit events are forwarded to ``audit_sink_url`` in real time.
        max_events_per_agent: Maximum usage events retained per agent in
            memory. Older events are evicted when the limit is reached.

    Example:
        auditor = AgentPrivilegeAuditor()
        await auditor.record_usage(
            agent_id=agent.id,
            tenant_id=tenant.tenant_id,
            privilege_level_used=2,
            configured_privilege_level=3,
            resource="urn:model:llama3",
            action=ACTION_EXECUTE,
            granted=True,
        )
        report = await auditor.generate_report(tenant_id=tenant.tenant_id)
    """

    def __init__(
        self,
        audit_sink_url: str | None = None,
        http_client: Any | None = None,
        max_events_per_agent: int = MAX_USAGE_EVENTS_PER_AGENT,
    ) -> None:
        self._audit_sink_url = audit_sink_url
        self._http_client = http_client
        self._max_events = max_events_per_agent

        # Storage keyed by (tenant_id, agent_id) → list[PrivilegeUsageEvent]
        # Using defaultdict(list) for O(1) insertion.
        self._events: dict[tuple[uuid.UUID, uuid.UUID], list[PrivilegeUsageEvent]] = defaultdict(list)

        # Escalation alerts keyed by tenant_id → list[EscalationAlert]
        self._escalation_alerts: dict[uuid.UUID, list[EscalationAlert]] = defaultdict(list)

        # Lock for thread-safe in-memory mutations
        self._lock = asyncio.Lock()

        logger.info(
            "AgentPrivilegeAuditor initialised",
            audit_sink_url=audit_sink_url or "none",
            max_events_per_agent=max_events_per_agent,
        )

    # -----------------------------------------------------------------------
    # Recording
    # -----------------------------------------------------------------------

    async def record_usage(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        privilege_level_used: int,
        configured_privilege_level: int,
        resource: str,
        action: str,
        granted: bool,
        ip_address: str | None = None,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PrivilegeUsageEvent:
        """Record a privilege usage event for an agent.

        Performs real-time escalation detection: if ``privilege_level_used``
        exceeds ``configured_privilege_level``, an EscalationAlert is also
        created and forwarded to the audit sink.

        Args:
            agent_id: UUID of the agent that acted.
            tenant_id: UUID of the tenant context.
            privilege_level_used: Actual privilege level exercised (1-5).
            configured_privilege_level: Agent's assigned maximum privilege level.
            resource: Resource URN or path that was accessed.
            action: Action category (use ACTION_* constants).
            granted: Whether the access was granted (True) or denied (False).
            ip_address: Optional caller IP address.
            correlation_id: Optional request correlation ID.
            metadata: Optional arbitrary additional context.

        Returns:
            The recorded PrivilegeUsageEvent.

        Raises:
            AumOSError: If privilege levels are out of range (1-5).
        """
        if not (1 <= privilege_level_used <= 5):
            raise AumOSError(
                message=f"privilege_level_used must be 1-5, got {privilege_level_used}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )
        if not (1 <= configured_privilege_level <= 5):
            raise AumOSError(
                message=f"configured_privilege_level must be 1-5, got {configured_privilege_level}",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        event = PrivilegeUsageEvent(
            event_id=uuid.uuid4(),
            agent_id=agent_id,
            tenant_id=tenant_id,
            privilege_level_used=privilege_level_used,
            configured_privilege_level=configured_privilege_level,
            resource=resource,
            action=action,
            granted=granted,
            timestamp=datetime.now(tz=timezone.utc),
            ip_address=ip_address,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )

        async with self._lock:
            key = (tenant_id, agent_id)
            bucket = self._events[key]

            # Evict oldest events when at capacity
            if len(bucket) >= self._max_events:
                bucket.pop(0)
            bucket.append(event)

            # Detect and record escalation
            if event.is_escalation:
                alert = EscalationAlert(
                    alert_id=uuid.uuid4(),
                    agent_id=agent_id,
                    tenant_id=tenant_id,
                    configured_level=configured_privilege_level,
                    used_level=privilege_level_used,
                    resource=resource,
                    action=action,
                    timestamp=event.timestamp,
                    correlation_id=correlation_id,
                )
                self._escalation_alerts[tenant_id].append(alert)

                logger.warning(
                    "Privilege escalation detected",
                    agent_id=str(agent_id),
                    tenant_id=str(tenant_id),
                    configured_level=configured_privilege_level,
                    used_level=privilege_level_used,
                    resource=resource,
                    action=action,
                    correlation_id=correlation_id,
                )

        # Forward to audit sink asynchronously (non-blocking)
        if self._audit_sink_url and self._http_client:
            asyncio.create_task(self._forward_event(event))

        logger.debug(
            "Privilege usage recorded",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            privilege_level_used=privilege_level_used,
            action=action,
            granted=granted,
        )
        return event

    # -----------------------------------------------------------------------
    # Escalation detection
    # -----------------------------------------------------------------------

    async def get_escalation_alerts(
        self,
        tenant_id: uuid.UUID,
        since: datetime | None = None,
        agent_id: uuid.UUID | None = None,
    ) -> list[EscalationAlert]:
        """Retrieve privilege escalation alerts for a tenant.

        Args:
            tenant_id: UUID of the tenant to query.
            since: If provided, return only alerts after this timestamp.
            agent_id: If provided, filter to a specific agent.

        Returns:
            List of EscalationAlert records, ordered by timestamp ascending.
        """
        async with self._lock:
            alerts = list(self._escalation_alerts.get(tenant_id, []))

        if since is not None:
            alerts = [a for a in alerts if a.timestamp >= since]
        if agent_id is not None:
            alerts = [a for a in alerts if a.agent_id == agent_id]

        return sorted(alerts, key=lambda a: a.timestamp)

    # -----------------------------------------------------------------------
    # Least-privilege analysis
    # -----------------------------------------------------------------------

    async def get_least_privilege_violations(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID | None = None,
    ) -> list[PrivilegeUsageEvent]:
        """Return usage events where an agent used higher privilege than necessary.

        A violation is recorded when an agent performs a read-only action using
        a privilege level above READ_ONLY (level 1). This indicates the agent
        could be reconfigured to a lower privilege tier without loss of function.

        Args:
            tenant_id: UUID of the tenant to query.
            agent_id: If provided, filter to a specific agent.

        Returns:
            List of PrivilegeUsageEvent records flagged as violations.
        """
        async with self._lock:
            if agent_id is not None:
                keys = [(tenant_id, agent_id)]
            else:
                keys = [k for k in self._events if k[0] == tenant_id]

            violations: list[PrivilegeUsageEvent] = []
            for key in keys:
                for event in self._events[key]:
                    if event.is_least_privilege_violation:
                        violations.append(event)

        return sorted(violations, key=lambda e: e.timestamp)

    # -----------------------------------------------------------------------
    # Usage analytics
    # -----------------------------------------------------------------------

    async def get_usage_analytics(
        self,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID | None = None,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Return aggregated privilege usage analytics for a tenant.

        Args:
            tenant_id: UUID of the tenant to analyse.
            agent_id: If provided, scope analytics to a single agent.
            since: If provided, consider only events after this timestamp.

        Returns:
            Dictionary with keys:
                - total_events: Total usage events in scope.
                - granted_events: Count of granted events.
                - denied_events: Count of denied events.
                - escalation_events: Count of escalation events.
                - least_privilege_violations: Count of over-privileged reads.
                - action_breakdown: Dict of action → count.
                - privilege_level_breakdown: Dict of level → count.
                - active_agents: Count of agents with at least one event.
        """
        async with self._lock:
            if agent_id is not None:
                keys = [(tenant_id, agent_id)]
            else:
                keys = [k for k in self._events if k[0] == tenant_id]

            all_events: list[PrivilegeUsageEvent] = []
            for key in keys:
                all_events.extend(self._events[key])

        if since is not None:
            all_events = [e for e in all_events if e.timestamp >= since]

        action_breakdown: dict[str, int] = defaultdict(int)
        privilege_breakdown: dict[int, int] = defaultdict(int)
        active_agents: set[uuid.UUID] = set()
        granted = denied = escalations = least_priv = 0

        for event in all_events:
            active_agents.add(event.agent_id)
            action_breakdown[event.action] += 1
            privilege_breakdown[event.privilege_level_used] += 1

            if event.granted:
                granted += 1
            else:
                denied += 1
            if event.is_escalation:
                escalations += 1
            if event.is_least_privilege_violation:
                least_priv += 1

        return {
            "total_events": len(all_events),
            "granted_events": granted,
            "denied_events": denied,
            "escalation_events": escalations,
            "least_privilege_violations": least_priv,
            "action_breakdown": dict(action_breakdown),
            "privilege_level_breakdown": {
                PRIVILEGE_LEVEL_NAMES.get(level, str(level)): count
                for level, count in privilege_breakdown.items()
            },
            "active_agents": len(active_agents),
        }

    # -----------------------------------------------------------------------
    # Dormant privilege identification
    # -----------------------------------------------------------------------

    async def get_dormant_agents(
        self,
        tenant_id: uuid.UUID,
        threshold_days: int = DORMANT_THRESHOLD_DAYS,
    ) -> list[AgentPrivilegeSummary]:
        """Identify agents with no privilege activity in ``threshold_days`` days.

        Agents that are dormant may still hold high privilege levels, representing
        an unnecessary attack surface. This method surfaces them for review.

        Args:
            tenant_id: UUID of the tenant to scan.
            threshold_days: Days of inactivity required to flag as dormant.

        Returns:
            List of AgentPrivilegeSummary for dormant agents, ordered by
            last_seen ascending (longest dormant first).
        """
        cutoff = datetime.now(tz=timezone.utc)
        summaries = await self._build_summaries(tenant_id, dormant_threshold_days=threshold_days)
        dormant = [s for s in summaries if s.is_dormant]

        logger.info(
            "Dormant agent scan complete",
            tenant_id=str(tenant_id),
            total_agents=len(summaries),
            dormant_agents=len(dormant),
            threshold_days=threshold_days,
        )
        # Suppress unused variable warning
        _ = cutoff

        return sorted(dormant, key=lambda s: (s.last_seen or datetime.min.replace(tzinfo=timezone.utc)))

    # -----------------------------------------------------------------------
    # Access review
    # -----------------------------------------------------------------------

    async def get_access_review_data(
        self,
        tenant_id: uuid.UUID,
    ) -> list[AccessReviewEntry]:
        """Generate periodic access review data for all agents in a tenant.

        Each entry contains a recommended privilege level and a risk score,
        allowing security teams to prioritise which agents need review.

        Risk score formula (0-100):
            - Base: 10 × configured_privilege_level (up to 50)
            - +20 if dormant
            - +20 if any escalations in last 30 days
            - +10 if least-privilege violations exist

        Args:
            tenant_id: UUID of the tenant to review.

        Returns:
            List of AccessReviewEntry sorted by risk_score descending
            (highest risk first).
        """
        now = datetime.now(tz=timezone.utc)
        thirty_days_ago = datetime(
            now.year, now.month, now.day, now.hour, now.minute, now.second,
            tzinfo=timezone.utc,
        )
        # Subtract 30 days manually to avoid dateutil dependency
        thirty_days_ago = datetime.fromtimestamp(
            now.timestamp() - (DORMANT_THRESHOLD_DAYS * 86400),
            tz=timezone.utc,
        )

        summaries = await self._build_summaries(tenant_id, dormant_threshold_days=DORMANT_THRESHOLD_DAYS)
        entries: list[AccessReviewEntry] = []

        for summary in summaries:
            # Count last-30d events
            async with self._lock:
                key = (tenant_id, summary.agent_id)
                recent_events = [e for e in self._events[key] if e.timestamp >= thirty_days_ago]

            recent_escalations = sum(1 for e in recent_events if e.is_escalation)
            recent_lp_violations = sum(1 for e in recent_events if e.is_least_privilege_violation)

            # Recommend the minimum privilege level observed in actual usage
            if summary.max_privilege_used == 0:
                recommended = summary.configured_privilege_level
                justification = "No usage observed — maintain current level pending decommission review."
            elif summary.max_privilege_used < summary.configured_privilege_level:
                recommended = summary.max_privilege_used
                justification = (
                    f"Agent never used privileges above level {summary.max_privilege_used} "
                    f"({PRIVILEGE_LEVEL_NAMES.get(summary.max_privilege_used, '?')}). "
                    "Recommend downgrading to match observed usage."
                )
            else:
                recommended = summary.configured_privilege_level
                justification = "Configured level aligns with observed usage."

            if summary.escalation_count > 0:
                justification += (
                    f" WARNING: {summary.escalation_count} escalation event(s) detected — "
                    "investigate before any privilege changes."
                )

            # Risk score calculation
            risk_score = min(50, 10 * summary.configured_privilege_level)
            if summary.is_dormant:
                risk_score += 20
            if recent_escalations > 0:
                risk_score += 20
            if recent_lp_violations > 0:
                risk_score += 10
            risk_score = min(100, risk_score)

            entries.append(
                AccessReviewEntry(
                    agent_id=summary.agent_id,
                    tenant_id=tenant_id,
                    configured_privilege_level=summary.configured_privilege_level,
                    recommended_privilege_level=recommended,
                    justification=justification,
                    last_activity=summary.last_seen,
                    total_events_last_30d=len(recent_events),
                    escalation_count_last_30d=recent_escalations,
                    is_dormant=summary.is_dormant,
                    risk_score=risk_score,
                )
            )

        return sorted(entries, key=lambda e: e.risk_score, reverse=True)

    # -----------------------------------------------------------------------
    # Audit report generation
    # -----------------------------------------------------------------------

    async def generate_report(
        self,
        tenant_id: uuid.UUID,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> PrivilegeAuditReport:
        """Generate a comprehensive privilege audit report for a tenant.

        The report covers all agents in the tenant with their aggregated
        privilege usage summaries, all escalation alerts in the period,
        and a prioritised access review list.

        Args:
            tenant_id: UUID of the tenant to report on.
            period_start: Start of the audit period (defaults to 30 days ago).
            period_end: End of the audit period (defaults to now).

        Returns:
            PrivilegeAuditReport with fully populated sections.
        """
        now = datetime.now(tz=timezone.utc)
        effective_end = period_end or now
        effective_start = period_start or datetime.fromtimestamp(
            now.timestamp() - (DORMANT_THRESHOLD_DAYS * 86400),
            tz=timezone.utc,
        )

        summaries = await self._build_summaries(tenant_id, dormant_threshold_days=DORMANT_THRESHOLD_DAYS)
        escalation_alerts = await self.get_escalation_alerts(
            tenant_id=tenant_id,
            since=effective_start,
        )
        access_review_entries = await self.get_access_review_data(tenant_id=tenant_id)

        dormant_count = sum(1 for s in summaries if s.is_dormant)
        agents_with_escalations = sum(1 for s in summaries if s.escalation_count > 0)
        total_escalations = sum(s.escalation_count for s in summaries)
        total_lp_violations = sum(s.least_privilege_violations for s in summaries)

        report = PrivilegeAuditReport(
            report_id=uuid.uuid4(),
            tenant_id=tenant_id,
            generated_at=now,
            period_start=effective_start,
            period_end=effective_end,
            total_agents=len(summaries),
            dormant_agents=dormant_count,
            agents_with_escalations=agents_with_escalations,
            total_escalation_events=total_escalations,
            total_least_privilege_violations=total_lp_violations,
            agent_summaries=summaries,
            escalation_alerts=escalation_alerts,
            access_review_entries=access_review_entries,
        )

        logger.info(
            "Privilege audit report generated",
            tenant_id=str(tenant_id),
            report_id=str(report.report_id),
            total_agents=len(summaries),
            dormant_agents=dormant_count,
            total_escalation_events=total_escalations,
        )
        return report

    # -----------------------------------------------------------------------
    # Per-agent history
    # -----------------------------------------------------------------------

    async def get_agent_history(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[PrivilegeUsageEvent]:
        """Return recent privilege usage events for a specific agent.

        Args:
            agent_id: UUID of the agent to query.
            tenant_id: UUID of the owning tenant.
            since: If provided, return only events after this timestamp.
            limit: Maximum number of events to return (newest first).

        Returns:
            List of PrivilegeUsageEvent ordered by timestamp descending.
        """
        async with self._lock:
            key = (tenant_id, agent_id)
            events = list(self._events.get(key, []))

        if since is not None:
            events = [e for e in events if e.timestamp >= since]

        # Return newest first
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]

    async def get_agent_summary(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> AgentPrivilegeSummary | None:
        """Return the privilege usage summary for a single agent.

        Args:
            agent_id: UUID of the agent.
            tenant_id: UUID of the owning tenant.

        Returns:
            AgentPrivilegeSummary or None if no events have been recorded.
        """
        async with self._lock:
            key = (tenant_id, agent_id)
            if key not in self._events or not self._events[key]:
                return None

        summaries = await self._build_summaries(tenant_id, specific_agent_id=agent_id)
        return summaries[0] if summaries else None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def close(self) -> None:
        """Release HTTP client resources if owned by this instance."""
        if self._http_client is not None:
            try:
                await self._http_client.aclose()
            except Exception:
                pass
        logger.info("AgentPrivilegeAuditor closed")

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    async def _build_summaries(
        self,
        tenant_id: uuid.UUID,
        dormant_threshold_days: int = DORMANT_THRESHOLD_DAYS,
        specific_agent_id: uuid.UUID | None = None,
    ) -> list[AgentPrivilegeSummary]:
        """Build AgentPrivilegeSummary objects from in-memory events.

        Args:
            tenant_id: UUID of the tenant to summarise.
            dormant_threshold_days: Days of inactivity for dormancy flag.
            specific_agent_id: If provided, summarise only this agent.

        Returns:
            List of AgentPrivilegeSummary records.
        """
        cutoff_ts = datetime.fromtimestamp(
            datetime.now(tz=timezone.utc).timestamp() - (dormant_threshold_days * 86400),
            tz=timezone.utc,
        )

        async with self._lock:
            if specific_agent_id is not None:
                keys = [(tenant_id, specific_agent_id)]
            else:
                keys = [k for k in self._events if k[0] == tenant_id]

            agent_event_map: dict[uuid.UUID, list[PrivilegeUsageEvent]] = {}
            for key in keys:
                agent_id = key[1]
                agent_event_map[agent_id] = list(self._events[key])

        summaries: list[AgentPrivilegeSummary] = []
        for agent_id, events in agent_event_map.items():
            if not events:
                continue

            action_breakdown: dict[str, int] = defaultdict(int)
            max_privilege_used = 0
            granted_count = denied_count = escalation_count = lp_violations = 0
            first_seen: datetime | None = None
            last_seen: datetime | None = None

            # Configured privilege level is taken from the most recent event
            configured_level = events[-1].configured_privilege_level

            for event in events:
                action_breakdown[event.action] += 1
                if event.privilege_level_used > max_privilege_used:
                    max_privilege_used = event.privilege_level_used
                if event.granted:
                    granted_count += 1
                else:
                    denied_count += 1
                if event.is_escalation:
                    escalation_count += 1
                if event.is_least_privilege_violation:
                    lp_violations += 1
                if first_seen is None or event.timestamp < first_seen:
                    first_seen = event.timestamp
                if last_seen is None or event.timestamp > last_seen:
                    last_seen = event.timestamp
                # Prefer most recent configured level
                configured_level = event.configured_privilege_level

            is_dormant = last_seen is None or last_seen < cutoff_ts

            summaries.append(
                AgentPrivilegeSummary(
                    agent_id=agent_id,
                    tenant_id=tenant_id,
                    configured_privilege_level=configured_level,
                    max_privilege_used=max_privilege_used,
                    total_events=len(events),
                    granted_events=granted_count,
                    denied_events=denied_count,
                    escalation_count=escalation_count,
                    least_privilege_violations=lp_violations,
                    action_breakdown=dict(action_breakdown),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    is_dormant=is_dormant,
                )
            )

        return summaries

    async def _forward_event(self, event: PrivilegeUsageEvent) -> None:
        """Forward a usage event to the configured audit sink endpoint.

        Silently swallows errors — audit forwarding must never block the
        primary authentication flow.

        Args:
            event: The PrivilegeUsageEvent to forward.
        """
        if self._http_client is None or self._audit_sink_url is None:
            return

        payload: dict[str, Any] = {
            "event_id": str(event.event_id),
            "agent_id": str(event.agent_id),
            "tenant_id": str(event.tenant_id),
            "privilege_level_used": event.privilege_level_used,
            "configured_privilege_level": event.configured_privilege_level,
            "resource": event.resource,
            "action": event.action,
            "granted": event.granted,
            "timestamp": event.timestamp.isoformat(),
            "is_escalation": event.is_escalation,
            "ip_address": event.ip_address,
            "correlation_id": event.correlation_id,
            "metadata": event.metadata,
        }

        try:
            response = await self._http_client.post(
                self._audit_sink_url,
                json=payload,
                timeout=5.0,
            )
            if response.status_code >= 400:
                logger.warning(
                    "Audit sink returned error",
                    status_code=response.status_code,
                    event_id=str(event.event_id),
                )
        except Exception as exc:
            logger.warning(
                "Failed to forward event to audit sink",
                event_id=str(event.event_id),
                error=str(exc),
            )
