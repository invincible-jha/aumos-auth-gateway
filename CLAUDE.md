# CLAUDE.md — AumOS Auth Gateway

## Project Overview

AumOS Enterprise is a composable enterprise AI platform with 9 products + 2 services
across 62 repositories. This repo (`aumos-auth-gateway`) is part of **Foundation Infrastructure**:
the security and identity backbone that every other AumOS service depends on.

**Release Tier:** A (Fully Open)
**Product Mapping:** Foundation — Auth Gateway
**Phase:** 1A (Months 1-4)

## Repo Purpose

The Auth Gateway provides centralized authentication and authorization for all AumOS services.
It wraps Keycloak for identity management (JWT issuance, realm management, OIDC), OPA for
policy enforcement (RBAC, ABAC, agent privilege gates), and Kong for API gateway JWT validation
and rate limiting. Every service in the AumOS platform authenticates through this gateway.

## Architecture Position

```
aumos-common ──► aumos-auth-gateway ──► ALL REPOS (every service authenticates here)
aumos-proto  ──►                     ──► aumos-event-bus (publishes auth events)
                                     ──► aumos-data-layer (stores agent identities, audit log)

External:
  Keycloak (IdP)  ◄──► aumos-auth-gateway
  OPA (policy)    ◄──► aumos-auth-gateway
  Kong (gateway)  ◄──► aumos-auth-gateway
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for Kafka events

**Downstream dependents (other repos IMPORT from this):**
- ALL AumOS repositories — every service validates tokens and enforces policies through this gateway

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | Database ORM |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| confluent-kafka | 2.3+ | Kafka producer/consumer |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| httpx | 0.27+ | Async HTTP client for Keycloak/OPA/Kong |
| python-jose | 3.3+ | JWT validation |
| bcrypt | 4.0+ | Agent secret hashing |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |

## Coding Standards

### ABSOLUTE RULES (violations will break integration with other repos)

1. **Import aumos-common, never reimplement.** If aumos-common provides it, use it.
   ```python
   # CORRECT
   from aumos_common.auth import get_current_tenant, get_current_user
   from aumos_common.database import get_db_session, Base, AumOSModel, BaseRepository
   from aumos_common.events import EventPublisher, Topics
   from aumos_common.errors import NotFoundError, ErrorCode
   from aumos_common.config import AumOSSettings
   from aumos_common.health import create_health_router
   from aumos_common.pagination import PageRequest, PageResponse, paginate
   from aumos_common.app import create_app
   ```

2. **Type hints on EVERY function.** No exceptions.

3. **Pydantic models for ALL API inputs/outputs.** Never return raw dicts.

4. **RLS tenant isolation via aumos-common.** Never write raw SQL that bypasses RLS.

5. **Structured logging via structlog.** Never use print() or logging.getLogger().

6. **Publish domain events to Kafka after state changes.**

7. **Async by default.** All I/O operations must be async.

8. **Google-style docstrings** on all public classes and functions.

### Style Rules

- Max line length: **120 characters**
- Import order: stdlib → third-party → aumos-common → local
- Linter: `ruff` (select E, W, F, I, N, UP, ANN, B, A, COM, C4, PT, RUF)
- Type checker: `mypy` strict mode
- Formatter: `ruff format`

### File Structure Convention

```
src/aumos_auth_gateway/
├── __init__.py
├── main.py                    # FastAPI app entry point using create_app()
├── settings.py                # Extends AumOSSettings (env prefix AUMOS_AUTH_)
├── api/
│   ├── __init__.py
│   ├── auth_routes.py         # /auth/* OIDC/token endpoints (no /api/v1 prefix)
│   ├── router.py              # /api/v1/* agent, policy, realm, IAM endpoints
│   └── schemas.py             # All Pydantic request/response models
├── core/
│   ├── __init__.py
│   ├── models.py              # AgentIdentity, PolicyEvaluation ORM models (ath_ prefix)
│   ├── services.py            # AuthService, AgentService, PolicyService, TenantIAMService
│   ├── interfaces.py          # Protocol interfaces for all services and adapters
│   └── opa_client.py          # OPA REST API client
└── adapters/
    ├── __init__.py
    ├── repositories.py        # AgentRepository, PolicyEvaluationRepository
    ├── kafka.py               # AuthEventPublisher
    ├── keycloak_client.py     # KeycloakAdminClient (also implements IKeycloakClient)
    └── kong_client.py         # KongAdminClient
```

## API Conventions

- Token endpoints: `/auth/token`, `/auth/refresh`, `/auth/revoke`, `/auth/userinfo`
- OIDC discovery: `/auth/.well-known/openid-configuration`
- Resource endpoints: `/api/v1/agents`, `/api/v1/policies/evaluate`, `/api/v1/realms`
- Auth: Bearer JWT token (validated by aumos-common)
- Tenant: `X-Tenant-ID` header (set by auth middleware)
- Request ID: `X-Request-ID` header (auto-generated if missing)

## Database Conventions

- Table prefix: `ath_` (auth-gateway)
- `ath_agent_identities` — AI-agent service identities with privilege levels
- `ath_policy_evaluations` — OPA policy evaluation audit log
- ALL tenant-scoped tables: extend `AumOSModel`
- Secrets stored as bcrypt hashes only — plaintext never persisted

## Kafka Events Published

| Event Type | Topic | Trigger |
|------------|-------|---------|
| auth.login | AUTH_EVENTS | Successful token issuance |
| auth.logout | AUTH_EVENTS | Token revocation |
| agent.created | AGENT_LIFECYCLE | New agent identity registered |
| agent.revoked | AGENT_LIFECYCLE | Agent identity deleted |
| policy.evaluated | POLICY_DECISIONS | Every OPA policy evaluation |

## Repo-Specific Context

### Agent Privilege System (5 Levels)

| Level | Name | Capabilities | HITL Required |
|-------|------|-------------|---------------|
| 1 | READ_ONLY | Read data, call read-only tools | No |
| 2 | STANDARD | Standard operations within own tenant | No |
| 3 | ELEVATED | Advanced tools, allowlisted models | No |
| 4 | PRIVILEGED | Cross-system operations | Yes (default) |
| 5 | SUPER_ADMIN | Full platform access, reserved for orchestrators | Yes (always) |

HITL gate is auto-enabled for privilege >= 4 at agent creation. The `requires_hitl` flag is
surfaced on `AgentResponse` and must be checked by orchestration layers before executing actions.

### OPA Policy Paths (auto-selected by resource type)

| Resource Pattern | Policy Path |
|-----------------|-------------|
| `urn:agent:*` | `agent/privilege_levels` |
| `urn:hitl:*` | `agent/hitl_gates` |
| `*tenant*` | `rbac/tenant_isolation` |
| `/api/*` | `rbac/roles` |
| (default) | `abac/resource_access` |

### Kong Integration

Agent identities are registered as Kong consumers on creation (UUID as consumer_id).
JWT credentials are set on the consumer for Kong-side token validation. When an agent
is revoked, its Kong consumer is deleted to immediately invalidate all active tokens.

### Keycloak Admin Credentials

Admin operations use the master realm admin-cli client. User/token operations use the
`aumos` realm. Never hardcode credentials — always pull from `AUMOS_AUTH_*` env vars.

### Security Requirements

- OPA failure: fail-closed (deny) — never fail-open
- Agent secrets: bcrypt hash only, plaintext returned once at creation/rotation
- Token blacklisting: store revoked JTIs in Redis with TTL = token expiry
- Privilege escalation: requires explicit approval (not self-service)

## What Claude Code Should NOT Do

1. **Do NOT reimplement anything in aumos-common.** JWT, auth, DB, Kafka, health — import it.
2. **Do NOT store agent secrets in plaintext.** Only bcrypt hashes in the database.
3. **Do NOT fail-open on OPA errors.** Always deny if OPA is unreachable.
4. **Do NOT skip privilege validation.** Every agent action must check privilege level.
5. **Do NOT bypass RLS.** Use `get_db_session_no_tenant` only for super-admin cross-tenant ops.
6. **Do NOT hardcode Keycloak/OPA/Kong URLs.** Always use settings.
7. **Do NOT return raw dicts.** Every API response must be a typed Pydantic model.
8. **Do NOT log secrets or tokens.** Redact all sensitive values before logging.
