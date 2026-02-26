# aumos-auth-gateway

[![CI](https://github.com/aumos-enterprise/aumos-auth-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/aumos-enterprise/aumos-auth-gateway/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/aumos-enterprise/aumos-auth-gateway/branch/main/graph/badge.svg)](https://codecov.io/gh/aumos-enterprise/aumos-auth-gateway)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> Centralized authentication, authorization, and AI-agent identity management for AumOS Enterprise — powered by Keycloak, OPA, and Kong.

## Overview

The Auth Gateway is the security backbone of the AumOS Enterprise platform. It provides:

- **Authentication** via Keycloak: JWT token issuance, refresh, revocation, OIDC discovery, and multi-realm management for enterprise tenant isolation
- **Authorization** via OPA: RBAC, ABAC, and AI-agent privilege enforcement with fail-closed semantics and full audit trail
- **API Gateway** via Kong: Consumer registration, JWT validation, and per-agent rate limiting for all AumOS platform APIs
- **Agent Identity Management**: A 5-level privilege system for AI-agent service accounts, with HITL (Human-in-the-Loop) gates enforced at privilege levels 4 and 5

Every service in the AumOS platform authenticates through this gateway. It is the first service that must be deployed in any AumOS installation.

**Product:** Foundation — Auth Gateway
**Tier:** Foundation Infrastructure (Release Tier A: Fully Open)
**Phase:** 1A (Months 1-4)

## Architecture

```
aumos-common ──► aumos-auth-gateway ──► ALL AumOS Services
aumos-proto  ──►                     ──► aumos-event-bus (auth events)
                                     ──► aumos-data-layer (agent identities, audit log)

External integrations:
  Keycloak (IdP)  ◄──► Token issuance, realm/user/role management
  OPA             ◄──► Policy evaluation (RBAC, ABAC, privilege gates)
  Kong            ◄──► Consumer registration, JWT validation, rate limiting
  Kafka           ──►  auth.login, auth.logout, agent.created, policy.evaluated
```

This service follows AumOS hexagonal architecture:

- `api/` — FastAPI routes (thin, delegates to services)
- `core/` — Business logic with no framework dependencies
- `adapters/` — External integrations (PostgreSQL, Kafka, Keycloak, OPA, Kong)

### Agent Privilege System

| Level | Name | Capabilities | HITL Required |
|-------|------|-------------|---------------|
| 1 | READ_ONLY | Read data, call read-only tools | No |
| 2 | STANDARD | Standard operations within own tenant | No |
| 3 | ELEVATED | Advanced tools and allowlisted models | No |
| 4 | PRIVILEGED | Cross-system operations | Yes (default) |
| 5 | SUPER_ADMIN | Full platform access | Yes (always) |

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Access to AumOS internal PyPI for `aumos-common` and `aumos-proto`

### Local Development

```bash
# Clone the repo
git clone https://github.com/aumos-enterprise/aumos-auth-gateway.git
cd aumos-auth-gateway

# Set up environment
cp .env.example .env
# Edit .env with your local values

# Install dependencies
make install

# Start infrastructure (PostgreSQL, Keycloak, OPA, Kong, Kafka)
make docker-run

# Run the service
uvicorn aumos_auth_gateway.main:app --reload
```

The service will be available at `http://localhost:8000`.

Health check: `http://localhost:8000/live`
API docs: `http://localhost:8000/docs`

## API Reference

### Authentication (no `/api/v1` prefix)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/token` | Exchange credentials for JWT token pair |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/revoke` | Revoke token (logout) |
| GET | `/auth/userinfo` | Get authenticated user info |
| GET | `/auth/.well-known/openid-configuration` | OIDC discovery document |

### Agent Identity Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/agents` | List agent identities (paginated) |
| POST | `/api/v1/agents` | Register new agent identity |
| GET | `/api/v1/agents/{agent_id}` | Get agent details |
| PUT | `/api/v1/agents/{agent_id}/privilege` | Update agent privilege level |
| DELETE | `/api/v1/agents/{agent_id}` | Revoke agent identity |
| POST | `/api/v1/agents/{agent_id}/rotate-secret` | Rotate agent secret |

### Policy Evaluation

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/policies/evaluate` | Evaluate OPA authorization policy |
| GET | `/api/v1/policies/evaluations` | List policy evaluation audit history |

### Realm Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/realms` | List Keycloak realms |
| POST | `/api/v1/realms` | Create new Keycloak realm |

### Tenant IAM

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/tenants/{tenant_id}/users` | List tenant users |
| POST | `/api/v1/tenants/{tenant_id}/users/{user_id}/roles` | Assign tenant user role |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/live` | Liveness probe |
| GET | `/ready` | Readiness probe (checks Postgres, Keycloak, OPA) |

Full OpenAPI spec available at `/docs` when running locally.

### Authentication Headers

All API endpoints require a valid Bearer JWT token:

```
Authorization: Bearer <token>
X-Tenant-ID: <tenant-uuid>
X-Request-ID: <correlation-id>  (auto-generated if missing)
```

## Configuration

All configuration is via environment variables with the `AUMOS_AUTH_` prefix.
See `.env.example` for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUMOS_SERVICE_NAME` | `aumos-auth-gateway` | Service identifier |
| `AUMOS_ENVIRONMENT` | `development` | Runtime environment |
| `AUMOS_DATABASE__URL` | — | PostgreSQL connection string (asyncpg) |
| `AUMOS_KAFKA__BROKERS` | `kafka:9092` | Kafka broker list |
| `AUMOS_AUTH_KEYCLOAK_BASE_URL` | `http://keycloak:8080` | Keycloak server URL |
| `AUMOS_AUTH_KEYCLOAK_ADMIN_PASSWORD` | — | Keycloak admin password |
| `AUMOS_AUTH_OPA_BASE_URL` | `http://opa:8181` | OPA REST API URL |
| `AUMOS_AUTH_KONG_ADMIN_URL` | `http://kong:8001` | Kong Admin API URL |
| `AUMOS_AUTH_HITL_REQUIRED_PRIVILEGE_LEVEL` | `4` | Minimum privilege for HITL gate |

See `src/aumos_auth_gateway/settings.py` for all available settings.

## Database Schema

Tables use the `ath_` prefix. All tables are created via Alembic migrations.

| Table | Description |
|-------|-------------|
| `ath_agent_identities` | AI-agent service accounts with privilege levels and capability constraints |
| `ath_policy_evaluations` | OPA policy evaluation audit log (every decision recorded) |

## Development

### Running Tests

```bash
# Full test suite with coverage
make test

# Fast run (stop on first failure)
make test-quick
```

### Linting and Formatting

```bash
# Check for issues
make lint

# Auto-fix formatting
make format

# Type checking
make typecheck
```

### Adding Dependencies

```bash
# Add a runtime dependency
# Edit pyproject.toml → [project] dependencies
# IMPORTANT: Verify the license is MIT, BSD, Apache, or ISC — never GPL/AGPL

# Add a dev dependency
# Edit pyproject.toml → [project.optional-dependencies] dev
```

## Kafka Events

The Auth Gateway publishes the following domain events:

| Event Type | Topic | Trigger |
|------------|-------|---------|
| `auth.login` | `AUTH_EVENTS` | Successful token issuance |
| `auth.logout` | `AUTH_EVENTS` | Token revocation |
| `agent.created` | `AGENT_LIFECYCLE` | New agent identity registered |
| `agent.revoked` | `AGENT_LIFECYCLE` | Agent identity deleted |
| `policy.evaluated` | `POLICY_DECISIONS` | Every OPA policy evaluation |

## Deployment

### Docker

```bash
# Build image
make docker-build

# Run with docker-compose
make docker-run
```

### Production

This service is deployed via the AumOS GitOps pipeline. Deployments are triggered
automatically on merge to `main` after CI passes.

**Resource requirements:**
- CPU: 1 core (burstable to 2)
- Memory: 512MB (limit 1GB)
- Replicas: 2+ for HA

**Infrastructure dependencies (must be healthy before startup):**
- PostgreSQL 16+
- Keycloak 24+
- OPA 0.63+
- Kong 3.6+
- Kafka 3.6+

## Related Repos

| Repo | Relationship | Description |
|------|-------------|-------------|
| [aumos-common](https://github.com/aumos-enterprise/aumos-common) | Dependency | Shared utilities, auth, database, events |
| [aumos-proto](https://github.com/aumos-enterprise/aumos-proto) | Dependency | Protobuf event schemas |
| [aumos-platform-core](https://github.com/aumos-enterprise/aumos-platform-core) | Upstream | K8s infrastructure this service runs on |
| ALL other aumos-* repos | Downstream | Every service validates tokens through this gateway |

## License

Copyright 2026 AumOS Enterprise. Licensed under the [Apache License 2.0](LICENSE).

This software must not incorporate AGPL or GPL licensed components.
See [CONTRIBUTING.md](CONTRIBUTING.md) for license compliance requirements.
