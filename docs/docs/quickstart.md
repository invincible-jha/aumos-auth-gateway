# Quickstart

Get the AumOS Auth Gateway running locally in 5 minutes.

## Prerequisites

- Docker and Docker Compose
- Python 3.11+
- `curl` and `jq` for API testing

## Step 1 — Start dependencies

```bash
cd aumos-auth-gateway
docker compose -f docker-compose.dev.yml up -d
```

This starts Keycloak, OPA, Kong, PostgreSQL, and Kafka with development defaults.

## Step 2 — Run database migrations

```bash
alembic upgrade head
```

## Step 3 — Start the gateway

```bash
uvicorn aumos_auth_gateway.main:app --reload --port 8000
```

The gateway is now listening at `http://localhost:8000`.

## Step 4 — Obtain a token

```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "admin@aumos.ai",
    "password": "changeme"
  }' | jq .
```

Save the `access_token` for subsequent requests:

```bash
export TOKEN="<access_token from response>"
```

## Step 5 — Register an agent identity

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-synthesis-agent",
    "agent_type": "synthesis",
    "privilege_level": 2,
    "allowed_tools": ["text_generation", "summarize"],
    "allowed_models": ["claude-sonnet-4-6"],
    "max_tokens_per_hr": 50000
  }' | jq .
```

Save the returned `plaintext_secret` — it cannot be recovered after this call.

## Step 6 — Verify OpenID Connect discovery

```bash
curl http://localhost:8000/auth/.well-known/openid-configuration | jq .
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUMOS_AUTH_KEYCLOAK_BASE_URL` | `http://localhost:8080` | Keycloak server URL |
| `AUMOS_AUTH_KEYCLOAK_ADMIN_PASSWORD` | `admin` | Admin realm password |
| `AUMOS_AUTH_KEYCLOAK_AUDIENCE` | `aumos-platform` | JWT audience |
| `AUMOS_AUTH_OPA_BASE_URL` | `http://localhost:8181` | OPA server URL |
| `AUMOS_AUTH_KONG_ADMIN_URL` | `http://localhost:8001` | Kong Admin API URL |
| `AUMOS_AUTH_DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection |
| `AUMOS_AUTH_KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka brokers |
