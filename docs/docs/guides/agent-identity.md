# Agent Identity Guide

AI-agent identities in AumOS are first-class security principals with a 5-level privilege system, capability constraints, and optional human-in-the-loop (HITL) gates.

## Creating an agent

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "data-synthesis-agent",
    "agent_type": "synthesis",
    "privilege_level": 2,
    "allowed_tools": ["text_generation", "summarize", "translate"],
    "allowed_models": ["claude-sonnet-4-6"],
    "max_tokens_per_hr": 100000,
    "requires_hitl": false
  }'
```

Save the `plaintext_secret` from the response — it cannot be retrieved again.

## Privilege levels

| Level | Name | When to use |
|-------|------|------------|
| 1 | READ_ONLY | Reporting and monitoring agents |
| 2 | STANDARD | Tenant-scoped automation agents |
| 3 | ELEVATED | Advanced tool use, model-specific workloads |
| 4 | PRIVILEGED | Cross-system orchestration (HITL enabled) |
| 5 | SUPER_ADMIN | Platform-wide orchestrators only |

Elevating an agent to level 4 or 5 automatically sets `requires_hitl=true`.

## Rotating a secret

```bash
curl -X POST http://localhost:8000/api/v1/agents/{agent_id}/rotate-secret \
  -H "Authorization: Bearer $TOKEN"
```

The old secret is immediately invalidated. The new plaintext secret is returned once.

## Applying a rate limit

```bash
curl -X PUT http://localhost:8000/api/v1/agents/{agent_id}/rate-limit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests_per_minute": 60,
    "requests_per_hour": 1000
  }'
```

Rate limits are enforced by Kong at the API gateway layer. They apply per agent, not per tenant.

## Viewing privilege metrics

```bash
curl http://localhost:8000/api/v1/agents/metrics/privilege \
  -H "Authorization: Bearer $TOKEN"
```

Returns the distribution of agents across privilege levels and counts of HITL-required agents.
