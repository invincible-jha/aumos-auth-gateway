# Rate Limiting

Per-agent rate limits are enforced by Kong at the API gateway layer. Each agent has its own Kong consumer with independently configurable rate limits.

## Apply a rate limit

```bash
curl -X PUT http://localhost:8000/api/v1/agents/{agent_id}/rate-limit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
    "requests_per_day": 10000
  }'
```

Response:
```json
{
  "agent_id": "uuid",
  "consumer_id": "uuid",
  "config": {
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
    "requests_per_day": 10000
  },
  "plugin_id": "kong-plugin-uuid"
}
```

## Rate limit fields

| Field | Required | Description |
|-------|----------|-------------|
| `requests_per_minute` | Yes | Hard cap on requests per 60 seconds |
| `requests_per_hour` | No | Additional hourly cap |
| `requests_per_day` | No | Additional daily cap |

Multiple limits can be combined — Kong enforces whichever limit is hit first.

## How Kong enforces limits

When an agent registers, the auth gateway creates a Kong consumer with the agent UUID as the consumer ID. The rate-limiting plugin is attached to this consumer entity, so limits apply per agent regardless of which API route is called.

Kong returns HTTP 429 with a `Retry-After` header when a limit is exceeded.

## Updating limits

Calling `PUT /api/v1/agents/{agent_id}/rate-limit` on an agent that already has a rate limit will update the existing Kong plugin via PATCH. No duplicate plugins are created.

## Removing limits

Rate limits cannot be removed via the auth gateway API directly. Use the Kong Admin API to delete the plugin if needed:

```bash
curl -X DELETE http://kong:8001/plugins/{plugin_id}
```
