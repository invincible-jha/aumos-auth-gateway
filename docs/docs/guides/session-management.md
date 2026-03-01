# Session Management

The auth gateway exposes admin endpoints to enumerate and terminate active Keycloak sessions for a tenant.

## List active sessions

```bash
curl "http://localhost:8000/api/v1/sessions?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "items": [
    {
      "session_id": "abc-123",
      "user_id": "user@tenant.com",
      "tenant_id": "uuid",
      "client_id": "aumos-platform",
      "ip_address": "10.0.0.5",
      "started_at": "2026-02-28T10:00:00Z",
      "last_access_at": "2026-02-28T10:45:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

## Terminate specific sessions

```bash
curl -X DELETE http://localhost:8000/api/v1/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "session_ids": ["abc-123", "def-456"],
    "reason": "Security incident — forced logout"
  }'
```

Returns 204 No Content on success.

## Terminate all sessions for a tenant

Pass an empty `session_ids` array to terminate all sessions in the realm:

```bash
curl -X DELETE http://localhost:8000/api/v1/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"session_ids": [], "reason": "Scheduled maintenance"}'
```

## Audit log

All session terminations are logged to the auth gateway audit trail, which is queryable via:

```bash
curl "http://localhost:8000/api/v1/audit?event_type=auth.logout" \
  -H "Authorization: Bearer $TOKEN"
```
