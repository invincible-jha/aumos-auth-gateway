# Troubleshooting

## Token issuance returns 401

**Symptoms:** `POST /auth/token` returns 401 Unauthorized.

**Diagnosis:**
1. Check credentials: username/password or client_id/client_secret
2. Verify the Keycloak realm exists: `GET /api/v1/realms`
3. Check Keycloak logs: `docker logs keycloak`
4. Verify `AUMOS_AUTH_KEYCLOAK_AUDIENCE` matches the client ID registered in Keycloak

## OPA returns 503 or policy evaluation fails

**Symptoms:** `POST /api/v1/policies/evaluate` returns 503, or all policy evaluations return `allow: false`.

**Diagnosis:**
1. Check OPA liveness: `curl http://opa:8181/health`
2. Verify OPA policies are loaded: `curl http://opa:8181/v1/policies`
3. Check `AUMOS_AUTH_OPA_BASE_URL` environment variable
4. OPA failures are **fail-closed** by design — 503 means access is denied

## Kong consumer creation fails on agent registration

**Symptoms:** `POST /api/v1/agents` returns 503 or `Failed to create Kong consumer`.

**Diagnosis:**
1. Check Kong Admin API: `curl http://kong:8001/status`
2. Verify `AUMOS_AUTH_KONG_ADMIN_URL` is reachable from the gateway pod
3. Check Kong Admin API logs: `docker logs kong`

## K8s token exchange returns 401

**Symptoms:** `POST /auth/token/exchange` returns 401 with a K8s SA token.

**Diagnosis:**
1. Verify `AUMOS_AUTH_K8S_API_URL` is set and reachable
2. Check the gateway's own SA has `system:auth-delegator` ClusterRole binding
3. Confirm the pod's SA token is mounted at the expected path
4. Verify the pod's namespace follows the `aumos-tenant-*` pattern

```bash
kubectl create clusterrolebinding aumos-auth-delegator \
  --clusterrole=system:auth-delegator \
  --serviceaccount=aumos:aumos-auth-gateway
```

## Token exchange returns 403

**Symptoms:** Keycloak returns 403 during token exchange step.

**Diagnosis:**
1. The Keycloak client specified by `AUMOS_AUTH_TOKEN_EXCHANGE_CLIENT_ID` must have token exchange enabled
2. In Keycloak admin UI: Client → Advanced → Fine Grain OpenID Connect Configuration → "Token Exchange" must be ON
3. Verify `AUMOS_AUTH_TOKEN_EXCHANGE_CLIENT_SECRET` is correct

## Database migrations fail

**Symptoms:** `alembic upgrade head` fails with connection error.

**Diagnosis:**
1. Verify `AUMOS_AUTH_DATABASE_URL` uses `postgresql+asyncpg://` scheme
2. Check PostgreSQL is running: `docker ps | grep postgres`
3. Verify database exists: `psql -U aumos -c "\l"`

## Agent secret rotation invalidates Kong JWT

**Symptoms:** After secret rotation, Kong still accepts the old token.

**Note:** Kong JWT validation uses the `iss` claim (service account name) and the secret stored in Kong. After rotation, the auth gateway updates the Kong JWT credential. If Kong is caching, wait for the cache TTL or flush with:

```bash
curl -X DELETE http://kong:8001/consumers/{consumer_id}/jwt/{credential_id}
```
