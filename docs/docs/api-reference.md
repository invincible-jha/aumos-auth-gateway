# API Reference

All endpoints require a valid `Authorization: Bearer <token>` header unless noted.
Interactive docs: `http://localhost:8000/docs`

## Authentication endpoints (`/auth/*`)

### POST /auth/token

Exchange credentials for a JWT token pair.

**Request:**
```json
{
  "grant_type": "password",
  "username": "user@tenant.com",
  "password": "secret"
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "scope": "openid profile email"
}
```

### POST /auth/token/exchange

RFC 8693 token exchange — converts a Kubernetes ServiceAccount token to an AumOS JWT.

**Request:**
```json
{
  "subject_token": "<k8s-sa-jwt>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "audience": "aumos-platform"
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 300
}
```

### POST /auth/refresh

Exchange a refresh token for a new access token.

### POST /auth/revoke

Revoke a refresh token (logout). Returns 204 No Content.

### GET /auth/userinfo

Returns OIDC claims for the authenticated user. Requires Bearer token.

### GET /auth/.well-known/openid-configuration

OIDC discovery document. No authentication required.

---

## Agent identity endpoints (`/api/v1/agents`)

### GET /api/v1/agents

List all agent identities for the current tenant (paginated).

Query params: `page`, `page_size`

### POST /api/v1/agents

Register a new agent identity. Returns the one-time plaintext secret.

**Request:**
```json
{
  "name": "synthesis-agent-1",
  "agent_type": "synthesis",
  "privilege_level": 2,
  "allowed_tools": ["text_generation"],
  "allowed_models": ["claude-sonnet-4-6"],
  "max_tokens_per_hr": 100000,
  "requires_hitl": false
}
```

### GET /api/v1/agents/{agent_id}

Get agent details by UUID.

### PUT /api/v1/agents/{agent_id}/privilege

Update an agent's privilege level.

**Request:**
```json
{
  "privilege_level": 3,
  "reason": "Promoted to elevated for analytics tasks"
}
```

### DELETE /api/v1/agents/{agent_id}

Revoke and delete an agent identity. Returns 204.

### POST /api/v1/agents/{agent_id}/rotate-secret

Rotate an agent's service account secret. Returns a new one-time plaintext secret.

### GET /api/v1/agents/metrics/privilege

Privilege-level distribution for all agents in the tenant.

**Response:**
```json
{
  "tenant_id": "uuid",
  "total_agents": 12,
  "distribution": [
    {"privilege_level": 1, "level_name": "READ_ONLY", "count": 5, "hitl_required": false},
    {"privilege_level": 2, "level_name": "STANDARD", "count": 4, "hitl_required": false},
    {"privilege_level": 3, "level_name": "ELEVATED", "count": 2, "hitl_required": false},
    {"privilege_level": 4, "level_name": "PRIVILEGED", "count": 1, "hitl_required": true},
    {"privilege_level": 5, "level_name": "SUPER_ADMIN", "count": 0, "hitl_required": true}
  ],
  "elevated_agent_count": 3,
  "hitl_required_count": 1
}
```

### PUT /api/v1/agents/{agent_id}/rate-limit

Apply a per-agent Kong rate limit.

**Request:**
```json
{
  "requests_per_minute": 60,
  "requests_per_hour": 1000,
  "requests_per_day": 10000
}
```

---

## Policy endpoints (`/api/v1/policies`)

### POST /api/v1/policies/evaluate

Evaluate an OPA authorization policy.

**Request:**
```json
{
  "resource": "/api/v1/agents",
  "action": "write",
  "context": {"agent_privilege": 3}
}
```

**Response:**
```json
{
  "allow": true,
  "decision": "allow",
  "policy_name": "rbac/roles",
  "evaluation_ms": 2.4
}
```

### GET /api/v1/policies/evaluations

List policy evaluation audit history (paginated).

---

## Session management (`/api/v1/sessions`)

### GET /api/v1/sessions

List active sessions for the current tenant.

### DELETE /api/v1/sessions

Terminate one or more sessions.

**Request:**
```json
{
  "session_ids": ["session-uuid-1", "session-uuid-2"],
  "reason": "Security incident response"
}
```

---

## Audit log (`/api/v1/audit`)

### GET /api/v1/audit

List auth gateway audit events for the current tenant.

Query params: `page`, `page_size`, `event_type`

---

## Passkey policy (`/api/v1/passkeys`)

### GET /api/v1/passkeys/policy

Get the current WebAuthn/FIDO2 policy.

### PUT /api/v1/passkeys/policy

Update the WebAuthn/FIDO2 policy.

**Request:**
```json
{
  "rp_entity_name": "AumOS Platform",
  "rp_id": "aumos.ai",
  "attestation_conveyance_preference": "none",
  "authenticator_attachment": "platform",
  "require_resident_key": true,
  "user_verification_requirement": "required",
  "passkey_registration_required": false
}
```

---

## Social identity providers (`/api/v1/idp`)

### GET /api/v1/idp

List all social identity providers for the tenant realm.

### POST /api/v1/idp

Register a social identity provider.

**Request (Google example):**
```json
{
  "alias": "google",
  "display_name": "Sign in with Google",
  "provider_id": "google",
  "client_id": "123456789-abc.apps.googleusercontent.com",
  "client_secret": "GOCSPX-...",
  "enabled": true,
  "trust_email": true
}
```

### DELETE /api/v1/idp/{alias}

Remove a social identity provider. Returns 204.

---

## Realm management (`/api/v1/realms`)

### GET /api/v1/realms

List all Keycloak realms. Requires SUPER_ADMIN.

### POST /api/v1/realms

Create a new Keycloak realm.

**Request:**
```json
{
  "realm_name": "tenant-acme",
  "display_name": "ACME Corporation",
  "enabled": true
}
```

---

## Tenant IAM (`/api/v1/tenants`)

### GET /api/v1/tenants/{tenant_id}/users

List users in a tenant.

### POST /api/v1/tenants/{tenant_id}/users/{user_id}/roles

Assign a role to a tenant user. Roles: `admin`, `developer`, `viewer`, `auditor`.
