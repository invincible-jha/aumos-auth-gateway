# AumOS Auth Gateway

The AumOS Auth Gateway is the centralized identity and authorization backbone for the entire AumOS platform. Every service, agent, and operator authenticates through this gateway.

## What it provides

| Capability | Technology | Description |
|-----------|-----------|-------------|
| Identity management | Keycloak 26.4 | JWT issuance, realm management, OIDC discovery |
| Policy enforcement | OPA | RBAC, ABAC, agent privilege gates |
| API gateway auth | Kong | JWT validation, per-agent rate limiting |
| Agent identity | Custom | 5-level privilege system with HITL gates |
| K8s OIDC | TokenReview API + RFC 8693 | Workload identity without static credentials |
| Passkeys | WebAuthn / FIDO2 | Passwordless authentication for tenant users |
| Social IdP | Keycloak identity brokering | Google, GitHub, Microsoft, generic OIDC/SAML |
| Session management | Keycloak Admin API | Enumerate and terminate active sessions |
| Audit trail | PostgreSQL | Full policy evaluation and auth event log |

## Quick links

- [Quickstart](quickstart.md) — Get running in 5 minutes
- [Architecture](architecture.md) — Component diagram and data flows
- [API Reference](api-reference.md) — Complete REST API reference
- [Agent Identity Guide](guides/agent-identity.md) — Register and manage AI-agent identities
- [K8s OIDC Guide](guides/k8s-oidc.md) — Workload identity integration
- [Helm Reference](helm-reference.md) — Production deployment values

## Release tier

**Tier A — Fully Open (Apache 2.0)**

Part of the AumOS Foundation Infrastructure. Required by all other AumOS repositories.
