# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffolding for aumos-auth-gateway
- Keycloak Admin client (realm, client, user, role management)
- OPA policy engine client (RBAC/ABAC evaluation with fail-closed semantics)
- Kong Admin client (service, route, plugin, consumer management)
- 5-level AI-agent privilege system (READ_ONLY through SUPER_ADMIN)
- Agent identity CRUD with bcrypt secret hashing and rotation
- Auth event publishing to Kafka (login, logout, agent lifecycle, policy decisions)
- OIDC endpoints: token issuance, refresh, revocation, userinfo, discovery
- API v1 endpoints: agents, policy evaluation, realm management, tenant IAM
- Hexagonal architecture: api/ core/ adapters/ layers
- All standard AumOS deliverables (CLAUDE.md, Dockerfile, CI/CD, etc.)
