# Security Policy

## Reporting a Vulnerability

The AumOS platform team takes security vulnerabilities seriously. We appreciate your
efforts to responsibly disclose your findings.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Email your findings to: **security@aumos.io**

Include in your report:
- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any proof-of-concept code (if applicable)
- Your recommended fix (if you have one)

You will receive an acknowledgment within **48 hours** and a detailed response
within **5 business days**.

## Scope

The following are in scope for security reports for the Auth Gateway specifically:

- Authentication and authorization bypass (token forgery, session hijacking)
- Tenant isolation violations (cross-tenant token validation)
- OPA fail-open vulnerabilities (policy evaluation bypass)
- Agent privilege escalation (bypassing the 5-level privilege system)
- HITL gate bypass (allowing privileged actions without human approval)
- Keycloak integration weaknesses (token replay, realm isolation)
- Kong consumer credential compromise
- Secret management issues (plaintext exposure, bcrypt bypass)
- SQL injection or other injection attacks
- Remote code execution
- Sensitive data exposure (tokens, agent secrets, PII)

The following are out of scope:
- Denial of service attacks
- Social engineering of AumOS staff
- Physical security issues
- Vulnerabilities in Keycloak, OPA, or Kong themselves (report to their maintainers)
- Issues in repositories not owned by AumOS Enterprise

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Status update | Every 7 days during investigation |
| Fix deployment (critical) | Within 7 days of confirmation |
| Fix deployment (high) | Within 30 days of confirmation |
| Fix deployment (medium/low) | Next scheduled release |

## Disclosure Policy

- We follow a **90-day coordinated disclosure** policy
- We will notify you when the fix is deployed
- We will credit you in our release notes (unless you prefer anonymity)
- We ask that you do not publicly disclose the vulnerability until we have released a fix

## Security Best Practices for Contributors

When contributing to this repository:

1. Never commit secrets, API keys, or credentials (even test credentials)
2. Never store agent secrets in plaintext — bcrypt hash only
3. Always fail-closed on OPA or Keycloak errors — deny by default
4. Validate all inputs at system boundaries using Pydantic
5. Never log sensitive data (tokens, passwords, agent secrets, PII)
6. Use parameterized queries — never string concatenation in SQL
7. Check dependency licenses and security advisories before adding packages
8. Report any security issues you discover, even if you are not sure of the impact
9. The 5-level agent privilege system must be enforced at every action — never skip
10. HITL gates at privilege >= 4 must never be bypassed without explicit override
