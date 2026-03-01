# Passkeys & FIDO2

AumOS Auth Gateway supports WebAuthn/FIDO2 passwordless authentication for tenant users via Keycloak's built-in WebAuthn authenticator.

## Get the current policy

```bash
curl http://localhost:8000/api/v1/passkeys/policy \
  -H "Authorization: Bearer $TOKEN"
```

Response:
```json
{
  "realm": "aumos",
  "enabled": true,
  "policy": {
    "rp_entity_name": "AumOS Platform",
    "rp_id": "aumos.ai",
    "attestation_conveyance_preference": "none",
    "authenticator_attachment": "platform",
    "require_resident_key": true,
    "user_verification_requirement": "required",
    "passkey_registration_required": false
  }
}
```

## Update the policy

```bash
curl -X PUT http://localhost:8000/api/v1/passkeys/policy \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rp_entity_name": "ACME Corp AumOS",
    "rp_id": "acme.aumos.ai",
    "attestation_conveyance_preference": "none",
    "authenticator_attachment": "platform",
    "require_resident_key": true,
    "user_verification_requirement": "required",
    "passkey_registration_required": true
  }'
```

## Policy fields

| Field | Options | Description |
|-------|---------|-------------|
| `rp_entity_name` | string | Display name shown in browser passkey dialogs |
| `rp_id` | domain string | Must match the browser origin domain |
| `attestation_conveyance_preference` | `none`, `indirect`, `direct`, `enterprise` | Level of attestation required |
| `authenticator_attachment` | `platform`, `cross-platform` | Device authenticator vs security key |
| `require_resident_key` | bool | Discoverable credential (passkey) vs server-side |
| `user_verification_requirement` | `required`, `preferred`, `discouraged` | Biometric/PIN verification policy |
| `passkey_registration_required` | bool | Force all users to register a passkey |

## Keycloak WebAuthn flow

Keycloak implements the full WebAuthn registration and authentication ceremony. The auth gateway manages the policy configuration; the actual WebAuthn handshake occurs in the Keycloak-hosted login UI.

To enable passkey login for a realm:
1. Update the policy via `PUT /api/v1/passkeys/policy`
2. Add the WebAuthn authenticator to the browser authentication flow in Keycloak admin UI
3. Set `passkey_registration_required: true` to prompt users to register on next login
