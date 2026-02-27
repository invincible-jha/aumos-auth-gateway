"""Internal Certificate Authority for AumOS agent X.509 certificates.

Issues short-lived Ed25519 X.509 certificates with agent_id and tenant_id
embedded in Subject Alternative Name (SAN) URI fields. All signing uses the
cryptography library — never PyCryptodome.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Certificate validity duration for issued agent certificates
_AGENT_CERT_VALIDITY_DAYS: Final[int] = 90
# CA certificate validity
_CA_CERT_VALIDITY_DAYS: Final[int] = 3650  # 10 years


class InternalCA:
    """Self-contained internal Certificate Authority for AumOS agent identities.

    Issues X.509 v3 certificates with the agent_id and tenant_id embedded
    as URI Subject Alternative Names. Certificates use Ed25519 keys.

    Args:
        ca_private_key_pem: PEM-encoded CA private key (Ed25519). If None, a
            new ephemeral CA is generated (suitable for testing only).
        ca_certificate_pem: PEM-encoded CA certificate. Required when
            ca_private_key_pem is provided.
        organization: Organization name in issued certificates.
    """

    def __init__(
        self,
        ca_private_key_pem: bytes | None = None,
        ca_certificate_pem: bytes | None = None,
        organization: str = "AumOS Enterprise",
    ) -> None:
        self._organization = organization

        if ca_private_key_pem is not None and ca_certificate_pem is not None:
            self._ca_key = serialization.load_pem_private_key(ca_private_key_pem, password=None)
            self._ca_cert = x509.load_pem_x509_certificate(ca_certificate_pem)
        else:
            # Generate ephemeral CA for testing/bootstrap
            logger.warning("Generating ephemeral CA — not suitable for production")
            self._ca_key, self._ca_cert = self._bootstrap_ca(organization)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue_agent_certificate(
        self,
        agent_id: uuid.UUID,
        tenant_id: uuid.UUID,
        agent_class: str,
        validity_days: int = _AGENT_CERT_VALIDITY_DAYS,
    ) -> tuple[x509.Certificate, Ed25519PrivateKey]:
        """Issue an X.509 certificate for an AI agent.

        Embeds agent_id and tenant_id as URI SANs following the pattern:
            urn:aumos:agent:{agent_id}
            urn:aumos:tenant:{tenant_id}

        Args:
            agent_id: UUID of the agent receiving the certificate.
            tenant_id: UUID of the owning tenant.
            agent_class: Agent class label (orchestrator/tool/evaluator/retriever/executor).
            validity_days: Certificate validity duration in days.

        Returns:
            Tuple of (certificate, private_key). The private key is NOT stored;
            it is the caller's responsibility to deliver it securely to the agent.
        """
        agent_private_key = Ed25519PrivateKey.generate()
        agent_public_key = agent_private_key.public_key()

        now = datetime.now(UTC)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._organization),
            x509.NameAttribute(NameOID.COMMON_NAME, f"agent:{agent_id}"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, agent_class),
        ])

        # SAN: URI SANs encoding agent identity
        san_uris = [
            x509.UniformResourceIdentifier(f"urn:aumos:agent:{agent_id}"),
            x509.UniformResourceIdentifier(f"urn:aumos:tenant:{tenant_id}"),
            x509.UniformResourceIdentifier(f"urn:aumos:class:{agent_class}"),
        ]
        san = x509.SubjectAlternativeName(san_uris)

        serial = x509.random_serial_number()

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(agent_public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.3.4"),  # emailProtection as mTLS marker
                ]),
                critical=False,
            )
            .sign(self._ca_key, algorithm=None)  # Ed25519 uses algorithm=None
        )

        logger.info(
            "Agent certificate issued",
            agent_id=str(agent_id),
            tenant_id=str(tenant_id),
            serial=hex(serial),
            not_valid_after=cert.not_valid_after_utc.isoformat(),
        )
        return cert, agent_private_key

    def get_certificate_pem(self, cert: x509.Certificate) -> str:
        """Serialize a certificate to PEM string.

        Args:
            cert: X.509 certificate object.

        Returns:
            PEM-encoded certificate string.
        """
        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def get_private_key_pem(self, private_key: Ed25519PrivateKey) -> str:
        """Serialize a private key to unencrypted PEM string.

        Args:
            private_key: Ed25519 private key.

        Returns:
            PEM-encoded private key string (PKCS8 format, unencrypted).
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    def get_ca_certificate_pem(self) -> str:
        """Return the CA certificate as a PEM string.

        Returns:
            PEM-encoded CA certificate.
        """
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def get_certificate_fingerprint(self, cert: x509.Certificate) -> str:
        """Compute the SHA-256 fingerprint of a certificate.

        Args:
            cert: X.509 certificate.

        Returns:
            Hex-encoded SHA-256 fingerprint string.
        """
        fingerprint_bytes = cert.fingerprint(hashes.SHA256())
        return fingerprint_bytes.hex()

    def verify_agent_certificate(
        self,
        certificate_pem: str,
        expected_agent_id: uuid.UUID,
        expected_tenant_id: uuid.UUID,
    ) -> bool:
        """Verify a certificate belongs to the expected agent and tenant.

        Checks:
        1. Certificate was issued by this CA (issuer match)
        2. Certificate is not expired
        3. SAN URIs contain the expected agent_id and tenant_id

        Args:
            certificate_pem: PEM-encoded certificate string.
            expected_agent_id: Expected agent UUID.
            expected_tenant_id: Expected tenant UUID.

        Returns:
            True if all checks pass, False otherwise.
        """
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))

            # Check issuer matches our CA
            if cert.issuer != self._ca_cert.subject:
                logger.warning("Certificate issuer mismatch", agent_id=str(expected_agent_id))
                return False

            # Check expiry
            now = datetime.now(UTC)
            if cert.not_valid_after_utc < now:
                logger.warning("Certificate expired", agent_id=str(expected_agent_id))
                return False

            # Check SAN URIs
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            uri_values = {v.value for v in san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)}

            expected_agent_uri = f"urn:aumos:agent:{expected_agent_id}"
            expected_tenant_uri = f"urn:aumos:tenant:{expected_tenant_id}"

            if expected_agent_uri not in uri_values or expected_tenant_uri not in uri_values:
                logger.warning(
                    "Certificate SAN mismatch",
                    agent_id=str(expected_agent_id),
                    tenant_id=str(expected_tenant_id),
                )
                return False

            return True

        except Exception as exc:
            logger.error("Certificate verification failed", error=str(exc))
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bootstrap_ca(organization: str) -> tuple[Ed25519PrivateKey, x509.Certificate]:
        """Generate a new ephemeral CA key pair and self-signed certificate.

        Args:
            organization: Organization name for the CA subject.

        Returns:
            Tuple of (ca_private_key, ca_certificate).
        """
        ca_key = Ed25519PrivateKey.generate()
        ca_public_key = ca_key.public_key()

        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, "AumOS Internal Agent CA"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=_CA_CERT_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, algorithm=None)
        )
        return ca_key, ca_cert
