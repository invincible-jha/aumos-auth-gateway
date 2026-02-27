"""MFA Engine adapter for AumOS Auth Gateway.

Implements multi-factor authentication: TOTP generation and validation (RFC 6238),
TOTP secret provisioning with QR code data, SMS OTP dispatch, Email OTP dispatch,
backup recovery codes, MFA enrollment flow, and MFA bypass for service accounts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)

# TOTP constants (RFC 6238)
_TOTP_STEP = 30              # Time step in seconds
_TOTP_DIGITS = 6             # OTP digit length
_TOTP_DRIFT_STEPS = 1        # Allowed clock drift (±1 window = ±30 seconds)
_TOTP_ALGORITHM = "SHA1"
_SECRET_BYTE_LENGTH = 20     # 160-bit secret (recommended minimum)

# Recovery code constants
_RECOVERY_CODE_LENGTH = 8    # Characters per recovery code
_RECOVERY_CODE_COUNT = 10    # Number of codes generated at enrollment

# SMS/Email OTP constants
_OTP_LENGTH = 6
_OTP_TTL_SECONDS = 300       # 5 minutes


@dataclass
class TOTPProvisioningData:
    """Data returned during TOTP enrollment.

    Attributes:
        user_id: User being enrolled.
        secret_b32: Base-32 encoded TOTP secret (shown to user for manual entry).
        qr_code_uri: otpauth:// URI for QR code generation.
        qr_code_svg: SVG string of the QR code (minimal text-based encoding).
        recovery_codes: One-time-use recovery codes.
    """

    user_id: str
    secret_b32: str
    qr_code_uri: str
    qr_code_svg: str
    recovery_codes: list[str]


@dataclass
class MFAEnrollmentRecord:
    """Records the MFA enrollment state for a user.

    Attributes:
        user_id: Enrolled user identifier.
        tenant_id: Tenant the user belongs to.
        totp_enrolled: Whether TOTP is enrolled.
        totp_secret_hash: SHA-256 of the TOTP secret (NOT the secret itself).
        sms_enrolled: Whether SMS OTP is enrolled.
        sms_phone_number: Masked phone number.
        email_enrolled: Whether Email OTP is enrolled.
        email_address: Masked email address.
        backup_codes_hashes: SHA-256 hashes of unused recovery codes.
        is_service_account: Service accounts bypass MFA by default.
        enrolled_at: UTC ISO timestamp.
    """

    user_id: str
    tenant_id: str
    totp_enrolled: bool = False
    totp_secret_hash: str = ""
    sms_enrolled: bool = False
    sms_phone_number: str = ""
    email_enrolled: bool = False
    email_address: str = ""
    backup_codes_hashes: list[str] = field(default_factory=list)
    is_service_account: bool = False
    enrolled_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class OTPRecord:
    """In-flight OTP record for SMS or Email channels.

    Attributes:
        otp_id: Unique OTP session identifier.
        user_id: User this OTP was issued for.
        channel: Delivery channel: sms or email.
        code_hash: SHA-256 of the plaintext OTP code.
        issued_at: Unix timestamp.
        expires_at: Unix timestamp.
        used: Whether this OTP has been validated.
    """

    otp_id: str
    user_id: str
    channel: str
    code_hash: str
    issued_at: float
    expires_at: float
    used: bool = False


class MFAEngine:
    """Multi-factor authentication engine for AumOS Auth Gateway.

    Provides TOTP (RFC 6238) generation and validation, TOTP secret provisioning
    with QR code URI data, SMS OTP dispatch via an external provider, Email OTP
    dispatch, backup recovery codes, MFA enrollment flow management, and
    MFA bypass logic for service account identities.

    Args:
        issuer_name: TOTP issuer name shown in authenticator apps.
        sms_provider_url: SMS gateway API base URL.
        sms_provider_auth: Auth header value for the SMS provider.
        email_provider_url: Email API base URL.
        email_provider_auth: Auth header value for the email provider.
        email_from: From address for OTP emails.
        http_timeout_seconds: HTTP client timeout.
    """

    def __init__(
        self,
        issuer_name: str = "AumOS Platform",
        sms_provider_url: str | None = None,
        sms_provider_auth: str | None = None,
        email_provider_url: str | None = None,
        email_provider_auth: str | None = None,
        email_from: str = "noreply@aumos.ai",
        http_timeout_seconds: int = 10,
    ) -> None:
        self._issuer = issuer_name
        self._email_from = email_from

        # In-memory stores (production: Redis + DB)
        self._enrollments: dict[str, MFAEnrollmentRecord] = {}
        self._otp_store: dict[str, OTPRecord] = {}
        self._totp_secrets: dict[str, bytes] = {}   # user_id -> raw bytes

        self._sms_client: httpx.AsyncClient | None = None
        if sms_provider_url:
            self._sms_client = httpx.AsyncClient(
                base_url=sms_provider_url.rstrip("/"),
                timeout=httpx.Timeout(http_timeout_seconds),
                headers={"Authorization": sms_provider_auth or ""},
            )

        self._email_client: httpx.AsyncClient | None = None
        if email_provider_url:
            self._email_client = httpx.AsyncClient(
                base_url=email_provider_url.rstrip("/"),
                timeout=httpx.Timeout(http_timeout_seconds),
                headers={"Authorization": email_provider_auth or ""},
            )

    # ------------------------------------------------------------------
    # TOTP provisioning
    # ------------------------------------------------------------------

    def provision_totp(
        self,
        user_id: str,
        tenant_id: str,
        account_name: str,
    ) -> TOTPProvisioningData:
        """Generate a TOTP secret and enrollment data for a user.

        Creates a cryptographically secure 160-bit secret, computes the
        otpauth:// URI for QR code display, and generates backup recovery codes.
        The secret is held in memory pending confirmation by the user.

        Args:
            user_id: User being enrolled.
            tenant_id: Tenant context.
            account_name: Human-readable account label shown in authenticator app.

        Returns:
            TOTPProvisioningData with secret, QR code URI, and recovery codes.
        """
        # Generate secret
        secret_bytes = os.urandom(_SECRET_BYTE_LENGTH)
        secret_b32 = base64.b32encode(secret_bytes).decode("ascii")
        self._totp_secrets[user_id] = secret_bytes

        # Build otpauth:// URI
        params = {
            "secret": secret_b32,
            "issuer": self._issuer,
            "algorithm": _TOTP_ALGORITHM,
            "digits": _TOTP_DIGITS,
            "period": _TOTP_STEP,
        }
        label = quote(f"{self._issuer}:{account_name}")
        qr_uri = f"otpauth://totp/{label}?{urlencode(params)}"

        # Generate backup recovery codes
        recovery_codes = self._generate_recovery_codes()
        code_hashes = [self._hash_code(code) for code in recovery_codes]

        # Update enrollment record (pending confirmation)
        enrollment = MFAEnrollmentRecord(
            user_id=user_id,
            tenant_id=tenant_id,
            totp_enrolled=False,
            totp_secret_hash=self._hash_code(secret_b32),
            backup_codes_hashes=code_hashes,
        )
        self._enrollments[user_id] = enrollment

        logger.info("TOTP provisioned", user_id=user_id, tenant_id=tenant_id)
        return TOTPProvisioningData(
            user_id=user_id,
            secret_b32=secret_b32,
            qr_code_uri=qr_uri,
            qr_code_svg=self._minimal_qr_svg(qr_uri),
            recovery_codes=recovery_codes,
        )

    def confirm_totp_enrollment(self, user_id: str, verification_code: str) -> bool:
        """Confirm TOTP enrollment by verifying the first user-submitted code.

        Args:
            user_id: User confirming enrollment.
            verification_code: First TOTP code from the authenticator app.

        Returns:
            True if code is valid and enrollment is confirmed.
        """
        if user_id not in self._totp_secrets:
            logger.warning("TOTP confirmation failed — no pending enrollment", user_id=user_id)
            return False

        if self.validate_totp(user_id, verification_code):
            enrollment = self._enrollments.get(user_id)
            if enrollment:
                enrollment.totp_enrolled = True
            logger.info("TOTP enrollment confirmed", user_id=user_id)
            return True

        logger.warning("TOTP enrollment confirmation failed — invalid code", user_id=user_id)
        return False

    def validate_totp(self, user_id: str, code: str) -> bool:
        """Validate a submitted TOTP code for a user.

        Accepts codes from the current time window and adjacent windows
        to handle clock drift (±1 step = ±30 seconds).

        Args:
            user_id: User submitting the code.
            code: 6-digit TOTP code string.

        Returns:
            True if the code is valid within the drift tolerance.
        """
        secret = self._totp_secrets.get(user_id)
        if not secret:
            logger.warning("TOTP validation failed — no secret found", user_id=user_id)
            return False

        current_step = int(time.time()) // _TOTP_STEP
        for drift in range(-_TOTP_DRIFT_STEPS, _TOTP_DRIFT_STEPS + 1):
            expected = self._compute_totp(secret, current_step + drift)
            if hmac.compare_digest(expected, code.strip()):
                return True

        logger.warning("TOTP validation failed — invalid code", user_id=user_id)
        return False

    # ------------------------------------------------------------------
    # SMS OTP
    # ------------------------------------------------------------------

    async def send_sms_otp(self, user_id: str, phone_number: str) -> str:
        """Generate and dispatch an SMS OTP to a phone number.

        Args:
            user_id: User requesting the OTP.
            phone_number: Destination phone number in E.164 format.

        Returns:
            OTP session ID for subsequent validation.

        Raises:
            AumOSError: If SMS provider is unreachable or returns an error.
        """
        code = self._generate_otp(_OTP_LENGTH)
        otp_id = str(uuid.uuid4())
        now = time.time()

        self._otp_store[otp_id] = OTPRecord(
            otp_id=otp_id,
            user_id=user_id,
            channel="sms",
            code_hash=self._hash_code(code),
            issued_at=now,
            expires_at=now + _OTP_TTL_SECONDS,
        )

        if self._sms_client:
            try:
                response = await self._sms_client.post(
                    "/messages",
                    json={
                        "to": phone_number,
                        "body": f"Your AumOS verification code is: {code}. Valid for 5 minutes.",
                    },
                )
                if response.status_code >= 400:
                    raise AumOSError(
                        message=f"SMS provider returned {response.status_code}",
                        error_code=ErrorCode.INTERNAL_ERROR,
                    )
            except httpx.ConnectError as exc:
                raise AumOSError(
                    message="SMS provider unreachable",
                    error_code=ErrorCode.SERVICE_UNAVAILABLE,
                ) from exc
        else:
            # Development mode: log the OTP
            logger.info("SMS OTP (dev mode)", user_id=user_id, code=code)

        logger.info("SMS OTP dispatched", user_id=user_id, otp_id=otp_id)
        return otp_id

    # ------------------------------------------------------------------
    # Email OTP
    # ------------------------------------------------------------------

    async def send_email_otp(self, user_id: str, email_address: str) -> str:
        """Generate and dispatch an Email OTP to an address.

        Args:
            user_id: User requesting the OTP.
            email_address: Destination email address.

        Returns:
            OTP session ID for subsequent validation.
        """
        code = self._generate_otp(_OTP_LENGTH)
        otp_id = str(uuid.uuid4())
        now = time.time()

        self._otp_store[otp_id] = OTPRecord(
            otp_id=otp_id,
            user_id=user_id,
            channel="email",
            code_hash=self._hash_code(code),
            issued_at=now,
            expires_at=now + _OTP_TTL_SECONDS,
        )

        if self._email_client:
            try:
                response = await self._email_client.post(
                    "/emails",
                    json={
                        "from": self._email_from,
                        "to": [email_address],
                        "subject": "Your AumOS Verification Code",
                        "text": f"Your verification code is: {code}\n\nThis code expires in 5 minutes.",
                        "html": f"<p>Your verification code is: <strong>{code}</strong></p><p>This code expires in 5 minutes.</p>",
                    },
                )
                if response.status_code >= 400:
                    raise AumOSError(
                        message=f"Email provider returned {response.status_code}",
                        error_code=ErrorCode.INTERNAL_ERROR,
                    )
            except httpx.ConnectError as exc:
                raise AumOSError(
                    message="Email provider unreachable",
                    error_code=ErrorCode.SERVICE_UNAVAILABLE,
                ) from exc
        else:
            logger.info("Email OTP (dev mode)", user_id=user_id, code=code, email=email_address)

        logger.info("Email OTP dispatched", user_id=user_id, otp_id=otp_id)
        return otp_id

    # ------------------------------------------------------------------
    # OTP validation
    # ------------------------------------------------------------------

    def validate_otp(self, otp_id: str, user_id: str, submitted_code: str) -> bool:
        """Validate a submitted SMS or Email OTP.

        Args:
            otp_id: OTP session identifier returned by send_sms_otp / send_email_otp.
            user_id: User submitting the code.
            submitted_code: The code entered by the user.

        Returns:
            True if valid, unexpired, and unused.
        """
        record = self._otp_store.get(otp_id)
        if not record:
            logger.warning("OTP validation failed — unknown OTP ID", otp_id=otp_id)
            return False

        if record.user_id != user_id:
            logger.warning("OTP validation failed — user mismatch", otp_id=otp_id)
            return False

        if record.used:
            logger.warning("OTP validation failed — already used", otp_id=otp_id)
            return False

        if time.time() > record.expires_at:
            logger.warning("OTP validation failed — expired", otp_id=otp_id)
            return False

        expected_hash = self._hash_code(submitted_code.strip())
        if not hmac.compare_digest(expected_hash, record.code_hash):
            logger.warning("OTP validation failed — wrong code", otp_id=otp_id)
            return False

        record.used = True
        logger.info("OTP validated successfully", otp_id=otp_id, channel=record.channel)
        return True

    # ------------------------------------------------------------------
    # Recovery codes
    # ------------------------------------------------------------------

    def validate_recovery_code(self, user_id: str, submitted_code: str) -> bool:
        """Validate and consume a backup recovery code.

        Args:
            user_id: User submitting the recovery code.
            submitted_code: Recovery code string.

        Returns:
            True if code is valid and has been consumed.
        """
        enrollment = self._enrollments.get(user_id)
        if not enrollment:
            return False

        code_hash = self._hash_code(submitted_code.strip().upper())
        if code_hash in enrollment.backup_codes_hashes:
            enrollment.backup_codes_hashes.remove(code_hash)
            logger.info("Recovery code consumed", user_id=user_id, codes_remaining=len(enrollment.backup_codes_hashes))
            return True

        logger.warning("Recovery code validation failed", user_id=user_id)
        return False

    # ------------------------------------------------------------------
    # Service account bypass
    # ------------------------------------------------------------------

    def is_mfa_required(self, user_id: str) -> bool:
        """Determine whether MFA is required for a given user.

        Service accounts are exempt from MFA. Human users are required
        to complete MFA if enrolled.

        Args:
            user_id: User to check.

        Returns:
            True if MFA must be satisfied before granting access.
        """
        enrollment = self._enrollments.get(user_id)
        if not enrollment:
            return False

        if enrollment.is_service_account:
            return False

        return enrollment.totp_enrolled or enrollment.sms_enrolled or enrollment.email_enrolled

    def mark_service_account(self, user_id: str, tenant_id: str) -> None:
        """Mark a user identifier as a service account (MFA bypass).

        Args:
            user_id: Service account identifier.
            tenant_id: Owning tenant context.
        """
        enrollment = self._enrollments.setdefault(
            user_id,
            MFAEnrollmentRecord(user_id=user_id, tenant_id=tenant_id),
        )
        enrollment.is_service_account = True
        logger.info("User marked as service account", user_id=user_id)

    # ------------------------------------------------------------------
    # Enrollment queries
    # ------------------------------------------------------------------

    def get_enrollment(self, user_id: str) -> MFAEnrollmentRecord | None:
        """Retrieve the MFA enrollment record for a user.

        Args:
            user_id: Target user.

        Returns:
            MFAEnrollmentRecord or None if not enrolled.
        """
        return self._enrollments.get(user_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_totp(secret: bytes, time_step: int) -> str:
        """Compute a TOTP value for a given time step (RFC 6238 / HOTP RFC 4226).

        Args:
            secret: Raw secret bytes.
            time_step: Integer time step counter.

        Returns:
            Zero-padded OTP string of length _TOTP_DIGITS.
        """
        msg = struct.pack(">Q", time_step)
        hmac_hash = hmac.new(secret, msg, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        truncated = struct.unpack(">I", hmac_hash[offset : offset + 4])[0] & 0x7FFFFFFF
        code = truncated % (10 ** _TOTP_DIGITS)
        return str(code).zfill(_TOTP_DIGITS)

    @staticmethod
    def _generate_otp(length: int) -> str:
        """Generate a cryptographically secure numeric OTP.

        Args:
            length: Number of digits.

        Returns:
            Zero-padded numeric OTP string.
        """
        return str(secrets.randbelow(10 ** length)).zfill(length)

    @staticmethod
    def _generate_recovery_codes() -> list[str]:
        """Generate a set of one-time-use recovery codes.

        Returns:
            List of uppercase alphanumeric recovery code strings.
        """
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return [
            "".join(secrets.choice(alphabet) for _ in range(_RECOVERY_CODE_LENGTH))
            for _ in range(_RECOVERY_CODE_COUNT)
        ]

    @staticmethod
    def _hash_code(code: str) -> str:
        """Compute a SHA-256 hash of an OTP or recovery code.

        Args:
            code: Plaintext code to hash.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @staticmethod
    def _minimal_qr_svg(uri: str) -> str:
        """Return a minimal placeholder SVG representing a QR code.

        In production, pass the URI to a proper QR library (qrcode or similar).

        Args:
            uri: The otpauth:// URI to encode.

        Returns:
            SVG string with the URI embedded as text (for dev use only).
        """
        escaped = uri.replace("&", "&amp;").replace('"', "&quot;")
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
            f'<rect width="200" height="200" fill="white"/>'
            f'<text x="10" y="20" font-size="8" fill="black">[QR: Scan in authenticator]</text>'
            f'<text x="10" y="35" font-size="6" fill="gray">{escaped[:80]}</text>'
            f"</svg>"
        )

    async def close(self) -> None:
        """Release HTTP client resources."""
        if self._sms_client:
            await self._sms_client.aclose()
        if self._email_client:
            await self._email_client.aclose()
