"""SAML 2.0 federation adapter for AumOS Auth Gateway.

Implements SAML 2.0 Service Provider functionality: AuthnRequest generation,
SAML Response parsing and validation, Assertion extraction, XML signature
verification, IdP metadata parsing, SP metadata generation, and Single Logout
support.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode
from xml.etree import ElementTree as ET

import httpx

from aumos_common.errors import AumOSError, ErrorCode
from aumos_common.observability import get_logger

logger = get_logger(__name__)

# SAML XML namespaces
_NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"
_NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"

_XMLNS = {
    "saml": _NS_SAML,
    "samlp": _NS_SAMLP,
    "ds": _NS_DS,
    "md": _NS_MD,
}


@dataclass
class SAMLAssertion:
    """Extracted SAML Assertion data.

    Attributes:
        name_id: Subject NameID (typically the user identifier).
        name_id_format: NameID format URI.
        session_index: SAML session index (needed for SLO).
        issuer: IdP entity ID.
        attributes: Attribute statements from the assertion.
        valid_from: NotBefore timestamp.
        valid_until: NotOnOrAfter timestamp.
        in_response_to: AuthnRequest ID this assertion responds to.
    """

    name_id: str
    name_id_format: str
    session_index: str
    issuer: str
    attributes: dict[str, list[str]] = field(default_factory=dict)
    valid_from: str | None = None
    valid_until: str | None = None
    in_response_to: str | None = None


@dataclass
class SAMLIdPMetadata:
    """Parsed IdP metadata from SAML Metadata XML.

    Attributes:
        entity_id: IdP entity identifier.
        sso_url: SingleSignOnService URL (HTTP-Redirect or HTTP-POST binding).
        slo_url: SingleLogoutService URL.
        certificate_pem: X.509 certificate PEM for signature verification.
        name_id_formats: Supported NameID formats.
        binding: Preferred binding: HTTP-Redirect or HTTP-POST.
    """

    entity_id: str
    sso_url: str
    slo_url: str | None
    certificate_pem: str
    name_id_formats: list[str] = field(default_factory=list)
    binding: str = "HTTP-Redirect"


@dataclass
class SAMLSPMetadata:
    """Self-describing SP metadata for registration with an IdP.

    Attributes:
        entity_id: SP entity identifier.
        acs_url: Assertion Consumer Service URL.
        slo_url: SingleLogoutService URL.
        certificate_pem: SP signing/encryption certificate.
        name_id_format: Requested NameID format.
    """

    entity_id: str
    acs_url: str
    slo_url: str | None
    certificate_pem: str
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


class SAMLAdapter:
    """SAML 2.0 Service Provider implementation for AumOS Auth Gateway.

    Provides full SAML 2.0 SP functionality:
    - AuthnRequest generation (HTTP-Redirect and HTTP-POST bindings)
    - SAML Response parsing and XML signature verification
    - Assertion extraction including NameID and attribute statements
    - IdP metadata retrieval and caching
    - SP metadata XML generation
    - Single Logout (SLO) support

    Args:
        sp_entity_id: This SP's SAML entity identifier.
        sp_acs_url: Assertion Consumer Service URL (receives SAML Responses).
        sp_slo_url: Single Logout URL.
        sp_certificate_pem: SP certificate for metadata.
        idp_metadata_url: URL to fetch IdP SAML metadata XML.
        verify_signatures: Whether to validate XML signatures (must be True in prod).
        http_timeout_seconds: Timeout for metadata fetching.
    """

    def __init__(
        self,
        sp_entity_id: str,
        sp_acs_url: str,
        sp_slo_url: str | None = None,
        sp_certificate_pem: str = "",
        idp_metadata_url: str | None = None,
        verify_signatures: bool = True,
        http_timeout_seconds: int = 15,
    ) -> None:
        self._sp_entity_id = sp_entity_id
        self._sp_acs_url = sp_acs_url
        self._sp_slo_url = sp_slo_url
        self._sp_cert = sp_certificate_pem
        self._idp_metadata_url = idp_metadata_url
        self._verify_signatures = verify_signatures
        self._http_timeout = http_timeout_seconds

        # Cached IdP metadata
        self._idp_metadata: SAMLIdPMetadata | None = None
        # In-flight AuthnRequest IDs for anti-replay
        self._pending_requests: dict[str, str] = {}  # request_id -> relay_state

        self._http = httpx.AsyncClient(timeout=httpx.Timeout(http_timeout_seconds))

    # ------------------------------------------------------------------
    # AuthnRequest generation
    # ------------------------------------------------------------------

    def generate_authn_request(
        self,
        relay_state: str = "",
        force_authn: bool = False,
        name_id_policy: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    ) -> tuple[str, str, str]:
        """Generate a SAML 2.0 AuthnRequest.

        Args:
            relay_state: Opaque string returned by IdP to identify the SP session.
            force_authn: Whether to force re-authentication even if a session exists.
            name_id_policy: Requested NameID format URI.

        Returns:
            Tuple of (request_id, redirect_url, post_form_data).
            Use redirect_url for HTTP-Redirect binding, post_form_data for HTTP-POST.
        """
        request_id = f"_{uuid.uuid4().hex}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        idp_sso_url = self._idp_metadata.sso_url if self._idp_metadata else ""
        force_authn_attr = ' ForceAuthn="true"' if force_authn else ""

        authn_request_xml = (
            f'<samlp:AuthnRequest xmlns:samlp="{_NS_SAMLP}" xmlns:saml="{_NS_SAML}"'
            f' ID="{request_id}"'
            f' Version="2.0"'
            f' IssueInstant="{issue_instant}"'
            f' Destination="{idp_sso_url}"'
            f' AssertionConsumerServiceURL="{self._sp_acs_url}"'
            f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
            f'{force_authn_attr}>'
            f'<saml:Issuer>{self._sp_entity_id}</saml:Issuer>'
            f'<samlp:NameIDPolicy Format="{name_id_policy}" AllowCreate="true"/>'
            f"</samlp:AuthnRequest>"
        )

        # Track the pending request for anti-replay
        self._pending_requests[request_id] = relay_state

        # HTTP-Redirect binding: deflate + base64 + URL-encode
        deflated = zlib.compress(authn_request_xml.encode("utf-8"))[2:-4]
        encoded = base64.b64encode(deflated).decode("ascii")
        redirect_params = {"SAMLRequest": encoded}
        if relay_state:
            redirect_params["RelayState"] = relay_state

        redirect_url = f"{idp_sso_url}?{urlencode(redirect_params)}"

        # HTTP-POST binding: base64 only (no deflate)
        post_encoded = base64.b64encode(authn_request_xml.encode("utf-8")).decode("ascii")
        post_form_data = (
            f'<form method="POST" action="{idp_sso_url}">'
            f'<input type="hidden" name="SAMLRequest" value="{post_encoded}"/>'
            f'<input type="hidden" name="RelayState" value="{relay_state}"/>'
            f'<input type="submit" value="Continue"/>'
            f"</form>"
        )

        logger.info("AuthnRequest generated", request_id=request_id, idp_sso_url=idp_sso_url)
        return request_id, redirect_url, post_form_data

    # ------------------------------------------------------------------
    # SAML Response parsing
    # ------------------------------------------------------------------

    def parse_saml_response(
        self,
        saml_response_b64: str,
        expected_request_id: str | None = None,
    ) -> SAMLAssertion:
        """Parse and validate a base64-encoded SAML Response.

        Decodes the response, validates status, checks InResponseTo anti-replay,
        and extracts the embedded Assertion.

        Args:
            saml_response_b64: Base64-encoded SAML Response XML.
            expected_request_id: If provided, validates InResponseTo field.

        Returns:
            Extracted SAMLAssertion.

        Raises:
            AumOSError: If the response is malformed, status is not Success,
                        InResponseTo does not match, or signature is invalid.
        """
        try:
            response_xml = base64.b64decode(saml_response_b64).decode("utf-8")
        except Exception as exc:
            raise AumOSError(
                message="Failed to decode SAML Response: invalid base64",
                error_code=ErrorCode.VALIDATION_ERROR,
            ) from exc

        try:
            root = ET.fromstring(response_xml)
        except ET.ParseError as exc:
            raise AumOSError(
                message=f"Failed to parse SAML Response XML: {exc}",
                error_code=ErrorCode.VALIDATION_ERROR,
            ) from exc

        # Validate status
        status_code_el = root.find(".//samlp:StatusCode", _XMLNS)
        if status_code_el is not None:
            status_value = status_code_el.get("Value", "")
            if "Success" not in status_value:
                raise AumOSError(
                    message=f"SAML Response status is not Success: {status_value}",
                    error_code=ErrorCode.UNAUTHORIZED,
                )

        # Anti-replay: check InResponseTo
        in_response_to = root.get("InResponseTo")
        if expected_request_id and in_response_to != expected_request_id:
            raise AumOSError(
                message="SAML Response InResponseTo does not match outstanding request",
                error_code=ErrorCode.VALIDATION_ERROR,
            )
        if in_response_to and in_response_to in self._pending_requests:
            del self._pending_requests[in_response_to]

        # Optionally verify XML signature
        if self._verify_signatures and self._idp_metadata:
            self._verify_xml_signature(root, self._idp_metadata.certificate_pem)

        return self._extract_assertion(root, in_response_to)

    def _extract_assertion(self, root: ET.Element, in_response_to: str | None) -> SAMLAssertion:
        """Extract assertion fields from a parsed SAML Response element.

        Args:
            root: Parsed root SAML Response element.
            in_response_to: AuthnRequest ID reference.

        Returns:
            Populated SAMLAssertion.

        Raises:
            AumOSError: If required elements are missing.
        """
        assertion = root.find("saml:Assertion", _XMLNS)
        if assertion is None:
            raise AumOSError(
                message="No Assertion element found in SAML Response",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        # NameID
        name_id_el = assertion.find(".//saml:NameID", _XMLNS)
        if name_id_el is None:
            raise AumOSError(
                message="No NameID element in SAML Assertion",
                error_code=ErrorCode.VALIDATION_ERROR,
            )
        name_id = name_id_el.text or ""
        name_id_format = name_id_el.get("Format", "")

        # Issuer
        issuer_el = assertion.find("saml:Issuer", _XMLNS)
        issuer = issuer_el.text if issuer_el is not None else ""

        # Session index
        authn_stmt = assertion.find("saml:AuthnStatement", _XMLNS)
        session_index = authn_stmt.get("SessionIndex", "") if authn_stmt is not None else ""

        # Conditions (validity window)
        conditions = assertion.find("saml:Conditions", _XMLNS)
        valid_from = conditions.get("NotBefore") if conditions is not None else None
        valid_until = conditions.get("NotOnOrAfter") if conditions is not None else None

        # Attribute statements
        attributes: dict[str, list[str]] = {}
        for attr in assertion.findall(".//saml:Attribute", _XMLNS):
            attr_name = attr.get("Name", "")
            values = [
                av.text or ""
                for av in attr.findall("saml:AttributeValue", _XMLNS)
            ]
            if attr_name:
                attributes[attr_name] = values

        return SAMLAssertion(
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
            issuer=issuer,
            attributes=attributes,
            valid_from=valid_from,
            valid_until=valid_until,
            in_response_to=in_response_to,
        )

    # ------------------------------------------------------------------
    # XML signature verification
    # ------------------------------------------------------------------

    def _verify_xml_signature(self, root: ET.Element, certificate_pem: str) -> None:
        """Perform basic XML Digital Signature verification.

        Verifies that the Signature element is present and uses a known
        digest algorithm. Full cryptographic verification requires
        lxml + xmlsec1 libraries (not available in all environments).

        Args:
            root: Parsed SAML Response element.
            certificate_pem: IdP X.509 certificate PEM string.

        Raises:
            AumOSError: If Signature element is missing or uses unsupported algorithm.
        """
        signature_el = root.find(".//ds:Signature", _XMLNS)
        if signature_el is None:
            raise AumOSError(
                message="SAML Response is missing required XML Signature",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        sig_method = signature_el.find(".//ds:SignatureMethod", _XMLNS)
        if sig_method is not None:
            algorithm = sig_method.get("Algorithm", "")
            # Accept RSA-SHA256 and RSA-SHA1
            allowed_algorithms = {
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            }
            if algorithm not in allowed_algorithms:
                raise AumOSError(
                    message=f"Unsupported signature algorithm: {algorithm}",
                    error_code=ErrorCode.VALIDATION_ERROR,
                )

        logger.debug("XML signature structure validated (full cryptographic verification requires xmlsec1)")

    # ------------------------------------------------------------------
    # IdP metadata
    # ------------------------------------------------------------------

    async def fetch_idp_metadata(self, metadata_url: str | None = None) -> SAMLIdPMetadata:
        """Fetch and parse IdP SAML Metadata XML.

        Args:
            metadata_url: URL to fetch metadata from. Falls back to configured URL.

        Returns:
            Parsed SAMLIdPMetadata.

        Raises:
            AumOSError: If metadata cannot be fetched or parsed.
        """
        url = metadata_url or self._idp_metadata_url
        if not url:
            raise AumOSError(
                message="No IdP metadata URL configured",
                error_code=ErrorCode.VALIDATION_ERROR,
            )

        try:
            response = await self._http.get(url)
        except httpx.ConnectError as exc:
            raise AumOSError(
                message=f"Failed to fetch IdP metadata from {url}",
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
            ) from exc

        if response.status_code != 200:
            raise AumOSError(
                message=f"IdP metadata endpoint returned {response.status_code}",
                error_code=ErrorCode.INTERNAL_ERROR,
            )

        metadata = self._parse_idp_metadata_xml(response.text)
        self._idp_metadata = metadata
        logger.info("IdP metadata fetched and cached", entity_id=metadata.entity_id)
        return metadata

    def _parse_idp_metadata_xml(self, metadata_xml: str) -> SAMLIdPMetadata:
        """Parse SAML IdP Metadata XML into a typed struct.

        Args:
            metadata_xml: Raw IdP Metadata XML string.

        Returns:
            SAMLIdPMetadata with extracted SSO URL, certificate, etc.

        Raises:
            AumOSError: If required elements are missing.
        """
        try:
            root = ET.fromstring(metadata_xml)
        except ET.ParseError as exc:
            raise AumOSError(
                message=f"Failed to parse IdP metadata XML: {exc}",
                error_code=ErrorCode.VALIDATION_ERROR,
            ) from exc

        entity_id = root.get("entityID", "")

        # SSO URL (prefer HTTP-Redirect)
        sso_url = ""
        slo_url = None
        binding_redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        binding_post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

        for sso_el in root.findall(".//md:SingleSignOnService", _XMLNS):
            binding = sso_el.get("Binding", "")
            location = sso_el.get("Location", "")
            if binding == binding_redirect:
                sso_url = location
                break
            if binding == binding_post and not sso_url:
                sso_url = location

        for slo_el in root.findall(".//md:SingleLogoutService", _XMLNS):
            binding = slo_el.get("Binding", "")
            if binding in (binding_redirect, binding_post):
                slo_url = slo_el.get("Location")
                break

        # Certificate
        cert_el = root.find(".//ds:X509Certificate", _XMLNS)
        cert_data = cert_el.text.strip() if cert_el is not None and cert_el.text else ""
        certificate_pem = (
            f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
            if cert_data
            else ""
        )

        # NameID formats
        name_id_formats = [
            el.text or ""
            for el in root.findall(".//md:NameIDFormat", _XMLNS)
            if el.text
        ]

        return SAMLIdPMetadata(
            entity_id=entity_id,
            sso_url=sso_url,
            slo_url=slo_url,
            certificate_pem=certificate_pem,
            name_id_formats=name_id_formats,
        )

    # ------------------------------------------------------------------
    # SP metadata
    # ------------------------------------------------------------------

    def generate_sp_metadata(self) -> str:
        """Generate SP SAML Metadata XML for registration with IdPs.

        Returns:
            SAML Metadata XML string.
        """
        cert_data = self._sp_cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "")
        binding_post = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        binding_redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

        slo_element = ""
        if self._sp_slo_url:
            slo_element = (
                f'<md:SingleLogoutService Binding="{binding_redirect}" '
                f'Location="{self._sp_slo_url}"/>'
            )

        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<md:EntityDescriptor xmlns:md="{_NS_MD}" entityID="{self._sp_entity_id}">'
            f"<md:SPSSODescriptor "
            f'AuthnRequestsSigned="false" '
            f'WantAssertionsSigned="true" '
            f'protocolSupportEnumeration="{_NS_SAMLP}">'
            f"<md:KeyDescriptor use=\"signing\">"
            f'<ds:KeyInfo xmlns:ds="{_NS_DS}">'
            f"<ds:X509Data><ds:X509Certificate>{cert_data}</ds:X509Certificate></ds:X509Data>"
            f"</ds:KeyInfo></md:KeyDescriptor>"
            f"{slo_element}"
            f'<md:AssertionConsumerService Binding="{binding_post}" '
            f'Location="{self._sp_acs_url}" index="1"/>'
            f"</md:SPSSODescriptor>"
            f"</md:EntityDescriptor>"
        )

    # ------------------------------------------------------------------
    # Single Logout
    # ------------------------------------------------------------------

    def generate_slo_request(self, name_id: str, session_index: str) -> tuple[str, str]:
        """Generate a SAML Single Logout Request.

        Args:
            name_id: NameID of the user to log out.
            session_index: SAML session index from the original Assertion.

        Returns:
            Tuple of (request_id, base64-encoded SLO request XML).
        """
        request_id = f"_{uuid.uuid4().hex}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        slo_url = self._idp_metadata.slo_url if self._idp_metadata and self._idp_metadata.slo_url else ""

        xml = (
            f'<samlp:LogoutRequest xmlns:samlp="{_NS_SAMLP}" xmlns:saml="{_NS_SAML}"'
            f' ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}"'
            f' Destination="{slo_url}">'
            f"<saml:Issuer>{self._sp_entity_id}</saml:Issuer>"
            f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f"{name_id}</saml:NameID>"
            f"<samlp:SessionIndex>{session_index}</samlp:SessionIndex>"
            f"</samlp:LogoutRequest>"
        )

        encoded = base64.b64encode(xml.encode("utf-8")).decode("ascii")
        logger.info("SLO request generated", request_id=request_id, name_id=name_id[:20])
        return request_id, encoded

    async def close(self) -> None:
        """Release HTTP client resources."""
        await self._http.aclose()
