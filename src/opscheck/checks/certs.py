"""TLS certificate checks.

Everything here is read-only: we open a connection, read the certificate the
server presents, and close the connection. Nothing is sent beyond a TLS
handshake (or EHLO + STARTTLS for SMTP).
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

# Ports where we expect to negotiate TLS via SMTP STARTTLS rather than
# implicit TLS. 465 is SMTPS (implicit TLS) so it is deliberately absent.
SMTP_STARTTLS_PORTS = {25, 587}


@dataclass
class CertResult:
    host: str
    port: int
    status: str  # ok | warning | critical | expired | error
    days_remaining: int | None = None
    not_before: str | None = None
    not_after: str | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    tls_version: str | None = None
    used_starttls: bool = False
    chain_valid: bool | None = None
    verification_error: str | None = None
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def assess_expiry(
    not_after: datetime,
    now: datetime | None = None,
    warn_days: int = 30,
    critical_days: int = 7,
) -> tuple[str, int]:
    """Return (status, days_remaining) for a certificate expiry date.

    Pure function so it can be unit-tested without the network.
    """
    now = now or datetime.now(timezone.utc)
    days = (not_after - now).days
    if not_after <= now:
        return "expired", days
    if days <= critical_days:
        return "critical", days
    if days <= warn_days:
        return "warning", days
    return "ok", days


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _parse_der(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    issuer = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME) or _name_attr(
        cert.issuer, NameOID.COMMON_NAME
    )
    return {
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": issuer,
        "sans": list(sans),
    }


def _grab_der(host: str, port: int, starttls: bool, timeout: float) -> tuple[bytes, str]:
    """Fetch the leaf certificate WITHOUT verifying it.

    We deliberately skip verification here so we can still report on
    expired / self-signed / mismatched certificates. Verification is done
    separately in _verify().
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if starttls:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                raise RuntimeError("server does not advertise STARTTLS")
            smtp.starttls(context=ctx)
            der = smtp.sock.getpeercert(binary_form=True)
            return der, smtp.sock.version()

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def _verify(host: str, port: int, starttls: bool, timeout: float) -> str | None:
    """Do a fully verified handshake. Returns None if OK, else the error text."""
    ctx = ssl.create_default_context()
    try:
        if starttls:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ctx)
        else:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host):
                    pass
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        return str(exc)
    return None


def check_certificate(
    host: str,
    port: int = 443,
    *,
    starttls: bool | None = None,
    warn_days: int = 30,
    critical_days: int = 7,
    timeout: float = 10.0,
) -> CertResult:
    if starttls is None:
        starttls = port in SMTP_STARTTLS_PORTS

    result = CertResult(host=host, port=port, status="error", used_starttls=starttls)
    try:
        der, tls_version = _grab_der(host, port, starttls, timeout)
    except (OSError, smtplib.SMTPException, RuntimeError, ssl.SSLError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    info = _parse_der(der)
    status, days = assess_expiry(
        info["not_after"], warn_days=warn_days, critical_days=critical_days
    )
    result.status = status
    result.days_remaining = days
    result.not_before = info["not_before"].isoformat()
    result.not_after = info["not_after"].isoformat()
    result.subject_cn = info["subject_cn"]
    result.issuer = info["issuer"]
    result.sans = info["sans"]
    result.tls_version = tls_version

    verr = _verify(host, port, starttls, timeout)
    result.chain_valid = verr is None
    result.verification_error = verr
    if verr and status == "ok":
        # A valid date range doesn't help if clients won't trust the cert.
        result.status = "warning"
        result.notes.append("Certificate dates are fine but verification failed.")
    if tls_version in ("TLSv1", "TLSv1.1"):
        result.notes.append(f"Server negotiated legacy {tls_version}.")

    return result
