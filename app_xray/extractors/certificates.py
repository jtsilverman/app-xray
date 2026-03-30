"""APK signing certificate analysis."""

from app_xray.models import CertificateInfo


def extract_certificate(apk) -> CertificateInfo | None:
    """Extract signing certificate info from APK."""
    certs = apk.get_certificates()
    if not certs:
        return None

    cert = certs[0]  # asn1crypto.x509.Certificate

    issuer = cert.issuer.human_friendly
    subject = cert.subject.human_friendly

    is_debug = "Android Debug" in subject or "debug" in subject.lower()

    return CertificateInfo(
        issuer=issuer,
        subject=subject,
        serial_number=str(cert.serial_number),
        sha256_fingerprint=cert.sha256_fingerprint,
        valid_from=str(cert.not_valid_before),
        valid_to=str(cert.not_valid_after),
        is_debug=is_debug,
    )
