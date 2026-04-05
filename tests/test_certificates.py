"""Tests for certificate extraction."""

from unittest.mock import MagicMock

from app_xray.extractors.certificates import extract_certificate
from app_xray.models import CertificateInfo


def _make_mock_cert(subject="CN=Test App", issuer="CN=Test CA", serial=12345,
                    fingerprint="ab" * 32, not_before="2024-01-01", not_after="2025-01-01"):
    """Build a mock asn1crypto-style certificate."""
    cert = MagicMock()
    cert.issuer.human_friendly = issuer
    cert.subject.human_friendly = subject
    cert.serial_number = serial
    cert.sha256_fingerprint = fingerprint
    cert.not_valid_before = not_before
    cert.not_valid_after = not_after
    return cert


def test_extract_certificate_basic():
    apk = MagicMock()
    apk.get_certificates.return_value = [_make_mock_cert()]
    result = extract_certificate(apk)
    assert isinstance(result, CertificateInfo)
    assert result.subject == "CN=Test App"
    assert result.issuer == "CN=Test CA"
    assert result.is_debug is False


def test_extract_certificate_debug_detected():
    apk = MagicMock()
    apk.get_certificates.return_value = [_make_mock_cert(subject="CN=Android Debug")]
    result = extract_certificate(apk)
    assert result.is_debug is True


def test_extract_certificate_debug_lowercase():
    apk = MagicMock()
    apk.get_certificates.return_value = [_make_mock_cert(subject="CN=My debug cert")]
    result = extract_certificate(apk)
    assert result.is_debug is True


def test_extract_certificate_no_certs():
    apk = MagicMock()
    apk.get_certificates.return_value = []
    result = extract_certificate(apk)
    assert result is None


def test_extract_certificate_multiple_certs_uses_first():
    cert1 = _make_mock_cert(subject="CN=First")
    cert2 = _make_mock_cert(subject="CN=Second")
    apk = MagicMock()
    apk.get_certificates.return_value = [cert1, cert2]
    result = extract_certificate(apk)
    assert result.subject == "CN=First"


def test_extract_certificate_fields_populated():
    apk = MagicMock()
    apk.get_certificates.return_value = [_make_mock_cert(
        serial=999, fingerprint="cc" * 32,
        not_before="2023-06-01", not_after="2026-06-01",
    )]
    result = extract_certificate(apk)
    assert result.serial_number == "999"
    assert result.sha256_fingerprint == "cc" * 32
    assert result.valid_from == "2023-06-01"
    assert result.valid_to == "2026-06-01"
