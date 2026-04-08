"""Tests for the analyze_apk orchestrator."""

import hashlib
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from app_xray.models import (
    AuditReport,
    CertificateInfo,
    Endpoint,
    Permission,
    SuspiciousPattern,
    Tracker,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_apk():
    """Mock androguard APK object (the 'a' return)."""
    a = MagicMock()
    a.get_package.return_value = "com.example.test"
    a.get_androidversion_name.return_value = "1.2.3"
    a.get_androidversion_code.return_value = "42"
    a.get_target_sdk_version.return_value = "34"
    a.get_min_sdk_version.return_value = "21"
    return a


@pytest.fixture
def mock_androguard(mock_apk):
    """Patch AnalyzeAPK to return mock a, d, dx."""
    d = [MagicMock()]
    dx = MagicMock()
    with patch("app_xray.analyzer._analyze_apk", return_value=(mock_apk, d, dx)) as m:
        m._apk = mock_apk
        m._dx = dx
        yield m


@pytest.fixture
def mock_extractors():
    """Patch all extractor modules and scoring."""
    perm = Permission("android.permission.CAMERA", "dangerous", True, True, "")
    tracker = Tracker("TestTracker", "com.test", "", "Analytics", [])
    endpoint = Endpoint("https://api.example.com", "Cls", "m", True, "api.example.com")
    pattern = SuspiciousPattern("hardcoded_ip", "IP found", "Cls.java", "medium", "1.2.3.4")
    cert = CertificateInfo("CN=Test", "CN=Test", "123", "abc", "2024", "2025", False)

    patches = {
        "manifest": patch(
            "app_xray.extractors.manifest.extract_permissions", return_value=[perm]
        ),
        "permissions": patch(
            "app_xray.extractors.permissions.analyze_permission_usage",
            return_value=[perm],
        ),
        "trackers": patch(
            "app_xray.extractors.trackers.detect_trackers", return_value=[tracker]
        ),
        "endpoints": patch(
            "app_xray.extractors.endpoints.extract_endpoints",
            return_value=[endpoint],
        ),
        "patterns": patch(
            "app_xray.extractors.patterns.detect_patterns", return_value=[pattern]
        ),
        "certificates": patch(
            "app_xray.extractors.certificates.extract_certificate", return_value=cert
        ),
        "network": patch(
            "app_xray.extractors.network_paths.trace_network_calls", return_value=[]
        ),
        "scoring": patch(
            "app_xray.scoring.calculate_score", return_value=(85, {"dangerous_perms_used": -15})
        ),
    }

    mocks = {}
    for name, p in patches.items():
        mocks[name] = p.start()

    mocks["_data"] = {
        "perm": perm,
        "tracker": tracker,
        "endpoint": endpoint,
        "pattern": pattern,
        "cert": cert,
    }

    yield mocks

    for p in patches.values():
        p.stop()


@pytest.fixture
def mock_filesystem():
    """Patch os.path.getsize and open for sha256 computation."""
    fake_content = b"fake apk bytes"
    expected_sha = hashlib.sha256(fake_content).hexdigest()

    with patch("app_xray.analyzer.os.path.getsize", return_value=1024) as sz, \
         patch("builtins.open", mock_open(read_data=fake_content)) as op:
        yield {"getsize": sz, "open": op, "expected_sha": expected_sha, "size": 1024}


# ---------------------------------------------------------------------------
# Tests: analyze_apk returns correct type
# ---------------------------------------------------------------------------

def test_analyze_apk_returns_audit_report(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert isinstance(report, AuditReport)


# ---------------------------------------------------------------------------
# Tests: all extractors are called
# ---------------------------------------------------------------------------

def test_all_extractors_called(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    analyze_apk("/fake/path.apk")

    mock_extractors["manifest"].assert_called_once()
    mock_extractors["permissions"].assert_called_once()
    mock_extractors["trackers"].assert_called_once()
    mock_extractors["endpoints"].assert_called_once()
    mock_extractors["patterns"].assert_called_once()
    mock_extractors["certificates"].assert_called_once()
    mock_extractors["scoring"].assert_called_once()


# ---------------------------------------------------------------------------
# Tests: trace_network flag
# ---------------------------------------------------------------------------

def test_trace_network_false_skips_network_calls(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    analyze_apk("/fake/path.apk", trace_network=False)
    mock_extractors["network"].assert_not_called()


def test_trace_network_true_calls_network_tracer(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    analyze_apk("/fake/path.apk", trace_network=True)
    mock_extractors["network"].assert_called_once()


# ---------------------------------------------------------------------------
# Tests: APK info fields populated correctly
# ---------------------------------------------------------------------------

def test_apk_info_fields(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")

    assert report.apk_info.package_name == "com.example.test"
    assert report.apk_info.version_name == "1.2.3"
    assert report.apk_info.version_code == 42
    assert report.apk_info.target_sdk == 34
    assert report.apk_info.min_sdk == 21
    assert report.apk_info.file_size == mock_filesystem["size"]


# ---------------------------------------------------------------------------
# Tests: sha256 computed from file contents
# ---------------------------------------------------------------------------

def test_sha256_computed(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert report.apk_info.sha256 == mock_filesystem["expected_sha"]


# ---------------------------------------------------------------------------
# Tests: score and breakdown from calculate_score
# ---------------------------------------------------------------------------

def test_score_from_calculate_score(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert report.privacy_score == 85
    assert report.score_breakdown == {"dangerous_perms_used": -15}


# ---------------------------------------------------------------------------
# Tests: report fields populated from extractors
# ---------------------------------------------------------------------------

def test_report_fields_from_extractors(mock_androguard, mock_extractors, mock_filesystem):
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")

    data = mock_extractors["_data"]
    assert report.permissions == [data["perm"]]
    assert report.trackers == [data["tracker"]]
    assert report.endpoints == [data["endpoint"]]
    assert report.suspicious_patterns == [data["pattern"]]
    assert report.certificate == data["cert"]


# ---------------------------------------------------------------------------
# Tests: _safe_int edge cases (negative / failure paths)
# ---------------------------------------------------------------------------

def test_safe_int_none_returns_zero(mock_androguard, mock_extractors, mock_filesystem):
    """When androguard returns None for version_code, _safe_int converts to 0."""
    mock_androguard._apk.get_androidversion_code.return_value = None
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert report.apk_info.version_code == 0


def test_safe_int_invalid_string_returns_zero(mock_androguard, mock_extractors, mock_filesystem):
    """When androguard returns garbage string, _safe_int converts to 0."""
    mock_androguard._apk.get_androidversion_code.return_value = "not_a_number"
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert report.apk_info.version_code == 0


def test_safe_int_valid_string_returns_int(mock_androguard, mock_extractors, mock_filesystem):
    """When androguard returns a numeric string, _safe_int converts properly."""
    mock_androguard._apk.get_androidversion_code.return_value = "99"
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert report.apk_info.version_code == 99


# ---------------------------------------------------------------------------
# Tests: version_name fallback
# ---------------------------------------------------------------------------

def test_version_name_none_falls_back_to_unknown(mock_androguard, mock_extractors, mock_filesystem):
    """When get_androidversion_name returns None, version_name defaults to 'unknown'."""
    mock_androguard._apk.get_androidversion_name.return_value = None
    from app_xray.analyzer import analyze_apk
    report = analyze_apk("/fake/path.apk")
    assert report.apk_info.version_name == "unknown"


# ---------------------------------------------------------------------------
# Tests: androguard failure (negative test)
# ---------------------------------------------------------------------------

def test_analyze_apk_propagates_androguard_error(mock_filesystem):
    """If AnalyzeAPK raises, analyze_apk does not swallow the exception."""
    with patch("app_xray.analyzer._analyze_apk", side_effect=FileNotFoundError("no such file")):
        from app_xray.analyzer import analyze_apk
        with pytest.raises(FileNotFoundError, match="no such file"):
            analyze_apk("/nonexistent.apk")
