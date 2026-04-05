"""Tests for report output modules."""

import json

from app_xray.models import (
    APKInfo,
    AuditReport,
    CertificateInfo,
    Endpoint,
    NetworkCallPath,
    Permission,
    SuspiciousPattern,
    Tracker,
)
from app_xray.reporters.json_out import to_json
from app_xray.reporters.html import generate_html
from app_xray.reporters.terminal import print_report
from app_xray.reporters.diff import print_diff


def _sample_report(**overrides) -> AuditReport:
    """Build a realistic AuditReport for testing."""
    defaults = dict(
        apk_info=APKInfo(
            package_name="com.example.testapp",
            version_name="1.2.3",
            version_code=42,
            target_sdk=34,
            min_sdk=24,
            file_size=5_500_000,
            sha256="a" * 64,
        ),
        permissions=[
            Permission("android.permission.INTERNET", "normal", True, True, "Full network access"),
            Permission("android.permission.CAMERA", "dangerous", True, True, "Access device camera"),
        ],
        trackers=[
            Tracker("Google Analytics", "com.google.analytics", "https://analytics.google.com", "Analytics", ["com.google.analytics.Tracker"]),
        ],
        endpoints=[
            Endpoint("https://api.example.com/v1", "com.example.Api", "fetch", True, "api.example.com"),
            Endpoint("http://legacy.example.com", "com.example.Legacy", "sync", False, "legacy.example.com"),
        ],
        suspicious_patterns=[
            SuspiciousPattern("hardcoded_ip", "Hardcoded IP address", "com.example.Config", "medium", "192.168.1.1"),
        ],
        certificate=CertificateInfo(
            issuer="CN=Test CA",
            subject="CN=Test App",
            serial_number="123456",
            sha256_fingerprint="b" * 64,
            valid_from="2024-01-01",
            valid_to="2025-01-01",
            is_debug=False,
        ),
        network_paths=[
            NetworkCallPath(
                sink="java.net.URL.openConnection",
                chain=["com.example.MainActivity.onCreate", "[library]", "java.net.URL.openConnection"],
                entry_type="Activity",
            ),
        ],
        privacy_score=72,
        score_breakdown={"dangerous_perms_used": -5, "http_endpoints": -3, "no_trackers_bonus": 0},
        scan_timestamp="2024-06-15T12:00:00Z",
    )
    defaults.update(overrides)
    return AuditReport(**defaults)


# --- JSON reporter ---

def test_to_json_valid():
    report = _sample_report()
    result = to_json(report)
    data = json.loads(result)
    assert data["apk_info"]["package_name"] == "com.example.testapp"


def test_to_json_contains_all_sections():
    report = _sample_report()
    data = json.loads(to_json(report))
    assert "permissions" in data
    assert "trackers" in data
    assert "endpoints" in data
    assert "suspicious_patterns" in data
    assert "network_paths" in data
    assert "privacy_score" in data


def test_to_json_empty_report():
    report = _sample_report(
        permissions=[], trackers=[], endpoints=[],
        suspicious_patterns=[], network_paths=[], certificate=None,
    )
    data = json.loads(to_json(report))
    assert data["permissions"] == []
    assert data["certificate"] is None


# --- HTML reporter ---

def test_generate_html_returns_string():
    report = _sample_report()
    html = generate_html(report)
    assert isinstance(html, str)
    assert len(html) > 100


def test_generate_html_contains_markers():
    report = _sample_report()
    html = generate_html(report)
    assert "com.example.testapp" in html
    assert "Privacy" in html or "privacy" in html


def test_generate_html_empty_lists():
    report = _sample_report(
        permissions=[], trackers=[], endpoints=[],
        suspicious_patterns=[], network_paths=[], certificate=None,
    )
    html = generate_html(report)
    assert isinstance(html, str)


# --- Terminal reporter ---

def test_print_report_no_crash(capsys):
    report = _sample_report()
    print_report(report)
    captured = capsys.readouterr()
    # Rich writes to its own console, but at minimum no exception was raised
    assert True


def test_print_report_empty_lists(capsys):
    report = _sample_report(
        permissions=[], trackers=[], endpoints=[],
        suspicious_patterns=[], network_paths=[], certificate=None,
    )
    print_report(report)
    assert True


# --- Diff reporter ---

def test_print_diff_no_crash(capsys):
    old = _sample_report(privacy_score=80)
    new = _sample_report(privacy_score=65)
    print_diff(old, new)
    assert True


def test_print_diff_identical_reports(capsys):
    report = _sample_report()
    print_diff(report, report)
    assert True


def test_print_diff_added_permission(capsys):
    old = _sample_report(permissions=[])
    new = _sample_report()
    print_diff(old, new)
    assert True
