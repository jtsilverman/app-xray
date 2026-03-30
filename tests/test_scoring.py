"""Tests for privacy scoring."""

from app_xray.models import Endpoint, Permission, SuspiciousPattern, Tracker
from app_xray.scoring import calculate_score


def test_perfect_score_no_issues():
    score, breakdown = calculate_score([], [], [], [])
    assert score == 100


def test_dangerous_permissions_reduce_score():
    perms = [
        Permission(f"android.permission.P{i}", "dangerous", True, True, "") for i in range(5)
    ]
    score, breakdown = calculate_score(perms, [], [], [])
    assert score < 100
    assert "dangerous_perms_used" in breakdown


def test_trackers_reduce_score():
    trackers = [
        Tracker("Google Analytics", "com.google.analytics", "", "Analytics", []),
    ]
    score, breakdown = calculate_score([], trackers, [], [])
    assert score < 100


def test_http_endpoints_reduce_score():
    endpoints = [
        Endpoint(f"http://example{i}.com/api", "", "", False, f"example{i}.com") for i in range(6)
    ]
    score, breakdown = calculate_score([], [], endpoints, [])
    assert "http_endpoints" in breakdown
    assert breakdown["http_endpoints"] < 0


def test_suspicious_patterns_reduce_score():
    patterns = [
        SuspiciousPattern("device_id", f"access {i}", "com.Foo.bar", "high", f"getImei{i}")
        for i in range(3)
    ]
    score, breakdown = calculate_score([], [], [], patterns)
    assert score < 100
    assert "high_severity_patterns" in breakdown


def test_no_trackers_bonus():
    score, breakdown = calculate_score([], [], [], [])
    assert breakdown.get("no_trackers_bonus") == 10


def test_score_never_below_zero():
    perms = [Permission(f"android.permission.P{i}", "dangerous", True, True, "") for i in range(30)]
    trackers = [Tracker(f"T{i}", f"com.t{i}", "", "Analytics", []) for i in range(20)]
    score, _ = calculate_score(perms, trackers, [], [])
    assert score >= 0
