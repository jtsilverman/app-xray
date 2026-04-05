"""Extended tests for scoring paths not covered by test_scoring.py."""

from app_xray.models import Endpoint, Permission, SuspiciousPattern, Tracker
from app_xray.scoring import calculate_score


def test_all_https_bonus():
    """Bonus triggers when all endpoints use HTTPS."""
    endpoints = [
        Endpoint("https://api.example.com", "", "", True, "api.example.com"),
        Endpoint("https://cdn.example.com", "", "", True, "cdn.example.com"),
    ]
    score, breakdown = calculate_score([], [], endpoints, [])
    assert breakdown.get("all_https_bonus") == 5


def test_all_https_bonus_not_given_with_http():
    """No bonus when any endpoint is HTTP."""
    endpoints = [
        Endpoint("https://api.example.com", "", "", True, "api.example.com"),
        Endpoint("http://legacy.example.com", "", "", False, "legacy.example.com"),
    ]
    _, breakdown = calculate_score([], [], endpoints, [])
    assert "all_https_bonus" not in breakdown


def test_all_https_bonus_not_given_with_no_endpoints():
    """No bonus when there are zero endpoints."""
    _, breakdown = calculate_score([], [], [], [])
    assert "all_https_bonus" not in breakdown


def test_minimal_permissions_bonus_zero_dangerous():
    """Bonus triggers with 0 dangerous permissions."""
    perms = [
        Permission("android.permission.INTERNET", "normal", True, True, ""),
    ]
    _, breakdown = calculate_score(perms, [], [], [])
    assert breakdown.get("minimal_permissions_bonus") == 5


def test_minimal_permissions_bonus_two_dangerous():
    """Bonus triggers with exactly 2 dangerous permissions (the threshold)."""
    perms = [
        Permission("android.permission.CAMERA", "dangerous", True, True, ""),
        Permission("android.permission.RECORD_AUDIO", "dangerous", True, False, ""),
    ]
    _, breakdown = calculate_score(perms, [], [], [])
    assert breakdown.get("minimal_permissions_bonus") == 5


def test_minimal_permissions_bonus_not_given_three_dangerous():
    """No bonus with 3 dangerous permissions (exceeds threshold)."""
    perms = [
        Permission(f"android.permission.P{i}", "dangerous", True, True, "")
        for i in range(3)
    ]
    _, breakdown = calculate_score(perms, [], [], [])
    assert "minimal_permissions_bonus" not in breakdown


def test_http_penalty_capped_at_minus_15():
    """HTTP penalty should cap at -15 even with many HTTP endpoints."""
    endpoints = [
        Endpoint(f"http://example{i}.com", "", "", False, f"example{i}.com")
        for i in range(10)
    ]
    _, breakdown = calculate_score([], [], endpoints, [])
    assert breakdown["http_endpoints"] == -15


def test_http_penalty_below_cap():
    """Fewer than 6 HTTP endpoints should not hit the cap."""
    endpoints = [
        Endpoint(f"http://example{i}.com", "", "", False, f"example{i}.com")
        for i in range(3)
    ]
    _, breakdown = calculate_score([], [], endpoints, [])
    assert breakdown["http_endpoints"] == -9  # 3 * -3


def test_http_penalty_exactly_at_cap():
    """5 HTTP endpoints = -15, exactly at cap."""
    endpoints = [
        Endpoint(f"http://example{i}.com", "", "", False, f"example{i}.com")
        for i in range(5)
    ]
    _, breakdown = calculate_score([], [], endpoints, [])
    assert breakdown["http_endpoints"] == -15


def test_unused_dangerous_perms_penalty():
    """Unused dangerous permissions get -3 each (not -5)."""
    perms = [
        Permission("android.permission.CAMERA", "dangerous", True, False, ""),
    ]
    _, breakdown = calculate_score(perms, [], [], [])
    assert breakdown.get("dangerous_perms_unused") == -3
    assert "dangerous_perms_used" not in breakdown


def test_ad_tracker_penalty():
    """Ad trackers get -8 each."""
    trackers = [
        Tracker("AdMob", "com.google.ads", "", "Advertisement", []),
        Tracker("FB Ads", "com.facebook.ads", "", "Advertising", []),
    ]
    _, breakdown = calculate_score([], trackers, [], [])
    assert breakdown.get("ad_trackers") == -16


def test_score_capped_at_100():
    """Score should not exceed 100 even with all bonuses."""
    # Base 100 + no_trackers(10) + all_https(5) + minimal_perms(5) = 120 -> cap at 100
    endpoints = [
        Endpoint("https://api.example.com", "", "", True, "api.example.com"),
    ]
    score, _ = calculate_score([], [], endpoints, [])
    assert score == 100
