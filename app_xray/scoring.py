"""Privacy risk scoring engine."""

from app_xray.models import Endpoint, Permission, SuspiciousPattern, Tracker


def calculate_score(
    permissions: list[Permission],
    trackers: list[Tracker],
    endpoints: list[Endpoint],
    patterns: list[SuspiciousPattern],
) -> tuple[int, dict]:
    """Calculate privacy score (0-100, 100 = most private).

    Returns (score, breakdown dict).
    """
    breakdown = {}
    score = 100

    # Dangerous permissions
    dangerous_used = sum(1 for p in permissions if p.protection_level == "dangerous" and p.used_in_code)
    dangerous_unused = sum(1 for p in permissions if p.protection_level == "dangerous" and not p.used_in_code)
    if dangerous_used:
        penalty = dangerous_used * -5
        breakdown["dangerous_perms_used"] = penalty
        score += penalty
    if dangerous_unused:
        penalty = dangerous_unused * -3
        breakdown["dangerous_perms_unused"] = penalty
        score += penalty

    # Trackers
    ad_trackers = sum(1 for t in trackers if t.category.lower() in ("advertisement", "ads", "advertising"))
    analytics_trackers = sum(1 for t in trackers if t.category.lower() in ("analytics",))
    other_trackers = len(trackers) - ad_trackers - analytics_trackers
    if ad_trackers:
        penalty = ad_trackers * -8
        breakdown["ad_trackers"] = penalty
        score += penalty
    if analytics_trackers:
        penalty = analytics_trackers * -8
        breakdown["analytics_trackers"] = penalty
        score += penalty
    if other_trackers:
        penalty = other_trackers * -5
        breakdown["other_trackers"] = penalty
        score += penalty

    # HTTP endpoints
    http_count = sum(1 for e in endpoints if not e.is_https)
    if http_count:
        penalty = max(http_count * -3, -15)  # cap at -15
        breakdown["http_endpoints"] = penalty
        score += penalty

    # Suspicious patterns
    high_patterns = sum(1 for p in patterns if p.severity == "high")
    medium_patterns = sum(1 for p in patterns if p.severity == "medium")
    low_patterns = sum(1 for p in patterns if p.severity == "low")
    if high_patterns:
        penalty = high_patterns * -10
        breakdown["high_severity_patterns"] = penalty
        score += penalty
    if medium_patterns:
        penalty = medium_patterns * -5
        breakdown["medium_severity_patterns"] = penalty
        score += penalty
    if low_patterns:
        penalty = low_patterns * -2
        breakdown["low_severity_patterns"] = penalty
        score += penalty

    # Bonuses
    if not trackers:
        breakdown["no_trackers_bonus"] = 10
        score += 10
    if endpoints and not http_count:
        breakdown["all_https_bonus"] = 5
        score += 5
    total_dangerous = dangerous_used + dangerous_unused
    if total_dangerous <= 2:
        breakdown["minimal_permissions_bonus"] = 5
        score += 5

    score = max(0, min(100, score))
    return score, breakdown
