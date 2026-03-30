"""Tests for suspicious pattern detection."""

import os
import pytest
from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
from app_xray.extractors.patterns import detect_patterns

FIXTURE_APK = os.path.join(os.path.dirname(__file__), "fixtures", "fdroid.apk")


@pytest.fixture(scope="module")
def dx():
    _, _, dx = AnalyzeAPK(FIXTURE_APK)
    return dx


def test_detect_patterns_returns_list(dx):
    patterns = detect_patterns(dx)
    assert isinstance(patterns, list)


def test_patterns_have_required_fields(dx):
    patterns = detect_patterns(dx)
    for p in patterns:
        assert p.pattern_type
        assert p.severity in ("high", "medium", "low")
        assert p.description
        assert p.evidence


def test_patterns_sorted_by_severity(dx):
    patterns = detect_patterns(dx)
    if len(patterns) > 1:
        order = {"high": 0, "medium": 1, "low": 2}
        severities = [order.get(p.severity, 3) for p in patterns]
        assert severities == sorted(severities)


def test_no_duplicate_patterns(dx):
    patterns = detect_patterns(dx)
    keys = [(p.pattern_type, p.evidence) for p in patterns]
    assert len(keys) == len(set(keys))
