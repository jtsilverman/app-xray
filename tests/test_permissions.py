"""Tests for permission usage analysis."""

import os
import pytest
from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
from app_xray.extractors.manifest import extract_permissions
from app_xray.extractors.permissions import analyze_permission_usage

FIXTURE_APK = os.path.join(os.path.dirname(__file__), "fixtures", "fdroid.apk")


@pytest.fixture(scope="module")
def apk_data():
    a, d, dx = AnalyzeAPK(FIXTURE_APK)
    return a, d, dx


def test_analyze_returns_same_count(apk_data):
    a, _, dx = apk_data
    perms = extract_permissions(a)
    analyzed = analyze_permission_usage(perms, dx)
    assert len(analyzed) == len(perms)


def test_some_permissions_marked_used(apk_data):
    a, _, dx = apk_data
    perms = extract_permissions(a)
    analyzed = analyze_permission_usage(perms, dx)
    # F-Droid uses bluetooth, camera (QR), notifications - at least some should be used
    used_count = sum(1 for p in analyzed if p.used_in_code)
    assert used_count > 0, "Expected at least some permissions to be marked as used"


def test_permission_fields_preserved(apk_data):
    a, _, dx = apk_data
    perms = extract_permissions(a)
    analyzed = analyze_permission_usage(perms, dx)
    for orig, updated in zip(perms, analyzed):
        assert orig.name == updated.name
        assert orig.protection_level == updated.protection_level
        assert orig.declared == updated.declared
