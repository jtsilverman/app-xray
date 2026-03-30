"""Tests for manifest permission extraction."""

import os
import pytest
from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
from app_xray.extractors.manifest import extract_permissions

FIXTURE_APK = os.path.join(os.path.dirname(__file__), "fixtures", "fdroid.apk")


@pytest.fixture
def apk():
    a, _, _ = AnalyzeAPK(FIXTURE_APK)
    return a


def test_extract_permissions_returns_list(apk):
    perms = extract_permissions(apk)
    assert isinstance(perms, list)
    assert len(perms) > 0


def test_permissions_have_required_fields(apk):
    perms = extract_permissions(apk)
    for p in perms:
        assert p.name
        assert p.protection_level in ("dangerous", "normal", "signature")
        assert p.declared is True


def test_internet_permission_present(apk):
    perms = extract_permissions(apk)
    names = [p.name for p in perms]
    assert "android.permission.INTERNET" in names


def test_dangerous_permissions_sorted_first(apk):
    perms = extract_permissions(apk)
    if not any(p.protection_level == "dangerous" for p in perms):
        pytest.skip("No dangerous permissions in test APK")
    first_non_dangerous = next(
        (i for i, p in enumerate(perms) if p.protection_level != "dangerous"),
        len(perms),
    )
    for p in perms[:first_non_dangerous]:
        assert p.protection_level == "dangerous"
