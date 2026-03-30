"""Tests for endpoint extraction."""

import os
import pytest
from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
from app_xray.extractors.endpoints import extract_endpoints

FIXTURE_APK = os.path.join(os.path.dirname(__file__), "fixtures", "fdroid.apk")


@pytest.fixture(scope="module")
def dx():
    _, _, dx = AnalyzeAPK(FIXTURE_APK)
    return dx


def test_extract_endpoints_returns_list(dx):
    endpoints = extract_endpoints(dx)
    assert isinstance(endpoints, list)


def test_endpoints_have_required_fields(dx):
    endpoints = extract_endpoints(dx)
    for e in endpoints:
        assert e.url
        assert e.domain
        assert isinstance(e.is_https, bool)


def test_no_system_urls_in_results(dx):
    endpoints = extract_endpoints(dx)
    system_domains = {"schemas.android.com", "www.w3.org", "xmlpull.org"}
    for e in endpoints:
        assert e.domain not in system_domains, f"System URL leaked: {e.url}"


def test_endpoints_sorted_by_domain(dx):
    endpoints = extract_endpoints(dx)
    if len(endpoints) > 1:
        domains = [e.domain for e in endpoints]
        assert domains == sorted(domains)
