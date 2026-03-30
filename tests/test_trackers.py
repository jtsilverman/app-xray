"""Tests for tracker detection."""

import os
import pytest
from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK
from app_xray.extractors.trackers import detect_trackers, _load_tracker_db

FIXTURE_APK = os.path.join(os.path.dirname(__file__), "fixtures", "fdroid.apk")


@pytest.fixture(scope="module")
def apk_data():
    a, d, dx = AnalyzeAPK(FIXTURE_APK)
    return a, d, dx


def test_load_tracker_db():
    db = _load_tracker_db()
    assert isinstance(db, list)
    assert len(db) > 100  # Exodus has 400+


def test_tracker_db_entries_have_required_fields():
    db = _load_tracker_db()
    for entry in db[:5]:
        assert "name" in entry
        assert "code_signature" in entry


def test_detect_trackers_returns_list(apk_data):
    a, d, dx = apk_data
    trackers = detect_trackers(a, dx)
    assert isinstance(trackers, list)


def test_tracker_objects_have_required_fields(apk_data):
    a, d, dx = apk_data
    trackers = detect_trackers(a, dx)
    for t in trackers:
        assert t.name
        assert t.code_signature
        assert t.category
        assert isinstance(t.matched_classes, list)
