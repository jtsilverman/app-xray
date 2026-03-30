"""Tracker detection via Exodus Privacy database."""

import json
import os
import re
import time

import requests

from app_xray.models import Tracker

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
CACHE_FILE = os.path.join(DATA_DIR, "trackers.json")
EXODUS_API = "https://reports.exodus-privacy.eu.org/api/trackers"
CACHE_MAX_AGE = 86400 * 7  # refresh weekly


def _load_tracker_db() -> list[dict]:
    """Load tracker database, fetching from Exodus if cache is stale."""
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(CACHE_FILE):
        age = time.time() - os.path.getmtime(CACHE_FILE)
        if age < CACHE_MAX_AGE:
            with open(CACHE_FILE) as f:
                return json.load(f)

    try:
        resp = requests.get(EXODUS_API, timeout=15)
        resp.raise_for_status()
        raw = resp.json().get("trackers", {})
        trackers = []
        for t in raw.values():
            if not t.get("code_signature"):
                continue
            trackers.append({
                "name": t["name"],
                "code_signature": t["code_signature"],
                "website": t.get("website", ""),
                "categories": t.get("categories", []),
            })
        with open(CACHE_FILE, "w") as f:
            json.dump(trackers, f, indent=2)
        return trackers
    except Exception:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE) as f:
                return json.load(f)
        return []


def _signature_to_patterns(sig: str) -> list[re.Pattern]:
    """Convert Exodus code_signature to regex patterns.

    Signatures use '|' as separator and '.' as literal package separator.
    Example: 'com.databerries.|com.geolocstation.' matches any class
    starting with those prefixes.
    """
    patterns = []
    for part in sig.split("|"):
        part = part.strip()
        if not part:
            continue
        escaped = re.escape(part)
        patterns.append(re.compile(escaped))
    return patterns


def detect_trackers(apk, dx) -> list[Tracker]:
    """Detect known trackers by matching class names against Exodus signatures."""
    db = _load_tracker_db()

    # Collect all class names from the APK
    class_names = set()
    for cls in dx.get_classes():
        name = cls.name
        # Convert Lcom/example/Foo; -> com.example.Foo
        if name.startswith("L") and name.endswith(";"):
            name = name[1:-1].replace("/", ".")
        class_names.add(name)

    found_trackers = []
    for tracker_def in db:
        patterns = _signature_to_patterns(tracker_def["code_signature"])
        matched = []
        for pattern in patterns:
            for cls in class_names:
                if pattern.search(cls):
                    matched.append(cls)
        if matched:
            categories = tracker_def.get("categories", [])
            category = categories[0] if categories else "Unknown"
            found_trackers.append(Tracker(
                name=tracker_def["name"],
                code_signature=tracker_def["code_signature"],
                website=tracker_def["website"],
                category=category,
                matched_classes=sorted(matched)[:10],  # cap at 10 examples
            ))

    found_trackers.sort(key=lambda t: t.name)
    return found_trackers
