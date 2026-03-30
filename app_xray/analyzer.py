"""Main analysis orchestrator."""

import hashlib
import os
from datetime import datetime, timezone

from loguru import logger
logger.disable("androguard")

from androguard.misc import AnalyzeAPK as _analyze_apk

from app_xray.models import APKInfo, AuditReport


def analyze_apk(apk_path: str, trace_network: bool = False) -> AuditReport:
    """Run full privacy audit on an APK file."""
    a, d, dx = _analyze_apk(apk_path)

    file_size = os.path.getsize(apk_path)
    with open(apk_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    def _safe_int(val) -> int:
        try:
            return int(val) if val else 0
        except (ValueError, TypeError):
            return 0

    apk_info = APKInfo(
        package_name=a.get_package(),
        version_name=a.get_androidversion_name() or "unknown",
        version_code=_safe_int(a.get_androidversion_code()),
        target_sdk=_safe_int(a.get_target_sdk_version()),
        min_sdk=_safe_int(a.get_min_sdk_version()),
        file_size=file_size,
        sha256=sha256,
    )

    from app_xray.extractors.manifest import extract_permissions
    permissions = extract_permissions(a)

    from app_xray.extractors.permissions import analyze_permission_usage
    permissions = analyze_permission_usage(permissions, dx)

    from app_xray.extractors.trackers import detect_trackers
    trackers = detect_trackers(a, dx)

    from app_xray.extractors.endpoints import extract_endpoints
    endpoints = extract_endpoints(dx)

    from app_xray.extractors.patterns import detect_patterns
    suspicious = detect_patterns(dx)

    from app_xray.extractors.certificates import extract_certificate
    certificate = extract_certificate(a)

    network_paths = []
    if trace_network:
        from app_xray.extractors.network_paths import trace_network_calls
        network_paths = trace_network_calls(dx)

    from app_xray.scoring import calculate_score
    score, breakdown = calculate_score(permissions, trackers, endpoints, suspicious)

    report = AuditReport(
        apk_info=apk_info,
        permissions=permissions,
        trackers=trackers,
        endpoints=endpoints,
        suspicious_patterns=suspicious,
        certificate=certificate,
        network_paths=network_paths,
        privacy_score=score,
        score_breakdown=breakdown,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
    )

    return report
