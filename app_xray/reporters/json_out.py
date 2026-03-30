"""JSON report output."""

import json
from dataclasses import asdict

from app_xray.models import AuditReport


def to_json(report: AuditReport) -> str:
    """Serialize AuditReport to JSON."""
    return json.dumps(asdict(report), indent=2)
