"""Data models for APK audit findings."""

from dataclasses import dataclass, field


@dataclass
class APKInfo:
    package_name: str
    version_name: str
    version_code: int
    target_sdk: int
    min_sdk: int
    file_size: int
    sha256: str


@dataclass
class Permission:
    name: str
    protection_level: str  # dangerous / normal / signature
    declared: bool
    used_in_code: bool
    description: str = ""


@dataclass
class Tracker:
    name: str
    code_signature: str
    website: str
    category: str
    matched_classes: list[str] = field(default_factory=list)


@dataclass
class Endpoint:
    url: str
    source_class: str
    source_method: str
    is_https: bool
    domain: str


@dataclass
class SuspiciousPattern:
    pattern_type: str  # hardcoded_ip / base64_url / device_id / native_lib / obfuscation
    description: str
    location: str
    severity: str  # high / medium / low
    evidence: str


@dataclass
class CertificateInfo:
    issuer: str
    subject: str
    serial_number: str
    sha256_fingerprint: str
    valid_from: str
    valid_to: str
    is_debug: bool


@dataclass
class NetworkCallPath:
    sink: str
    chain: list[str]
    entry_type: str


@dataclass
class AuditReport:
    apk_info: APKInfo
    permissions: list[Permission] = field(default_factory=list)
    trackers: list[Tracker] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    suspicious_patterns: list[SuspiciousPattern] = field(default_factory=list)
    certificate: CertificateInfo | None = None
    network_paths: list[NetworkCallPath] = field(default_factory=list)
    privacy_score: int = 100
    score_breakdown: dict = field(default_factory=dict)
    scan_timestamp: str = ""
