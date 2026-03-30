"""Suspicious pattern detection in APK bytecode."""

import base64
import re

from app_xray.models import SuspiciousPattern

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# Known private/local IPs to ignore
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.", "127.", "0.")

# Device ID harvesting APIs
DEVICE_ID_APIS = [
    ("getDeviceId", "IMEI/device ID access"),
    ("getImei", "IMEI access"),
    ("getSubscriberId", "Subscriber ID (IMSI) access"),
    ("getMacAddress", "MAC address access"),
    ("getSerialNumber", "Device serial number"),
    ("ANDROID_ID", "Android device ID access"),
    ("advertisingId", "Advertising ID access"),
    ("getAdvertisingIdInfo", "Google Advertising ID"),
]

# Clipboard access
CLIPBOARD_APIS = [
    ("ClipboardManager", "Clipboard access"),
    ("getPrimaryClip", "Reading clipboard content"),
    ("setPrimaryClip", "Writing to clipboard"),
]

# Native library loading
NATIVE_LOAD_APIS = [
    ("System.loadLibrary", "Native library loading"),
    ("System.load", "Native library loading (direct path)"),
    ("Runtime.loadLibrary", "Native library loading via Runtime"),
]

# Crypto/obfuscation indicators
CRYPTO_APIS = [
    ("javax.crypto.Cipher", "Encryption/decryption"),
    ("javax.crypto.spec.SecretKeySpec", "Symmetric key creation"),
    ("DESede", "Triple DES encryption (weak)"),
    ("Blowfish", "Blowfish encryption"),
]


def detect_patterns(dx) -> list[SuspiciousPattern]:
    """Scan bytecode for suspicious privacy patterns."""
    patterns = []
    all_strings = {}

    for s in dx.get_strings():
        value = str(s.get_value())
        # Track source location for each string
        xrefs = s.get_xref_from()
        location = ""
        if xrefs:
            for cls, method in xrefs:
                name = cls.name
                if name.startswith("L") and name.endswith(";"):
                    name = name[1:-1].replace("/", ".")
                method_name = method.name if method else ""
                location = f"{name}.{method_name}"
                break
        all_strings[value] = location

    # Hardcoded IPs - only flag IPs in network-relevant contexts
    for value, location in all_strings.items():
        # Skip OID-like strings (crypto library constants)
        if location and ("bouncycastle" in location.lower()
                         or "asn1" in location.lower()
                         or "ObjectIdentifier" in location):
            continue
        for match in IP_PATTERN.finditer(value):
            ip = match.group(0)
            if ip.startswith(PRIVATE_IP_PREFIXES):
                continue
            # Skip multicast addresses (224.x.x.x - 239.x.x.x)
            first_octet = int(ip.split(".")[0])
            if first_octet >= 224:
                continue
            # Skip IPs that look like version numbers or OIDs (very low first octet)
            if first_octet < 10:
                continue
            # Only flag if the string looks network-related
            value_lower = value.lower()
            if any(kw in value_lower for kw in ("http", "://", "socket", "connect", "host", "server", "api", "url", "endpoint")):
                patterns.append(SuspiciousPattern(
                    pattern_type="hardcoded_ip",
                    description=f"Hardcoded public IP address: {ip}",
                    location=location,
                    severity="medium",
                    evidence=ip,
                ))
            elif len(value.strip()) <= 15:
                # Standalone IP string (just the IP, nothing else)
                patterns.append(SuspiciousPattern(
                    pattern_type="hardcoded_ip",
                    description=f"Hardcoded public IP address: {ip}",
                    location=location,
                    severity="medium",
                    evidence=ip,
                ))

    # Base64-encoded URLs
    for value, location in all_strings.items():
        for match in BASE64_PATTERN.finditer(value):
            b64 = match.group(0)
            try:
                decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
                if "http" in decoded.lower() and "://" in decoded:
                    patterns.append(SuspiciousPattern(
                        pattern_type="base64_url",
                        description=f"Base64-encoded URL: {decoded[:60]}",
                        location=location,
                        severity="high",
                        evidence=b64[:40],
                    ))
            except Exception:
                pass

    # Device ID harvesting
    for api, desc in DEVICE_ID_APIS:
        for value, location in all_strings.items():
            if api in value:
                patterns.append(SuspiciousPattern(
                    pattern_type="device_id",
                    description=desc,
                    location=location,
                    severity="high",
                    evidence=api,
                ))
                break  # one match per API is enough

    # Clipboard access
    for api, desc in CLIPBOARD_APIS:
        for value, location in all_strings.items():
            if api in value:
                patterns.append(SuspiciousPattern(
                    pattern_type="clipboard",
                    description=desc,
                    location=location,
                    severity="medium",
                    evidence=api,
                ))
                break

    # Native library loading
    for api, desc in NATIVE_LOAD_APIS:
        for value, location in all_strings.items():
            if api in value:
                patterns.append(SuspiciousPattern(
                    pattern_type="native_lib",
                    description=desc,
                    location=location,
                    severity="low",
                    evidence=api,
                ))
                break

    # Crypto indicators
    for api, desc in CRYPTO_APIS:
        for value, location in all_strings.items():
            if api in value:
                patterns.append(SuspiciousPattern(
                    pattern_type="crypto",
                    description=desc,
                    location=location,
                    severity="low",
                    evidence=api,
                ))
                break

    # Deduplicate by (pattern_type, evidence)
    seen = set()
    unique = []
    for p in patterns:
        key = (p.pattern_type, p.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(p)

    unique.sort(key=lambda p: {"high": 0, "medium": 1, "low": 2}.get(p.severity, 3))
    return unique
