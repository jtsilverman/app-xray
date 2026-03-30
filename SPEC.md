# App X-Ray - SPEC

## Overview

CLI tool that takes an Android APK and generates a comprehensive privacy audit report. Decompiles the app, scans for trackers, analyzes permissions, extracts network endpoints, detects suspicious patterns, and produces a risk-scored report. What security researchers do manually in hours, automated into one command.

Inspired by the viral "I Decompiled the White House's New App" post (2,349 upvotes on r/programming). The twist: nobody has built a tool that automates the full privacy audit pipeline from APK to report in a single CLI command.

## Scope

### Phase 1 - Core
- CLI that accepts an APK file path
- APK metadata extraction (package name, version, target SDK, signing info)
- AndroidManifest.xml permission extraction and categorization (dangerous/normal/signature)
- Tracker detection by matching class/package names against Exodus Privacy database (432 trackers)
- URL and API endpoint extraction from DEX bytecode
- Colored terminal report with risk summary

### Phase 2 - Full Product
- Permission usage analysis (declared vs. actually referenced in code)
- Suspicious pattern detection (hardcoded IPs, base64-encoded URLs, native library loading, device ID harvesting, crypto/obfuscation indicators)
- Risk scoring system (0-100 privacy score based on weighted findings)
- HTML report generation (self-contained, shareable)
- APK comparison mode (diff two versions, show what changed in permissions/trackers/endpoints)
- Certificate analysis (signing info, debug vs release, known bad signers)
- Ship: README, deploy to PyPI, verify install

### Phase 3 - Stretch
- Network behavior simulation (trace which code paths lead to network calls)
- YARA rule support for custom pattern matching
- GitHub Action for CI integration (scan APKs on PR)
- Batch scanning (directory of APKs)

### Not Building
- iOS IPA support (different binary format, separate project)
- Dynamic analysis (running the app in an emulator)
- Real-time monitoring
- Web UI / SaaS

### Ship Target
- PyPI (`pip install app-xray`)
- GitHub (`jtsilverman/app-xray`)

## Project Type
Pure code

## Stack
- **Python 3.12** - androguard is Python-native, makes this the clear choice
- **androguard 4.1.3** - APK decompilation, DEX bytecode analysis, manifest parsing. No Java/Android SDK needed.
- **Click** - CLI framework (lightweight, proven)
- **Rich** - Terminal output (tables, colors, progress bars)
- **Jinja2** - HTML report templates
- Diversity note: Jake has 2 Python projects (market-signals, travel-concierge) but those are web apps with FastAPI. This is a pure CLI analysis tool, a different shape.

## Architecture

```
app-xray/
  app_xray/
    __init__.py
    cli.py            # Click CLI entry point
    analyzer.py        # Main analysis orchestrator
    extractors/
      __init__.py
      manifest.py      # AndroidManifest.xml parsing, permissions
      trackers.py      # Tracker detection via Exodus DB
      endpoints.py     # URL/endpoint extraction from bytecode
      patterns.py      # Suspicious pattern detection
      certificates.py  # Signing certificate analysis
      permissions.py   # Declared vs used permission analysis
    models.py          # Data classes for findings
    scoring.py         # Risk scoring engine
    reporters/
      __init__.py
      terminal.py      # Rich terminal output
      html.py          # HTML report generation
      diff.py          # APK comparison reporter
    data/
      trackers.json    # Cached Exodus tracker database
    templates/
      report.html      # Jinja2 HTML report template
  tests/
    test_manifest.py
    test_trackers.py
    test_endpoints.py
    test_patterns.py
    test_scoring.py
    test_cli.py
    fixtures/          # Test APK files
  setup.py
  pyproject.toml
  README.md
```

### Data Models

```python
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
    name: str                    # e.g. "android.permission.CAMERA"
    protection_level: str        # dangerous / normal / signature
    declared: bool               # in manifest
    used_in_code: bool           # referenced in bytecode
    description: str             # human-readable explanation

@dataclass
class Tracker:
    name: str
    code_signature: str          # package pattern matched
    website: str
    category: str                # analytics / ads / social / etc.
    matched_classes: list[str]   # actual classes found in APK

@dataclass
class Endpoint:
    url: str
    source_class: str            # where it was found
    source_method: str
    is_https: bool
    domain: str

@dataclass
class SuspiciousPattern:
    pattern_type: str            # hardcoded_ip / base64_url / device_id / native_lib / obfuscation
    description: str
    location: str                # class.method
    severity: str                # high / medium / low
    evidence: str                # the actual string/code found

@dataclass
class AuditReport:
    apk_info: APKInfo
    permissions: list[Permission]
    trackers: list[Tracker]
    endpoints: list[Endpoint]
    suspicious_patterns: list[SuspiciousPattern]
    privacy_score: int           # 0-100 (100 = most private)
    scan_timestamp: str
```

## Task List

# Phase 1: Core

## 1A: Project Scaffold

### Task 1A.1: Project setup and CLI skeleton
**Files:** `pyproject.toml` (create), `app_xray/__init__.py` (create), `app_xray/cli.py` (create), `app_xray/models.py` (create)
**Do:** Set up Python project with pyproject.toml (name=app-xray, entry point=app-xray). Create Click CLI with `scan` command accepting APK file path. Define all dataclasses in models.py. CLI should validate the file exists and is an APK.
**Validate:** `pip install -e . && app-xray scan --help` shows usage

## 1B: APK Metadata & Manifest

### Task 1B.1: APK info extraction
**Files:** `app_xray/analyzer.py` (create), `app_xray/extractors/__init__.py` (create), `app_xray/extractors/manifest.py` (create), `tests/test_manifest.py` (create)
**Do:** Use androguard's `AnalyzeAPK` to extract package name, version, target/min SDK, file size, SHA256. Parse AndroidManifest.xml for all declared permissions. Categorize each permission as dangerous/normal/signature using Android's protection level definitions (hardcode the known dangerous permissions list). Return APKInfo and list[Permission] (declared=True, used_in_code=False for now).
**Validate:** `python -m pytest tests/test_manifest.py -v` passes with a test APK

### Task 1B.2: Test APK fixture
**Files:** `tests/fixtures/` (create dir), download or generate a test APK
**Do:** Download a known open-source APK for testing (e.g., F-Droid's own APK or a simple test APK from GitHub). This is the test fixture all tests will use. Also create a minimal synthetic APK using androguard if possible.
**Validate:** `ls tests/fixtures/*.apk` shows at least one APK file

## 1C: Tracker Detection

### Task 1C.1: Exodus tracker database integration
**Files:** `app_xray/extractors/trackers.py` (create), `app_xray/data/trackers.json` (create), `tests/test_trackers.py` (create)
**Do:** Fetch Exodus Privacy tracker list from `https://reports.exodus-privacy.eu.org/api/trackers`. Cache as `data/trackers.json`. For each tracker, store name, code_signature (package pattern), website, and category. Scanner matches APK's class names against tracker code signatures. Return list[Tracker] with matched classes.
**Validate:** `python -m pytest tests/test_trackers.py -v` passes

## 1D: Endpoint Extraction

### Task 1D.1: URL and API endpoint extraction
**Files:** `app_xray/extractors/endpoints.py` (create), `tests/test_endpoints.py` (create)
**Do:** Scan DEX bytecode strings for URL patterns (http/https), IP addresses, and API paths. For each URL found, record the source class and method, whether it's HTTPS, and extract the domain. Filter out common Android system URLs (schemas.android.com, google.com/android, etc.). Return list[Endpoint].
**Validate:** `python -m pytest tests/test_endpoints.py -v` passes

## 1E: Terminal Report

### Task 1E.1: Rich terminal output
**Files:** `app_xray/reporters/__init__.py` (create), `app_xray/reporters/terminal.py` (create), `app_xray/analyzer.py` (modify)
**Do:** Wire up the full scan pipeline in analyzer.py: load APK -> extract manifest -> detect trackers -> extract endpoints -> build AuditReport. Create terminal reporter using Rich: colored tables for permissions (red=dangerous), tracker list with categories, endpoint list grouped by domain, summary section with counts. Wire into CLI so `app-xray scan <file.apk>` produces the full report.
**Validate:** `app-xray scan tests/fixtures/*.apk` produces colored terminal output with all sections

# Phase 2: Full Product

## 2A: Permission Usage Analysis

### Task 2A.1: Declared vs used permission detection
**Files:** `app_xray/extractors/permissions.py` (create), `tests/test_permissions.py` (create), `app_xray/extractors/manifest.py` (modify)
**Do:** Build a mapping of Android permissions to the API classes/methods that require them (e.g., CAMERA -> android.hardware.Camera, ACCESS_FINE_LOCATION -> LocationManager.getLastKnownLocation). Scan DEX bytecode for these API calls. Cross-reference with declared permissions. Flag: permissions declared but never used in code (suspicious), and API calls that require permissions not declared (broken). Update Permission.used_in_code field.
**Validate:** `python -m pytest tests/test_permissions.py -v` passes

## 2B: Suspicious Pattern Detection

### Task 2B.1: Pattern scanner
**Files:** `app_xray/extractors/patterns.py` (create), `tests/test_patterns.py` (create)
**Do:** Scan bytecode for suspicious patterns:
- Hardcoded IPs (regex, excluding common private ranges used for localhost)
- Base64-encoded strings that decode to URLs
- Device ID harvesting (IMEI, ANDROID_ID, MAC address API calls)
- Native library loading (System.loadLibrary calls - potential for hidden native code)
- Crypto/obfuscation indicators (custom encryption, XOR patterns on strings)
- Clipboard access (ClipboardManager)
- SMS/call log access APIs
Return list[SuspiciousPattern] with severity and evidence.
**Validate:** `python -m pytest tests/test_patterns.py -v` passes

## 2C: Risk Scoring

### Task 2C.1: Privacy score engine
**Files:** `app_xray/scoring.py` (create), `tests/test_scoring.py` (create)
**Do:** Compute a privacy score (0-100, 100=most private) based on weighted findings:
- Dangerous permissions: -5 each (declared+used), -3 each (declared only)
- Trackers found: -8 each (ads/analytics), -5 each (social)
- HTTP (non-HTTPS) endpoints: -3 each
- Suspicious patterns: -10 (high severity), -5 (medium), -2 (low)
- Unused permissions: -2 each
- Bonus: no trackers (+10), all HTTPS (+5), minimal permissions (+5)
Score starts at 100, subtract penalties, floor at 0. Return score + breakdown.
**Validate:** `python -m pytest tests/test_scoring.py -v` passes

## 2D: Certificate Analysis

### Task 2D.1: Signing certificate extraction
**Files:** `app_xray/extractors/certificates.py` (create), `app_xray/analyzer.py` (modify)
**Do:** Extract APK signing certificate info using androguard: issuer, subject, validity dates, serial number, SHA-256 fingerprint. Detect if it's a debug certificate (CN=Android Debug). Add to AuditReport and terminal output.
**Validate:** `app-xray scan tests/fixtures/*.apk` shows certificate section in output

## 2E: HTML Report

### Task 2E.1: HTML report generation
**Files:** `app_xray/reporters/html.py` (create), `app_xray/templates/report.html` (create), `app_xray/cli.py` (modify)
**Do:** Create self-contained HTML report using Jinja2. Include: header with APK info + privacy score gauge, permissions table with color coding, tracker list with links to Exodus, endpoints grouped by domain, suspicious patterns with severity badges, certificate info. All CSS inline (no external deps). Add `--format html` and `--output` flags to CLI.
**Validate:** `app-xray scan tests/fixtures/*.apk --format html --output report.html && open report.html` produces a valid HTML report

## 2F: APK Comparison

### Task 2F.1: Diff mode
**Files:** `app_xray/reporters/diff.py` (create), `app_xray/cli.py` (modify)
**Do:** Add `app-xray diff <old.apk> <new.apk>` command. Scan both APKs, compare: new/removed permissions, new/removed trackers, new/removed endpoints, score change. Output as a diff table showing what changed between versions.
**Validate:** `app-xray diff tests/fixtures/v1.apk tests/fixtures/v2.apk` produces diff output (will need a second test fixture)

## 2G: JSON Output

### Task 2G.1: JSON export
**Files:** `app_xray/reporters/json_out.py` (create), `app_xray/cli.py` (modify)
**Do:** Add `--format json` flag. Serialize full AuditReport to JSON. Useful for piping to other tools or CI integration.
**Validate:** `app-xray scan tests/fixtures/*.apk --format json | python3 -c "import json,sys; json.load(sys.stdin)"` exits 0

## 2H: Ship

### Task 2H.1: README, PyPI publish, verify
**Files:** `README.md` (create), `pyproject.toml` (modify)
**Do:** Write portfolio-ready README with: problem statement, demo output (terminal screenshot), features, install instructions, usage examples, tech stack, "The Hard Part" section. Ensure pyproject.toml has all metadata for PyPI. Push to GitHub, publish to PyPI.
**Validate:** `pip install app-xray` from PyPI works and `app-xray scan --help` shows usage

# Phase 3: Stretch

## 3A: Network Call Tracing

### Task 3A.1: Code path analysis to network calls
**Files:** `app_xray/extractors/network_paths.py` (create)
**Do:** Use androguard's call graph to trace which code paths lead to network API calls. Show the call chain from entry points (Activities, Services, BroadcastReceivers) to network sinks. This reveals which user actions trigger data exfiltration.
**Validate:** Produces call path output for test APK

## 3B: Custom Rules

### Task 3B.1: YARA-style rule support
**Files:** `app_xray/rules.py` (create)
**Do:** Support custom YAML rules for pattern matching (simpler than YARA, specific to APK analysis). Users can define their own patterns to scan for.
**Validate:** Custom rule file loads and matches patterns in test APK

## 3C: CI Integration

### Task 3C.1: GitHub Action
**Files:** `action.yml` (create)
**Do:** Create a GitHub Action that scans APKs in PRs and comments with the privacy report. Fails if score drops below configurable threshold.
**Validate:** Action YAML is valid

## The One Hard Thing

**Accurate tracker detection and permission-to-API mapping.**

Why it's hard: Tracker SDKs evolve constantly, obfuscated APKs rename packages (breaking signature matching), and the Android permission-to-API mapping is massive and version-dependent. ProGuard/R8 obfuscation can hide tracker class names entirely.

Approach: Start with Exodus signature matching (proven, 432 trackers). For obfuscated APKs, fall back to network endpoint domain matching (trackers phone home to known domains even when code is obfuscated). For permissions, maintain a curated mapping of the most common dangerous permission -> API pairs rather than trying to cover everything.

Fallback: If signature matching is insufficient, add heuristic detection: analyze the shape of code (analytics patterns, ad loading patterns) rather than exact class names. This is less precise but catches obfuscated variants.

## Risks

- **Medium - Obfuscation defeating tracker detection:** ProGuard/R8 can rename all classes. Mitigation: domain-based fallback, heuristic patterns.
- **Low - androguard parsing failures:** Some APKs with exotic features may fail to parse. Mitigation: graceful error handling, report what we can.
- **Low - Test fixture availability:** Need real APKs with known trackers for testing. Mitigation: Use well-known apps (F-Droid, known tracker-heavy apps) or create synthetic test APKs.
