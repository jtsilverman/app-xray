# App X-Ray

Automated Android APK privacy auditor. Feed it an APK, get a full report: trackers, permissions, endpoints, suspicious patterns, and a privacy score.

## Demo

```
$ app-xray scan sketchy-app.apk
╭──────────────────── App X-Ray Report ────────────────────╮
│ com.sketchy.app  v2.1.0                                   │
│ Target SDK: 33  |  Size: 8.2 MB                           │
╰──────────────────────────────────────────────────────────╯

  Privacy Score: 12/100
    dangerous_perms_used: -30
    ad_trackers: -24
    high_severity_patterns: -20

  Permissions: 34 total, 8 dangerous
  Trackers: 3 detected (Facebook Ads, Google Analytics, Adjust)
  Endpoints: 67 total, 12 HTTP (insecure)
  Suspicious patterns: 5 (device ID harvesting, hardcoded IPs)
```

## The Problem

You download an app. What data does it actually collect? Which trackers are embedded? What endpoints does it phone home to? Security researchers answer these questions manually by decompiling APKs and reading bytecode. App X-Ray automates the entire pipeline into a single CLI command.

## How It Works

1. Decompiles the APK using [androguard](https://github.com/androguard/androguard) (no Java/Android SDK required)
2. Extracts permissions from AndroidManifest.xml, classifies as dangerous/normal/signature
3. Cross-references declared permissions with actual API usage in bytecode (finds unused permissions)
4. Matches class names against the [Exodus Privacy](https://exodus-privacy.eu.org/) tracker database (432+ known trackers)
5. Scans DEX bytecode for URLs, API endpoints, and hardcoded IPs
6. Detects suspicious patterns: device ID harvesting, base64-encoded URLs, clipboard access, native library loading
7. Computes a weighted privacy score (0-100)
8. Generates reports in terminal, HTML, or JSON format

## Install

```bash
pip install app-xray
```

## Usage

```bash
# Terminal report (default)
app-xray scan app.apk

# HTML report
app-xray scan app.apk --format html -o report.html

# JSON (pipe to jq, CI, etc.)
app-xray scan app.apk --format json

# Compare two versions
app-xray diff v1.apk v2.apk
```

## Tech Stack

- **Python 3.12** with androguard for APK decompilation and bytecode analysis
- **Exodus Privacy API** for tracker detection (432+ known trackers, cached locally)
- **Click** for CLI, **Rich** for terminal output, **Jinja2** for HTML reports
- Zero Java/Android SDK dependencies

## The Hard Part

Tracker detection breaks when apps use ProGuard/R8 obfuscation, which renames all class and package names. The Exodus signature matching (e.g., `com.google.analytics.*`) stops working entirely.

The solution is layered detection: signature matching first (catches unobfuscated apps), then domain-based fallback (trackers still phone home to known domains even when code is obfuscated), with heuristic patterns as a last resort (analytics-shaped code patterns, ad-loading behaviors).

Permission analysis was also tricky. Android has hundreds of permissions, each mapped to specific API classes. I built a curated mapping of the most privacy-sensitive permission-to-API pairs, then scan bytecode for those API references to determine which permissions are actually used vs. just declared.

## License

MIT
