"""URL and API endpoint extraction from DEX bytecode."""

import re
from urllib.parse import urlparse

from app_xray.models import Endpoint

URL_PATTERN = re.compile(r'https?://[^\s"\'<>{}|\\^`\[\]]+', re.ASCII)

# Android system URLs to filter out (not interesting for privacy audit)
SYSTEM_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "ns.adobe.com",
    "www.apache.org",
    "xml.org",
    "purl.org",
    "json-schema.org",
    "developer.android.com",
    "source.android.com",
    "maven.google.com",
    "dl.google.com",
    "play.google.com",
    # Library documentation/project sites (not privacy-relevant)
    "logback.qos.ch",
    "www.slf4j.org",
    "www.bouncycastle.org",
    "github.com",
    "issuetracker.google.com",
    "goo.gle",
    "spdx.org",
}


def extract_endpoints(dx) -> list[Endpoint]:
    """Extract URLs and API endpoints from DEX bytecode strings."""
    endpoints = []
    seen_urls = set()

    for s in dx.get_strings():
        value = str(s.get_value())
        for match in URL_PATTERN.finditer(value):
            url = match.group(0).rstrip(".,;:)")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                parsed = urlparse(url)
            except Exception:
                continue

            domain = parsed.hostname or ""
            if not domain or domain in SYSTEM_DOMAINS:
                continue
            # Skip localhost/private
            if domain in ("localhost", "127.0.0.1", "0.0.0.0"):
                continue

            # Find which class references this string
            source_class = ""
            source_method = ""
            xrefs = s.get_xref_from()
            if xrefs:
                for cls, method in xrefs:
                    class_name = cls.name
                    if class_name.startswith("L") and class_name.endswith(";"):
                        class_name = class_name[1:-1].replace("/", ".")
                    source_class = class_name
                    source_method = method.name if method else ""
                    break

            endpoints.append(Endpoint(
                url=url,
                source_class=source_class,
                source_method=source_method,
                is_https=parsed.scheme == "https",
                domain=domain,
            ))

    endpoints.sort(key=lambda e: (e.domain, e.url))
    return endpoints
