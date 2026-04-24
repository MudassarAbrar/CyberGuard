"""NVD CVE API v2 client.

Fetches CVSS scores and details from the National Vulnerability Database.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from .cache import DiskCache

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 30

_cache = DiskCache(namespace="nvd", ttl_seconds=86_400)


def get_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return NVD CVE data for *cve_id* (e.g. ``"CVE-2021-44228"``).

    Returns the raw NVD vulnerability dict, or ``None`` on error / not found.
    The result is cached for 24 hours.
    """
    cached = _cache.get(cve_id)
    if cached is not None:
        return cached

    params = urllib.parse.urlencode({"cveId": cve_id})
    url = f"{_NVD_BASE_URL}?{params}"

    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            data: Dict[str, Any] = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    result: Dict[str, Any] = vulns[0]
    _cache.set(cve_id, result)
    return result


def extract_cvss_score(cve_data: Dict[str, Any]) -> Optional[float]:
    """Extract the highest available CVSS base score from NVD CVE data."""
    metrics = cve_data.get("cve", {}).get("metrics", {})

    # Prefer CVSSv3.1, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def extract_cvss_vector(cve_data: Dict[str, Any]) -> Optional[str]:
    """Extract the CVSS vector string from NVD CVE data."""
    metrics = cve_data.get("cve", {}).get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return str(entries[0]["cvssData"]["vectorString"])
            except (KeyError, TypeError):
                continue
    return None
