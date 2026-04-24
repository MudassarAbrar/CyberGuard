"""OSV (Open Source Vulnerabilities) API client.

Queries https://api.osv.dev/v1/query for known vulnerabilities given a
package name, version, and ecosystem.  No API key is required.

Reference: https://google.github.io/osv.dev/post-v1-query/
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .cache import DiskCache

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

_TIMEOUT = 30  # seconds

_cache = DiskCache(namespace="osv", ttl_seconds=86_400)


def query_package(name: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """Return a list of OSV vulnerability objects for the given package.

    Parameters
    ----------
    name:
        Package name (e.g. ``"requests"``).
    version:
        Installed version string (e.g. ``"2.27.0"``).
    ecosystem:
        OSV ecosystem string: ``"PyPI"``, ``"npm"``, ``"Go"``, ``"Maven"``,
        ``"RubyGems"``.

    Returns
    -------
    list
        Raw OSV vulnerability dicts; empty if none found or on error.
    """
    cache_key = f"{ecosystem}:{name}:{version}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    payload = json.dumps(
        {
            "version": version,
            "package": {"name": name, "ecosystem": ecosystem},
        }
    ).encode()

    try:
        req = urllib.request.Request(
            _OSV_QUERY_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data: Dict[str, Any] = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []

    vulns: List[Dict[str, Any]] = data.get("vulns", [])
    _cache.set(cache_key, vulns)
    return vulns


def extract_fixed_version(vuln: Dict[str, Any], ecosystem: str) -> Optional[str]:
    """Best-effort extraction of the first fixed version from an OSV vuln object."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem", "").lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None
