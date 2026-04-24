"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Downloads and caches the CISA KEV JSON feed, which lists CVEs that are
actively exploited in the wild.

Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Set

from .cache import DiskCache

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_TIMEOUT = 30

_cache = DiskCache(namespace="kev", ttl_seconds=86_400)
_KEV_CACHE_KEY = "catalog"

# In-process cache so we don't hit disk on every lookup within one scan.
_kev_set: Optional[Set[str]] = None


def get_kev_cve_ids() -> Set[str]:
    """Return a set of CVE IDs present in the CISA KEV catalog.

    The catalog is fetched once per day (disk cache) and once per
    process (in-memory cache).  Returns an empty set on network errors.
    """
    global _kev_set
    if _kev_set is not None:
        return _kev_set

    catalog: Optional[Dict[str, Any]] = _cache.get(_KEV_CACHE_KEY)
    if catalog is None:
        catalog = _fetch_catalog()
        if catalog is not None:
            _cache.set(_KEV_CACHE_KEY, catalog)

    if catalog is None:
        _kev_set = set()
    else:
        _kev_set = {
            entry.get("cveID", "")
            for entry in catalog.get("vulnerabilities", [])
            if entry.get("cveID")
        }

    return _kev_set


def is_in_kev(cve_id: str) -> bool:
    """Return ``True`` if *cve_id* is listed in the CISA KEV catalog."""
    return cve_id in get_kev_cve_ids()


def _fetch_catalog() -> Optional[Dict[str, Any]]:
    try:
        with urllib.request.urlopen(_KEV_URL, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None
