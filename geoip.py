"""
geoip.py – NetWatch GeoIP enrichment
Uses the free ip-api.com JSON API (no API key, rate-limited to 45 req/min).
Results are cached in-memory and optionally persisted to the DB.

For offline use, install geoip2 + MaxMind GeoLite2-City.mmdb:
    pip install geoip2
    # download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from typing import Optional
from urllib.request import urlopen
from urllib.error import URLError


# ─── Private / reserved address blocks ───────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


# ─── GeoIP result ────────────────────────────────────────────────────────────

EMPTY_GEO = {
    "country":     "",
    "country_code": "",
    "region":      "",
    "city":        "",
    "lat":         None,
    "lon":         None,
    "isp":         "",
    "asn":         "",
    "org":         "",
    "private":     False,
}


# ─── GeoIP resolver ──────────────────────────────────────────────────────────

class GeoIPResolver:
    """
    Lookup geographic + ASN information for public IP addresses.
    Caches results to avoid repeated network calls.

    Priority:
      1. In-memory LRU cache
      2. MaxMind GeoIP2 local DB (if installed + configured)
      3. ip-api.com HTTP API (free, 45 req/min)
    """

    def __init__(self, maxmind_db: str = "", cache_size: int = 2048):
        self._cache:    dict[str, dict] = {}
        self._lock      = threading.Lock()
        self._max_cache = cache_size
        self._last_req  = 0.0          # rate-limit ip-api (45/min → 1.4 s)
        self._req_lock  = threading.Lock()

        # Try to load MaxMind reader
        self._mm_reader = None
        if maxmind_db:
            try:
                import geoip2.database
                self._mm_reader = geoip2.database.Reader(maxmind_db)
                print(f"[geoip] Using MaxMind DB: {maxmind_db}")
            except Exception as e:
                print(f"[geoip] MaxMind unavailable ({e}), falling back to ip-api.com")

    def lookup(self, ip: str) -> dict:
        """Return geo dict. Never raises — returns EMPTY_GEO on failure."""
        if is_private(ip):
            result = dict(EMPTY_GEO)
            result["private"] = True
            return result

        with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        result = self._fetch(ip)

        with self._lock:
            if len(self._cache) >= self._max_cache:
                # Evict oldest 10%
                to_del = list(self._cache.keys())[:self._max_cache // 10]
                for k in to_del:
                    del self._cache[k]
            self._cache[ip] = result

        return result

    def batch_lookup(self, ips: list[str]) -> dict[str, dict]:
        """Lookup multiple IPs; deduplicated, skips privates."""
        results = {}
        public  = [ip for ip in set(ips) if not is_private(ip)]
        for ip in public:
            results[ip] = self.lookup(ip)
        return results

    def _fetch(self, ip: str) -> dict:
        # 1. MaxMind local DB
        if self._mm_reader:
            try:
                return self._from_maxmind(ip)
            except Exception:
                pass

        # 2. ip-api.com
        return self._from_ipapi(ip)

    def _from_maxmind(self, ip: str) -> dict:
        resp = self._mm_reader.city(ip)
        return {
            "country":      resp.country.name or "",
            "country_code": resp.country.iso_code or "",
            "region":       resp.subdivisions.most_specific.name or "",
            "city":         resp.city.name or "",
            "lat":          resp.location.latitude,
            "lon":          resp.location.longitude,
            "isp":          "",
            "asn":          str(resp.traits.autonomous_system_number or ""),
            "org":          resp.traits.autonomous_system_organization or "",
            "private":      False,
        }

    def _from_ipapi(self, ip: str) -> dict:
        # Respect rate limit
        with self._req_lock:
            elapsed = time.time() - self._last_req
            if elapsed < 1.4:
                time.sleep(1.4 - elapsed)
            self._last_req = time.time()

        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,asn,org"
        try:
            with urlopen(url, timeout=4) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") != "success":
                return dict(EMPTY_GEO)
            return {
                "country":      data.get("country",     ""),
                "country_code": data.get("countryCode", ""),
                "region":       data.get("regionName",  ""),
                "city":         data.get("city",        ""),
                "lat":          data.get("lat"),
                "lon":          data.get("lon"),
                "isp":          data.get("isp",         ""),
                "asn":          data.get("asn",         ""),
                "org":          data.get("org",         ""),
                "private":      False,
            }
        except (URLError, Exception):
            return dict(EMPTY_GEO)

    def enrich_snapshot(self, snap: dict) -> dict:
        """Add geo info to top_hosts and top_flows in-place (public IPs only)."""
        all_ips = set()
        for h in snap.get("top_hosts", []):
            all_ips.add(h["ip"])
        for f in snap.get("top_flows", []):
            all_ips.add(f["src_ip"])
            all_ips.add(f["dst_ip"])

        geo_map = self.batch_lookup(list(all_ips))

        for h in snap.get("top_hosts", []):
            h["geo"] = geo_map.get(h["ip"], dict(EMPTY_GEO))
        for f in snap.get("top_flows", []):
            f["src_geo"] = geo_map.get(f["src_ip"], dict(EMPTY_GEO))
            f["dst_geo"] = geo_map.get(f["dst_ip"], dict(EMPTY_GEO))

        return snap
