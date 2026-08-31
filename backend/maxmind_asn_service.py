"""
TraceXMail Local MaxMind ASN Intelligence Service
Module: backend/maxmind_asn_service.py

PHASE 10 — MaxMind Origin Intelligence
=======================================
Provides a fast, fully offline ASN + organization lookup for IPv4/IPv6
addresses using the GeoLite2-ASN-Blocks CSV files shipped by MaxMind.

Why CSV instead of the .mmdb binary?
-------------------------------------
Reading the .mmdb binary format requires the `geoip2` / `maxminddb`
packages. Those aren't always installable in restricted/offline
environments. MaxMind ships the exact same routing data as plain CSV
("GeoLite2-ASN-Blocks-IPv4.csv" / "...IPv6.csv"), so this module parses
those directly with the standard library and does a binary search over
the sorted network ranges. No network calls, no third-party deps.

If `geoip2`/`maxminddb` *are* installed and backend/data/maxmind/GeoLite2-ASN.mmdb
is present, you can swap this module's lookup() implementation for a
geoip2.database.Reader without changing any caller — the public
lookup_asn() contract stays the same.

Data expected at:
    backend/data/maxmind/GeoLite2-ASN-Blocks-IPv4.csv
    backend/data/maxmind/GeoLite2-ASN-Blocks-IPv6.csv
"""

import bisect
import csv
import ipaddress
import logging
import os
import pickle
import threading
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("TraceXMail.MaxMindASN")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "maxmind")
_IPV4_CSV = os.path.join(_DATA_DIR, "GeoLite2-ASN-Blocks-IPv4.csv")
_IPV6_CSV = os.path.join(_DATA_DIR, "GeoLite2-ASN-Blocks-IPv6.csv")


def _parse_ipv4_cidr(cidr: str) -> Tuple[int, int]:
    """Fast integer bit-shift calculation for IPv4 network start & end."""
    ip_str, prefix_str = cidr.split('/')
    prefix = int(prefix_str)
    a, b, c, d = map(int, ip_str.split('.'))
    ip_int = (a << 24) | (b << 16) | (c << 8) | d
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix > 0 else 0
    start = ip_int & mask
    end = start | (~mask & 0xFFFFFFFF)
    return start, end


def _parse_ipv6_cidr(cidr: str) -> Tuple[int, int]:
    """Parses IPv6 CIDR to integer start and broadcast addresses."""
    net = ipaddress.ip_network(cidr, strict=False)
    return int(net.network_address), int(net.broadcast_address)


# Well-known hosting/cloud ASN organizations -> normalized provider name.
# Mirrors the CLOUD_PROVIDER_PATTERNS idea from infra_classifier.py but
# keyed off the raw MaxMind organization string for a fast first-pass hint.
_HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "ovh", "hetzner", "linode", "akamai", "oracle", "alibaba",
    "cloudflare", "vultr", "choopa", "leaseweb", "contabo", "scaleway",
    "hosting", "cloud", "data center", "datacenter", "colo", "server",
)


class _ASNTable:
    """Sorted range table for one IP family, supporting O(log n) lookup."""

    def __init__(self, is_ipv6: bool = False) -> None:
        self.is_ipv6 = is_ipv6
        self._starts: List[int] = []
        self._ends: List[int] = []
        self._asn: List[int] = []
        self._org: List[str] = []
        self.loaded = False
        self.row_count = 0

    def load(self, csv_path: str) -> None:
        cache_path = csv_path.replace(".csv", ".cache.pkl")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "rb") as f:
                    data = pickle.load(f)
                    self._starts = data.get("starts", [])
                    self._ends = data.get("ends", [])
                    self._asn = data.get("asn", [])
                    self._org = data.get("org", [])
                    self.row_count = len(self._starts)
                    self.loaded = self.row_count > 0
                    if self.loaded:
                        logger.info(f"Loaded {self.row_count} ASN ranges from cache {cache_path}")
                        return
            except Exception as e:
                logger.warning(f"Failed to load ASN cache {cache_path}: {e}")

        if not os.path.exists(csv_path):
            logger.warning(f"MaxMind ASN CSV not found at {csv_path}; local ASN lookup disabled for this family.")
            return

        starts: List[int] = []
        ends: List[int] = []
        asn: List[int] = []
        org: List[str] = []

        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader, None)  # network, autonomous_system_number, autonomous_system_organization
                rows: List[Tuple[int, int, int, str]] = []
                for row in reader:
                    if len(row) < 3:
                        continue
                    network_str, asn_str, org_str = row[0], row[1], row[2]
                    try:
                        if self.is_ipv6:
                            s, e = _parse_ipv6_cidr(network_str)
                        else:
                            s, e = _parse_ipv4_cidr(network_str)
                        rows.append((s, e, int(asn_str), org_str))
                    except (ValueError, TypeError, Exception):
                        continue

                rows.sort(key=lambda r: r[0])
                for s, e, a, o in rows:
                    starts.append(s)
                    ends.append(e)
                    asn.append(a)
                    org.append(o)

            self._starts, self._ends, self._asn, self._org = starts, ends, asn, org
            self.row_count = len(starts)
            self.loaded = self.row_count > 0
            logger.info(f"Loaded {self.row_count} ASN ranges from {csv_path}")

            try:
                with open(cache_path, "wb") as f:
                    pickle.dump({"starts": starts, "ends": ends, "asn": asn, "org": org}, f, protocol=pickle.HIGHEST_PROTOCOL)
            except Exception as ce:
                logger.debug(f"Could not save ASN cache: {ce}")
        except Exception as e:
            logger.error(f"Error reading ASN CSV {csv_path}: {e}")

    def lookup(self, ip_int: int) -> Optional[Tuple[int, str]]:
        if not self.loaded or not self._starts:
            return None
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx < 0:
            return None
        if self._starts[idx] <= ip_int <= self._ends[idx]:
            return self._asn[idx], self._org[idx]
        return None


_ipv4_table = _ASNTable(is_ipv6=False)
_ipv6_table = _ASNTable(is_ipv6=True)
_load_lock = threading.Lock()
_initialized = False


def _ensure_loaded() -> None:
    global _initialized
    if _initialized:
        return
    with _load_lock:
        if _initialized:
            return
        _ipv4_table.load(_IPV4_CSV)
        _ipv6_table.load(_IPV6_CSV)
        _initialized = True


def is_available() -> bool:
    """Whether at least one local ASN table loaded successfully."""
    _ensure_loaded()
    return _ipv4_table.loaded or _ipv6_table.loaded


def is_likely_hosting_org(asn_org: str) -> bool:
    """Cheap keyword hint — real classification still belongs to infra_classifier.py."""
    if not asn_org:
        return False
    lowered = asn_org.lower()
    return any(kw in lowered for kw in _HOSTING_KEYWORDS)


def lookup_asn(ip_str: str) -> Dict[str, Any]:
    """
    Local, offline ASN + organization lookup for a single IP address.

    Returns a dict shaped to slot directly into origin_intelligence.py's
    geolocation payload:
        {
          "ip": "...",
          "found": bool,
          "asn": "AS13335" | "UNKNOWN",
          "asn_org": "Cloudflare, Inc." | "UNKNOWN",
          "is_likely_hosting": bool,
          "lookup_method": "MaxMind GeoLite2-ASN (local CSV)"
        }
    Never raises — an unparsable/unresolvable IP just comes back not found.
    """
    _ensure_loaded()

    result = {
        "ip": ip_str,
        "found": False,
        "asn": "UNKNOWN",
        "asn_org": "UNKNOWN",
        "is_likely_hosting": False,
        "lookup_method": "MaxMind GeoLite2-ASN (local CSV)",
    }

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip().strip("[]()"))
    except ValueError:
        result["lookup_method"] = "MaxMind GeoLite2-ASN (local CSV) — invalid IP"
        return result

    table = _ipv6_table if ip_obj.version == 6 else _ipv4_table
    hit = table.lookup(int(ip_obj))
    if hit is None:
        return result

    asn_num, asn_org = hit
    result["found"] = True
    result["asn"] = f"AS{asn_num}"
    result["asn_org"] = asn_org or "UNKNOWN"
    result["is_likely_hosting"] = is_likely_hosting_org(asn_org)
    return result


def stats() -> Dict[str, Any]:
    """Diagnostic info — how many ranges are loaded, for a health-check endpoint."""
    _ensure_loaded()
    return {
        "ipv4_ranges_loaded": _ipv4_table.row_count,
        "ipv6_ranges_loaded": _ipv6_table.row_count,
        "ipv4_available": _ipv4_table.loaded,
        "ipv6_available": _ipv6_table.loaded,
    }
