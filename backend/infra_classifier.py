# Infrastructure Classifier Module

import os
import time
import urllib.request
import re
import ipaddress

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CACHE_FILE = "/tmp/tor_exit_nodes.txt"
TOR_CACHE_TTL_SEC = 6 * 3600  # 6 hours

HOSTING_KEYWORDS = (
    "hetzner", "digitalocean", "linode", "ovh", "aws", "amazon", "google cloud",
    "gcp", "azure", "microsoft corp", "vultr", "scaleway", "leaseweb", "contabo",
    "hostgator", "bluehost", "godaddy", "rackspace", "choopa", "fastly", "cloudflare",
    "datacenter", "data center", "hosting", "server", "vps", "cloud", "zettahost"
)

VPN_KEYWORDS = (
    "mullvad", "nordvpn", "expressvpn", "private internet access", "pia",
    "protonvpn", "surfshark", "cyberghost", "ipvanish", "windscribe", "vyprvpn",
    "hide.me", "vpn", "proxy"
)

RESIDENTIAL_KEYWORDS = (
    "comcast", "verizon", "att", "at&t", "spectrum", "charter", "cox", "centurylink",
    "bt", "vodafone", "telekom", "orange", "telefonica", "broadband", "telecom",
    "cable", "fiber", "dsl", "residential"
)

_tor_nodes_set = None
_tor_fetch_time = 0
_tor_fetch_status = "not_attempted"

def _get_tor_exit_nodes() -> tuple[set[str], str]:
    global _tor_nodes_set, _tor_fetch_time, _tor_fetch_status

    now = time.time()
    # Check memory cache
    if _tor_nodes_set is not None and (now - _tor_fetch_time) < TOR_CACHE_TTL_SEC:
        return _tor_nodes_set, _tor_fetch_status

    # Check disk cache
    if os.path.exists(TOR_CACHE_FILE):
        mtime = os.path.getmtime(TOR_CACHE_FILE)
        if (now - mtime) < TOR_CACHE_TTL_SEC:
            try:
                with open(TOR_CACHE_FILE, "r", encoding="utf-8") as f:
                    ips = {line.strip() for line in f if line.strip() and not line.startswith("#")}
                _tor_nodes_set = ips
                _tor_fetch_time = now
                _tor_fetch_status = "ok_cached_disk"
                return _tor_nodes_set, _tor_fetch_status
            except Exception as e:
                pass

    # Fetch live
    try:
        req = urllib.request.Request(TOR_EXIT_LIST_URL, headers={"User-Agent": "TraceXMail-Forensics/2.1"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
            ips = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
            
            # Save to disk
            try:
                with open(TOR_CACHE_FILE, "w", encoding="utf-8") as f:
                    f.write("\n".join(ips))
            except Exception:
                pass

            _tor_nodes_set = ips
            _tor_fetch_time = now
            _tor_fetch_status = "ok_live"
            return _tor_nodes_set, _tor_fetch_status
    except Exception as e:
        _tor_fetch_status = f"error: {str(e)}"
        if _tor_nodes_set is not None:
            return _tor_nodes_set, f"stale_memory_fallback: {str(e)}"
        return set(), _tor_fetch_status


def classify_infrastructure(
    ip_str: str,
    asn: str = None,
    asn_org: str = None,
    isp: str = None,
    hostname: str = None,
    is_private: bool = False
) -> dict:
    """
    Produces honest best-effort infrastructure classification based on real signal sources.
    """
    # Auto-detect RFC 1918 or private address
    if not is_private and ip_str:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                is_private = True
        except Exception:
            pass

    if is_private or not ip_str:
        return {
            "is_hosting_cloud": False,
            "is_vpn": False,
            "is_tor": False,
            "is_residential": False,
            "is_open_relay": False,
            "category": "INTERNAL_PRIVATE" if is_private else "UNKNOWN",
            "confidence": 1.0 if is_private else 0.0,
            "basis": "RFC 1918 private local network IP space (non-routable)" if is_private else "No IP provided",
            "lookup_method": "signal_analysis",
            "status": "ok" if is_private else "unavailable"
        }

    asn_org_str = str(asn_org or isp or "").lower()
    host_str = str(hostname or "").lower()

    signals_checked = 0
    corroborating_signals = 0

    # 1. Tor Exit Node Check
    tor_ips, tor_status = _get_tor_exit_nodes()
    signals_checked += 1
    is_tor = (ip_str in tor_ips) if "ok" in tor_status or "stale" in tor_status else False
    if is_tor:
        corroborating_signals += 1

    # 2. VPN/Proxy Pattern
    signals_checked += 1
    is_vpn = any(kw in asn_org_str or kw in host_str for kw in VPN_KEYWORDS)
    if is_vpn:
        corroborating_signals += 1

    # 3. Hosting/Cloud Pattern
    signals_checked += 1
    is_hosting = any(kw in asn_org_str or kw in host_str for kw in HOSTING_KEYWORDS)
    if is_hosting:
        corroborating_signals += 1

    # 4. Residential Pattern
    signals_checked += 1
    is_residential = False
    if not is_hosting and not is_vpn and not is_tor:
        if any(kw in asn_org_str or kw in host_str for kw in RESIDENTIAL_KEYWORDS):
            is_residential = True
            corroborating_signals += 1

    # 5. Open Relay / Botnet Indicator
    signals_checked += 1
    is_open_relay = "open-relay" in host_str or "openrelay" in host_str
    if is_open_relay:
        corroborating_signals += 1

    # Category determination
    if is_tor:
        category = "TOR"
    elif is_vpn:
        category = "VPN"
    elif is_open_relay:
        category = "OPEN_RELAY"
    elif is_hosting:
        category = "HOSTING_CLOUD"
    elif is_residential:
        category = "RESIDENTIAL"
    else:
        category = "UNKNOWN"

    # Compute honest confidence based on signal quality
    if category == "UNKNOWN":
        confidence = 0.2 if asn_org_str else 0.0
    else:
        confidence = round(min(1.0, 0.5 + (0.25 * corroborating_signals)), 2)

    basis_parts = []
    if is_tor:
        basis_parts.append(f"Matched official Tor bulk exit list ({tor_status})")
    elif "error" in tor_status:
        basis_parts.append("Tor list check unavailable")

    if is_vpn:
        basis_parts.append(f"VPN provider indicator in ASN/Host ({asn_org_str})")
    if is_hosting:
        basis_parts.append(f"Hosting/Cloud infrastructure provider ({asn_org_str})")
    if is_residential:
        basis_parts.append(f"Residential ISP provider pattern ({asn_org_str})")
    if category == "UNKNOWN":
        basis_parts.append("No specific infrastructure category matched available signals")

    basis = "; ".join(basis_parts)

    return {
        "is_hosting_cloud": is_hosting,
        "is_vpn": is_vpn,
        "is_tor": is_tor,
        "is_residential": is_residential,
        "is_open_relay": is_open_relay,
        "category": category,
        "confidence": confidence,
        "basis": basis,
        "lookup_method": "signal_analysis",
        "status": "ok"
    }
