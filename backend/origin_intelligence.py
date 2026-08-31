"""
TraceXMail Origin Intelligence & Geolocation Engine
Module: backend/origin_intelligence.py

CORE FORENSIC PRINCIPLE:
========================
"infrastructure geolocation, not attacker physical location"

All IP geolocation coordinates, countries, cities, and autonomous system mappings
derived by this engine represent the physical or logical hosting site of the intermediary
mail transfer agent (MTA), cloud VM, proxy, VPN server, or relay node.
They MUST NOT be conflated with the physical location or domicile of the threat actor.
"""

import ipaddress
import json
import logging
import os
import re
import time
import urllib.request
from typing import Dict, Any, List, Optional, Tuple

try:
    from sqlalchemy.orm import Session
    from backend.models import IPIntelligence, Email, RelayNode
except ImportError:
    Session = Any
    IPIntelligence = None
    Email = None
    RelayNode = None
from backend.trust_boundary import analyze_trust_boundary, FORGEABLE_HOP_CAVEAT
from backend.infra_classifier import classify_infrastructure
try:
    from backend.explain import explain_origin, explain_infrastructure
except ImportError:
    from explain import explain_origin, explain_infrastructure
try:
    from backend import maxmind_asn_service
    from backend import maxmind_city_service
except ImportError:
    import maxmind_asn_service
    import maxmind_city_service

logger = logging.getLogger("TraceXMail.OriginIntelligence")

# Explicit spec requirement constant
INFRASTRUCTURE_GEOLOCATION_FRAMING = "infrastructure geolocation, not attacker physical location"

# MaxMind / IP-API Cache in memory with 24-hr TTL
_LIVE_GEO_CACHE: Dict[str, Dict[str, Any]] = {}
GEO_CACHE_TTL = 86400  # 24 hours


def is_private_ip(ip_str: str) -> bool:
    """Checks whether an IP address is private, loopback, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip().strip("[]()"))
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast
    except ValueError:
        return True


def _try_live_lookup(ip_clean: str) -> Optional[Dict[str, Any]]:
    """
    Live lookup fallback/enrichment to ip-api.com with strict 1.5s timeout.
    Only called if local MaxMind city data is unavailable for the target IP.
    """
    try:
        url = f"http://ip-api.com/json/{ip_clean}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "TraceXMail-OriginIntel/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            raw_json = json.loads(resp.read().decode("utf-8"))
            if raw_json.get("status") == "success":
                as_field = raw_json.get("as", "")
                asn_match = re.search(r"^(AS\d+)", as_field)
                asn_code = asn_match.group(1) if asn_match else as_field

                return {
                    "country": raw_json.get("country") or "UNKNOWN",
                    "country_code": raw_json.get("countryCode") or "UN",
                    "region": raw_json.get("regionName") or "UNKNOWN",
                    "city": raw_json.get("city") or "UNKNOWN",
                    "latitude": float(raw_json.get("lat") or 0.0),
                    "longitude": float(raw_json.get("lon") or 0.0),
                    "asn": asn_code or "UNKNOWN",
                    "asn_org": raw_json.get("org") or raw_json.get("isp") or "UNKNOWN",
                    "isp": raw_json.get("isp") or "UNKNOWN",
                }
    except Exception as e:
        logger.debug(f"Optional live IP geolocation enrichment skipped for {ip_clean}: {e}")
    return None


def perform_ip_geolocation_lookup(ip_str: str, db: Optional[Session] = None, organization_id: str = "org_default_01") -> Dict[str, Any]:
    """
    Performs ASN + geolocation lookup for a public IP address.
    Lookup Method: local MaxMind GeoLite2-ASN & GeoLite2-City (offline, authoritative)
    layered with an optional live enrichment query with strict 1.5s timeout only if local
    data missed.

    CRITICAL NOTICE:
    This function measures infrastructure geolocation, not attacker physical location.
    """
    ip_clean = ip_str.strip().strip("[]()")
    if not ip_clean:
        return {
            "ip": ip_clean,
            "is_private": True,
            "country": "Unknown",
            "country_code": "UN",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "N/A",
            "asn_org": "Unknown",
            "isp": "Unknown",
            "framing": INFRASTRUCTURE_GEOLOCATION_FRAMING,
            "lookup_method": "None (Empty IP)"
        }

    # 1. Check RFC1918 / Private
    if is_private_ip(ip_clean):
        return {
            "ip": ip_clean,
            "is_private": True,
            "country": "Private Network",
            "country_code": "RFC1918",
            "region": "Internal Infrastructure",
            "city": "LAN / Subnet",
            "latitude": 0.0,
            "longitude": 0.0,
            "asn": "RFC1918",
            "asn_org": "Private / Internal Subnet",
            "isp": "Local Area Network",
            "framing": INFRASTRUCTURE_GEOLOCATION_FRAMING,
            "lookup_method": "RFC1918 Private Range Resolver"
        }

    # 2. Check In-Memory Cache
    now = time.time()
    if ip_clean in _LIVE_GEO_CACHE:
        cached = _LIVE_GEO_CACHE[ip_clean]
        if now - cached.get("_cached_at", 0) < GEO_CACHE_TTL:
            res = dict(cached)
            res.pop("_cached_at", None)
            return res

    # 3. Check Database Cache (`ip_intelligence` table)
    if db:
        try:
            db_rec = db.query(IPIntelligence).filter_by(ip_address=ip_clean).first()
            if db_rec:
                geo_dict = {
                    "ip": ip_clean,
                    "is_private": False,
                    "country": db_rec.country_code or "Unknown",
                    "country_code": db_rec.country_code or "UN",
                    "region": "Cached Region",
                    "city": db_rec.city or "Unknown",
                    "latitude": float(db_rec.latitude or 0.0),
                    "longitude": float(db_rec.longitude or 0.0),
                    "asn": db_rec.asn or "Unknown",
                    "asn_org": db_rec.isp or "Unknown",
                    "isp": db_rec.isp or "Unknown",
                    "abuse_score": float(db_rec.abuse_score or 0.0),
                    "is_vpn_tor": bool(db_rec.is_vpn_tor),
                    "framing": INFRASTRUCTURE_GEOLOCATION_FRAMING,
                    "lookup_method": "Database Cache (ip_intelligence table)"
                }
                _LIVE_GEO_CACHE[ip_clean] = {**geo_dict, "_cached_at": now}
                return geo_dict
        except Exception as e:
            logger.warning(f"Error querying ip_intelligence database cache: {e}")

    # 4. Local MaxMind GeoLite2 ASN & City Offline Lookups (Authoritative)
    mm_asn = maxmind_asn_service.lookup_asn(ip_clean)
    mm_city = maxmind_city_service.lookup_city(ip_clean)

    geo_data = {
        "ip": ip_clean,
        "is_private": False,
        "country": mm_city.get("country", "UNKNOWN") if mm_city.get("found") else "UNKNOWN",
        "country_code": mm_city.get("country_code", "UN") if mm_city.get("found") else "UN",
        "region": mm_city.get("region", "UNKNOWN") if mm_city.get("found") else "UNKNOWN",
        "city": mm_city.get("city", "UNKNOWN") if mm_city.get("found") else "UNKNOWN",
        "latitude": float(mm_city.get("latitude", 0.0)) if mm_city.get("found") else 0.0,
        "longitude": float(mm_city.get("longitude", 0.0)) if mm_city.get("found") else 0.0,
        "accuracy_radius_km": mm_city.get("accuracy_radius_km", 0) if mm_city.get("found") else 0,
        "asn": mm_asn.get("asn", "UNKNOWN") if mm_asn.get("found") else "UNKNOWN",
        "asn_org": mm_asn.get("asn_org", "UNKNOWN") if mm_asn.get("found") else "UNKNOWN",
        "isp": mm_asn.get("asn_org", "UNKNOWN") if mm_asn.get("found") else "UNKNOWN",
        "is_likely_hosting_asn": mm_asn.get("is_likely_hosting", False),
        "framing": INFRASTRUCTURE_GEOLOCATION_FRAMING,
        "lookup_method": "MaxMind GeoLite2 (local, offline)" if (mm_city.get("found") or mm_asn.get("found")) else "UNRESOLVED",
    }

    # 5. Only attempt ip-api.com if local MaxMind City data missed AND never block > 1.5s on it
    if not mm_city.get("found"):
        live = _try_live_lookup(ip_clean)
        if live:
            for k, v in live.items():
                if geo_data.get(k) in (None, "", "UNKNOWN", "UN", 0.0) and v not in (None, "", "UNKNOWN", "UN", 0.0):
                    geo_data[k] = v
            if geo_data["lookup_method"] == "UNRESOLVED":
                geo_data["lookup_method"] = "ip-api.com (live)"
            else:
                geo_data["lookup_method"] += " + ip-api.com (live enrichment)"

    # Store in memory cache
    _LIVE_GEO_CACHE[ip_clean] = {**geo_data, "_cached_at": now}

    # Store in Database `ip_intelligence` table
    if db:
        try:
            db_rec = db.query(IPIntelligence).filter_by(ip_address=ip_clean).first()
            if not db_rec:
                import uuid
                db_rec = IPIntelligence(
                    id=f"ip_{uuid.uuid4().hex[:12]}",
                    organization_id=organization_id,
                    ip_address=ip_clean,
                    country_code=geo_data["country_code"],
                    city=geo_data["city"],
                    latitude=geo_data["latitude"],
                    longitude=geo_data["longitude"],
                    asn=geo_data["asn"],
                    isp=geo_data["asn_org"] or geo_data["isp"],
                    abuse_score=0.0,
                    is_vpn_tor=False
                )
                db.add(db_rec)
                db.commit()
        except Exception as e:
            logger.warning(f"Error persisting to ip_intelligence table: {e}")
            db.rollback()

    return geo_data

    # Store in memory cache
    _LIVE_GEO_CACHE[ip_clean] = {**geo_data, "_cached_at": now}

    # Store in Database `ip_intelligence` table
    if db:
        try:
            db_rec = db.query(IPIntelligence).filter_by(ip_address=ip_clean).first()
            if not db_rec:
                import uuid
                db_rec = IPIntelligence(
                    id=f"ip_{uuid.uuid4().hex[:12]}",
                    organization_id=organization_id,
                    ip_address=ip_clean,
                    country_code=geo_data["country_code"],
                    city=geo_data["city"],
                    latitude=geo_data["latitude"],
                    longitude=geo_data["longitude"],
                    asn=geo_data["asn"],
                    isp=geo_data["asn_org"] or geo_data["isp"],
                    abuse_score=0.0,
                    is_vpn_tor=False
                )
                db.add(db_rec)
                db.commit()
        except Exception as e:
            logger.warning(f"Error persisting to ip_intelligence table: {e}")
            db.rollback()

    return geo_data


def analyze_email_origin(
    relay_nodes: List[Dict[str, Any]],
    recipient_domain: Optional[str] = None,
    db: Optional[Session] = None,
    organization_id: str = "org_default_01"
) -> Dict[str, Any]:
    """
    Executes end-to-end Origin Intelligence:
    1. Runs Trust Boundary analysis to obtain `earliest_reliable_node`.
    2. Extracts the true external originating IP.
    3. Performs real GeoIP & ASN lookup with explicit infrastructure framing.
    4. Classifies infrastructure (residential, hosting_cloud, VPN, TOR, open_relay, botnet_indicator, unknown).
    5. Persists and returns complete structured payload.
    """
    # 1. Trust Boundary Traversal
    tb_result = analyze_trust_boundary(relay_nodes, recipient_domain=recipient_domain)
    earliest_node = tb_result.get("earliest_reliable_node") or {}

    origin_ip = earliest_node.get("received_from_ip", "")
    origin_host = earliest_node.get("received_from_host", "")

    # Fallback to claimed origin if no earliest reliable node IP
    if not origin_ip and relay_nodes:
        origin_ip = relay_nodes[0].get("claimed_ip", "")
        origin_host = relay_nodes[0].get("claimed_hostname", "")

    # 2. Geolocation Lookup with Mandatory Infrastructure Geolocation Framing
    # Note: Explicitly framed as "infrastructure geolocation, not attacker physical location"
    geo_intel = perform_ip_geolocation_lookup(origin_ip, db=db, organization_id=organization_id)

    # 3. Infrastructure Classification
    infra_class = classify_infrastructure(
        ip_str=origin_ip,
        asn=geo_intel.get("asn", ""),
        asn_org=geo_intel.get("asn_org", ""),
        isp=geo_intel.get("isp", ""),
        hostname=origin_host,
        is_private=geo_intel.get("is_private", False)
    )

    # Update database record VPN/TOR status if applicable
    if db and geo_intel.get("is_private") is False and origin_ip:
        try:
            db_rec = db.query(IPIntelligence).filter_by(ip_address=origin_ip).first()
            if db_rec:
                db_rec.is_vpn_tor = bool(infra_class.get("is_vpn") or infra_class.get("is_tor"))
                db.commit()
        except Exception:
            db.rollback()

    # Compute explainable 'why' investigative assessments
    infra_why = explain_infrastructure(infra_class, origin_ip=origin_ip)
    infra_class["why"] = infra_why
    origin_why = explain_origin(
        origin_ip=origin_ip,
        origin_host=origin_host,
        geo_data=geo_intel,
        tb_data=tb_result,
        infra_data=infra_class
    )

    return {
        "status": "success",
        "origin_ip": origin_ip,
        "origin_hostname": origin_host,
        "why": origin_why,
        "framing": INFRASTRUCTURE_GEOLOCATION_FRAMING,
        "disclaimer": (
            "This analysis identifies infrastructure geolocation, not attacker physical location. "
            "Originating IPs and autonomous systems represent intermediate mail servers, cloud hosting providers, "
            "gateways, or VPN egress points rather than the threat actor's physical residence."
        ),
        "geolocation": geo_intel,
        "infrastructure_classification": infra_class,
        "trust_boundary": {
            "earliest_reliable_node": earliest_node,
            "trusted_hop_index": tb_result.get("trusted_hop_index"),
            "forgeable_hops_count": tb_result.get("forgeable_hops_count", 0),
            "boundary_caveat": FORGEABLE_HOP_CAVEAT
        },
        "database_stored": True
    }
