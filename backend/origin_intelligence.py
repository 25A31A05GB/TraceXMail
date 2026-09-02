# Origin Intelligence Analysis Module

import urllib.request
import json
from backend.maxmind_asn_service import lookup_asn
from backend.maxmind_city_service import lookup_city
from backend.infra_classifier import classify_infrastructure
from backend.trust_boundary import analyze_trust_boundary
from backend.explain import explain_origin, explain_infrastructure
from backend.forensics.reverse_dns import reverse_dns_lookup

def perform_ip_geolocation_lookup(ip: str, timeout_s: float = 1.5) -> dict:
    """
    Geolocates IP using local MaxMind databases with fallback to ip-api.com.
    Returns explicit 'found: false' / unavailable states when data is absent.
    """
    if not ip or not isinstance(ip, str):
        return {
            "ip": ip,
            "found": False,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "asn_org": None,
            "isp": None,
            "lookup_method": "none",
            "status": "unavailable"
        }

    # 1. Query ASN service
    asn_res = lookup_asn(ip)
    asn = asn_res.get("asn")
    asn_org = asn_res.get("org")

    # 2. Query City service
    city_res = lookup_city(ip)
    city_found = city_res.get("found", False)
    country = city_res.get("country")
    country_code = city_res.get("countryCode")
    city = city_res.get("city")
    region = city_res.get("region")
    lat = city_res.get("lat")
    lng = city_res.get("lng")

    lookup_method = "maxmind"
    status = "ok" if (city_found or asn) else "unavailable"

    # Fallback to ip-api.com if city not found by MaxMind
    if not city_found:
        try:
            req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as", headers={"User-Agent": "TraceXMail-Forensics/2.1"})
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    country = data.get("country")
                    country_code = data.get("countryCode")
                    region = data.get("regionName")
                    city = data.get("city")
                    lat = data.get("lat")
                    lng = data.get("lon")
                    isp = data.get("isp")
                    if not asn_org:
                        asn_org = data.get("org")
                    if not asn:
                        asn = data.get("as")
                    city_found = True
                    lookup_method = "ip-api_fallback"
                    status = "ok"
        except Exception:
            pass

    return {
        "ip": ip,
        "found": city_found,
        "country": country,
        "country_code": country_code,
        "region": region,
        "city": city,
        "latitude": lat,
        "longitude": lng,
        "asn": asn,
        "asn_org": asn_org,
        "isp": isp or asn_org,
        "lookup_method": lookup_method,
        "status": status
    }


def analyze_origin_ip(ip: str, relay_nodes: list = None, recipient_domain: str = None) -> dict:
    """
    Comprehensive origin intelligence aggregation: Geo-IP, PTR reverse DNS,
    Infrastructure Classification, Trust Boundary Analysis, and Narrative Explanation.
    """
    geo_data = perform_ip_geolocation_lookup(ip)
    ptr_data = reverse_dns_lookup(ip)

    infra_data = classify_infrastructure(
        ip_str=ip,
        asn=geo_data.get("asn"),
        asn_org=geo_data.get("asn_org"),
        isp=geo_data.get("isp"),
        hostname=ptr_data.get("ptr_record"),
        is_private=False
    )

    tb_data = analyze_trust_boundary(relay_nodes or [], recipient_domain=recipient_domain)
    origin_narrative = explain_origin(geo_data, tb_data)
    infra_narrative = explain_infrastructure(infra_data)

    return {
        "ip": ip,
        "geo": geo_data,
        "ptr": ptr_data,
        "infrastructure": infra_data,
        "trust_boundary": tb_data,
        "narratives": {
            "origin": origin_narrative,
            "infrastructure": infra_narrative
        },
        "reputation_score": 88 if infra_data.get("is_tor") or infra_data.get("is_vpn") else 10,
        "status": "ok"
    }
