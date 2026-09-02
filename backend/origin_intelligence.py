# Origin Intelligence Analysis Module

import urllib.request
import json
import ipaddress
from backend.maxmind_asn_service import lookup_asn
from backend.maxmind_city_service import lookup_city
from backend.infra_classifier import classify_infrastructure
from backend.trust_boundary import analyze_trust_boundary
from backend.explain import explain_origin, explain_infrastructure
from backend.forensics.reverse_dns import reverse_dns_lookup

def get_private_ip_metadata(ip: str) -> tuple[bool, bool, str, str, str]:
    """
    Evaluates if an IP is private/RFC 1918, returning:
    (is_private, is_rfc1918, subnet_type, cidr, description)
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            parts = str(ip_obj).split('.')
            p0 = int(parts[0]) if len(parts) == 4 else None
            p1 = int(parts[1]) if len(parts) == 4 else None

            if p0 == 10:
                return True, True, "RFC 1918 Class A", "10.0.0.0/8", "Enterprise Intranet / Datacenter LAN (Non-routable over public internet)"
            if p0 == 172 and p1 and 16 <= p1 <= 31:
                return True, True, "RFC 1918 Class B", "172.16.0.0/12", "Corporate Internal DMZ / Virtual Private Cloud (Non-routable over public internet)"
            if p0 == 192 and p1 == 168:
                return True, True, "RFC 1918 Class C", "192.168.0.0/16", "Local Area Network (LAN) / Office Subnet (Non-routable over public internet)"
            if ip_obj.is_loopback:
                return True, False, "Loopback Interface", "127.0.0.0/8", "Localhost / Internal System Mailer Loopback"
            if ip_obj.is_link_local:
                return True, False, "Link-Local APIPA", "169.254.0.0/16", "Automatic Private IP Addressing (APIPA) Link-Local"
            return True, True, "Private Network", "Private/Special", "Non-routable internal address space"
    except Exception:
        pass
    return False, False, "Public Internet", "Public IPv4", "Public routable internet IP"


def perform_ip_geolocation_lookup(ip: str, timeout_s: float = 1.5) -> dict:
    """
    Geolocates IP using local MaxMind databases with fallback to ip-api.com.
    Accurately classifies RFC 1918 private subnets without inventing coordinates.
    """
    if not ip or not isinstance(ip, str):
        return {
            "ip": ip,
            "found": False,
            "is_private": False,
            "is_rfc1918": False,
            "subnet_type": "None",
            "cidr": "N/A",
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

    # 1. Check for RFC 1918 or private network address
    is_priv, is_rfc, subnet_type, cidr, subnet_desc = get_private_ip_metadata(ip)
    if is_priv:
        return {
            "ip": ip,
            "found": False,
            "is_private": True,
            "is_rfc1918": is_rfc,
            "subnet_type": subnet_type,
            "cidr": cidr,
            "description": subnet_desc,
            "scope": "NON_ROUTABLE_INTERNAL",
            "country": "Private Network (RFC 1918)",
            "country_code": "LAN",
            "region": "Internal Subnet",
            "city": "Internal Relay",
            "latitude": None,
            "longitude": None,
            "asn": "RFC 1918",
            "asn_org": "Private / Internal Network",
            "isp": "Corporate Intranet",
            "lookup_method": "rfc1918_subnet_classifier",
            "status": "internal_private"
        }

    # 2. Query ASN service
    asn_res = lookup_asn(ip)
    asn = asn_res.get("asn")
    asn_org = asn_res.get("org")
    isp = None

    # 3. Query City service
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

    # Fallback to ip-api.com if city not found by MaxMind and IP is public
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
        "is_private": False,
        "is_rfc1918": False,
        "subnet_type": subnet_type,
        "cidr": cidr,
        "description": subnet_desc,
        "scope": "PUBLIC_INTERNET",
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
    Handles RFC 1918 private subnets cleanly.
    """
    geo_data = perform_ip_geolocation_lookup(ip)
    ptr_data = reverse_dns_lookup(ip)
    is_priv = geo_data.get("is_private", False)

    infra_data = classify_infrastructure(
        ip_str=ip,
        asn=geo_data.get("asn"),
        asn_org=geo_data.get("asn_org"),
        isp=geo_data.get("isp"),
        hostname=ptr_data.get("ptr_record"),
        is_private=is_priv
    )

    tb_data = analyze_trust_boundary(relay_nodes or [], recipient_domain=recipient_domain)
    
    if is_priv:
        origin_narrative = (
            f"The analyzed IP {ip} resides in the {geo_data.get('subnet_type')} private subnet ({geo_data.get('cidr')}). "
            f"It represents an internal non-routable intranet hop (client submission, corporate mail routing agent, or DMZ gateway). "
            f"Public geolocation coordinates and internet route telemetry do not apply to RFC 1918 address space."
        )
    else:
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
        "reputation_score": 0 if is_priv else (88 if infra_data.get("is_tor") or infra_data.get("is_vpn") else 10),
        "status": "ok"
    }
