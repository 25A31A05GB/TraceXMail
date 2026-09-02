# Threat Intelligence Integration Module

import os
import json
import urllib.request
import urllib.parse

_THREAT_INTEL_CACHE = {}

def query_abuseipdb_ip(ip: str, timeout_s: float = 3.0) -> dict:
    """
    Queries AbuseIPDB API v2 check endpoint.
    If API key is missing, returns status: 'unconfigured' with no fabricated data.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "ip": ip,
            "status": "unconfigured",
            "message": "AbuseIPDB API key not configured in environment",
            "abuse_confidence_score": None,
            "total_reports": None,
            "is_whitelisted": None,
            "usage_type": None,
            "lookup_method": "abuseipdb"
        }

    if not ip or not isinstance(ip, str):
        return {
            "ip": ip,
            "status": "error",
            "message": "Invalid IP address provided",
            "lookup_method": "abuseipdb"
        }

    cache_key = f"abuseipdb:{ip}"
    if cache_key in _THREAT_INTEL_CACHE:
        return _THREAT_INTEL_CACHE[cache_key]

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "TraceXMail-Forensics/2.1"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                data = body.get("data", {})
                res = {
                    "ip": ip,
                    "status": "ok",
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "total_reports": data.get("totalReports"),
                    "is_whitelisted": data.get("isWhitelisted"),
                    "usage_type": data.get("usageType"),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "lookup_method": "abuseipdb"
                }
                _THREAT_INTEL_CACHE[cache_key] = res
                return res
            else:
                return {
                    "ip": ip,
                    "status": "error",
                    "message": f"AbuseIPDB HTTP status {resp.status}",
                    "lookup_method": "abuseipdb"
                }
    except Exception as e:
        return {
            "ip": ip,
            "status": "error",
            "message": f"AbuseIPDB request failed: {str(e)}",
            "lookup_method": "abuseipdb"
        }


def query_virustotal_domain(domain: str, timeout_s: float = 3.0) -> dict:
    """
    Queries VirusTotal v3 domain report endpoint.
    If API key is missing, returns status: 'unconfigured' with no fabricated data.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "domain": domain,
            "status": "unconfigured",
            "message": "VirusTotal API key not configured in environment",
            "positives": None,
            "total": None,
            "reputation": None,
            "lookup_method": "virustotal"
        }

    if not domain or not isinstance(domain, str):
        return {
            "domain": domain,
            "status": "error",
            "message": "Invalid domain provided",
            "lookup_method": "virustotal"
        }

    cache_key = f"vt:{domain}"
    if cache_key in _THREAT_INTEL_CACHE:
        return _THREAT_INTEL_CACHE[cache_key]

    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": "TraceXMail-Forensics/2.1"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                attributes = body.get("data", {}).get("attributes", {})
                analysis_stats = attributes.get("last_analysis_stats", {})

                malicious = analysis_stats.get("malicious", 0)
                suspicious = analysis_stats.get("suspicious", 0)
                harmless = analysis_stats.get("harmless", 0)
                undetected = analysis_stats.get("undetected", 0)

                positives = malicious + suspicious
                total = malicious + suspicious + harmless + undetected

                res = {
                    "domain": domain,
                    "status": "ok",
                    "positives": positives,
                    "total": total,
                    "reputation": attributes.get("reputation"),
                    "categories": attributes.get("categories", {}),
                    "lookup_method": "virustotal"
                }
                _THREAT_INTEL_CACHE[cache_key] = res
                return res
            else:
                return {
                    "domain": domain,
                    "status": "error",
                    "message": f"VirusTotal HTTP status {resp.status}",
                    "lookup_method": "virustotal"
                }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "message": f"VirusTotal request failed: {str(e)}",
            "lookup_method": "virustotal"
        }


def get_threat_intelligence_for_email(origin_ip: str = None, domains: list = None) -> dict:
    """
    Aggregates threat intelligence across origin IP and associated email domains.
    """
    ip_threat = None
    if origin_ip:
        ip_threat = query_abuseipdb_ip(origin_ip)

    domain_threats = []
    if domains:
        for dom in domains:
            if dom:
                vt_res = query_virustotal_domain(dom)
                domain_threats.append(vt_res)

    return {
        "origin_ip_threat": ip_threat,
        "domain_threats": domain_threats,
        "status": "ok"
    }
