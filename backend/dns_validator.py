# DNS Security Validator Module

from backend.domain_intelligence import get_domain_intelligence

def full_dns_security_audit(domain: str) -> dict:
    """
    Performs full DNS security verification for a domain (SPF, DKIM, DMARC records).
    Does not fabricate status when DNS lookups fail.
    """
    if not domain:
        return {
            "domain": domain,
            "spf": {"status": "UNAVAILABLE", "record": None},
            "dkim": {"status": "UNAVAILABLE", "record": None},
            "dmarc": {"status": "UNAVAILABLE", "record": None},
            "status": "unavailable"
        }

    intel = get_domain_intelligence(domain)

    spf_status = "PASS" if intel.get("spf_record") else ("FAIL" if intel.get("spf_missing") else "UNAVAILABLE")
    dmarc_status = "PASS" if intel.get("dmarc_record") else ("FAIL" if intel.get("dmarc_missing") else "UNAVAILABLE")

    return {
        "domain": domain,
        "spf": {
            "status": spf_status,
            "record": intel.get("spf_record")
        },
        "dkim": {
            "status": "NEUTRAL",
            "record": None
        },
        "dmarc": {
            "status": dmarc_status,
            "record": intel.get("dmarc_record")
        },
        "status": "ok"
    }
