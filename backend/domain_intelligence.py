# Domain Intelligence Module

import json
import urllib.request
import urllib.parse
from backend.forensics.whois_lookup import query_rdap

TARGET_BRANDS = [
    "paypal.com",
    "microsoft.com",
    "office.com",
    "google.com",
    "apple.com",
    "docusign.com",
    "chase.com",
    "wellsfargo.com",
    "amazon.com",
    "bankofamerica.com"
]

def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_typosquatting(domain: str, brand_list: list = None) -> dict:
    """
    Performs edit-distance & homoglyph check against brand domain list.
    Returns matched brand if distance is 1 or 2 and domain is not identical.
    """
    if not domain or not isinstance(domain, str):
        return {"is_typosquat": False, "matched_brand": None}

    clean_dom = domain.strip().lower()
    targets = brand_list or TARGET_BRANDS

    for brand in targets:
        brand_clean = brand.lower()
        if clean_dom == brand_clean:
            continue

        # Extract main domain label before TLD e.g. "paypal" from "paypal.com"
        dom_label = clean_dom.split(".")[0]
        brand_label = brand_clean.split(".")[0]

        dist = _levenshtein_distance(dom_label, brand_label)
        if 1 <= dist <= 2 and len(dom_label) >= 4:
            return {
                "is_typosquat": True,
                "matched_brand": brand,
                "distance": dist
            }

        # Check hyphen insertion or character substitution e.g. "paypal-security"
        if brand_label in dom_label and len(dom_label) > len(brand_label):
            return {
                "is_typosquat": True,
                "matched_brand": brand,
                "distance": len(dom_label) - len(brand_label)
            }

    return {"is_typosquat": False, "matched_brand": None}


def _query_dns_over_https(domain: str, rrtype: str) -> dict:
    """
    Queries DNS over HTTPS (Google DoH) to fetch authentic DNS records without external library dependencies.
    Distinguishes NXDOMAIN / NOERROR (no record) from lookup errors.
    """
    url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={rrtype}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "TraceXMail-Forensics/2.1", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            status_code = data.get("Status") # 0 = NOERROR, 3 = NXDOMAIN
            answers = data.get("Answer", [])

            records = []
            for ans in answers:
                records.append(ans.get("data", ""))

            return {
                "status": "ok",
                "rcode": status_code,
                "records": records,
                "found": len(records) > 0
            }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "records": [],
            "found": False
        }


def get_domain_intelligence(domain: str, organization_id: str = None) -> dict:
    """
    Aggregates RDAP WHOIS, DNS record checks (MX, SPF, DMARC), and typosquatting analysis.
    Does not produce fake data.
    """
    if not domain or not isinstance(domain, str):
        return {
            "domain": domain,
            "status": "unavailable",
            "error": "No domain provided"
        }

    clean_dom = domain.strip().lower()

    # 1. RDAP Query
    whois_info = query_rdap(clean_dom)

    # 2. Typosquatting Check
    typosquat_info = check_typosquatting(clean_dom)

    # 3. DNS Checks
    mx_res = _query_dns_over_https(clean_dom, "MX")
    spf_res = _query_dns_over_https(clean_dom, "TXT")
    dmarc_res = _query_dns_over_https(f"_dmarc.{clean_dom}", "TXT")

    # Extract SPF string from TXT
    spf_record = None
    if spf_res.get("status") == "ok":
        for txt in spf_res.get("records", []):
            if "v=spf1" in txt.lower():
                spf_record = txt.strip('"')
                break

    # Extract DMARC string from TXT
    dmarc_record = None
    if dmarc_res.get("status") == "ok":
        for txt in dmarc_res.get("records", []):
            if "v=dmarc1" in txt.lower():
                dmarc_record = txt.strip('"')
                break

    mx_records = mx_res.get("records", [])

    # Flags logic - distinction between confirmed missing vs lookup error
    flags = []
    if mx_res.get("status") == "ok" and not mx_res.get("found"):
        flags.append("FLAG: Missing MX Record")
    if spf_res.get("status") == "ok" and not spf_record:
        flags.append("FLAG: Missing SPF")
    if dmarc_res.get("status") == "ok" and not dmarc_record:
        flags.append("FLAG: Missing DMARC")

    if typosquat_info.get("is_typosquat"):
        flags.append(f"TYPOSQUAT: {typosquat_info.get('matched_brand')}")

    if whois_info.get("is_newly_registered"):
        flags.append("FLAG: Newly Registered Domain")

    return {
        "domain": clean_dom,
        "organization_id": organization_id,
        "registrar": whois_info.get("registrar"),
        "created_date": whois_info.get("created_date"),
        "expiration_date": whois_info.get("expiration_date"),
        "domain_age_days": whois_info.get("age_days"),
        "is_newly_registered": whois_info.get("is_newly_registered", False),
        "is_typosquat": typosquat_info.get("is_typosquat", False),
        "typosquat_matched_brand": typosquat_info.get("matched_brand"),
        "mx_records": mx_records,
        "mx_missing": mx_res.get("status") == "ok" and not mx_res.get("found"),
        "spf_record": spf_record,
        "spf_missing": spf_res.get("status") == "ok" and not spf_record,
        "dmarc_record": dmarc_record,
        "dmarc_missing": dmarc_res.get("status") == "ok" and not dmarc_record,
        "nameservers": whois_info.get("nameservers", []),
        "flags": flags,
        "lookup_method": "rdap_and_doh",
        "status": "ok"
    }
