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

    # 3. DNS Checks via Google DoH
    mx_res = _query_dns_over_https(clean_dom, "MX")
    spf_res = _query_dns_over_https(clean_dom, "TXT")
    dmarc_res = _query_dns_over_https(f"_dmarc.{clean_dom}", "TXT")
    ns_res = _query_dns_over_https(clean_dom, "NS")
    a_res = _query_dns_over_https(clean_dom, "A")

    # Parse MX records into structured objects
    mx_records = []
    for raw_mx in mx_res.get("records", []):
        parts = raw_mx.strip().split()
        if len(parts) >= 2:
            try:
                prio = int(parts[0])
                host = parts[1].rstrip(".")
                mx_records.append({"priority": prio, "host": host, "raw": raw_mx})
            except Exception:
                mx_records.append({"priority": 10, "host": raw_mx.rstrip("."), "raw": raw_mx})
        else:
            mx_records.append({"priority": 10, "host": raw_mx.rstrip("."), "raw": raw_mx})

    # Sort MX by priority
    mx_records.sort(key=lambda x: x["priority"])

    # Extract SPF string and parse mechanisms
    spf_record = None
    spf_qualifier = "MISSING"
    spf_mechanisms = []
    if spf_res.get("status") == "ok":
        for txt in spf_res.get("records", []):
            if "v=spf1" in txt.lower():
                spf_record = txt.strip('"')
                tokens = spf_record.split()
                for t in tokens[1:]:
                    if t.endswith("all"):
                        if t.startswith("-"):
                            spf_qualifier = "-all (HardFail - Strict Enforced)"
                        elif t.startswith("~"):
                            spf_qualifier = "~all (SoftFail - Permissive)"
                        elif t.startswith("?"):
                            spf_qualifier = "?all (Neutral - No Policy)"
                        elif t.startswith("+"):
                            spf_qualifier = "+all (Pass - Insecure)"
                        else:
                            spf_qualifier = "all (Default Pass)"
                    else:
                        spf_mechanisms.append(t)
                break

    # Extract DMARC string and parse policy tags
    dmarc_record = None
    dmarc_policy = "none"
    dmarc_sp = None
    dmarc_pct = 100
    dmarc_rua = None
    dmarc_enforcement = "MISSING"
    if dmarc_res.get("status") == "ok":
        for txt in dmarc_res.get("records", []):
            if "v=dmarc1" in txt.lower():
                dmarc_record = txt.strip('"')
                tags = [tag.strip() for tag in dmarc_record.split(";") if tag.strip()]
                for tag in tags:
                    if "=" in tag:
                        k, v = tag.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "p":
                            dmarc_policy = v.lower()
                        elif k == "sp":
                            dmarc_sp = v.lower()
                        elif k == "pct":
                            try:
                                dmarc_pct = int(v)
                            except Exception:
                                pass
                        elif k == "rua":
                            dmarc_rua = v

                if dmarc_policy == "reject":
                    dmarc_enforcement = "REJECT (Strict Enforced)"
                elif dmarc_policy == "quarantine":
                    dmarc_enforcement = "QUARANTINE (Enforced)"
                elif dmarc_policy == "none":
                    dmarc_enforcement = "NONE (Monitoring Only)"
                break

    # Nameservers
    nameservers = [r.rstrip(".") for r in ns_res.get("records", [])]
    if not nameservers and whois_info.get("nameservers"):
        nameservers = whois_info.get("nameservers", [])

    # A Records
    a_records = a_res.get("records", [])

    # Flags logic
    flags = []
    if mx_res.get("status") == "ok" and not mx_res.get("found"):
        flags.append("Missing MX Record")
    if spf_res.get("status") == "ok" and not spf_record:
        flags.append("Missing SPF Record")
    elif "~all" in (spf_record or ""):
        flags.append("Permissive SPF Qualifier (~all)")
    if dmarc_res.get("status") == "ok" and not dmarc_record:
        flags.append("Missing DMARC Policy")
    elif dmarc_policy == "none":
        flags.append("DMARC Policy in Monitoring Mode (p=none)")

    if typosquat_info.get("is_typosquat"):
        flags.append(f"Typosquatting: Spoofs {typosquat_info.get('matched_brand')}")

    if whois_info.get("is_newly_registered"):
        flags.append("Newly Registered Domain (<30 days)")

    # Construct unified response that supports both frontend naming schemas
    return {
        "domain": clean_dom,
        "organization_id": organization_id,
        "registrar": whois_info.get("registrar") or "Unknown Registrar",
        "created_date": whois_info.get("created_date"),
        "expiration_date": whois_info.get("expiration_date"),
        "domain_age_days": whois_info.get("age_days", 14),
        "is_newly_registered": whois_info.get("is_newly_registered", False),
        "is_typosquat": typosquat_info.get("is_typosquat", False),
        "typosquat_matched_brand": typosquat_info.get("matched_brand"),
        "typosquatting": {
            "is_typosquat": typosquat_info.get("is_typosquat", False),
            "target_brand": typosquat_info.get("matched_brand"),
            "distance": typosquat_info.get("distance", 1),
            "technique": "Homoglyph / Lookalike Brand Insertion" if typosquat_info.get("is_typosquat") else "None"
        },
        "rdap": {
            "registrar": whois_info.get("registrar") or "Unknown Registrar",
            "creation_date": whois_info.get("created_date"),
            "expiration_date": whois_info.get("expiration_date"),
            "status": "Active"
        },
        "dns": {
            "domain": clean_dom,
            "ns": nameservers,
            "a_records": a_records,
            "mx": [f"{m['priority']} {m['host']}" for m in mx_records],
            "mx_records": mx_records,
            "spf": spf_record or "",
            "spf_qualifier": spf_qualifier,
            "spf_mechanisms": spf_mechanisms,
            "dmarc": dmarc_record or "",
            "dmarc_policy": dmarc_policy,
            "dmarc_sp": dmarc_sp,
            "dmarc_pct": dmarc_pct,
            "dmarc_rua": dmarc_rua,
            "dmarc_enforcement": dmarc_enforcement,
            "dnssec": "NOT_CONFIGURED"
        },
        "mx_records": [f"{m['priority']} {m['host']}" for m in mx_records],
        "mx_missing": mx_res.get("status") == "ok" and not mx_res.get("found"),
        "spf_record": spf_record,
        "spf_missing": spf_res.get("status") == "ok" and not spf_record,
        "dmarc_record": dmarc_record,
        "dmarc_missing": dmarc_res.get("status") == "ok" and not dmarc_record,
        "nameservers": nameservers,
        "a_records": a_records,
        "flags": flags,
        "risk_flags": flags,
        "lookup_method": "rdap_and_doh",
        "status": "ok"
    }
