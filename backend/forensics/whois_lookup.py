# RDAP / WHOIS Lookup Module

import urllib.request
import json
import datetime
import urllib.parse

_RDAP_CACHE = {}

def query_rdap(domain: str, timeout_s: float = 3.0) -> dict:
    """
    Queries real RDAP endpoint for domain registration details.
    Does not fabricate data on failure.
    """
    if not domain or not isinstance(domain, str):
        return {
            "domain": domain,
            "found": False,
            "registrar": None,
            "created_date": None,
            "expiration_date": None,
            "age_days": None,
            "is_newly_registered": False,
            "nameservers": [],
            "status": [],
            "lookup_method": "rdap",
            "error": "Invalid or empty domain provided"
        }

    clean_domain = domain.strip().lower()
    if clean_domain in _RDAP_CACHE:
        return _RDAP_CACHE[clean_domain]

    rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(clean_domain)}"

    try:
        req = urllib.request.Request(rdap_url, headers={"User-Agent": "TraceXMail-Forensics/2.1", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                res = {
                    "domain": clean_domain,
                    "found": False,
                    "registrar": None,
                    "created_date": None,
                    "expiration_date": None,
                    "age_days": None,
                    "is_newly_registered": False,
                    "nameservers": [],
                    "status": [],
                    "lookup_method": "rdap",
                    "error": f"RDAP endpoint returned HTTP status {resp.status}"
                }
                return res

            data = json.loads(resp.read().decode("utf-8"))

            # Parse registrar entity
            registrar = None
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard_array = entity.get("vcardArray", [])
                    if len(vcard_array) > 1:
                        for entry in vcard_array[1]:
                            if entry[0] == "fn":
                                registrar = entry[3]
                                break

            # Parse events (registration / expiration)
            created_date_str = None
            expiration_date_str = None
            events = data.get("events", [])
            for evt in events:
                action = evt.get("eventAction")
                date_val = evt.get("eventDate")
                if action in ("registration", "created"):
                    created_date_str = date_val
                elif action in ("expiration", "expired"):
                    expiration_date_str = date_val

            # Compute age
            age_days = None
            is_newly_registered = False
            if created_date_str:
                try:
                    # Clean ISO format e.g. 2023-10-15T12:00:00Z
                    iso_clean = created_date_str.replace("Z", "+00:00")
                    dt_created = datetime.datetime.fromisoformat(iso_clean)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    age_days = (now - dt_created).days
                    if age_days >= 0:
                        is_newly_registered = (age_days < 30)
                except Exception:
                    pass

            # Parse nameservers
            nameservers = []
            ns_list = data.get("nameservers", [])
            for ns in ns_list:
                ldh_name = ns.get("ldhName")
                if ldh_name:
                    nameservers.append(ldh_name)

            statuses = data.get("status", [])

            result = {
                "domain": clean_domain,
                "found": True,
                "registrar": registrar,
                "created_date": created_date_str,
                "expiration_date": expiration_date_str,
                "age_days": age_days,
                "is_newly_registered": is_newly_registered,
                "nameservers": nameservers,
                "status": statuses,
                "lookup_method": "rdap",
                "error": None
            }

            _RDAP_CACHE[clean_domain] = result
            return result

    except Exception as e:
        res = {
            "domain": clean_domain,
            "found": False,
            "registrar": None,
            "created_date": None,
            "expiration_date": None,
            "age_days": None,
            "is_newly_registered": False,
            "nameservers": [],
            "status": [],
            "lookup_method": "rdap",
            "error": f"RDAP query failed: {str(e)}"
        }
        return res
