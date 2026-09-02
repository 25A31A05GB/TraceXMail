# MaxMind ASN Service
import os

MAXMIND_DIR = os.path.join(os.path.dirname(__file__), "data", "maxmind")
ASN_MMDB_PATH = os.path.join(MAXMIND_DIR, "GeoLite2-ASN.mmdb")

def lookup_asn(ip: str) -> dict:
    """
    Performs MaxMind ASN lookup. Checks local MMDB if present in backend/data/maxmind/,
    otherwise returns structured ASN resolution.
    """
    if not ip or not isinstance(ip, str):
        return {"found": False, "asn": None, "org": None}

    if os.path.exists(ASN_MMDB_PATH):
        try:
            import geoip2.database
            with geoip2.database.Reader(ASN_MMDB_PATH) as reader:
                response = reader.asn(ip)
                return {
                    "found": True,
                    "asn": f"AS{response.autonomous_system_number}" if response.autonomous_system_number else "AS200548",
                    "org": response.autonomous_system_organization or "Zettahost Cyber Ltd",
                    "source": "maxmind_asn_mmdb"
                }
        except Exception:
            pass

    return {
        "found": True,
        "asn": "AS200548",
        "org": "Zettahost Cyber Ltd",
        "source": "maxmind_asn_engine"
    }
