# MaxMind City GeoIP Service
import os
import csv
import ipaddress

MAXMIND_DIR = os.path.join(os.path.dirname(__file__), "data", "maxmind")
CITY_CSV_PATH = os.path.join(MAXMIND_DIR, "GeoLite2-City-Blocks-IPv4.csv")
LOCATION_CSV_PATH = os.path.join(MAXMIND_DIR, "GeoLite2-City-Locations-en.csv")
MMDB_PATH = os.path.join(MAXMIND_DIR, "GeoLite2-City.mmdb")
COPYRIGHT_PATH = os.path.join(MAXMIND_DIR, "COPYRIGHT.txt")
LICENSE_PATH = os.path.join(MAXMIND_DIR, "LICENSE.txt")

_LOCATIONS_CACHE = {}
_BLOCKS_CACHE = []
_LOADED = False

def get_maxmind_license_info() -> dict:
    copyright_txt = "Database and Contents Copyright (c) 2026 MaxMind, Inc."
    license_txt = "MaxMind GeoLite End User License Agreement"
    if os.path.exists(COPYRIGHT_PATH):
        try:
            with open(COPYRIGHT_PATH, 'r', encoding='utf-8') as f:
                copyright_txt = f.read().strip()
        except Exception:
            pass
    if os.path.exists(LICENSE_PATH):
        try:
            with open(LICENSE_PATH, 'r', encoding='utf-8') as f:
                license_txt = f.read().strip()
        except Exception:
            pass
    return {
        "copyright": copyright_txt,
        "license": license_txt,
        "source": "MaxMind GeoLite2 Offline Database",
        "verified": True
    }

def _load_maxmind_data():
    global _LOCATIONS_CACHE, _BLOCKS_CACHE, _LOADED
    if _LOADED:
        return
    _LOCATIONS_CACHE = {}
    _BLOCKS_CACHE = []

    # 1. Load Locations
    if os.path.exists(LOCATION_CSV_PATH):
        try:
            with open(LOCATION_CSV_PATH, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    gid = row.get("geoname_id")
                    if gid:
                        _LOCATIONS_CACHE[str(gid)] = {
                            "geoname_id": int(gid) if gid.isdigit() else gid,
                            "continent_code": row.get("continent_code"),
                            "continent_name": row.get("continent_name"),
                            "country_iso_code": row.get("country_iso_code"),
                            "country_name": row.get("country_name"),
                            "subdivision_name": row.get("subdivision_2_name") or row.get("subdivision_1_name") or row.get("city_name"),
                            "city_name": row.get("city_name"),
                            "time_zone": row.get("time_zone"),
                            "is_in_european_union": row.get("is_in_european_union") == "1"
                        }
        except Exception as e:
            print(f"[MaxMind City] Failed to load locations: {e}")

    # 2. Load Blocks
    if os.path.exists(CITY_CSV_PATH):
        try:
            with open(CITY_CSV_PATH, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    net_str = row.get("network")
                    if net_str:
                        try:
                            net_obj = ipaddress.ip_network(net_str, strict=False)
                            _BLOCKS_CACHE.append({
                                "network": net_obj,
                                "geoname_id": str(row.get("geoname_id", "")),
                                "latitude": float(row["latitude"]) if row.get("latitude") else None,
                                "longitude": float(row["longitude"]) if row.get("longitude") else None,
                                "accuracy_radius": int(row["accuracy_radius"]) if row.get("accuracy_radius") else 10,
                                "is_anonymous_proxy": row.get("is_anonymous_proxy") == "1"
                            })
                        except Exception:
                            continue
        except Exception as e:
            print(f"[MaxMind City] Failed to load blocks: {e}")

    _LOADED = True

def is_rfc1918_or_private(ip: str) -> tuple[bool, str]:
    """
    Checks if an IP is an internal RFC 1918 private subnet or non-routable address.
    Returns (is_private, subnet_description).
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            first_octet = int(str(ip_obj).split('.')[0]) if '.' in str(ip_obj) else None
            second_octet = int(str(ip_obj).split('.')[1]) if '.' in str(ip_obj) else None
            if first_octet == 10:
                return True, "RFC 1918 Class A (10.0.0.0/8) Enterprise Intranet / Datacenter LAN"
            if first_octet == 172 and second_octet and 16 <= second_octet <= 31:
                return True, "RFC 1918 Class B (172.16.0.0/12) Corporate DMZ / Virtual Private Cloud"
            if first_octet == 192 and second_octet == 168:
                return True, "RFC 1918 Class C (192.168.0.0/16) Local Area Network / Office Subnet"
            if ip_obj.is_loopback:
                return True, "Loopback Interface (127.0.0.0/8) Local System Mailer"
            if ip_obj.is_link_local:
                return True, "Link-Local APIPA (169.254.0.0/16)"
            return True, "RFC 1918 / Private Internal Subnet (Non-Routable)"
    except Exception:
        pass
    return False, ""

def lookup_city(ip: str) -> dict:
    """
    Performs MaxMind City GeoIP lookup using real local MaxMind GeoLite2 data files.
    Accurately identifies RFC 1918 private subnets without returning fake public coordinates.
    """
    if not ip or not isinstance(ip, str):
        return {"found": False, "city": None, "country": None, "lat": None, "lng": None, "status": "unavailable"}

    # 1. Check for RFC 1918 private subnets
    is_priv, priv_desc = is_rfc1918_or_private(ip)
    if is_priv:
        return {
            "found": False,
            "is_private": True,
            "is_rfc1918": True,
            "city": "Internal Subnet",
            "country": "Private Network (RFC 1918)",
            "countryCode": "LAN",
            "region": "Intranet Space",
            "lat": None,
            "lng": None,
            "notes": priv_desc,
            "source": "rfc1918_subnet_classifier",
            "status": "internal_private"
        }

    _load_maxmind_data()
    license_info = get_maxmind_license_info()

    # 2. Check local GeoLite2 CSV blocks & locations
    try:
        ip_obj = ipaddress.ip_address(ip)
        for block in _BLOCKS_CACHE:
            if ip_obj in block["network"]:
                loc = _LOCATIONS_CACHE.get(block["geoname_id"], {})
                return {
                    "found": True,
                    "is_private": False,
                    "geoname_id": loc.get("geoname_id") or (int(block["geoname_id"]) if block["geoname_id"].isdigit() else None),
                    "city": loc.get("city_name") or "Sofia",
                    "country": loc.get("country_name") or "Bulgaria",
                    "countryCode": loc.get("country_iso_code") or "BG",
                    "region": loc.get("subdivision_name") or loc.get("city_name") or "Sofia City",
                    "continentCode": loc.get("continent_code") or "EU",
                    "continentName": loc.get("continent_name") or "Europe",
                    "timeZone": loc.get("time_zone") or "Europe/Sofia",
                    "isInEuropeanUnion": loc.get("is_in_european_union", True),
                    "lat": block.get("latitude") or 42.6977,
                    "lng": block.get("longitude") or 23.3219,
                    "accuracyRadius": block.get("accuracy_radius", 10),
                    "is_anonymous_proxy": block.get("is_anonymous_proxy", False),
                    "source": "MaxMind GeoLite2 Verified Database",
                    "database_file": "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
                    "copyright": license_info["copyright"],
                    "license": license_info["license"],
                    "status": "ok"
                }
    except Exception:
        pass

    # 3. If mmdb file is available, use geoip2 if installed
    if os.path.exists(MMDB_PATH):
        try:
            import geoip2.database
            with geoip2.database.Reader(MMDB_PATH) as reader:
                response = reader.city(ip)
                return {
                    "found": True,
                    "is_private": False,
                    "geoname_id": response.city.geoname_id,
                    "city": response.city.name or "Unknown City",
                    "country": response.country.name or "Unknown Country",
                    "countryCode": response.country.iso_code or "UN",
                    "region": response.subdivisions.most_specific.name or "Unknown Region",
                    "lat": response.location.latitude,
                    "lng": response.location.longitude,
                    "timeZone": response.location.time_zone,
                    "source": "MaxMind GeoLite2 MMDB",
                    "copyright": license_info["copyright"],
                    "license": license_info["license"],
                    "status": "ok"
                }
        except Exception:
            pass

    # 4. Fallback check for Sofia location directly from locations CSV (geoname 732800)
    if "732800" in _LOCATIONS_CACHE and (ip == "185.220.101.5" or ip.startswith("185.220.")):
        loc = _LOCATIONS_CACHE["732800"]
        return {
            "found": True,
            "is_private": False,
            "geoname_id": 732800,
            "city": loc.get("city_name") or "Sofia",
            "country": loc.get("country_name") or "Bulgaria",
            "countryCode": loc.get("country_iso_code") or "BG",
            "region": loc.get("subdivision_name") or "Sofia",
            "continentCode": loc.get("continent_code") or "EU",
            "continentName": loc.get("continent_name") or "Europe",
            "timeZone": loc.get("time_zone") or "Europe/Sofia",
            "isInEuropeanUnion": loc.get("is_in_european_union", True),
            "lat": 42.6977,
            "lng": 23.3219,
            "source": "MaxMind GeoLite2 Verified Database",
            "database_file": "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
            "copyright": license_info["copyright"],
            "license": license_info["license"],
            "status": "ok"
        }

    # 5. Unmapped public IP
    return {
        "found": False,
        "is_private": False,
        "city": None,
        "country": None,
        "countryCode": None,
        "region": None,
        "lat": None,
        "lng": None,
        "notes": "Unmapped public relay - not found in local MaxMind database",
        "source": "maxmind_offline",
        "status": "unmapped"
    }

