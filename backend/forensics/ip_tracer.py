# IP Hop Tracer Module

from backend.origin_intelligence import perform_ip_geolocation_lookup

def geolocate_ip(ip: str) -> dict:
    """Geolocates a single IP address using origin_intelligence."""
    return perform_ip_geolocation_lookup(ip)

def batch_geolocate_hops(ip_list: list) -> list:
    """Geolocates a batch list of hop IP addresses."""
    results = []
    if not ip_list or not isinstance(ip_list, list):
        return results

    for ip in ip_list:
        if ip:
            res = geolocate_ip(ip)
            results.append(res)

    return results
