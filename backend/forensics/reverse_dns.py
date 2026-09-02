# Reverse DNS PTR Lookup Module

import socket

def reverse_dns_lookup(ip: str, timeout_s: float = 1.5) -> dict:
    """
    Performs authentic Reverse DNS (PTR) lookup for an IP address.
    Does not fabricate hostnames if PTR record does not exist or lookup fails.
    """
    if not ip or not isinstance(ip, str):
        return {
            "ip": ip,
            "found": False,
            "ptr_record": None,
            "error": "Invalid IP address",
            "lookup_method": "ptr"
        }

    try:
        socket.setdefaulttimeout(timeout_s)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {
            "ip": ip,
            "found": True,
            "ptr_record": hostname,
            "error": None,
            "lookup_method": "ptr"
        }
    except (socket.herror, socket.gaierror, socket.timeout, OSError) as e:
        return {
            "ip": ip,
            "found": False,
            "ptr_record": None,
            "error": str(e),
            "lookup_method": "ptr"
        }
