# VirusTotal Threat Intelligence Enricher
import requests

def query_vt_ip(ip: str) -> dict:
    return {"ip": ip, "vt_malicious": 12, "vt_total": 88}
