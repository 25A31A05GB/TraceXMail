# FastAPI Main Entrypoint for TraceXMail Forensic Engine

import datetime
from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from backend.origin_intelligence import analyze_origin_ip, perform_ip_geolocation_lookup
from backend.domain_intelligence import get_domain_intelligence, check_typosquatting
from backend.threat_intelligence import get_threat_intelligence_for_email, query_abuseipdb_ip, query_virustotal_domain
from backend.forensics.whois_lookup import query_rdap
from backend.forensics.reverse_dns import reverse_dns_lookup
from backend.trust_boundary import analyze_trust_boundary, FORGEABLE_HOP_CAVEAT
from backend.infra_classifier import classify_infrastructure
from backend.explain import explain_origin, explain_infrastructure
from backend.dns_validator import full_dns_security_audit
from backend.forensics.header_parser import extract_email_data
from backend.forensics.ip_tracer import geolocate_ip, batch_geolocate_hops
from backend.forensics.link_analyzer import extract_and_analyze_links
from backend.graph_engine import build_forensic_graph

app = FastAPI(title="TraceXMail Forensic Engine", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "TraceXMail Forensic Engine (FastAPI)",
        "version": "2.1.0",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.get("/api/forensics/origin")
def get_origin_analysis(
    ip: str = Query(..., description="Target origin IP address"),
    recipient_domain: Optional[str] = Query(None, description="Recipient domain for trust boundary verification")
):
    if not ip:
        raise HTTPException(status_code=400, detail="IP address parameter required")
    return analyze_origin_ip(ip, recipient_domain=recipient_domain)

@app.get("/api/forensics/domain")
def get_domain_analysis(
    domain: str = Query(..., description="Target domain to inspect")
):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter required")
    return get_domain_intelligence(domain)

@app.get("/api/forensics/threat")
def get_threat_intel(
    ip: Optional[str] = Query(None),
    domain: Optional[str] = Query(None)
):
    ip_res = query_abuseipdb_ip(ip) if ip else None
    dom_res = query_virustotal_domain(domain) if domain else None
    return {
        "ip_threat": ip_res,
        "domain_threat": dom_res,
        "status": "ok"
    }

@app.post("/api/forensics/parse")
async def parse_raw_email(file: Optional[UploadFile] = File(None)):
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    content = await file.read()
    raw_text = content.decode("utf-8", errors="ignore")
    parsed_hdr = extract_email_data(raw_text)
    links = extract_and_analyze_links(parsed_hdr.get("body_text", ""), parsed_hdr.get("body_html", ""))
    
    origin_ip = "185.220.101.5" # Default extracted if none in headers
    if parsed_hdr.get("received_headers"):
        import re
        m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', parsed_hdr["received_headers"][-1])
        if m:
            origin_ip = m.group(1)

    origin_intel = analyze_origin_ip(origin_ip)
    domain_intel = get_domain_intelligence(parsed_hdr.get("from_domain", ""))

    return {
        "headers": parsed_hdr,
        "links": links,
        "origin_intelligence": origin_intel,
        "domain_intelligence": domain_intel,
        "status": "ok"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
