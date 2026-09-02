# Investigative Narrative Generator

def explain_origin(geo_data: dict, trust_boundary_data: dict = None) -> dict:
    """
    Generates a human-readable investigative narrative strictly from real geo and trust boundary inputs.
    No invented facts or hardcoded claims.
    """
    ip = geo_data.get("ip") or "Unknown IP"
    country = geo_data.get("country") or geo_data.get("country_code") or "Unknown Country"
    city = geo_data.get("city") or "Unknown City"
    asn = geo_data.get("asn") or "Unknown ASN"
    asn_org = geo_data.get("asn_org") or geo_data.get("org") or "Unknown Org"

    sentences = []
    
    if geo_data.get("found"):
        sentences.append(f"Origin IP {ip} is located in {city}, {country} within network {asn} ({asn_org}).")
    else:
        sentences.append(f"Origin IP {ip} could not be resolved to a known geographic location.")

    if trust_boundary_data and trust_boundary_data.get("trust_boundary_found"):
        reliable = trust_boundary_data.get("earliest_reliable_node") or {}
        hop_num = reliable.get("hop_number")
        recv_ip = reliable.get("received_from_ip")
        if recv_ip:
            sentences.append(f"Trust boundary established at hop {hop_num} receiving from {recv_ip}.")
        forgeable = trust_boundary_data.get("forgeable_hops_count", 0)
        if forgeable > 0:
            sentences.append(f"Upstream mail headers contain {forgeable} forgeable relay hop(s) beyond independently verified boundary.")

    narrative = " ".join(sentences)

    return {
        "narrative": narrative,
        "evidence_summary": sentences,
        "confidence": geo_data.get("confidence", 0.5)
    }


def explain_infrastructure(infra_data: dict, threat_data: dict = None) -> dict:
    """
    Generates an infrastructure assessment narrative from real classification and threat signals.
    Confidence is strictly derived from actual signal count and availability.
    """
    category = infra_data.get("category", "UNKNOWN")
    basis = infra_data.get("basis", "")
    confidence = infra_data.get("confidence", 0.0)

    sentences = []
    
    if category != "UNKNOWN":
        sentences.append(f"Infrastructure categorized as {category} based on signal analysis.")
    else:
        sentences.append("Infrastructure category could not be definitively classified.")

    if basis:
        sentences.append(f"Assessment basis: {basis}.")

    if threat_data:
        abuse_score = threat_data.get("abuse_confidence_score")
        status = threat_data.get("status")
        if abuse_score is not None and status == "ok":
            sentences.append(f"AbuseIPDB reputation score: {abuse_score}/100.")
        elif status == "unconfigured":
            sentences.append("AbuseIPDB reputation check was not performed (API key unconfigured).")

    narrative = " ".join(sentences)

    return {
        "narrative": narrative,
        "category": category,
        "confidence": confidence,
        "evidence_summary": sentences
    }
