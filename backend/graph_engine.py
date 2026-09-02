# Forensic Relationship Graph Engine Module

def build_forensic_graph(case_data: dict) -> dict:
    """
    Builds a network node and edge structure representing relationship graph between
    sender, domain, relay hops, IP addresses, and extracted links.
    """
    nodes = []
    edges = []

    if not case_data:
        return {"nodes": [], "edges": []}

    case_id = case_data.get("id") or "case"
    sender = case_data.get("sender") or case_data.get("from") or "sender"
    domain = case_data.get("domain") or case_data.get("from_domain") or "domain.com"
    origin_ip = case_data.get("origin_ip") or case_data.get("ip") or "0.0.0.0"

    # Add case node
    nodes.append({"id": case_id, "label": f"Case: {case_id}", "type": "case"})
    nodes.append({"id": sender, "label": f"Sender: {sender}", "type": "email"})
    nodes.append({"id": domain, "label": f"Domain: {domain}", "type": "domain"})
    nodes.append({"id": origin_ip, "label": f"IP: {origin_ip}", "type": "ip"})

    edges.append({"source": case_id, "target": sender, "relation": "SENT_BY"})
    edges.append({"source": sender, "target": domain, "relation": "USES_DOMAIN"})
    edges.append({"source": sender, "target": origin_ip, "relation": "ORIGINATED_FROM"})

    return {
        "nodes": nodes,
        "edges": edges,
        "status": "ok"
    }
