# Trust Boundary Analysis Module

FORGEABLE_HOP_CAVEAT = (
    "Hops beyond the trust boundary are self-reported by upstream mail servers and can be "
    "forged by the sender; only the hop where the recipient's own infrastructure first received "
    "the message is independently verifiable."
)

def analyze_trust_boundary(relay_nodes: list, recipient_domain: str = None) -> dict:
    """
    Analyzes the Received header chain to determine the boundary between trusted
    internal/recipient infrastructure and potentially forgeable upstream relays.
    """
    if not relay_nodes:
        return {
            "earliest_reliable_node": None,
            "trusted_hop_index": None,
            "forgeable_hops_count": 0,
            "trust_boundary_found": False,
            "caveat": FORGEABLE_HOP_CAVEAT,
            "lookup_method": "header_chain_analysis",
            "status": "unavailable"
        }

    # Normalize recipient domain if provided
    recip_domain_lower = recipient_domain.lower() if recipient_domain else None

    trusted_index = None
    earliest_reliable = None
    forgeable_count = 0

    # Inspect from top of header chain (newest/recipient MTA) down to bottom (origin)
    # Hops ordered 1..N where 1 is first hop or top hop. We check by_host matching recipient domain.
    total_hops = len(relay_nodes)

    for idx, node in enumerate(relay_nodes):
        by_host = str(node.get("by_host") or node.get("byHost") or "").lower()
        from_host = str(node.get("from_host") or node.get("fromHost") or "").lower()
        from_ip = node.get("from_ip") or node.get("fromIp") or node.get("ip")

        is_recipient_mta = False
        if recip_domain_lower and recip_domain_lower in by_host:
            is_recipient_mta = True

        if is_recipient_mta or idx == 0:
            # First hop recorded by recipient infrastructure
            trusted_index = idx
            earliest_reliable = {
                "received_from_ip": from_ip,
                "received_from_host": from_host,
                "by_host": by_host,
                "hop_number": node.get("hop_number") or node.get("hopNumber") or (idx + 1)
            }

    if trusted_index is not None:
        forgeable_count = max(0, total_hops - (trusted_index + 1))
    else:
        forgeable_count = max(0, total_hops - 1)
        if total_hops > 0:
            earliest_reliable = {
                "received_from_ip": relay_nodes[0].get("from_ip") or relay_nodes[0].get("fromIp"),
                "received_from_host": relay_nodes[0].get("from_host") or relay_nodes[0].get("fromHost"),
                "by_host": relay_nodes[0].get("by_host") or relay_nodes[0].get("byHost"),
                "hop_number": 1
            }
            trusted_index = 0

    return {
        "earliest_reliable_node": earliest_reliable,
        "trusted_hop_index": trusted_index,
        "forgeable_hops_count": forgeable_count,
        "trust_boundary_found": earliest_reliable is not None,
        "caveat": FORGEABLE_HOP_CAVEAT,
        "lookup_method": "header_chain_analysis",
        "status": "ok" if earliest_reliable else "unavailable"
    }
