# BEC Engine for analyzing executive spoofing and wire fraud indicators

def evaluate_bec_risk(headers: dict, body: str) -> float:
    score = 0.0
    if "urgent" in body.lower():
        score += 0.3
    if "wire" in body.lower() or "bank" in body.lower():
        score += 0.4
    return min(score, 1.0)
