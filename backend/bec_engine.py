"""
TraceXMail BEC (Business Email Compromise) Analysis Engine
Implements 8 explainable, high-precision detection rules with granular scoring and evidence extraction:

1. payment_diversion: Bank-account-change language + urgency
2. fake_invoice: Invoice/billing keywords + vendor-domain mismatch
3. credential_harvesting: Login-form-style link or href/anchor domain mismatch
4. executive_impersonation: Protected executive name in display name + unauthorized external domain
5. bank_account_change: Explicit sub-case of payment_diversion specifically requesting banking detail updates
6. vendor_impersonation: Claimed vendor brand/entity vs actual sending/return-path/reply-to domain
7. urgent_transfer_request: Urgency keywords + financial keywords co-occurring within the same paragraph
8. payroll_manipulation: Payroll/direct-deposit keywords + account change request

Every rule returns:
- score: float (0.0 to 1.0)
- evidence: list of structured evidence objects referencing triggering phrases, exact locations, and explanations
"""

import re
import html
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from backend.explain import explain_bec_analysis, explain_bec_rule
except ImportError:
    from explain import explain_bec_analysis, explain_bec_rule

try:
    from backend.ml.bec_model import predict_bec_category_scores
except ImportError:
    try:
        from ml.bec_model import predict_bec_category_scores
    except ImportError:
        predict_bec_category_scores = lambda text: None



# Default organizational configuration (can be overridden dynamically per organization/tenant)
DEFAULT_PROTECTED_EXECUTIVES = [
    "John Miller", "Sarah Jenkins", "Michael Chang", "David Vance", "Amanda Ross",
    "Robert Taylor", "Elena Rostova", "Marcus Brody", "Chief Executive Officer",
    "Chief Financial Officer", "Chief Operating Officer", "Chief Information Officer",
    "CEO", "CFO", "COO", "CIO", "President", "Executive Director", "General Counsel",
    "VP of Finance", "Head of Payroll", "IT Director"
]

DEFAULT_ORG_DOMAINS = [
    "corporate-enterprise.com", "mycompany.com", "enterprise.org", "internal-corp.net"
]

FREE_WEBMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com",
    "proton.me", "aol.com", "icloud.com", "mail.com", "zoho.com", "yandex.com",
    "tutanota.com", "gmx.com", "fastmail.com"
}

KNOWN_VENDORS_MAP = {
    "paypal": ["paypal.com", "paypal-communication.com", "paypal.co.uk"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "google": ["google.com", "workspace.google.com", "accounts.google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com", "id.apple.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wells fargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com", "citigroup.com"],
    "global logistics": ["global-logistics.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "stripe": ["stripe.com"],
    "quickbooks": ["intuit.com", "quickbooks.com", "intuit.ca"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "irs": ["irs.gov"]
}

# Regex patterns for rule triggers
URGENCY_KEYWORDS = [
    r"\burgent\b", r"\burgently\b", r"\bimmediately\b", r"\bimmediate\b",
    r"\baction required\b", r"\bact now\b", r"\bsuspended\b", r"\bsuspension\b",
    r"\brestricted\b", r"\brestriction\b", r"\bwithin 24 hours\b", r"\bwithin 48 hours\b",
    r"\bwithin 12 hours\b", r"\b24 hours\b", r"\b48 hours\b", r"\bexpires\b",
    r"\bexpiring\b", r"\bcritical\b", r"\bdeadline\b", r"\bpromptly\b",
    r"\boverdue\b", r"\bfinal notice\b", r"\btime-sensitive\b", r"\basap\b",
    r"\btoday only\b", r"\bwithout delay\b", r"\blast chance\b", r"\bmandatory\b",
    r"\bhalt all deliveries\b", r"\bcollection lien\b", r"\bpast due\b"
]

FINANCIAL_KEYWORDS = [
    r"\bwire transfer\b", r"\bwire\b", r"\bwired\b", r"\binvoice\b", r"\bbank\b",
    r"\bbanking\b", r"\bcredit card\b", r"\brouting number\b", r"\biban\b",
    r"\bswift\b", r"\bswift code\b", r"\bdirect deposit\b", r"\bpayment\b",
    r"\bpayments\b", r"\bpay\b", r"\bremittance\b", r"\bremit\b", r"\bfunds\b",
    r"\bsettlement\b", r"\bbalance\b", r"\bamount due\b", r"\$\s?[0-9,]+",
    r"€\s?[0-9,]+", r"£\s?[0-9,]+", r"\b[0-9,]+(\.[0-9]{2})?\s?(usd|eur|gbp)\b",
    r"\bescrow\b", r"\baccount balance\b", r"\bpaycheck\b", r"\bsalary\b", r"\bpayroll\b"
]

BANK_CHANGE_KEYWORDS = [
    r"new bank (?:account|details|information|instructions)",
    r"update (?:our|my|the|your) bank (?:account|details|info|information)",
    r"change (?:our|my|the|your) bank (?:account|details|info)",
    r"bank (?:account|details) (?:has|have) changed",
    r"new routing (?:number|details)",
    r"new iban\b",
    r"new wire (?:instructions|details)",
    r"remit (?:payment|funds) to (?:our|the) new (?:account|bank)",
    r"updated banking (?:details|instructions|info)",
    r"switch (?:payment|banking) to",
    r"banking details (?:have been|are) updated",
    r"escrow account"
]

PAYROLL_CHANGE_KEYWORDS = [
    r"(?:update|change|switch|modify) (?:my|our) (?:direct deposit|payroll|paycheck|salary)",
    r"direct deposit (?:information|account|details|form)",
    r"(?:new|updated) (?:direct deposit|payroll account|bank for payroll)",
    r"deposit (?:my|the) (?:paycheck|salary|funds) (?:into|to) (?:this|my new)",
    r"change of direct deposit",
    r"payroll direct deposit"
]

INVOICE_KEYWORDS = [
    r"\binvoice\b", r"\bbilling statement\b", r"\boverdue invoice\b",
    r"\bpast due\b", r"\bamount due\b", r"\bremittance advice\b",
    r"\bunpaid invoice\b", r"#?inv-[0-9a-z-]+", r"\bfreight shipping\b",
    r"\bcontainer freight\b", r"\bshipping invoice\b", r"\bvendor payment\b",
    r"\bpurchase order\b", r"\bpo #[0-9a-z-]+"
]


def extract_paragraphs(text: str, html_content: str = "") -> List[Tuple[str, str]]:
    """
    Extracts ordered paragraphs with labels ('Subject line', 'Paragraph 1', 'Paragraph 2', etc.)
    """
    if isinstance(text, dict):
        text = str(text.get("body_text") or text.get("text") or "")
    elif not isinstance(text, str):
        text = str(text or "")

    if isinstance(html_content, dict):
        html_content = str(html_content.get("body_html") or html_content.get("html") or "")
    elif not isinstance(html_content, str):
        html_content = str(html_content or "")

    paragraphs: List[Tuple[str, str]] = []
    
    # Strip HTML tags if HTML is provided
    clean_html = ""
    if html_content:
        # replace block tags with newlines
        clean_html = re.sub(r"<(?:p|div|br|h[1-6]|tr|li)[^>]*>", "\n", html_content, flags=re.IGNORECASE)
        clean_html = re.sub(r"<[^>]+>", " ", clean_html)
        clean_html = html.unescape(clean_html)

    full_content = text if len(text.strip()) >= len(clean_html.strip()) else clean_html
    raw_blocks = [b.strip() for b in re.split(r"\n\s*\n|\r\n\s*\r\n", full_content) if b.strip()]

    if not raw_blocks:
        lines = [line.strip() for line in full_content.splitlines() if line.strip()]
        raw_blocks = lines

    for idx, block in enumerate(raw_blocks):
        label = f"Paragraph {idx + 1}"
        paragraphs.append((label, block))

    return paragraphs


def extract_links_with_anchor(html_content: str, text_content: str = "") -> List[Dict[str, str]]:
    """
    Extracts all HTML links pairing visible anchor text with target href and location.
    """
    links = []
    if html_content:
        matches = re.finditer(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_content, flags=re.IGNORECASE | re.DOTALL)
        for idx, m in enumerate(matches):
            href = m.group(1).strip()
            anchor = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            links.append({
                "href": href,
                "anchor_text": anchor or href,
                "location": f"HTML Link #{idx + 1}"
            })
    
    # Fallback to plain text URLs if no HTML links
    if not links and text_content:
        plain_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_content)
        for idx, u in enumerate(plain_urls):
            links.append({
                "href": u,
                "anchor_text": u,
                "location": f"Plain text link #{idx + 1}"
            })

    return links


def parse_address_parts(header_val: str) -> Tuple[str, str, str]:
    """Parses 'Display Name <user@domain.com>' into (display_name, email_address, domain)."""
    if not header_val:
        return "", "", ""
    
    display_name = ""
    email_addr = ""
    
    match = re.search(r'^(.*?)\s*<([^>]+)>', header_val.strip())
    if match:
        display_name = match.group(1).strip(' "\'')
        email_addr = match.group(2).strip()
    else:
        email_addr = header_val.strip(' "\'<>')
        display_name = email_addr.split('@')[0] if '@' in email_addr else email_addr

    domain = email_addr.split('@')[1].lower() if '@' in email_addr else ""
    return display_name, email_addr, domain


def analyze_bec_rules(
    subject: str,
    body_text: str,
    body_html: str = "",
    from_header: str = "",
    reply_to_header: str = "",
    return_path: str = "",
    protected_executives: Optional[List[str]] = None,
    org_domains: Optional[List[str]] = None,
    known_vendors: Optional[Dict[str, List[str]]] = None
) -> Dict[str, Any]:
    """
    Executes 8 dedicated explainable BEC rules and returns structured scores and evidence.
    """
    exec_list = protected_executives or DEFAULT_PROTECTED_EXECUTIVES
    org_domain_list = [d.lower() for d in (org_domains or DEFAULT_ORG_DOMAINS)]
    vendors_map = known_vendors or KNOWN_VENDORS_MAP

    from_display, from_addr, from_domain = parse_address_parts(from_header)
    reply_display, reply_addr, reply_domain = parse_address_parts(reply_to_header)
    _, return_addr, return_domain = parse_address_parts(return_path)

    effective_sending_domain = from_domain or return_domain

    paragraphs = extract_paragraphs(body_text, body_html)
    all_sections = [("Subject line", subject)] + paragraphs
    links = extract_links_with_anchor(body_html, body_text)

    full_text = f"{subject}\n{body_text}\n" + (re.sub(r'<[^>]+>', ' ', body_html) if body_html else "")

    bec_ml_scores = predict_bec_category_scores(full_text)

    def resolve_score(category: str, rule_default: float) -> float:
        if bec_ml_scores and category in bec_ml_scores and bec_ml_scores[category] is not None:
            learned = bec_ml_scores[category]
            if learned > 0.05:
                return round(max(rule_default * 0.7, learned), 2)
        return rule_default

    # Storage for rule scores & evidence
    scores: Dict[str, float] = {
        "payment_diversion": 0.0,
        "fake_invoice": 0.0,
        "credential_harvesting": 0.0,
        "executive_impersonation": 0.0,
        "bank_account_change": 0.0,
        "vendor_impersonation": 0.0,
        "urgent_transfer_request": 0.0,
        "payroll_manipulation": 0.0
    }

    evidence: Dict[str, List[Dict[str, Any]]] = {k: [] for k in scores.keys()}

    # -------------------------------------------------------------
    # Rule 1: payment_diversion (Bank-account-change language + urgency)
    # -------------------------------------------------------------
    bank_change_matches: List[Tuple[str, str, str]] = []  # (phrase, location, context)
    urgency_matches: List[Tuple[str, str, str]] = []

    for loc, text_content in all_sections:
        for pattern in BANK_CHANGE_KEYWORDS:
            m = re.search(pattern, text_content, re.IGNORECASE)
            if m:
                bank_change_matches.append((m.group(0), loc, text_content))
        for pattern in URGENCY_KEYWORDS:
            m = re.search(pattern, text_content, re.IGNORECASE)
            if m:
                urgency_matches.append((m.group(0), loc, text_content))

    if bank_change_matches and urgency_matches:
        s_val = resolve_score("payment_diversion", 0.92)
        scores["payment_diversion"] = s_val
        for b_phrase, b_loc, b_ctx in bank_change_matches[:2]:
            u_phrase = urgency_matches[0][0]
            u_loc = urgency_matches[0][1]
            evidence["payment_diversion"].append({
                "score": s_val,
                "trigger_phrase": f"'{b_phrase}' ({b_loc}) with urgency '{u_phrase}' ({u_loc})",
                "location": f"{b_loc} / {u_loc}",
                "explanation": "Detected bank account change directive coupled with high-urgency pressure."
            })
    elif bank_change_matches:
        s_val = resolve_score("payment_diversion", 0.70)
        scores["payment_diversion"] = s_val
        for b_phrase, b_loc, _ in bank_change_matches[:2]:
            evidence["payment_diversion"].append({
                "score": s_val,
                "trigger_phrase": b_phrase,
                "location": b_loc,
                "explanation": "Detected bank account change language without explicit urgency co-occurrence."
            })

    # -------------------------------------------------------------
    # Rule 2: fake_invoice (Invoice/billing keywords + vendor-domain mismatch)
    # -------------------------------------------------------------
    invoice_triggers: List[Tuple[str, str]] = []
    for loc, text_content in all_sections:
        for pattern in INVOICE_KEYWORDS:
            m = re.search(pattern, text_content, re.IGNORECASE)
            if m:
                invoice_triggers.append((m.group(0), loc))

    vendor_mismatch_detected = False
    mismatch_details = ""

    # Check claimed vendor in From / Subject / Body vs sending domain
    for vendor_name, valid_domains in vendors_map.items():
        claimed = False
        if vendor_name in from_display.lower() or vendor_name in subject.lower():
            claimed = True
        elif any(vendor_name in text_content.lower() for _, text_content in all_sections):
            claimed = True

        if claimed:
            is_valid_domain = any(from_domain.endswith(vd) for vd in valid_domains)
            if not is_valid_domain and from_domain:
                vendor_mismatch_detected = True
                mismatch_details = f"Claimed vendor '{vendor_name.title()}' but sending domain is '{from_domain}' (expected {', '.join(valid_domains)})"
                break

    # Also check From domain vs Reply-To domain / Return-Path domain
    if not vendor_mismatch_detected and from_domain and reply_domain and from_domain != reply_domain:
        vendor_mismatch_detected = True
        mismatch_details = f"Sender domain '@{from_domain}' diverges from Reply-To '@{reply_domain}'"
    elif not vendor_mismatch_detected and from_domain and return_domain and from_domain != return_domain:
        vendor_mismatch_detected = True
        mismatch_details = f"Sender domain '@{from_domain}' diverges from Return-Path '@{return_domain}'"

    if invoice_triggers and vendor_mismatch_detected:
        s_val = resolve_score("fake_invoice", 0.88)
        scores["fake_invoice"] = s_val
        inv_phrase, inv_loc = invoice_triggers[0]
        evidence["fake_invoice"].append({
            "score": s_val,
            "trigger_phrase": f"Invoice keyword '{inv_phrase}' with domain anomaly: {mismatch_details}",
            "location": f"{inv_loc} / Header",
            "explanation": f"Detected invoice/billing request alongside sender domain anomaly ({mismatch_details})."
        })
    elif invoice_triggers and len(invoice_triggers) >= 2:
        s_val = resolve_score("fake_invoice", 0.45)
        scores["fake_invoice"] = s_val
        inv_phrase, inv_loc = invoice_triggers[0]
        evidence["fake_invoice"].append({
            "score": s_val,
            "trigger_phrase": inv_phrase,
            "location": inv_loc,
            "explanation": "Detected invoice and billing keywords; domain validation pending or neutral."
        })

    # -------------------------------------------------------------
    # Rule 3: credential_harvesting (Login-form-style link or href/anchor domain mismatch)
    # -------------------------------------------------------------
    cred_keywords = [r"\blogin\b", r"\bsign in\b", r"\bverify your (?:identity|account)\b", r"\breset password\b", r"\bpassword\b", r"\bupdate credentials\b"]
    login_terms_found = []
    for loc, text_content in all_sections:
        for ck in cred_keywords:
            m = re.search(ck, text_content, re.IGNORECASE)
            if m:
                login_terms_found.append((m.group(0), loc))

    link_mismatch_found = False
    for lk in links:
        href = lk["href"]
        anchor = lk["anchor_text"]
        loc = lk["location"]

        parsed_href = urlparse(href)
        href_domain = parsed_href.netloc.lower()

        # Check if anchor contains a domain or URL different from href
        anchor_domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', anchor)
        if anchor_domain_match:
            anchor_domain = anchor_domain_match.group(1).lower()
            if href_domain and anchor_domain and anchor_domain != href_domain and not href_domain.endswith(f".{anchor_domain}"):
                link_mismatch_found = True
                s_val = resolve_score("credential_harvesting", 0.94)
                scores["credential_harvesting"] = s_val
                evidence["credential_harvesting"].append({
                    "score": s_val,
                    "trigger_phrase": f"Visible anchor text displays '{anchor}' but points to '{href}'",
                    "location": loc,
                    "explanation": f"Anchor text domain ({anchor_domain}) does not match target URL destination domain ({href_domain})."
                })

        # Check for login / verify path in link target with login terminology in text
        if any(term in href.lower() for term in ["login", "signin", "auth", "verify", "secure", "account-update", "redirect"]):
            if login_terms_found and not link_mismatch_found:
                s_val = resolve_score("credential_harvesting", 0.85)
                scores["credential_harvesting"] = max(scores["credential_harvesting"], s_val)
                term_str, term_loc = login_terms_found[0]
                evidence["credential_harvesting"].append({
                    "score": s_val,
                    "trigger_phrase": f"Login credential lure '{term_str}' ({term_loc}) linking to '{href}'",
                    "location": f"{term_loc} / {loc}",
                    "explanation": f"Email text contains credential harvesting keywords with targeted authentication link '{href}'."
                })

    # -------------------------------------------------------------
    # Rule 4: executive_impersonation (Protected name in display name + non-org domain)
    # -------------------------------------------------------------
    exec_name_matched = ""
    for protected in exec_list:
        p_clean = protected.lower()
        if p_clean in from_display.lower() or p_clean in subject.lower():
            exec_name_matched = protected
            break

    if exec_name_matched:
        is_legit_org = any(from_domain.endswith(od) for od in org_domain_list)
        is_free_mail = from_domain in FREE_WEBMAIL_PROVIDERS

        if not is_legit_org:
            base_def = 0.96 if is_free_mail else 0.88
            score_val = resolve_score("executive_impersonation", base_def)
            scores["executive_impersonation"] = score_val
            evidence["executive_impersonation"].append({
                "score": score_val,
                "trigger_phrase": f"Sender display name '{from_display}' matches protected executive '{exec_name_matched}' from external address <{from_addr}>",
                "location": "Header: From",
                "explanation": f"Protected executive name '{exec_name_matched}' sent from unauthorized domain '@{from_domain}'" + (" (Free Webmail Provider)" if is_free_mail else "") + "."
            })

    # -------------------------------------------------------------
    # Rule 5: bank_account_change (Explicit sub-case of payment_diversion)
    # -------------------------------------------------------------
    explicit_bank_triggers: List[Tuple[str, str, str]] = []
    for loc, text_content in all_sections:
        for pattern in BANK_CHANGE_KEYWORDS:
            m = re.search(pattern, text_content, re.IGNORECASE)
            if m:
                explicit_bank_triggers.append((m.group(0), loc, text_content))

    if explicit_bank_triggers:
        s_val = resolve_score("bank_account_change", 0.90)
        scores["bank_account_change"] = s_val
        for phrase, loc, _ in explicit_bank_triggers[:2]:
            evidence["bank_account_change"].append({
                "score": s_val,
                "trigger_phrase": phrase,
                "location": loc,
                "explanation": f"Explicit request to update or switch banking/wire details identified in {loc}."
            })

    # -------------------------------------------------------------
    # Rule 6: vendor_impersonation (Claimed vendor identity vs domain mismatch)
    # -------------------------------------------------------------
    for vendor_name, valid_domains in vendors_map.items():
        claimed_in_sender = vendor_name in from_display.lower() or vendor_name in from_addr.lower()
        claimed_in_subject = vendor_name in subject.lower()
        claimed_in_body = any(vendor_name in text_content.lower() for _, text_content in all_sections)

        if claimed_in_sender or claimed_in_subject or (claimed_in_body and ("service" in from_display.lower() or "support" in from_display.lower() or "billing" in from_display.lower())):
            is_valid = any(from_domain.endswith(vd) for vd in valid_domains)
            if not is_valid and from_domain:
                s_val = resolve_score("vendor_impersonation", 0.91)
                scores["vendor_impersonation"] = s_val
                evidence["vendor_impersonation"].append({
                    "score": s_val,
                    "trigger_phrase": f"Claimed brand '{vendor_name.title()}' (in sender '{from_display}' / subject '{subject}') with sending domain '@{from_domain}'",
                    "location": "Header: From / Subject",
                    "explanation": f"Sender claims brand identity '{vendor_name.title()}' but is dispatched from unverified domain '@{from_domain}'."
                })
                break

    # -------------------------------------------------------------
    # Rule 7: urgent_transfer_request (Urgency + financial keywords in SAME paragraph)
    # -------------------------------------------------------------
    for loc, paragraph_text in all_sections:
        u_in_para = []
        f_in_para = []

        for u_pat in URGENCY_KEYWORDS:
            m = re.search(u_pat, paragraph_text, re.IGNORECASE)
            if m:
                u_in_para.append(m.group(0))

        for f_pat in FINANCIAL_KEYWORDS:
            m = re.search(f_pat, paragraph_text, re.IGNORECASE)
            if m:
                f_in_para.append(m.group(0))

        if u_in_para and f_in_para:
            s_val = resolve_score("urgent_transfer_request", 0.92)
            scores["urgent_transfer_request"] = max(scores["urgent_transfer_request"], s_val)
            evidence["urgent_transfer_request"].append({
                "score": s_val,
                "trigger_phrase": f"Urgency '{u_in_para[0]}' and financial term '{f_in_para[0]}' co-occurring in {loc}",
                "location": loc,
                "explanation": f"High-risk proximity match: Urgency keyword ('{u_in_para[0]}') and financial keyword ('{f_in_para[0]}') co-occur within the same paragraph."
            })

    # -------------------------------------------------------------
    # Rule 8: payroll_manipulation (Payroll/direct-deposit keywords + account change)
    # -------------------------------------------------------------
    payroll_triggers: List[Tuple[str, str]] = []
    for loc, text_content in all_sections:
        for pattern in PAYROLL_CHANGE_KEYWORDS:
            m = re.search(pattern, text_content, re.IGNORECASE)
            if m:
                payroll_triggers.append((m.group(0), loc))

    if payroll_triggers:
        s_val = resolve_score("payroll_manipulation", 0.93)
        scores["payroll_manipulation"] = s_val
        for phrase, loc in payroll_triggers[:2]:
            evidence["payroll_manipulation"].append({
                "score": s_val,
                "trigger_phrase": phrase,
                "location": loc,
                "explanation": f"Payroll diversion attempt: Request to alter employee direct deposit/salary account detected in {loc}."
            })

    # Calculate overall BEC score and risk level
    active_scores = [s for s in scores.values() if s > 0.0]
    overall_score = round(max(active_scores), 2) if active_scores else 0.0
    triggered_count = len([s for s in scores.values() if s >= 0.5])

    if overall_score >= 0.80 or triggered_count >= 2:
        risk_level = "CRITICAL" if overall_score >= 0.90 and triggered_count >= 2 else "HIGH"
    elif overall_score >= 0.40 or triggered_count >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Compute rule-level and overall explainable 'why' objects
    rules_why: Dict[str, Any] = {}
    for rule_name, score in scores.items():
        if score > 0.0:
            rules_why[rule_name] = explain_bec_rule(rule_name, score, evidence.get(rule_name, []))

    raw_bec_dict = {
        "bec_analysis": scores,
        "evidence": evidence,
        "overall_bec_score": overall_score,
        "risk_level": risk_level,
        "triggered_rules_count": triggered_count,
    }
    overall_why = explain_bec_analysis(raw_bec_dict, subject=subject, from_header=from_header)

    return {
        "bec_analysis": scores,
        "evidence": evidence,
        "overall_bec_score": overall_score,
        "risk_level": risk_level,
        "triggered_rules_count": triggered_count,
        "summary": f"BEC Engine evaluated 8 rules. {triggered_count} rules triggered (Highest Score: {overall_score}, Risk: {risk_level}).",
        "why": overall_why,
        "rules_why": rules_why
    }
