"""
TraceXMail Content Intelligence Engine (NLP Feature Extraction)
Extracts inspectable, named NLP features from email subject and body:
- Urgency-keyword density (maintained keyword list, scored as ratio of total word count)
- Imperative / command rate (rule-based sentence-initial action verbs & directive command pattern analysis)
- Authority-tone signals (phrases invoking executive authority, policy, or legal coercion)
- Financial and credential terminology density (two separate maintained keyword lists)
- Second-person usage rate (pronoun density tell for social engineering)
- Entity extraction (organizations, persons, account numbers, currencies, and payment patterns)
- Impersonation signal (cross-comparison of claimed identity/display name against sender & reply-to domains)
"""

import re
from typing import Dict, Any, List, Optional, Tuple

try:
    from backend.ml.content_intelligence_model import predict_content_signals
except ImportError:
    try:
        from ml.content_intelligence_model import predict_content_signals
    except ImportError:
        predict_content_signals = lambda text: None


# =====================================================================
# 1. MAINTAINED KEYWORD & PHRASE DICTIONARIES
# =====================================================================

URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediately", "immediate", "action required", "act now",
    "suspended", "suspension", "suspend", "restricted", "restriction", "restrict",
    "within 24 hours", "within 48 hours", "within 12 hours", "within 1 hour",
    "24 hours", "48 hours", "expires", "expiration", "expiring", "expire",
    "critical", "threat", "attention", "deadline", "promptly", "instant", "instantly",
    "terminate", "termination", "overdue", "final notice", "time-sensitive",
    "respond immediately", "today only", "asap", "without delay", "last chance",
    "mandatory", "immediate attention", "strictly required", "clock is ticking",
    "loss of access", "account lock", "account locked", "deactivation", "deactivated"
]

AUTHORITY_PHRASES = [
    "as your manager", "as your ceo", "as ceo", "as your director", "as your cfo",
    "per company policy", "company policy", "legal action", "executive directive",
    "board of directors", "human resources", "hr department", "compliance department",
    "compliance team", "internal audit", "security operations", "it helpdesk",
    "it department", "system administrator", "corporate security", "court order",
    "subpoena", "law enforcement", "federal bureau", "disciplinary action",
    "strictly confidential", "authorized personnel", "mandatory compliance",
    "management request", "legal counsel", "chief executive officer",
    "chief financial officer", "chief information security officer",
    "office of the ceo", "executive management", "confidential wire",
    "authorized signature", "direct order", "attorney general", "internal revenue service",
    "security team", "security center", "fraud prevention department", "risk management"
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "wire", "invoice", "bank", "banking", "credit card", "debit card",
    "routing number", "iban", "swift", "swift code", "direct deposit", "payment", "payments",
    "crypto", "bitcoin", "ethereum", "btc", "wallet", "balance", "payout", "refund",
    "remittance", "remit", "tax refund", "ach", "ach transfer", "transaction", "transactions",
    "billing", "funds", "settlement", "account balance", "overdue payment", "payroll",
    "amount due", "dollars", "usd", "eur", "gbp", "$", "€", "£", "remittance advice",
    "purchase order", "po number", "vendor payment", "unpaid invoice", "compensation",
    "direct transfer", "escrow", "checking account", "savings account", "statement"
]

CREDENTIAL_KEYWORDS = [
    "password", "passwords", "credential", "credentials", "verify your account",
    "verify identity", "verify your identity", "log in", "login", "sign in", "signin",
    "authenticate", "authentication", "2fa", "mfa", "passcode", "pin", "pin number",
    "otp", "one-time password", "reset password", "change password", "security questions",
    "unlock", "unlock account", "session", "access key", "identity verification",
    "account access", "security token", "sso", "jwt", "api key", "secret key",
    "re-authenticate", "login portal", "confirm credentials", "validate identity",
    "security code", "authorization code", "keychain", "master password"
]

IMPERATIVE_VERBS = [
    "click", "verify", "update", "log in", "login", "sign in", "signin", "confirm",
    "review", "download", "pay", "submit", "contact", "transfer", "reset", "open",
    "call", "provide", "check", "proceed", "complete", "fill out", "authorize",
    "validate", "install", "execute", "reply", "send", "enable", "disable",
    "authenticate", "forward", "re-enter", "renew", "dispute", "cancel", "sign",
    "view", "access", "follow", "insist", "ensure", "secure", "prevent", "claim"
]

SECOND_PERSON_PRONOUNS = ["you", "your", "yours", "yourself", "yourselves"]


# Known brands and institutional entities
KNOWN_BRAND_ENTITIES = [
    {"name": "PayPal", "domains": ["paypal.com", "paypal-communication.com", "customeremail.paypal.com"]},
    {"name": "Microsoft", "domains": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"]},
    {"name": "Google", "domains": ["google.com", "googlemail.com", "workspace.google.com", "accounts.google.com"]},
    {"name": "Apple", "domains": ["apple.com", "icloud.com", "id.apple.com"]},
    {"name": "Chase Bank", "domains": ["chase.com", "jpmorganchase.com"]},
    {"name": "Wells Fargo", "domains": ["wellsfargo.com"]},
    {"name": "Citibank", "domains": ["citi.com", "citibank.com", "citigroup.com"]},
    {"name": "Amazon", "domains": ["amazon.com", "amazon.co.uk", "aws.amazon.com"]},
    {"name": "DocuSign", "domains": ["docusign.com", "docusign.net"]},
    {"name": "FedEx", "domains": ["fedex.com"]},
    {"name": "DHL", "domains": ["dhl.com", "dhl.de"]},
    {"name": "IRS", "domains": ["irs.gov"]},
    {"name": "Stripe", "domains": ["stripe.com"]},
    {"name": "GitHub", "domains": ["github.com", "githubstatus.com"]},
    {"name": "Dropbox", "domains": ["dropbox.com"]},
    {"name": "Netflix", "domains": ["netflix.com"]},
    {"name": "Bank of America", "domains": ["bankofamerica.com", "bofa.com"]},
    {"name": "Meta / Facebook", "domains": ["meta.com", "facebookmail.com", "fb.com"]},
    {"name": "Slack", "domains": ["slack.com", "slack-messages.com"]}
]


# =====================================================================
# 2. HELPER UTILITIES
# =====================================================================

def clean_text_and_tokenize(text: str) -> List[str]:
    """Tokenizes text into words."""
    if not text:
        return []
    # Replace HTML tags if present
    no_html = re.sub(r"<[^>]+>", " ", text)
    # Split on non-alphanumeric (keep single quotes for contractions)
    tokens = re.findall(r"\b[a-zA-Z0-9$€£'-]+\b", no_html.lower())
    return tokens


def split_sentences(text: str) -> List[str]:
    """Splits text into sentences."""
    if not text:
        return []
    no_html = re.sub(r"<[^>]+>", " ", text)
    # Split on period, exclamation, question mark, or newlines
    raw_sents = re.split(r"[.!?\n]+", no_html)
    cleaned = [s.strip() for s in raw_sents if s.strip() and len(s.strip().split()) >= 2]
    return cleaned


def extract_domain_from_email(addr: str) -> str:
    """Extracts lowercase domain from an email address or header string."""
    if not addr:
        return ""
    # Extract inside angle brackets if present
    match = re.search(r"<([^>]+)>", addr)
    target = match.group(1) if match else addr
    if "@" in target:
        return target.split("@")[-1].strip().lower().rstrip(">")
    return target.strip().lower()


def extract_display_name_and_email(header_val: str) -> Tuple[str, str, str]:
    """Returns (display_name, email_address, domain)."""
    if not header_val:
        return ("", "", "")
    match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', header_val)
    if match:
        name = match.group(1).strip()
        email = match.group(2).strip().lower()
        domain = email.split("@")[-1] if "@" in email else ""
        return (name, email, domain)
    if "@" in header_val:
        email = header_val.strip().lower()
        domain = email.split("@")[-1]
        return ("", email, domain)
    return (header_val.strip(), "", "")


# =====================================================================
# 3. FEATURE EXTRACTION IMPLEMENTATIONS
# =====================================================================

def compute_keyword_density(tokens: List[str], text_lower: str, keywords: List[str]) -> Dict[str, Any]:
    """
    Computes keyword occurrences and density ratio against total word count.
    Supports single words and multi-word phrases.
    """
    total_words = max(1, len(tokens))
    matched_terms: List[str] = []
    total_count = 0

    for kw in keywords:
        kw_lower = kw.lower()
        if " " in kw_lower or kw_lower in ["$", "€", "£"]:
            # Phrase match with regex word boundaries
            escaped = re.escape(kw_lower)
            occurrences = len(re.findall(r"(?:^|\W)" + escaped + r"(?:$|\W)", text_lower))
            if occurrences > 0:
                matched_terms.append(kw)
                total_count += occurrences
        else:
            occurrences = tokens.count(kw_lower)
            if occurrences > 0:
                matched_terms.append(kw)
                total_count += occurrences

    density = total_count / total_words
    density_per_100 = (total_count / total_words) * 100.0

    return {
        "count": total_count,
        "density": round(density, 4),
        "density_per_100_words": round(density_per_100, 2),
        "matched_keywords": sorted(list(set(matched_terms)))
    }


def compute_imperative_command_rate(sentences: List[str]) -> Dict[str, Any]:
    """
    Computes imperative / command rate.
    Approach: Rule-based sentence-initial action verbs & directive command pattern analysis.
    Identifies sentences that start with an action verb (e.g. 'Click here', 'Verify your account', 'Download the invoice')
    or contain direct imperative modal structures ('You must immediately', 'Please verify', 'Ensure you').
    """
    total_sentences = max(1, len(sentences))
    imperative_sentences: List[Dict[str, str]] = []
    directive_patterns = [
        r"^(?:please\s+)?(click|verify|update|log\s*in|sign\s*in|confirm|review|download|pay|submit|contact|transfer|reset|open|call|provide|check|proceed|complete|fill\s+out|authorize|validate|install|execute|reply|send|enable|disable|authenticate|forward|renew|dispute|cancel|sign|view|access|follow)\b",
        r"^(?:you\s+must|you\s+need\s+to|make\s+sure\s+to|ensure\s+you|kindly\s+click|kindly\s+verify|action\s+is\s+required\s+to)\b",
        r"\b(?:click\s+here\s+to|follow\s+the\s+link\s+below|download\s+attachment|sign\s+the\s+attached|send\s+the\s+wire|update\s+your\s+billing)\b"
    ]

    for sent in sentences:
        sent_clean = sent.strip()
        sent_lower = sent_clean.lower()
        matched = False
        matched_trigger = ""

        for pat in directive_patterns:
            m = re.search(pat, sent_lower)
            if m:
                matched = True
                matched_trigger = m.group(0)
                break

        if not matched:
            first_word = sent_lower.split()[0] if sent_lower.split() else ""
            if first_word in IMPERATIVE_VERBS:
                matched = True
                matched_trigger = first_word

        if matched:
            imperative_sentences.append({
                "sentence": sent_clean[:120] + ("..." if len(sent_clean) > 120 else ""),
                "directive_trigger": matched_trigger
            })

    command_count = len(imperative_sentences)
    rate = command_count / total_sentences

    return {
        "approach": "rule_based_sentence_initial_action_verbs_and_directive_patterns",
        "total_sentences": len(sentences),
        "imperative_sentence_count": command_count,
        "imperative_rate": round(rate, 4),
        "imperative_percentage": round(rate * 100.0, 2),
        "sample_commands": imperative_sentences[:5]
    }


def compute_authority_tone_signals(text_lower: str, tokens: List[str]) -> Dict[str, Any]:
    """
    Detects authority-tone phrases invoking institutional power, management, or legal pressure.
    """
    total_words = max(1, len(tokens))
    detected: List[str] = []
    total_occurrences = 0

    for phrase in AUTHORITY_PHRASES:
        p_lower = phrase.lower()
        count = len(re.findall(r"(?:^|\W)" + re.escape(p_lower) + r"(?:$|\W)", text_lower))
        if count > 0:
            detected.append(phrase)
            total_occurrences += count

    score = min(1.0, total_occurrences * 0.25)
    return {
        "count": total_occurrences,
        "detected_phrases": sorted(list(set(detected))),
        "authority_score": round(score, 3),
        "is_authority_lure_present": total_occurrences > 0
    }


def compute_second_person_usage(tokens: List[str]) -> Dict[str, Any]:
    """
    Computes second-person pronoun density ('you', 'your', 'yours', 'yourself').
    """
    total_words = max(1, len(tokens))
    second_person_count = 0
    breakdown: Dict[str, int] = {}

    for pron in SECOND_PERSON_PRONOUNS:
        cnt = tokens.count(pron)
        if cnt > 0:
            breakdown[pron] = cnt
            second_person_count += cnt

    density = second_person_count / total_words
    density_per_100 = (second_person_count / total_words) * 100.0

    return {
        "second_person_count": second_person_count,
        "density": round(density, 4),
        "density_per_100_words": round(density_per_100, 2),
        "breakdown": breakdown,
        "is_elevated": density_per_100 >= 3.5
    }


def extract_named_entities(text: str) -> Dict[str, Any]:
    """
    Extracts named entities from text:
    - Company / Brand names (recognized high-risk target brands)
    - Person names & titles (executives, sign-offs, self-identifications)
    - Financial & payment entities (account numbers, IBANs, amounts, invoices)
    """
    text_clean = re.sub(r"<[^>]+>", " ", text)
    tokens = clean_text_and_tokenize(text)

    # 1. Company / Brand Names
    detected_organizations: List[str] = []
    for brand in KNOWN_BRAND_ENTITIES:
        b_name = brand["name"].lower()
        if re.search(r"(?:^|\W)" + re.escape(b_name) + r"(?:$|\W)", text_clean, re.IGNORECASE):
            detected_organizations.append(brand["name"])

    # Regex for common generic org suffixes
    generic_orgs = re.findall(r"\b([A-Z][a-zA-Z0-9&]+(?:\s+[A-Z][a-zA-Z0-9&]+)*\s+(?:Inc|LLC|Corp|Corporation|Bank|Security|Group|Technologies|Foundation|Department|Center))\b", text_clean)
    for org in generic_orgs:
        if org not in detected_organizations:
            detected_organizations.append(org)

    # 2. Person Names & Titles
    person_entities: List[str] = []
    # Match greeting / sign-off names
    signoff_matches = re.findall(r"(?:Regards|Sincerely|Thanks|Best regards|From|Cheer|Respectfully),?\s*\n+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)", text_clean)
    for name in signoff_matches:
        if name not in person_entities:
            person_entities.append(name.strip())

    # Executive titles with names
    title_matches = re.findall(r"\b(?:CEO|CFO|COO|President|Director|Manager|Dr\.|Mr\.|Ms\.|Mrs\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)", text_clean)
    for name in title_matches:
        if name not in person_entities:
            person_entities.append(name.strip())

    # Self-identification patterns: "I am [Name]"
    self_id_matches = re.findall(r"\b(?:I am|This is|I'm)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)", text_clean)
    for name in self_id_matches:
        if name not in person_entities:
            person_entities.append(name.strip())

    # 3. Financial Entities & Payment Patterns
    # Currency amounts
    currency_patterns = re.findall(r"([$€£]\s*\d+(?:,\d{3})*(?:\.\d{2})?|\b\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|dollars)\b)", text_clean, re.IGNORECASE)
    
    # Account numbers
    account_patterns = re.findall(r"\b(?:Account|Acc|Acct|Checking|Savings|Card|Ending in)[: #]*([A-Z0-9-]{4,20})\b", text_clean, re.IGNORECASE)
    
    # Invoice numbers
    invoice_patterns = re.findall(r"\b(?:Invoice|INV|Order|Payment|Notice)[: #]*([A-Z0-9-]{4,24})\b", text_clean, re.IGNORECASE)
    
    # IBAN / SWIFT
    iban_patterns = re.findall(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b", text_clean)
    swift_patterns = re.findall(r"\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b", text_clean)

    return {
        "organizations": sorted(list(set(detected_organizations))),
        "persons": sorted(list(set(person_entities))),
        "financial_entities": {
            "monetary_amounts": sorted(list(set(currency_patterns))),
            "account_identifiers": sorted(list(set(account_patterns))),
            "invoice_numbers": sorted(list(set(invoice_patterns))),
            "ibans": sorted(list(set(iban_patterns))),
            "swift_codes": sorted(list(set(swift_patterns)))
        }
    }


def compute_impersonation_signals(
    from_header: str,
    reply_to_header: str = "",
    body_text: str = "",
    subject: str = ""
) -> Dict[str, Any]:
    """
    Compares claimed identity (display name + body self-identification)
    against actual sender email, sender domain, and Reply-To domain.
    Flags mismatches explicitly with the two values shown.
    """
    from_name, from_email, from_domain = extract_display_name_and_email(from_header)
    reply_name, reply_email, reply_domain = extract_display_name_and_email(reply_to_header)
    full_text = f"{subject}\n{body_text}"

    # 1. Detect Claimed Identity from Display Name
    claimed_entities: List[Dict[str, str]] = []
    
    # Check if display name targets a recognized brand
    for brand in KNOWN_BRAND_ENTITIES:
        b_name = brand["name"].lower()
        if b_name in from_name.lower() or (from_name and re.search(r"\b" + re.escape(b_name) + r"\b", from_name, re.IGNORECASE)):
            claimed_entities.append({
                "type": "BRAND_IN_DISPLAY_NAME",
                "claimed_identity": brand["name"],
                "expected_domains": brand["domains"]
            })

    # Check if body contains self-identification ("I am [Name], your CEO", "This is [Name] from Security")
    body_self_id = re.search(r"\b(?:I am|This is|I'm)\s+([A-Za-z0-9\s,.-]+?)(?:,\s*(?:your\s+)?(CEO|CFO|Director|President|Manager|Administrator|IT Support))?\b", full_text, re.IGNORECASE)
    claimed_person = ""
    if body_self_id:
        claimed_person = body_self_id.group(1).strip()
        if body_self_id.group(2):
            claimed_person += f" ({body_self_id.group(2).upper()})"
        claimed_entities.append({
            "type": "BODY_SELF_IDENTIFICATION",
            "claimed_identity": claimed_person,
            "expected_domains": []
        })

    # 2. Check for Mismatches
    mismatches: List[Dict[str, Any]] = []
    is_impersonation = False

    # Check Display Name vs Sender Domain
    for entity in claimed_entities:
        if entity["type"] == "BRAND_IN_DISPLAY_NAME":
            brand_name = entity["claimed_identity"]
            expected_domains = entity["expected_domains"]
            matches_expected = any(from_domain == d or from_domain.endswith("." + d) for d in expected_domains)
            if not matches_expected:
                is_impersonation = True
                mismatches.append({
                    "signal": "DISPLAY_NAME_VS_SENDER_DOMAIN_MISMATCH",
                    "claimed_identity": brand_name,
                    "actual_sender_email": from_email,
                    "actual_sender_domain": from_domain,
                    "description": f"Display name claims '{from_name}' ({brand_name}), but email originated from unauthorized domain '{from_domain}'."
                })

    # Check From Domain vs Reply-To Domain
    if reply_domain and from_domain and reply_domain != from_domain:
        is_impersonation = True
        mismatches.append({
            "signal": "REPLY_TO_DOMAIN_MISMATCH",
            "from_domain": from_domain,
            "reply_to_domain": reply_domain,
            "actual_reply_to_email": reply_email,
            "description": f"Sender domain is '{from_domain}', but Reply-To redirects responses to different domain '{reply_domain}'."
        })

    # Check executive impersonation on freemail
    freemail_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com"]
    if claimed_person and from_domain in freemail_domains:
        is_impersonation = True
        mismatches.append({
            "signal": "EXECUTIVE_ON_FREEMAIL_PROVIDER",
            "claimed_identity": claimed_person,
            "actual_sender_email": from_email,
            "freemail_domain": from_domain,
            "description": f"Sender claims to be executive '{claimed_person}' using a public webmail domain '{from_domain}'."
        })

    primary_claimed = from_name if from_name else (claimed_person if claimed_person else "None specified")

    return {
        "is_impersonation": is_impersonation,
        "claimed_identity": primary_claimed,
        "claimed_display_name": from_name,
        "body_claimed_identity": claimed_person,
        "actual_sender_email": from_email,
        "actual_sender_domain": from_domain,
        "reply_to_email": reply_email,
        "reply_to_domain": reply_domain,
        "mismatches_count": len(mismatches),
        "mismatches": mismatches
    }


# =====================================================================
# 4. COMPREHENSIVE CONTENT INTELLIGENCE PIPELINE
# =====================================================================

def analyze_content_signals(subject: str, body: str) -> dict:
    text = f"{subject}\n{body}"
    trained = predict_content_signals(text)
    if trained:
        return {
            "urgency_score": trained["urgency"],
            "authority_score": trained["authority"],
            "financial_score": trained["financial"],
            "credential_score": trained["credential"],
            "imperative_score": trained["imperative"],
            "scoring_method": "trained_model",
        }
    
    # Fallback to existing keyword-density functions if model not yet trained —
    # never let a missing model file break the pipeline.
    tokens = clean_text_and_tokenize(text)
    text_lower = text.lower()
    sentences = split_sentences(text)
    urgency_stats = compute_keyword_density(tokens, text_lower, URGENCY_KEYWORDS)
    authority_stats = compute_authority_tone_signals(text_lower, tokens)
    financial_stats = compute_keyword_density(tokens, text_lower, FINANCIAL_KEYWORDS)
    credential_stats = compute_keyword_density(tokens, text_lower, CREDENTIAL_KEYWORDS)
    command_stats = compute_imperative_command_rate(sentences)

    return {
        "urgency_score": round(min(1.0, urgency_stats["density_per_100_words"] / 2.0), 4),
        "authority_score": authority_stats["authority_score"],
        "financial_score": round(min(1.0, financial_stats["count"] * 0.2), 4),
        "credential_score": round(min(1.0, credential_stats["count"] * 0.25), 4),
        "imperative_score": round(command_stats["imperative_rate"], 4),
        "scoring_method": "rule_based_fallback",
    }


def extract_content_features(
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    from_header: str = "",
    reply_to_header: str = ""
) -> Dict[str, Any]:
    """
    Executes full NLP content intelligence feature extraction on an email message.
    Returns structured, named, inspectable metrics per the specification.
    """
    combined_body = (body_text or "") + "\n" + (body_html or "")
    full_text = f"{subject}\n{combined_body}".strip()
    
    tokens = clean_text_and_tokenize(full_text)
    text_lower = full_text.lower()
    sentences = split_sentences(full_text)

    # Signal Scoring (Trained multi-label model or rule-based fallback)
    content_signals = analyze_content_signals(subject, combined_body)

    # 1. Urgency keyword density
    urgency_stats = compute_keyword_density(tokens, text_lower, URGENCY_KEYWORDS)

    # 2. Imperative / command rate
    command_stats = compute_imperative_command_rate(sentences)

    # 3. Authority-tone signals
    authority_stats = compute_authority_tone_signals(text_lower, tokens)

    # 4. Financial & Credential terminology densities (two separate lists)
    financial_stats = compute_keyword_density(tokens, text_lower, FINANCIAL_KEYWORDS)
    credential_stats = compute_keyword_density(tokens, text_lower, CREDENTIAL_KEYWORDS)

    # 5. Second-person usage rate
    second_person_stats = compute_second_person_usage(tokens)

    # 6. Entity extraction
    entities = extract_named_entities(full_text)

    # 7. Impersonation signal (claimed identity vs sender & reply-to)
    impersonation_stats = compute_impersonation_signals(
        from_header=from_header,
        reply_to_header=reply_to_header,
        body_text=combined_body,
        subject=subject
    )

    # Calculate aggregate Content Risk Score
    content_risk_score = 0.0

    if content_signals["scoring_method"] == "trained_model":
        content_risk_score += content_signals["urgency_score"] * 0.20
        content_risk_score += content_signals["imperative_score"] * 0.15
        content_risk_score += content_signals["authority_score"] * 0.18
        content_risk_score += content_signals["financial_score"] * 0.15
        content_risk_score += content_signals["credential_score"] * 0.20
    else:
        if urgency_stats["density_per_100_words"] > 1.5:
            content_risk_score += 0.20
        elif urgency_stats["count"] > 0:
            content_risk_score += 0.10

        if command_stats["imperative_rate"] > 0.25:
            content_risk_score += 0.15
        elif command_stats["imperative_sentence_count"] > 0:
            content_risk_score += 0.08

        if authority_stats["is_authority_lure_present"]:
            content_risk_score += 0.18

        if financial_stats["count"] > 0:
            content_risk_score += 0.15
        if credential_stats["count"] > 0:
            content_risk_score += 0.20

    if second_person_stats["is_elevated"]:
        content_risk_score += 0.10

    if impersonation_stats["is_impersonation"]:
        content_risk_score += 0.35

    normalized_score = round(min(1.0, max(0.0, content_risk_score)), 3)

    return {
        "text_statistics": {
            "total_words": len(tokens),
            "total_sentences": len(sentences),
            "subject_length": len(subject)
        },
        "content_signals": content_signals,
        "urgency_keyword_density": urgency_stats,
        "imperative_command_rate": command_stats,
        "authority_tone_signals": authority_stats,
        "terminology_densities": {
            "financial_terms": financial_stats,
            "credential_terms": credential_stats
        },
        "second_person_usage": second_person_stats,
        "named_entities": entities,
        "impersonation_analysis": impersonation_stats,
        "aggregate_content_risk_score": normalized_score,
        "risk_level": "HIGH_RISK" if normalized_score >= 0.65 else ("SUSPICIOUS" if normalized_score >= 0.35 else "LOW_RISK")
    }
