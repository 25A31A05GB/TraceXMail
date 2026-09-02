import { EmailAnalysis } from '../types';

export const SAMPLE_ANALYSES: EmailAnalysis[] = [
  {
    id: 'sample-paypal-phish',
    sessionId: 'Analysis-2024-0718-B',
    trackingId: '88f2b7a1-8d2e-4e9e-bd9d-5a1f28e23921',
    name: 'Nazario Phish: PayPal Urgent Restriction',
    analyzedAt: '2024-07-18 13:12:15 UTC',
    headers: {
      subject: '[URGENT] Your PayPal Account Has Been Temporarily Restricted',
      from: '"PayPal Security Center" <service@paypal.com>',
      fromEmail: 'service@paypal.com',
      fromName: 'PayPal Security Center',
      to: 'victim@enterprise.corp',
      replyTo: '"PayPal Verification Team" <verification-support@secure-pp-auth.net>',
      returnPath: 'service@paypal-account-security-update.com',
      date: 'Mon, 18 Jul 2024 13:12:10 +0200',
      messageId: '<20240718111210.89123.PAYPAL.SECURE@paypal.com>',
      priority: '1 (Highest)',
      userAgent: 'Thunderbird 102.4.0 (Windows NT 10.0; Win64)',
      allHeaders: {
        'Delivered-To': 'victim@enterprise.corp',
        'Received-SPF': 'neutral (google.com: 89.144.20.12 is neither permitted nor denied by domain of service@paypal-account-security-update.com)',
        'Authentication-Results': 'mx.google.com; spf=neutral smtp.mailfrom=service@paypal-account-security-update.com; dkim=fail header.i=@paypal.com; dmarc=fail (p=REJECT) header.from=paypal.com',
        'From': '"PayPal Security Center" <service@paypal.com>',
        'Reply-To': '"PayPal Verification Team" <verification-support@secure-pp-auth.net>',
        'Return-Path': '<service@paypal-account-security-update.com>',
        'To': 'victim@enterprise.corp',
        'Subject': '[URGENT] Your PayPal Account Has Been Temporarily Restricted',
        'Date': 'Mon, 18 Jul 2024 13:12:10 +0200',
        'Message-ID': '<20240718111210.89123.PAYPAL.SECURE@paypal.com>',
        'MIME-Version': '1.0',
        'Content-Type': 'text/html; charset="UTF-8"',
        'X-Priority': '1 (Highest)',
        'X-Originating-IP': '[185.220.101.5]',
      },
    },
    auth: {
      spf: {
        status: 'FAIL',
        record: 'v=spf1 ip4:89.144.20.0/24 -all',
        ip: '185.220.101.5',
        domain: 'paypal.com',
        details: 'Sender IP 185.220.101.5 is not authorized by paypal.com SPF record',
      },
      dkim: {
        status: 'FAIL',
        selector: 's=20210512',
        domain: 'paypal.com',
        details: 'Body hash verification failed: bh=X8d9f+12k3... mismatch',
      },
      dmarc: {
        status: 'REJECT',
        policy: 'p=reject; sp=reject; pct=100',
        domain: 'paypal.com',
        details: 'Both SPF and DKIM failed alignment with From: header domain paypal.com',
      },
      arc: {
        status: 'FAIL',
      },
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'unknown (185.220.101.5)',
        fromIp: '185.220.101.5',
        byHost: 'mail.paypal-account-security-update.com',
        protocol: 'ESMTP (Postfix)',
        timestamp: '13:12:10 UTC',
        delaySec: 2,
        city: 'Sofia',
        country: 'Bulgaria',
        countryCode: 'BG',
        lat: 42.6977,
        lng: 23.3219,
        asn: 'AS200548',
        org: 'Zettahost Cyber Ltd',
        reverseDns: 'tor-exit-node.bg.zettahost.net',
        abuseScore: 88,
        isBlacklisted: true,
        isProxyOrVpn: true,
        isOrigin: true,
        geonameId: 732800,
        continentCode: 'EU',
        continentName: 'Europe',
        timeZone: 'Europe/Sofia',
        isInEuropeanUnion: true,
        accuracyRadius: 10,
        maxmindVerified: true,
        maxmindSource: 'backend/data/maxmind/GeoLite2-City-Locations-en.csv',
        maxmindCopyright: 'Database and Contents Copyright (c) 2026 MaxMind, Inc.',
        maxmindLicense: "MaxMind GeoLite End User License Agreement (CC BY 4.0 GeoNames)",
        lookupMethod: 'MaxMind GeoLite2 Offline Database (Local Real Data)'
      },
      {
        hopNumber: 2,
        fromHost: 'mail.paypal-account-security-update.com',
        fromIp: '89.144.20.12',
        byHost: 'mx.google.com',
        protocol: 'ESMTP',
        timestamp: '13:12:14 UTC',
        delaySec: 4,
        city: 'Frankfurt',
        country: 'Germany',
        countryCode: 'DE',
        lat: 50.1109,
        lng: 8.6821,
        asn: 'AS24940',
        org: 'Hetzner Online GmbH',
        reverseDns: 'static.89-144-20-12.clients.your-server.de',
        abuseScore: 32,
        isBlacklisted: false,
        isProxyOrVpn: false,
      },
      {
        hopNumber: 3,
        fromHost: 'mx.google.com',
        fromIp: '172.217.194.27',
        byHost: 'internal-filter.enterprise.corp',
        protocol: 'TLSv1.3',
        timestamp: '13:12:15 UTC',
        delaySec: 1,
        city: 'Ashburn',
        country: 'United States',
        countryCode: 'US',
        lat: 39.0438,
        lng: -77.4874,
        asn: 'AS15169',
        org: 'Google LLC',
        reverseDns: 'mail-sor-f27.google.com',
        abuseScore: 0,
        isBlacklisted: false,
        isProxyOrVpn: false,
      },
    ],
    urls: [
      {
        url: 'https://paypal-account-security-update.com/signin?id=99281',
        defangedUrl: 'hxxps://paypal-account-security-update[.]com/signin?id=99281',
        domain: 'paypal-account-security-update.com',
        status: 'MALICIOUS',
        virustotalScore: '24/88 Engines',
        category: 'Credential Harvesting / Phishing',
        redirectsTo: 'http://185.220.101.5/auth/login.php',
      },
      {
        url: 'https://bit.ly/3gX992PaypalSec',
        defangedUrl: 'hxxps://bit[.]ly/3gX992PaypalSec',
        domain: 'bit.ly',
        status: 'MALICIOUS',
        virustotalScore: '18/88 Engines',
        category: 'Obfuscated Phishing Shortener',
        redirectsTo: 'https://paypal-account-security-update.com/signin',
      },
      {
        url: 'https://www.paypal.com/us/smarthelp/contact-us',
        defangedUrl: 'hxxps://www.paypal[.]com/us/smarthelp/contact-us',
        domain: 'paypal.com',
        status: 'CLEAN',
        virustotalScore: '0/88 Engines',
        category: 'Legitimate Decoy Link',
      },
    ],
    attachments: [
      {
        filename: 'Statement_Restriction_Notice.html',
        size: '14.2 KB',
        mimeType: 'text/html',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        md5: 'd41d8cd98f00b204e9800998ecf8427e',
        status: 'MALICIOUS',
        vtDetection: '38/72 Engines (Phishing Form)',
      },
    ],
    heuristics: [
      {
        id: 'h1',
        title: 'Display Name vs Return-Path Mismatch',
        severity: 'CRITICAL',
        description: 'Header claims "PayPal" (@paypal.com), but envelope Return-Path is @paypal-account-security-update.com and Reply-To is @secure-pp-auth.net',
        triggered: true,
      },
      {
        id: 'h2',
        title: 'Tor Exit Node / Bulletproof IP Relay',
        severity: 'CRITICAL',
        description: 'Origin hop 185.220.101.5 is an active Tor exit node with AbuseIPDB confidence score 88%',
        triggered: true,
      },
      {
        id: 'h3',
        title: 'DMARC Enforcement Violation',
        severity: 'CRITICAL',
        description: 'Domain paypal.com specifies p=reject; message failed both SPF and DKIM cryptographic alignment',
        triggered: true,
      },
      {
        id: 'h4',
        title: 'Urgency & Account Restriction Trigger Words',
        severity: 'HIGH',
        description: 'Subject contains "[URGENT] Your PayPal Account Has Been Temporarily Restricted" aiming to force immediate victim reaction',
        triggered: true,
      },
      {
        id: 'h5',
        title: 'HTML Form / Executable in Attachment',
        severity: 'HIGH',
        description: 'Contains standalone HTML payload with hidden JavaScript credential submission endpoints',
        triggered: true,
      },
    ],
    logs: [
      { id: 'l1', timestamp: '13:12:15.102', tag: 'INIT', message: 'Parsing raw RFC822 stream (3,191 bytes)' },
      { id: 'l2', timestamp: '13:12:15.140', tag: 'INFO', message: 'Hop extraction complete: 3 relays identified' },
      { id: 'l3', timestamp: '13:12:15.185', tag: 'DNS', message: 'Querying TXT record for paypal.com -> v=spf1 ip4:89.144... -all' },
      { id: 'l4', timestamp: '13:12:15.220', tag: 'SEC', message: 'SPF check failed: origin 185.220.101.5 not permitted' },
      { id: 'l5', timestamp: '13:12:15.275', tag: 'SEC', message: 'DKIM signature invalid: body hash does not match public key' },
      { id: 'l6', timestamp: '13:12:15.310', tag: 'SEC', message: 'DMARC policy evaluation: REJECT enforced' },
      { id: 'l7', timestamp: '13:12:15.420', tag: 'API', message: 'AbuseIPDB reputation query for 185.220.101.5: Score 88/100 (Blacklisted)' },
      { id: 'l8', timestamp: '13:12:15.540', tag: 'API', message: 'VirusTotal URL scan: bit.ly/3gX992PaypalSec flagged 24/88' },
      { id: 'l9', timestamp: '13:12:15.610', tag: 'ML', message: 'Scikit-Learn Random Forest ensemble: 0.984 probability PHISH' },
      { id: 'l10', timestamp: '13:12:15.680', tag: 'GRAPH', message: 'NetworkX adjacency map: Bulgaria (BG) -> Germany (DE) -> US (Ashburn)' },
      { id: 'l11', timestamp: '13:12:15.700', tag: 'ALERT', message: 'Automated SOC recommendation: BLOCK SENDER & PURGE INBOX', highlight: true },
    ],
    riskScore: 98,
    verdict: 'MALICIOUS PHISH',
    mlConfidence: 0.984,
    why: {
      why: 'Multi-vector forensic analysis confirmed a high-confidence credential phishing attack impersonating PayPal Security with Tor egress routing and spoofed authentication headers.',
      evidence_chain: [
        '1. Envelope From header claims @paypal.com while Return-Path resolves to lookalike domain @paypal-account-security-update.com.',
        '2. DKIM cryptographic signature failed body hash verification; SPF failed against official PayPal SPF records.',
        '3. First-hop origin relay resolved to 185.220.101.5 (Sofia, Bulgaria), an active Tor exit node with AbuseIPDB confidence score 88%.',
        '4. Extracted URL bit.ly/3gX992PaypalSec redirects to credential harvesting endpoint flagged by 24 VirusTotal security engines.',
        '5. Machine learning classifier evaluated text lure and header signals at 98.4% malicious probability.'
      ],
      confidence: 0.984,
      limitation: 'Attribution identifies technical attack modality, malicious infrastructure, and impersonated brand; does not identify the physical operator of the Tor exit relay.'
    },
    domain_intelligence: {
      status: "ok",
      domain: "paypal-account-security-update.com",
      from_cache: true,
      dns: {
        domain: "paypal-account-security-update.com",
        a: ["185.199.108.153"],
        aaaa: [],
        mx: [],
        ns: ["ns1.hostgator.com", "ns2.hostgator.com"],
        txt: [],
        spf: "",
        dmarc: ""
      },
      rdap: {
        domain: "paypal-account-security-update.com",
        registrar: "NameCheap, Inc.",
        creation_date: "2023-10-15T00:00:00Z",
        expiration_date: "2024-10-15T00:00:00Z",
        updated_date: "2023-10-15T00:00:00Z",
        domain_age_days: 14,
        is_newly_registered: true,
        nameservers: ["ns1.hostgator.com"],
        rdap_status: ["clientTransferProhibited"]
      },
      typosquatting: {
        is_typosquat: true,
        target_brand: "paypal.com",
        similarity_score: 0.95,
        is_exact_match: false,
        reasons: ["Brand 'paypal' embedded in suspicious lookalike domain"]
      },
      domain_age_days: 14,
      is_newly_registered: true,
      risk_flags: ["Newly Registered Domain", "Missing MX Record", "Missing SPF"]
    },
    maxmindIntelligence: {
      geonameId: 732800,
      city: "Sofia",
      region: "Sofia",
      country: "Bulgaria",
      countryCode: "BG",
      continentCode: "EU",
      continentName: "Europe",
      timeZone: "Europe/Sofia",
      isInEuropeanUnion: true,
      lat: 42.6977,
      lng: 23.3219,
      accuracyRadius: 10,
      asn: "AS200548",
      asnOrg: "Zettahost Cyber Ltd",
      sourceFile: "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
      copyright: "Database and Contents Copyright (c) 2026 MaxMind, Inc.",
      license: "MaxMind GeoLite End User License Agreement (incorporates GeoNames under CC BY 4.0)",
      isVerified: true,
      filesFound: [
        "backend/data/maxmind/COPYRIGHT.txt",
        "backend/data/maxmind/LICENSE.txt",
        "backend/data/maxmind/GeoLite2-City-Locations-en.csv",
        "backend/data/maxmind/GeoLite2-City-Blocks-IPv4.csv",
        "backend/data/maxmind/GeoLite2-ASN-Blocks-IPv4.csv"
      ]
    },
    originWhy: {
      why: 'Earliest reliable origin relay resolved to 185.220.101.5 in Sofia, Bulgaria (AS200548 - Zettahost Cyber Ltd), operating as an active Tor exit node.',
      evidence_chain: [
        '1. Traversed envelope Received headers from corporate MX backwards across trust boundaries.',
        '2. Discarded 0 forgeable internal hops; identified 185.220.101.5 as the client submission node.',
        '3. Verified reverse DNS (tor-exit-node.bg.zettahost.net) against Tor Project directory consensus.',
        '4. Cross-referenced AbuseIPDB blacklist telemetry showing 88% confidence of malicious activity.'
      ],
      confidence: 0.95,
      limitation: 'Reflects infrastructure geolocation of intermediate proxy node, not attacker physical location.'
    },
    attributionWhy: {
      why: 'Attributed to Domain Spoofing & Lookalike Impersonation campaign targeting financial credentials via anonymized Tor infrastructure.',
      evidence_chain: [
        '1. Fused 6 independent forensic vectors (cryptographic auth, BEC heuristics, domain typosquatting, threat intel, NLP ML, infrastructure).',
        '2. Evaluated deterministic hypothesis "spoofed_domain" with leading score 96.0/100.',
        '3. Corroborated with "anonymized_infrastructure" hypothesis score 88.0/100.'
      ],
      confidence: 0.96,
      limitation: 'Attribution reflects technical methodology; does not constitute legal proof of individual criminal identity.'
    },
    becWhy: {
      why: 'BEC engine triggered 2 high-risk rules (Credential Harvesting Link & Vendor Impersonation) with overall score 0.95.',
      evidence_chain: [
        '1. Detected credential submission form in attached HTML payload and body links.',
        '2. Detected high-urgency account restriction pretext ("[URGENT] Your PayPal Account Has Been Temporarily Restricted").',
        '3. Matched vendor brand "PayPal" against unaligned sending domain "paypal-account-security-update.com".'
      ],
      confidence: 0.95,
      limitation: 'Establishes deceptive linguistic intent and structural impersonation heuristics; does not verify account ownership.'
    },
    ai_narrative: {
      narrative: 'Automated forensic synthesis indicates a sophisticated credential harvesting campaign targeting enterprise PayPal users. The attacker forged the display name to impersonate "PayPal Security Center" while relaying through an active Tor exit node (185.220.101.5) in Sofia, Bulgaria. Both SPF and DKIM cryptographic checks failed against the authentic paypal.com domain policy (DMARC p=reject). Embedded URL bit.ly/3gX992PaypalSec directs to an unauthorized domain (paypal-account-security-update.com) registered 14 days prior on NameCheap. Immediate mitigation: purge from inboxes and block inbound traffic from AS200548.',
      model: 'llama-3.3-70b-versatile',
      source: 'Groq AI Narrative Engine',
      disclaimer: 'AI-generated narrative summary based on deterministic forensic telemetry. Verify independently before regulatory or legal submission.'
    },
    rawEml: `Delivered-To: victim@enterprise.corp
Received: by 10.216.86.136 with SMTP id v8cs107530wee;
        Mon, 18 Jul 2024 13:12:15 -0700 (PDT)
Received: from mail.paypal-account-security-update.com (89.144.20.12) by mx.google.com
        with ESMTP id c7si3819286wac.2024.07.18.13.12.14;
Received: from [192.168.1.104] (unknown [185.220.101.5])
	by mail.paypal-account-security-update.com (Postfix) with ESMTP id 4NzX9B1lKpz12b8
	for <victim@enterprise.corp>; Mon, 18 Jul 2024 13:12:10 +0200 (CEST)
Authentication-Results: mx.google.com;
       spf=neutral smtp.mailfrom=service@paypal-account-security-update.com;
       dkim=fail header.i=@paypal.com;
       dmarc=fail (p=REJECT) header.from=paypal.com
From: "PayPal Security Center" <service@paypal.com>
Reply-To: "PayPal Verification Team" <verification-support@secure-pp-auth.net>
Return-Path: <service@paypal-account-security-update.com>
To: victim@enterprise.corp
Subject: [URGENT] Your PayPal Account Has Been Temporarily Restricted
Date: Mon, 18 Jul 2024 13:12:10 +0200
Message-ID: <20240718111210.89123.PAYPAL.SECURE@paypal.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Priority: 1 (Highest)

<!DOCTYPE html>
<html>
<body>
<p>Dear Customer,</p>
<p>We detected suspicious activity on your account. Please confirm your identity immediately via <a href="https://bit.ly/3gX992PaypalSec">PayPal Resolution Center</a>.</p>
</body>
</html>`,
    summary: 'High-severity targeted phishing email impersonating PayPal Security. Employs lookalike domain redirection, Tor exit relay origin in Bulgaria, spoofed From header, and failed DMARC validation with 98.4% ML model confidence.',
  },
  {
    id: 'sample-citibank-wire',
    sessionId: 'Analysis-2024-0802-C',
    trackingId: 'c2199b00-47b1-46da-b7ae-247514a6e300',
    name: 'Nazario Phish: CitiBank Wire Transfer Authorization',
    analyzedAt: '2024-08-02 09:44:18 UTC',
    headers: {
      subject: 'Action Required: Pending Wire Transfer of $48,200.00 Ref #CT-88902',
      from: '"Citi Commercial Banking" <alerts@citi-secure-auth.org>',
      fromEmail: 'alerts@citi-secure-auth.org',
      fromName: 'Citi Commercial Banking',
      to: 'cfo@manufacturing-group.com',
      replyTo: 'wire-verification@citibank-support-desk.com',
      returnPath: 'bounce-handler@citi-secure-auth.org',
      date: 'Fri, 02 Aug 2024 09:43:55 +0000',
      messageId: '<88902.WIRE.ALERT.20240802@citi-secure-auth.org>',
      priority: '1 (Highest)',
      userAgent: 'Microsoft Outlook 16.0',
      allHeaders: {
        'Authentication-Results': 'mx.corporate.com; spf=softfail smtp.mailfrom=bounce-handler@citi-secure-auth.org; dkim=none; dmarc=none header.from=citi-secure-auth.org',
        'From': '"Citi Commercial Banking" <alerts@citi-secure-auth.org>',
        'Reply-To': 'wire-verification@citibank-support-desk.com',
        'Return-Path': '<bounce-handler@citi-secure-auth.org>',
        'To': 'cfo@manufacturing-group.com',
        'Subject': 'Action Required: Pending Wire Transfer of $48,200.00 Ref #CT-88902',
        'Date': 'Fri, 02 Aug 2024 09:43:55 +0000',
        'Message-ID': '<88902.WIRE.ALERT.20240802@citi-secure-auth.org>',
        'X-Originating-IP': '[194.26.29.112]',
      },
    },
    auth: {
      spf: {
        status: 'SOFTFAIL',
        record: 'v=spf1 ~all',
        ip: '194.26.29.112',
        domain: 'citi-secure-auth.org',
        details: 'IP 194.26.29.112 not explicitly listed in permissive ~all policy',
      },
      dkim: {
        status: 'NONE',
        selector: 'none',
        domain: 'citi-secure-auth.org',
        details: 'No DKIM signature found on outbound payload',
      },
      dmarc: {
        status: 'QUARANTINE',
        policy: 'p=quarantine; pct=100',
        domain: 'citi-secure-auth.org',
        details: 'Unregistered freshly created domain (< 48 hrs old)',
      },
      arc: {
        status: 'NONE',
      },
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'vps-194-26-29-112.datacenter.md',
        fromIp: '194.26.29.112',
        byHost: 'relay01.citi-secure-auth.org',
        protocol: 'ESMTPS',
        timestamp: '09:43:58 UTC',
        delaySec: 3,
        city: 'Chisinau',
        country: 'Moldova',
        countryCode: 'MD',
        lat: 47.0105,
        lng: 28.8638,
        asn: 'AS57523',
        org: 'AlexHost SRL',
        reverseDns: 'srv112.alexhost.md',
        abuseScore: 94,
        isBlacklisted: true,
        isProxyOrVpn: true,
        isOrigin: true,
      },
      {
        hopNumber: 2,
        fromHost: 'relay01.citi-secure-auth.org',
        fromIp: '194.26.29.112',
        byHost: 'mx1.corporate.com',
        protocol: 'ESMTPS',
        timestamp: '09:44:15 UTC',
        delaySec: 17,
        city: 'London',
        country: 'United Kingdom',
        countryCode: 'GB',
        lat: 51.5074,
        lng: -0.1278,
        asn: 'AS13335',
        org: 'Cloudflare Inc',
        reverseDns: 'mx-inbound.corporate.com',
        abuseScore: 0,
        isBlacklisted: false,
        isProxyOrVpn: false,
      },
    ],
    urls: [
      {
        url: 'https://citi-commercial-portal.auth-verification.top/wire-cancel?id=48200',
        defangedUrl: 'hxxps://citi-commercial-portal[.]auth-verification[.]top/wire-cancel?id=48200',
        domain: 'auth-verification.top',
        status: 'MALICIOUS',
        virustotalScore: '31/88 Engines',
        category: 'BEC / Wire Fraud Portal',
        redirectsTo: 'https://194.26.29.112/citi/login.htm',
      },
      {
        url: 'https://www.citi.com/privacy',
        defangedUrl: 'hxxps://www[.]citi[.]com/privacy',
        domain: 'citi.com',
        status: 'CLEAN',
        virustotalScore: '0/88 Engines',
        category: 'Legitimate Footer',
      },
    ],
    attachments: [
      {
        filename: 'WIRE_TRANSACTION_DETAILS_#48200.pdf.exe',
        size: '412.5 KB',
        mimeType: 'application/x-msdownload',
        sha256: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
        md5: '5f4dcc3b5aa765d61d8327deb882cf99',
        status: 'MALICIOUS',
        vtDetection: '52/70 Engines (AsyncRAT Loader)',
      },
    ],
    heuristics: [
      {
        id: 'h1',
        title: 'Double Extension Executable Attachment',
        severity: 'CRITICAL',
        description: 'Attachment uses deceptive ".pdf.exe" double extension to disguise Windows PE malware binary as a PDF document',
        triggered: true,
      },
      {
        id: 'h2',
        title: 'Business Email Compromise (BEC) Financial Pretext',
        severity: 'CRITICAL',
        description: 'Fabricated high-value wire transfer ($48,200.00) designed to induce panic cancellation click',
        triggered: true,
      },
      {
        id: 'h3',
        title: 'Newly Registered Lookalike Domain (.top TLD)',
        severity: 'HIGH',
        description: 'Domain auth-verification.top registered 2 days ago via privacy proxy registrar',
        triggered: true,
      },
      {
        id: 'h4',
        title: 'Bulletproof Hosting AS57523 (AlexHost Moldova)',
        severity: 'HIGH',
        description: 'Relay server hosted in high-abuse bulletproof hosting subnet known for hosting C2 infrastructure',
        triggered: true,
      },
    ],
    logs: [
      { id: 'l1', timestamp: '09:44:18.010', tag: 'INIT', message: 'Loaded EML file: wire_citi_phish.eml (488 KB)' },
      { id: 'l2', timestamp: '09:44:18.045', tag: 'DNS', message: 'Resolving domain citi-secure-auth.org: Created 2024-08-01' },
      { id: 'l3', timestamp: '09:44:18.110', tag: 'SEC', message: 'DKIM signature missing; SPF evaluated as SoftFail' },
      { id: 'l4', timestamp: '09:44:18.230', tag: 'API', message: 'VirusTotal hash query: AsyncRAT signature detected (52 engines)' },
      { id: 'l5', timestamp: '09:44:18.350', tag: 'ML', message: 'Financial Phishing Heuristic Vector: 0.992 Risk Weight' },
      { id: 'l6', timestamp: '09:44:18.410', tag: 'ALERT', message: 'CRITICAL: Double extension .pdf.exe payload detected', highlight: true },
    ],
    riskScore: 99,
    verdict: 'MALICIOUS PHISH',
    mlConfidence: 0.992,
    why: {
      why: 'High-severity BEC and malware delivery campaign delivering AsyncRAT loader with fabricated $48,200 wire authorization pretext from bulletproof hosting in Moldova.',
      evidence_chain: [
        '1. Attachment "WIRE_TRANSACTION_DETAILS_#48200.pdf.exe" uses double extension to camouflage Windows PE executable.',
        '2. VirusTotal hash telemetry identified AsyncRAT malware payload across 52 AV engines.',
        '3. Outbound domain citi-secure-auth.org was registered 2 days ago without DKIM signature (SPF SoftFail).',
        '4. Origin relay resolved to 194.26.29.112 (Chisinau, Moldova) on high-abuse bulletproof host AS57523 (AbuseIPDB 94%).',
        '5. High-pressure financial loss pretext ($48,200.00 wire transfer) designed to force emergency click.'
      ],
      confidence: 0.992,
      limitation: 'Identifies malware binary, bulletproof hosting infrastructure, and fraudulent pretext; does not establish actor true name.'
    },
    originWhy: {
      why: 'Earliest reliable origin relay resolved to 194.26.29.112 in Chisinau, Moldova (AS57523 - AlexHost SRL), a known bulletproof hosting network.',
      evidence_chain: [
        '1. Evaluated received hops backward from corporate MX inbound relay.',
        '2. Identified submission relay 194.26.29.112 with reverse DNS srv112.alexhost.md.',
        '3. AbuseIPDB confidence score 94% with 480+ recent abuse reports in AS57523.'
      ],
      confidence: 0.96,
      limitation: 'Identifies bulletproof server infrastructure hosting the malware staging endpoint, not physical actor location.'
    },
    attributionWhy: {
      why: 'Attributed to Direct Threat Actor Infrastructure / Known Bad Environment deploying AsyncRAT loader and BEC financial lures.',
      evidence_chain: [
        '1. Multi-vector fusion scored direct_actor_env hypothesis at 95.0/100.',
        '2. Corroborated with domain_spoofing score 92.0/100 and BEC urgent wire transfer pattern 96.0/100.'
      ],
      confidence: 0.97,
      limitation: 'Attribution characterizes threat group TTPs and infrastructure signature; does not establish legal perpetrator identity.'
    },
    becWhy: {
      why: 'BEC engine triggered 3 high-risk rules (Urgent Transfer Request, Fake Invoice / Wire Alert, Vendor Impersonation) with overall score 0.98.',
      evidence_chain: [
        '1. Triggered urgent wire transfer lure referencing $48,200.00 unauthorized transfer.',
        '2. Claimed Citibank Commercial brand while sending from newly registered lookalike domain citi-secure-auth.org.',
        '3. Reply-To header routed to third-party verification desk citibank-support-desk.com.'
      ],
      confidence: 0.98,
      limitation: 'Establishes financial fraud and social engineering patterns; does not verify corporate bank account ledger.'
    },
    ai_narrative: {
      narrative: 'High-severity Business Email Compromise (BEC) and malware dropper campaign impersonating Citibank Commercial Banking. The attack vector delivers an urgent financial notification ($48,200.00 wire transfer) with a double-extension attachment "WIRE_TRANSACTION_DETAILS_#48200.pdf.exe" embedding an AsyncRAT payload. The message originated from bulletproof infrastructure at 194.26.29.112 (AlexHost SRL, Moldova), failing SPF alignment against official banking records. SOC analyst action: isolate recipient host and initiate endpoint EDR scan.',
      model: 'llama-3.3-70b-versatile',
      source: 'Groq AI Narrative Engine',
      disclaimer: 'AI-generated narrative summary based on deterministic forensic telemetry. Verify independently before regulatory or legal submission.'
    },
    rawEml: `Authentication-Results: mx.corporate.com; spf=softfail; dkim=none; dmarc=none
From: "Citi Commercial Banking" <alerts@citi-secure-auth.org>
Reply-To: wire-verification@citibank-support-desk.com
To: cfo@manufacturing-group.com
Subject: Action Required: Pending Wire Transfer of $48,200.00 Ref #CT-88902
Date: Fri, 02 Aug 2024 09:43:55 +0000
Message-ID: <88902.WIRE.ALERT.20240802@citi-secure-auth.org>
Content-Type: multipart/mixed; boundary="----=_Part_9921_Citi"

------=_Part_9921_Citi
Content-Type: text/plain; charset=UTF-8

A wire transfer of USD $48,200.00 has been initiated from your corporate account.
If you did not authorize this, download the attachment or visit our portal immediately.
------=_Part_9921_Citi--`,
    summary: 'Critical BEC & Malware distribution attack posing as CitiBank Wire Alert. Carries an AsyncRAT malware binary disguised as a PDF attachment with a high-risk origin in Moldova.',
  },
  {
    id: 'sample-github-legit',
    sessionId: 'Analysis-2024-0820-A',
    trackingId: '10f44a99-92c1-45bc-8a33-9081e28da991',
    name: 'Legitimate: GitHub Security Alert',
    analyzedAt: '2024-08-20 16:02:11 UTC',
    headers: {
      subject: '[GitHub] A personal access token has been generated on your account',
      from: '"GitHub" <noreply@github.com>',
      fromEmail: 'noreply@github.com',
      fromName: 'GitHub',
      to: 'developer@myorganization.io',
      replyTo: 'noreply@github.com',
      returnPath: 'noreply@github.com',
      date: 'Tue, 20 Aug 2024 16:02:05 +0000',
      messageId: '<github/github/security/tokens/991204@github.com>',
      priority: '3 (Normal)',
      userAgent: 'GitHub Mailer Service',
      allHeaders: {
        'Delivered-To': 'developer@myorganization.io',
        'Authentication-Results': 'mx.google.com; dkim=pass header.i=@github.com header.s=pf2014; spf=pass (google.com: domain of noreply@github.com designates 192.30.252.204 as permitted sender) smtp.mailfrom=noreply@github.com; dmarc=pass (p=REJECT sp=REJECT dis=none) header.from=github.com',
        'DKIM-Signature': 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2014; t=1724169725; bh=xY9k2L...; b=M8j2...',
        'From': '"GitHub" <noreply@github.com>',
        'To': 'developer@myorganization.io',
        'Subject': '[GitHub] A personal access token has been generated on your account',
        'Date': 'Tue, 20 Aug 2024 16:02:05 +0000',
        'Message-ID': '<github/github/security/tokens/991204@github.com>',
        'X-GitHub-Recipient': 'developer',
      },
    },
    auth: {
      spf: {
        status: 'PASS',
        record: 'v=spf1 ip4:192.30.252.0/22 ip4:140.82.112.0/20 ~all',
        ip: '192.30.252.204',
        domain: 'github.com',
        details: 'Sender IP 192.30.252.204 verified in GitHub CIDR range',
      },
      dkim: {
        status: 'PASS',
        selector: 's=pf2014',
        domain: 'github.com',
        details: 'Cryptographic signature valid with 2048-bit RSA key',
      },
      dmarc: {
        status: 'PASS',
        policy: 'p=reject; sp=reject; pct=100',
        domain: 'github.com',
        details: 'Full SPF and DKIM domain alignment verified with From: github.com',
      },
      arc: {
        status: 'PASS',
      },
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'smtp.github.com (192.30.252.204)',
        fromIp: '192.30.252.204',
        byHost: 'mx.google.com',
        protocol: 'ESMTPS (TLSv1.3)',
        timestamp: '16:02:06 UTC',
        delaySec: 1,
        city: 'San Francisco',
        country: 'United States',
        countryCode: 'US',
        lat: 37.7749,
        lng: -122.4194,
        asn: 'AS36459',
        org: 'GitHub, Inc.',
        reverseDns: 'smtp.github.com',
        abuseScore: 0,
        isBlacklisted: false,
        isProxyOrVpn: false,
        isOrigin: true,
      },
      {
        hopNumber: 2,
        fromHost: 'mx.google.com',
        fromIp: '172.217.194.27',
        byHost: 'mail-sor-f27.google.com',
        protocol: 'ESMTPS',
        timestamp: '16:02:11 UTC',
        delaySec: 5,
        city: 'Mountain View',
        country: 'United States',
        countryCode: 'US',
        lat: 37.3861,
        lng: -122.0839,
        asn: 'AS15169',
        org: 'Google LLC',
        reverseDns: 'mail-sor-f27.google.com',
        abuseScore: 0,
        isBlacklisted: false,
        isProxyOrVpn: false,
      },
    ],
    urls: [
      {
        url: 'https://github.com/settings/tokens',
        defangedUrl: 'hxxps://github[.]com/settings/tokens',
        domain: 'github.com',
        status: 'CLEAN',
        virustotalScore: '0/88 Engines',
        category: 'Official Developer Portal',
      },
      {
        url: 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure',
        defangedUrl: 'hxxps://docs[.]github[.]com/en/authentication/keeping-your-account-and-data-secure',
        domain: 'github.com',
        status: 'CLEAN',
        virustotalScore: '0/88 Engines',
        category: 'Official Documentation',
      },
    ],
    attachments: [],
    heuristics: [
      {
        id: 'h1',
        title: 'Authentic Cryptographic Signatures',
        severity: 'INFO',
        description: 'DKIM signature signed by d=github.com with verified public key',
        triggered: false,
      },
      {
        id: 'h2',
        title: 'Envelope Alignment',
        severity: 'INFO',
        description: 'From and Return-Path domains match identically (github.com)',
        triggered: false,
      },
      {
        id: 'h3',
        title: 'Verified AS36459 Infrastructure',
        severity: 'INFO',
        description: 'Originating IP 192.30.252.204 belongs to official GitHub Inc. ASN',
        triggered: false,
      },
    ],
    logs: [
      { id: 'l1', timestamp: '16:02:11.002', tag: 'INIT', message: 'Ingesting legitimate signed mail: github_security.eml' },
      { id: 'l2', timestamp: '16:02:11.025', tag: 'DNS', message: 'Resolved SPF record for github.com: MATCH (192.30.252.204)' },
      { id: 'l3', timestamp: '16:02:11.040', tag: 'SEC', message: 'DKIM RSA-SHA256 signature PASS (selector: pf2014)' },
      { id: 'l4', timestamp: '16:02:11.070', tag: 'SEC', message: 'DMARC PASS (Strict Alignment satisfied)' },
      { id: 'l5', timestamp: '16:02:11.120', tag: 'ML', message: 'ML Classification: 0.002 probability PHISH (Legitimate)' },
      { id: 'l6', timestamp: '16:02:11.135', tag: 'INFO', message: 'All security posture metrics optimal' },
    ],
    riskScore: 2,
    verdict: 'LEGITIMATE',
    mlConfidence: 0.002,
    why: {
      why: 'Cryptographic authentication, strict domain alignment, and clean reputation telemetry confirm authentic notification email from GitHub Inc.',
      evidence_chain: [
        '1. Inbound relay 192.30.252.204 is authorized in official GitHub SPF record (v=spf1 ip4:192.30.252.0/22...).',
        '2. DKIM signature valid (s=pf2014, d=github.com) with 2048-bit RSA key verification.',
        '3. DMARC policy passed with 100% strict alignment to header From: github.com.',
        '4. All URLs point directly to official github.com domain with zero VirusTotal malicious detections.',
        '5. Machine learning classifier rated phishing probability at 0.002 (CLEAN).'
      ],
      confidence: 0.998,
      limitation: 'Validates cryptographic authenticity and network origin; does not confirm user account security status outside email scope.'
    },
    originWhy: {
      why: 'Origin relay resolved to official GitHub Inc. infrastructure (192.30.252.204) in San Francisco, CA (AS36459).',
      evidence_chain: [
        '1. Envelope Received header verified directly from smtp.github.com to mx.google.com.',
        '2. Origin IP 192.30.252.204 belongs to GitHub Inc. Autonomous System AS36459 with 0 abuse reports.'
      ],
      confidence: 0.99,
      limitation: 'Validates intermediate mail sending MTA infrastructure.'
    },
    attributionWhy: {
      why: 'Attributed as authentic, benign system notification from GitHub Inc.',
      evidence_chain: [
        '1. Multi-vector analysis found no malicious signals (Risk: 2/100).',
        '2. All 4 deterministic threat hypotheses scored below threshold (< 5/100).'
      ],
      confidence: 0.99,
      limitation: 'Reflects authentic communication verification.'
    },
    rawEml: `Delivered-To: developer@myorganization.io
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2014;
From: "GitHub" <noreply@github.com>
To: developer@myorganization.io
Subject: [GitHub] A personal access token has been generated on your account
Date: Tue, 20 Aug 2024 16:02:05 +0000
Message-ID: <github/github/security/tokens/991204@github.com>
Content-Type: text/plain; charset=UTF-8

Hey developer!
A new personal access token (classic) was recently generated on your account.
If this was you, you can safely ignore this email.
Review active tokens at: https://github.com/settings/tokens`,
    summary: 'Authentic, cryptographically validated notification from GitHub Inc. Passes SPF, DKIM, and DMARC with flawless envelope alignment and clean domain reputation.',
  },
  {
    id: 'sample-irs-fraud',
    sessionId: 'Analysis-2024-0825-D',
    trackingId: '55e81a33-d912-4c22-b918-091a998bc12a',
    name: 'Nazario Phish: IRS Direct Tax Refund Wire',
    analyzedAt: '2024-08-25 11:30:42 UTC',
    headers: {
      subject: 'INTERNAL REVENUE SERVICE: Notice of Unclaimed Tax Refund #IRS-9821',
      from: '"Internal Revenue Service" <tax-refunds@irs-gov-portal.org>',
      fromEmail: 'tax-refunds@irs-gov-portal.org',
      fromName: 'Internal Revenue Service',
      to: 'taxpayer@personal-email.com',
      replyTo: 'refund-claim-desk@irs-gov-portal.org',
      returnPath: 'bounce@irs-gov-portal.org',
      date: 'Sun, 25 Aug 2024 11:30:10 +0300',
      messageId: '<IRS.REFUND.NOTICE.20240825@irs-gov-portal.org>',
      priority: '1 (Highest)',
      userAgent: 'PHP/8.1 Mailer Daemon',
      allHeaders: {
        'Authentication-Results': 'mx.google.com; spf=fail smtp.mailfrom=bounce@irs-gov-portal.org; dkim=fail header.i=@irs.gov; dmarc=fail (p=REJECT) header.from=irs.gov',
        'From': '"Internal Revenue Service" <tax-refunds@irs-gov-portal.org>',
        'To': 'taxpayer@personal-email.com',
        'Subject': 'INTERNAL REVENUE SERVICE: Notice of Unclaimed Tax Refund #IRS-9821',
        'Date': 'Sun, 25 Aug 2024 11:30:10 +0300',
        'Message-ID': '<IRS.REFUND.NOTICE.20240825@irs-gov-portal.org>',
      },
    },
    auth: {
      spf: {
        status: 'FAIL',
        record: 'v=spf1 include:_spf.irs.gov -all',
        ip: '45.141.87.65',
        domain: 'irs.gov',
        details: 'IP 45.141.87.65 not authorized by official irs.gov SPF record',
      },
      dkim: {
        status: 'FAIL',
        selector: 's=2023tax',
        domain: 'irs.gov',
        details: 'Signature corrupted / no valid public key found on DNS',
      },
      dmarc: {
        status: 'REJECT',
        policy: 'p=reject; pct=100',
        domain: 'irs.gov',
        details: 'Official IRS domain mandates strict REJECT for unaligned relays',
      },
      arc: {
        status: 'FAIL',
      },
    },
    hops: [
      {
        hopNumber: 1,
        fromHost: 'dedicated-server-45-141-87-65.net',
        fromIp: '45.141.87.65',
        byHost: 'relay-inbound.irs-gov-portal.org',
        protocol: 'ESMTPA',
        timestamp: '11:30:15 UTC',
        delaySec: 5,
        city: 'Bucharest',
        country: 'Romania',
        countryCode: 'RO',
        lat: 44.4268,
        lng: 26.1025,
        asn: 'AS49981',
        org: 'WorldStream B.V.',
        reverseDns: 'host87-65.romania-vps.ro',
        abuseScore: 91,
        isBlacklisted: true,
        isProxyOrVpn: true,
        isOrigin: true,
      },
      {
        hopNumber: 2,
        fromHost: 'relay-inbound.irs-gov-portal.org',
        fromIp: '45.141.87.65',
        byHost: 'mx.google.com',
        protocol: 'ESMTP',
        timestamp: '11:30:40 UTC',
        delaySec: 25,
        city: 'Amsterdam',
        country: 'Netherlands',
        countryCode: 'NL',
        lat: 52.3676,
        lng: 4.9041,
        asn: 'AS15169',
        org: 'Google Ingest MX',
        reverseDns: 'mx-inbound-nl.google.com',
        abuseScore: 0,
        isBlacklisted: false,
        isProxyOrVpn: false,
      },
    ],
    urls: [
      {
        url: 'https://irs-direct-refund-claim.online/ssn-verify.php',
        defangedUrl: 'hxxps://irs-direct-refund-claim[.]online/ssn-verify.php',
        domain: 'irs-direct-refund-claim.online',
        status: 'MALICIOUS',
        virustotalScore: '41/88 Engines',
        category: 'SSN & Bank Credential Harvesting',
        redirectsTo: 'https://45.141.87.65/collect/post.php',
      },
    ],
    attachments: [],
    heuristics: [
      {
        id: 'h1',
        title: 'Government Agency Brand Impersonation',
        severity: 'CRITICAL',
        description: 'Impersonates IRS (.gov) using non-governmental .org and .online domains',
        triggered: true,
      },
      {
        id: 'h2',
        title: 'SSN & Tax Refund Social Engineering',
        severity: 'CRITICAL',
        description: 'Pretexts $1,840.00 unclaimed refund to extract Social Security numbers and bank routing credentials',
        triggered: true,
      },
      {
        id: 'h3',
        title: 'High Abuse Origin IP in Romania',
        severity: 'HIGH',
        description: 'Originating IP 45.141.87.65 reported in 320 spam/phishing incidents over 30 days',
        triggered: true,
      },
    ],
    logs: [
      { id: 'l1', timestamp: '11:30:42.010', tag: 'INIT', message: 'Ingesting irs_tax_wire.eml' },
      { id: 'l2', timestamp: '11:30:42.030', tag: 'DNS', message: 'Checking SPF for irs.gov: SENDER NOT PERMITTED' },
      { id: 'l3', timestamp: '11:30:42.080', tag: 'SEC', message: 'DMARC REJECT triggered on forged government From header' },
      { id: 'l4', timestamp: '11:30:42.150', tag: 'API', message: 'Threat Intel: Domain irs-direct-refund-claim.online flagged malicious' },
      { id: 'l5', timestamp: '11:30:42.220', tag: 'ML', message: 'Government Impersonation Risk index: 0.991 (Phish)' },
    ],
    riskScore: 97,
    verdict: 'MALICIOUS PHISH',
    mlConfidence: 0.991,
    why: {
      why: 'Government agency brand impersonation attack attempting to harvest SSN and bank credentials via a spoofed IRS tax refund lure originating from high-abuse infrastructure in Romania.',
      evidence_chain: [
        '1. Envelope From header claims official IRS brand while routing from unauthorized lookalike domain irs-gov-portal.org.',
        '2. Official irs.gov SPF and DMARC checks failed with strict REJECT policy enforcement.',
        '3. First-hop origin IP 45.141.87.65 in Bucharest, Romania (AS49981 - WorldStream B.V.) exhibits 91% AbuseIPDB blacklist score.',
        '4. Phishing URL irs-direct-refund-claim.online/ssn-verify.php flagged by 41 VirusTotal engines for credential harvesting.',
        '5. Machine learning classifier rated phishing probability at 99.1% based on government impersonation and financial lure features.'
      ],
      confidence: 0.991,
      limitation: 'Identifies fraudulent tax pretext and Romanian VPS staging; does not establish legal actor identity.'
    },
    originWhy: {
      why: 'Origin relay resolved to 45.141.87.65 in Bucharest, Romania (AS49981 - WorldStream B.V.), a high-abuse VPS hosting provider.',
      evidence_chain: [
        '1. Traversed received headers backward from corporate Google MX ingest relay.',
        '2. Identified submission node 45.141.87.65 with reverse DNS host87-65.romania-vps.ro.',
        '3. AbuseIPDB confidence score 91% with 320+ reported phishing incidents.'
      ],
      confidence: 0.94,
      limitation: 'Measures intermediate mail relay infrastructure, not actor physical location.'
    },
    attributionWhy: {
      why: 'Attributed to Domain Spoofing & Government Impersonation campaign targeting tax refund credentials.',
      evidence_chain: [
        '1. Multi-vector fusion scored spoofed_domain hypothesis at 96.0/100.',
        '2. Corroborated with direct_actor_env score 90.0/100.'
      ],
      confidence: 0.96,
      limitation: 'Attribution reflects technical attack modality and infrastructure indicators.'
    },
    becWhy: {
      why: 'BEC engine triggered 2 high-risk rules (Credential Harvesting Link & Vendor/Government Impersonation) with overall score 0.96.',
      evidence_chain: [
        '1. Identified $1,840.00 unclaimed direct deposit tax refund lure.',
        '2. Harvests SSN and banking routing numbers on external non-governmental domain.'
      ],
      confidence: 0.96,
      limitation: 'Establishes social engineering and credential harvesting heuristics; does not verify IRS filings.'
    },
    rawEml: `From: "Internal Revenue Service" <tax-refunds@irs-gov-portal.org>
To: taxpayer@personal-email.com
Subject: INTERNAL REVENUE SERVICE: Notice of Unclaimed Tax Refund #IRS-9821
Date: Sun, 25 Aug 2024 11:30:10 +0300

You have an unclaimed direct deposit refund of $1,840.00.
To submit direct deposit bank information, access the portal: https://irs-direct-refund-claim.online/ssn-verify.php`,
    summary: 'High-threat tax refund phishing attempt targeting SSN and banking routing numbers through a spoofed IRS brand and a malicious Romanian VPS relay.',
  },
];
