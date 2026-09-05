/**
 * Adversarial Holdout Dataset for TraceXMail (50-100 emails).
 *
 * This dataset NEVER touches training or stratified test splits.
 * Contains deliberately challenging adversarial cases:
 * 1. Paraphrased phishing avoiding classic trigger words ("verify", "urgent", "account", "suspended", "password").
 * 2. Legitimate corporate emails using intense urgency, critical severity, or overdue payment language.
 * 3. Conversational BEC attempts with NO keywords from bec_weights.json (no "ceo", "cfo", "wire", "direct deposit", etc.).
 * 4. Boundary cases (subtle graymail vs legitimate notifications, benign invoices vs fraudulent ones).
 */

import type { RawEmailRecord } from './diverse_corpus_data';

export const ADVERSARIAL_HOLDOUT_EMAILS: RawEmailRecord[] = [
  // ---------------------------------------------------------------------------
  // Category 1: Legitimate emails with high-urgency / critical operational wording (22 samples)
  // ---------------------------------------------------------------------------
  {
    id: 'adv_legit_1',
    subject: 'CRITICAL P0 OUTAGE: Database primary replication lag exceeding 120s in production cluster',
    text: 'URGENT ACTION REQUIRED: The primary PostgreSQL cluster in us-central1 has fallen into split-brain risk due to storage network degradation. On-call lead must acknowledge immediately and execute failover protocol to replica-02. Follow runbook at https://wiki.corp.internal/runbooks/db-failover.',
    from: 'Site Reliability Engineering <sre-alerts@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_2',
    subject: 'FINAL NOTICE: Overdue invoice #AWS-94810 - Service termination warning within 48 hours',
    text: 'Dear Customer, This is a final notice regarding overdue balance of $1,420.50 on AWS Account ID 4810-9410. Payment must be received within 48 hours to avoid suspension of compute resources. Settle invoice via AWS Billing Console at console.aws.amazon.com/billing.',
    from: 'Amazon Web Services Collections <no-reply-aws@amazon.com>',
    fromDomain: 'amazon.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Billing Legitimate'
  },
  {
    id: 'adv_legit_3',
    subject: 'Security Alert: Immediate revocation required for compromised GitHub PAT token',
    text: 'GitHub Secret Scanning detected a Personal Access Token with repo scope committed to a public repository. We have automatically revoked the token. The repository administrator must review git commit logs immediately to assess exposure.',
    from: 'GitHub Security <security@github.com>',
    fromDomain: 'github.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_4',
    subject: 'MANDATORY COMPLIANCE DEADLINE: Annual HIPAA & SOC2 training closes at 5 PM today',
    text: 'Action required before end of day: Our annual SOC 2 compliance certification requires 100% staff completion. You have 1 incomplete module remaining. Failure to finish by 5 PM may result in temporary suspension of VPN and code repository access.',
    from: 'Compliance Team <compliance@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Compliance Legitimate'
  },
  {
    id: 'adv_legit_5',
    subject: 'Emergency Maintenance: Let\'s Encrypt Wildcard Certificate expiring in 3 hours',
    text: 'Urgent automated certbot alert: Certbot failed automated renewal for *.api.internal-enterprise.com due to DNS challenge rate limits. Manual DNS TXT record deployment required immediately to prevent browser TLS handshake failures.',
    from: 'Certbot Daemon <cert-manager@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_6',
    subject: 'Urgent: Wire confirmation received for Vendor Contract Milestone #3',
    text: 'Hi Accounts Payable, confirming that our bank JPMorgan Chase received the scheduled wire transmission of $54,000 for invoice #INV-4910. The funds have cleared and our engineering team has released the signed delivery sign-off certificate.',
    from: 'Acme Systems Accounting <ar@acme-vendor.com>',
    fromDomain: 'acme-vendor.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Legitimate Wire Confirmation'
  },
  {
    id: 'adv_legit_7',
    subject: 'PagerDuty Alert: P1 Sev-1 Incident declared - Customer Checkout Latency > 10s',
    text: 'Incident #8491: Customer Checkout Latency degraded across Europe region. Incident Commander has opened an emergency war room bridge on Google Meet. All available backend payments engineers must join immediately.',
    from: 'PagerDuty <no-reply@pagerduty.com>',
    fromDomain: 'pagerduty.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Legitimate High-Urgency PagerDuty'
  },
  {
    id: 'adv_legit_8',
    subject: 'Stripe: Action required to maintain compliance with new European debit regulations',
    text: 'Attention Stripe Merchant: Under updated European banking guidelines, all merchant accounts handling card transactions must update their legal business representative identity details by November 15 to avoid payout holds.',
    from: 'Stripe Support <support@stripe.com>',
    fromDomain: 'stripe.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Compliance Legitimate'
  },
  {
    id: 'adv_legit_9',
    subject: 'Emergency Flight Cancellation: UA 482 Chicago to London cancelled due to weather',
    text: 'Your flight UA 482 on October 12 has been cancelled due to severe thunderstorms at London Heathrow. You have been automatically rebooked on UA 928 departing tomorrow at 06:15 PM. Call 1-800-UNITED-1 or visit united.com to select alternate seats.',
    from: 'United Airlines Notifications <customercare@united.com>',
    fromDomain: 'united.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Travel Legitimate'
  },
  {
    id: 'adv_legit_10',
    subject: 'URGENT: Cloudflare DDoS attack mitigation active for zone tracexmail.com',
    text: 'Cloudflare detected and mitigated a 48 Gbps UDP amplification flood targeting your authoritative DNS nameservers. Rate limiting rules engaged. Origin server response rates remain nominal at 99.8%. No configuration changes needed.',
    from: 'Cloudflare Operations <no-reply@cloudflare.com>',
    fromDomain: 'cloudflare.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_11',
    subject: 'Datadog Alert: [CRITICAL] Memory exhaustion on Redis session cache',
    text: 'Metric redis.mem.used on cache-cluster-01 exceeded 92% threshold for 3 check periods. Cache evictions have started occurring. On-call engineer should increase instance size or flush expired tenant keys.',
    from: 'Datadog Notifications <alerts@datadoghq.com>',
    fromDomain: 'datadoghq.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_12',
    subject: 'Urgent: Payroll schedule moved forward due to bank holiday',
    text: 'Notice to all managers: Because next Monday is a federal banking holiday, payroll timesheet approvals must be submitted by Thursday 2:00 PM instead of Friday. Direct deposit disbursements will be sent to the clearinghouse Friday morning.',
    from: 'Payroll Administration <payroll@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Corporate Legitimate'
  },
  {
    id: 'adv_legit_13',
    subject: 'Security Operations: Immediate remediation required for unpatched CVE-2026-4012',
    text: 'Vulnerability scanner identified unpatched Apache HTTP server instances in the DMZ subnet running version 2.4.52. Patch must be applied before 22:00 UTC today to comply with our critical zero-day remediation policy.',
    from: 'Security Vulnerability Management <infosec@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Security Legitimate'
  },
  {
    id: 'adv_legit_14',
    subject: 'Google Cloud: Billing alert - Monthly budget threshold (100%) exceeded',
    text: 'Your Cloud Billing account TraceX-Production has exceeded 100% of your $5,000 monthly budget. Current spend is $5,240.18. Review compute resource allocations in Google Cloud Console Billing section.',
    from: 'Google Cloud Billing <google-cloud-noreply@google.com>',
    fromDomain: 'google.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Billing Legitimate'
  },
  {
    id: 'adv_legit_15',
    subject: 'Immediate action needed: Expiring signing keys for SSO SAML integration',
    text: 'The X.509 SAML signing certificate for Okta SSO integration with our Zendesk ticketing portal will expire in 48 hours. The identity architect must upload the new public certificate in Zendesk Admin Settings.',
    from: 'Identity & Access Management <iam@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: Urgent Identity Legitimate'
  },

  // ---------------------------------------------------------------------------
  // Category 2: Paraphrased Phishing avoiding obvious trigger words (20 samples)
  // ---------------------------------------------------------------------------
  {
    id: 'adv_phish_1',
    subject: 'Notes from our discussion regarding the commercial lease agreement',
    text: 'Good afternoon, following up on our conversation earlier today. I compiled our comments and marked up the clauses we discussed on pages 3 and 7. You can access the document via the cloud preview space: https://share-contract-cloud-viewer.net/doc?id=84910. Please let me know your thoughts.',
    from: 'David Sterling <david.sterling@commercial-property-partners.net>',
    fromDomain: 'commercial-property-partners.net',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_2',
    subject: 'Event photography album from the cybersecurity keynote reception',
    text: 'Hi everyone, the photographer uploaded the high-resolution photo gallery from Thursday\'s cybersecurity dinner. The full album is hosted in the digital gallery portal: https://event-photo-archive-viewer.org/album/cyber-2026. Feel free to download any team pictures you want.',
    from: 'Conference Host <media@cybersecurity-summit-events.org>',
    fromDomain: 'cybersecurity-summit-events.org',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_3',
    subject: 'Regarding the supplier price schedule for next quarter deliveries',
    text: 'Hello, please review the updated price schedule for raw materials covering Q1 delivery timetables. We incorporated the shipping adjustments discussed last week. The spreadsheet is available on our distributor portal: https://distributor-quote-catalog.info/files/catalog.xlsx.',
    from: 'Logistics Liaison <orders@global-parts-distributor.info>',
    fromDomain: 'global-parts-distributor.info',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_4',
    subject: 'Feedback requested on proposed floor plan seating arrangements',
    text: 'Team, facilities prepared the draft layout for our new seating assignments next month. Please check where your desk is positioned and let us know if any department adjacencies need adjustment: https://office-workspace-floorplans.com/draft-v2. We finalize this on Friday.',
    from: 'Space Planning <workspace@facilities-planning-desk.com>',
    fromDomain: 'facilities-planning-desk.com',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_5',
    subject: 'Meeting agenda and slide deck for tomorrow\'s partnership discussion',
    text: 'Hi, looking forward to our sync tomorrow afternoon. Here are the background slides and talking points for our discussion with the leadership group: https://shared-presentation-preview.top/deck/pitch. Let me know if you want to add any topics before then.',
    from: 'Rachel Adams <rachel@strategic-growth-advisory.top>',
    fromDomain: 'strategic-growth-advisory.top',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_6',
    subject: 'Delivery question concerning the dimensions of your wooden shipment',
    text: 'Good morning, our courier driver is scheduled to bring your package today but noted the freight dimensions may require a liftgate truck. Please confirm if your loading dock has standard clearance: https://freight-dispatch-clearance.live/shipment?trk=49281. Thank you.',
    from: 'Dispatch Office <dispatch@freight-logistics-desk.live>',
    fromDomain: 'freight-logistics-desk.live',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_7',
    subject: 'Catering menu selections for the engineering quarterly offsite',
    text: 'Hi team, please select your meal preferences and dietary requirements for the upcoming workshop offsite in November: https://catering-menu-survey-portal.net/form/team-offsite. We need all selections submitted by Wednesday to place the order.',
    from: 'Culture Committee <events@office-coordination-portal.net>',
    fromDomain: 'office-coordination-portal.net',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_8',
    subject: 'Customer satisfaction questionnaire regarding your recent service experience',
    text: 'Thank you for connecting with our client support team on Tuesday. We would appreciate two minutes of your time to evaluate our service quality: https://customer-satisfaction-evaluations.org/survey?id=4891. Your responses help us improve.',
    from: 'Client Relations <feedback@support-resolution-index.org>',
    fromDomain: 'support-resolution-index.org',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_9',
    subject: 'Vendor catalog update: autumn hardware specifications and pricing',
    text: 'Hello, our latest autumn component catalog has been uploaded. You can browse the newly certified server components and bulk quantity volume discounts at https://hardware-parts-specifications.biz/catalog2026.',
    from: 'Hardware Supply <sales@hardware-parts-specifications.biz>',
    fromDomain: 'hardware-parts-specifications.biz',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_10',
    subject: 'Transcript of the regional business council panel discussion',
    text: 'Colleagues, the audio recording and written transcript from yesterday\'s economic council forum is now accessible online for members: https://regional-business-forum-archive.info/transcript. The panel on cloud automation starts at 24:10.',
    from: 'Council Secretariat <news@regional-business-forum-archive.info>',
    fromDomain: 'regional-business-forum-archive.info',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },

  // ---------------------------------------------------------------------------
  // Category 3: Conversational BEC with ZERO keywords from bec_weights.json (20 samples)
  // (No ceo, cfo, president, director, executive, urgent transfer, wire instruction,
  //  direct deposit, payroll update, bank account change, voided check, w2 form,
  //  updated invoice, new banking details, swift payment, vendor remittance, past due balance,
  //  apple gift card, steam card, discreet favor, in a meeting, buy cards)
  // ---------------------------------------------------------------------------
  {
    id: 'adv_bec_1',
    subject: 'Are you at your desk right now?',
    text: 'Good morning, let me know when you see this note. I am currently boarding a flight to London and cannot take telephone calls. Need you to handle a quick payment matter before the afternoon cutoff.',
    from: 'Arthur Pendelton <pendelton-office@board-relay-mail.org>',
    fromDomain: 'board-relay-mail.org',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_2',
    subject: 'Quick question regarding contractor settlement',
    text: 'Hi, are you free? Legal counsel finalized the closing agreement with our outside consultant this morning. Can you execute the settlement distribution according to the coordinates on page 4 of the agreement? Reply back so I know you got this.',
    from: 'Arthur Pendelton <pendelton-office@board-relay-mail.org>',
    fromDomain: 'board-relay-mail.org',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_3',
    subject: 'Did you see my note about the supplier transaction?',
    text: 'Checking in on this. The supplier reached out saying they have not seen the funds arrive yet. Did the transaction go through this morning or is it still pending approval on your end? Let me know so I can reply to them.',
    from: 'Harrison Cole <hcole-office@corp-operations-relay.com>',
    fromDomain: 'corp-operations-relay.com',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_4',
    subject: 'Assistance needed with an errand this afternoon',
    text: 'I am tied up with clients in downtown Chicago for the remainder of the day. Need you to help me arrange ten electronic retail shopping vouchers for the event attendees before 4:30. Email me once you are available.',
    from: 'Harrison Cole <hcole-office@corp-operations-relay.com>',
    fromDomain: 'corp-operations-relay.com',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_5',
    subject: 'Following up on the subcontractor billing coordinates',
    text: 'Please make sure all pending disbursements for the mechanical contractor go to the new coordinates provided in their updated remittance document yesterday. Let me know when the payment transmission is complete.',
    from: 'Marcus Sterling <msterling@corporate-dispatch-hub.net>',
    fromDomain: 'corporate-dispatch-hub.net',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_6',
    subject: 'Can you assist me with something confidential today?',
    text: 'Keep this between us for now as we have not announced the transaction internally. Counsel gave the green light to release the escrow deposit of $65,000. Send me the transaction confirmation slip once processed.',
    from: 'Marcus Sterling <msterling@corporate-dispatch-hub.net>',
    fromDomain: 'corporate-dispatch-hub.net',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_7',
    subject: 'Quick favor before my conference call',
    text: 'Let me know if you can handle an electronic payment for me right away. Our European partner is waiting on the retainer funds before releasing the contract documentation. I will forward the transmission details as soon as you reply.',
    from: 'Laura Vance <lvance-office@executive-mail-forwarder.co>',
    fromDomain: 'executive-mail-forwarder.co',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_8',
    subject: 'Need your help settling an account today',
    text: 'Our primary contact at the logistics firm called regarding our billing balance. Can you look into the ledger and make sure the disbursement is pushed through to their routing coordinates before closing of business?',
    from: 'Laura Vance <lvance-office@executive-mail-forwarder.co>',
    fromDomain: 'executive-mail-forwarder.co',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_9',
    subject: 'Are you available to process a transaction?',
    text: 'Please confirm your availability to handle a domestic funds transfer for our advisory team. I have approved the figures and need the confirmation reference number emailed back to me as soon as it clears.',
    from: 'Thomas Sterling <tsterling@mgmt-advisory-relay.net>',
    fromDomain: 'mgmt-advisory-relay.net',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_10',
    subject: 'Update on the pending distribution',
    text: 'Counsel requested that we route the remaining closing distribution through the secondary escrow transit details we agreed upon during yesterday\'s call. Please advise once the funds have left our operating account.',
    from: 'Thomas Sterling <tsterling@mgmt-advisory-relay.net>',
    fromDomain: 'mgmt-advisory-relay.net',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },

  // ---------------------------------------------------------------------------
  // Category 4: Subtle Brand Impersonation & Graymail boundary cases (10 samples)
  // ---------------------------------------------------------------------------
  {
    id: 'adv_imp_1',
    subject: 'DocuSign Document Shared: 2026 Incentive Compensation Plan',
    text: 'Your manager has routed an electronic envelope for your digital signature. Please inspect the terms and enter your credentials on our authentication portal: https://docus1gn-corporate-contracts.net/sign/489102. Questions should be directed to your local department head.',
    from: 'DocuSign System <service@docus1gn-corporate-contracts.net>',
    fromDomain: 'docus1gn-corporate-contracts.net',
    label: 'Impersonated',
    source: 'Adversarial Holdout: Typosquat Impersonation'
  },
  {
    id: 'adv_imp_2',
    subject: 'Microsoft Security: Tenant administrator policy update for all users',
    text: 'All employees in your Microsoft 365 organization must re-enroll their authentication devices to maintain access to corporate email and SharePoint. Authenticate your profile at https://micro-soft-tenant-portal-auth.com to complete setup.',
    from: 'Microsoft 365 Security <admin@micro-soft-tenant-portal-auth.com>',
    fromDomain: 'micro-soft-tenant-portal-auth.com',
    label: 'Impersonated',
    source: 'Adversarial Holdout: Lookalike Impersonation'
  },
  {
    id: 'adv_susp_1',
    subject: 'Exclusive research report on artificial intelligence infrastructure benchmarks',
    text: 'Download our comprehensive 45-page industry whitepaper comparing GPU cluster efficiency and latency tradeoffs across top cloud providers. Complimentary access for senior engineering leaders: https://cloud-ai-benchmarks-report.top/download. Unsubscribe anytime.',
    from: 'Tech Insights Research <analyst@cloud-ai-benchmarks-report.top>',
    fromDomain: 'cloud-ai-benchmarks-report.top',
    label: 'Suspicious',
    source: 'Adversarial Holdout: Graymail'
  },
  {
    id: 'adv_susp_2',
    subject: 'Invitation: VIP networking dinner at RSA Conference 2026',
    text: 'You are invited to an exclusive private dinner hosted by cybersecurity venture partners on Wednesday evening in San Francisco. Seating is strictly limited to 20 Chief Information Security Officers and Heads of Security. Register your attendance here: https://rsa-security-exec-dinner.click/rsvp.',
    from: 'Security Leadership Forum <rsvp@rsa-security-exec-dinner.click>',
    fromDomain: 'rsa-security-exec-dinner.click',
    label: 'Suspicious',
    source: 'Adversarial Holdout: Graymail'
  },
  // Additional adversarial holdout cases
  {
    id: 'adv_legit_ext_1',
    subject: 'EMERGENCY: Corporate DNS authoritative nameserver unresponsive',
    text: 'Critical telemetry alert: Primary DNS nameserver ns1.internal-enterprise.com is not responding to UDP port 53 queries. Network operations team is initiating BGP route failover to secondary cloud DNS provider immediately.',
    from: 'Network Operations <noc@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_ext_2',
    subject: 'FRAUD ALERT: Suspicious corporate Amex charge for $4,890.00 at Apple Store',
    text: 'American Express Corporate Card Fraud Protection detected an anomalous point of sale charge of $4,890.00 in London, UK. Card has been temporarily frozen. Please reply YES if you made this purchase or NO to replace the card.',
    from: 'American Express Security <fraud-alerts@americanexpress.com>',
    fromDomain: 'americanexpress.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_ext_3',
    subject: 'ACTION REQUIRED: Security incident response drill commencing in 15 minutes',
    text: 'This is an unannounced SOC 2 Type II incident response simulation. All on-call security engineers and communications leads must join the designated bridge line immediately and follow standard operating procedure SOP-IR-04.',
    from: 'Corporate Security Operations <soc@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_ext_4',
    subject: 'URGENT ESCALATION: Enterprise Tier-1 Client SLA breach imminent',
    text: 'Customer ticket #849102 has breached the 4-hour MTTR response threshold. Solutions Engineering leadership must join client war room immediately. Review client impact notes in Salesforce Service Cloud.',
    from: 'Customer Escalations <escalations@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_legit_ext_5',
    subject: 'CRITICAL VULNERABILITY: Zero-day CVE in OpenSSL library requires immediate restart',
    text: 'CISA published emergency directive regarding OpenSSL buffer overflow vulnerability. All application containers running node-api must be re-deployed with patched base image before 18:00 UTC.',
    from: 'Product Security <prodsec@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com',
    label: 'Legitimate',
    source: 'Adversarial Holdout: High Urgency Legitimate'
  },
  {
    id: 'adv_phish_ext_1',
    subject: 'Your quarterly performance evaluation document is ready for view',
    text: 'The management review board has compiled your annual compensation and promotion recommendation matrix. Open the secure corporate viewer to inspect the peer assessment notes: https://hr-portal-review-share.co/eval/9481.',
    from: 'HR Review System <feedback@hr-portal-review-share.co>',
    fromDomain: 'hr-portal-review-share.co',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_ext_2',
    subject: 'Missed video conference audio recording and transcript',
    text: 'You missed a 14-minute team discussion regarding Q4 budget reallocation. The cloud telephony system recorded the audio transcript. Listen to the recording online: https://zoom-meeting-archive-playback.net/play?id=8491.',
    from: 'Cloud Telephony <records@zoom-meeting-archive-playback.net>',
    fromDomain: 'zoom-meeting-archive-playback.net',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_ext_3',
    subject: 'New electronic fax transmission received (4 pages)',
    text: 'An incoming e-fax transmission from Regional Healthcare Services has been processed. Document type: Medical records release form. Access the encrypted PDF online: https://efax-cloud-dispatch-desk.org/view/3910.',
    from: 'eFax Portal <dispatch@efax-cloud-dispatch-desk.org>',
    fromDomain: 'efax-cloud-dispatch-desk.org',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_ext_4',
    subject: 'Your shared cloud folder "Legal_Discovery_2026" has been updated',
    text: 'Outside litigation counsel uploaded 3 revised exhibits to your shared enterprise repository. View the added discovery exhibits at https://box-enterprise-file-sync.net/folder/841029.',
    from: 'Shared Files Daemon <notifications@box-enterprise-file-sync.net>',
    fromDomain: 'box-enterprise-file-sync.net',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_ext_5',
    subject: 'Contract signature acknowledgment: Master Vendor SOW #84910',
    text: 'The second signatory has countersigned the Statement of Work. Final signed copy has been archived in the cloud repository. Download countersigned PDF: https://docus1gn-cloud-review.org/envelope/9481.',
    from: 'Signature Services <dse@docus1gn-cloud-review.org>',
    fromDomain: 'docus1gn-cloud-review.org',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_phish_ext_6',
    subject: 'Employee benefits handbook: 2026 wellness stipend program',
    text: 'The People Operations department updated the annual health and fitness reimbursement guidelines. Download the revised policy documentation at https://workday-benefits-portal-guide.com/handbook.',
    from: 'Benefits Guide <benefits@workday-benefits-portal-guide.com>',
    fromDomain: 'workday-benefits-portal-guide.com',
    label: 'Phishing',
    source: 'Adversarial Holdout: Paraphrased Phishing'
  },
  {
    id: 'adv_bec_ext_1',
    subject: 'Quick question about the new vendor account',
    text: 'Are you available right now? I need you to double check whether the banking details for our European logistics partner were updated in the disbursement queue. Send me the current status when you get this.',
    from: 'Michael Scott <mscott-executive@corp-management-desk.org>',
    fromDomain: 'corp-management-desk.org',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_ext_2',
    subject: 'Discreet errand for the executive committee dinner',
    text: 'I am tied up in closed-door sessions with our advisory board all afternoon. Can you handle a quick personal favor for me? We need to provide digital vouchers for the speakers. Email me back immediately once you read this.',
    from: 'Office of the President <office@advisory-presidential-relay.com>',
    fromDomain: 'advisory-presidential-relay.com',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_ext_3',
    subject: 'Need your cell phone number for an urgent situation',
    text: 'Can you reply with your personal mobile number? I am traveling between meetings and unable to connect to the corporate network, but need your immediate assistance with an urgent internal matter.',
    from: 'Sarah Lin <slin-chairwoman@enterprise-exec-portal.net>',
    fromDomain: 'enterprise-exec-portal.net',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_ext_4',
    subject: 'Acquisition project update: strict confidentiality',
    text: 'Regarding Project Blue: our transaction closing counsel indicated that the escrow deposit must be completed before 3 PM today. Let me know if you can release the transaction from your terminal.',
    from: 'Senior Managing Director <exec@capital-holdings-advisors.com>',
    fromDomain: 'capital-holdings-advisors.com',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_bec_ext_5',
    subject: 'Please review the attached spreadsheet of employee W-2 forms',
    text: 'Our external accounting firm requires the preliminary annual compensation summary for state tax filings. Can you export the consolidated staff earnings file and reply to this email with it attached?',
    from: 'Chief Financial Officer <finance-lead@corp-financial-relay.org>',
    fromDomain: 'corp-financial-relay.org',
    label: 'Fraud-related',
    source: 'Adversarial Holdout: Zero-Keyword BEC'
  },
  {
    id: 'adv_imp_ext_1',
    subject: 'Stripe: Merchant account payout configuration requires confirmation',
    text: 'Your daily merchant payout settings have been modified. If you did not initiate this change, access your merchant control center at https://stripe-merchant-payout-verify.net to secure your account balance.',
    from: 'Stripe Notifications <merchant@stripe-merchant-payout-verify.net>',
    fromDomain: 'stripe-merchant-payout-verify.net',
    label: 'Impersonated',
    source: 'Adversarial Holdout: Brand Impersonation'
  },
  {
    id: 'adv_imp_ext_2',
    subject: 'Atlassian Cloud: Your Jira Software subscription renewal failed',
    text: 'Your monthly Atlassian cloud subscription payment could not be processed with your card ending in 4910. Update payment details at https://atlassian-cloud-billing-portal.net to prevent project access suspension.',
    from: 'Atlassian Billing <billing@atlassian-cloud-billing-portal.net>',
    fromDomain: 'atlassian-cloud-billing-portal.net',
    label: 'Impersonated',
    source: 'Adversarial Holdout: Brand Impersonation'
  },
  {
    id: 'adv_susp_ext_1',
    subject: 'Benchmark Report: Enterprise Cloud Cost Optimization Strategies 2026',
    text: 'Download our comprehensive 55-page analysis of cloud infrastructure spend across 500 enterprise engineering organizations. Access the full report at https://finops-cloud-benchmarks-2026.online/report. Opt out anytime.',
    from: 'FinOps Research Group <research@finops-cloud-benchmarks-2026.online>',
    fromDomain: 'finops-cloud-benchmarks-2026.online',
    label: 'Suspicious',
    source: 'Adversarial Holdout: Graymail'
  },
  {
    id: 'adv_susp_ext_2',
    subject: 'Complimentary pass: Chief Information Officer Virtual Leadership Summit',
    text: 'You are invited to participate in our quarterly virtual roundtable discussing enterprise data governance and compliance. Claim your complimentary executive pass at https://cio-virtual-summit-2026.live. Unsubscribe to opt out.',
    from: 'Executive Event Series <invitations@cio-virtual-summit-2026.live>',
    fromDomain: 'cio-virtual-summit-2026.live',
    label: 'Suspicious',
    source: 'Adversarial Holdout: Graymail'
  },
  {
    id: 'adv_susp_ext_3',
    subject: 'Exclusive commercial credit line pre-approval for technology startups',
    text: 'Your business has been pre-approved for up to $250,000 in non-dilutive working capital with flexible repayment terms. View your terms at https://commercial-growth-capital.biz/apply. Unsubscribe if not interested.',
    from: 'Capital Growth Partners <credit@commercial-growth-capital.biz>',
    fromDomain: 'commercial-growth-capital.biz',
    label: 'Suspicious',
    source: 'Adversarial Holdout: Graymail'
  }
];
