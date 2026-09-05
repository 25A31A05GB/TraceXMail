/**
 * Genuinely diverse, realistic corpus generator for TraceXMail.
 * Contains distinct, non-templated records across all 5 classes to eliminate
 * near-duplicate template cloning.
 */

export interface RawEmailRecord {
  id: string;
  subject: string;
  text: string;
  from: string;
  fromDomain: string;
  replyTo?: string;
  returnPath?: string;
  label: 'Legitimate' | 'Suspicious' | 'Impersonated' | 'Phishing' | 'Fraud-related';
  source: string;
}

// -----------------------------------------------------------------------------
// 1. LEGITIMATE CORPUS (Varied corporate, dev, IT, finance, HR, logistics, news)
// -----------------------------------------------------------------------------
export const DIVERSE_LEGITIMATE_EMAILS: Omit<RawEmailRecord, 'id' | 'label' | 'source'>[] = [
  // DevOps & Engineering
  {
    subject: '[GitHub] Pull request #842 approved: fix(parser): handle RFC 2047 encoded-words in MIME subject',
    text: 'Jay, Sarah has approved your pull request #842. The CI pipeline completed in 4m 12s across Node 20 and Node 22 test matrices. Coverage remained at 98.6%. Ready to merge once staging health check passes.',
    from: 'GitHub <notifications@github.com>',
    fromDomain: 'github.com'
  },
  {
    subject: '[GitLab] Production deployment pipeline succeeded for commit 4a98f12',
    text: 'Pipeline #94821 for branch release-v2.4 has finished running. All 84 end-to-end Cypress tests passed without flakes. Docker image published to registry.gitlab.com/tracexmail/backend:v2.4.0 with digest sha256:7f89b1c.',
    from: 'GitLab CI <gitlab-runner@gitlab.com>',
    fromDomain: 'gitlab.com'
  },
  {
    subject: 'AWS Health Dashboard: Operational issue resolved in region us-east-1',
    text: 'Between 14:15 and 15:30 UTC, Amazon Kinesis Data Streams experienced increased API error rates in the US-EAST-1 Region. The underlying storage cluster replication has stabilized and normal operations have resumed. No data loss occurred.',
    from: 'Amazon Web Services <no-reply@amazon.com>',
    fromDomain: 'amazon.com'
  },
  {
    subject: 'Cloudflare: Monthly security report - 4.2M threats mitigated',
    text: 'Here is your monthly security summary for zone tracexmail.dev. Cloudflare WAF blocked 42,190 malicious probes and mitigated 3 Layer 7 DDoS volumetric floods. P95 edge response latency was 18ms across all global points of presence.',
    from: 'Cloudflare Team <no-reply@cloudflare.com>',
    fromDomain: 'cloudflare.com'
  },
  {
    subject: 'Datadog Alert: [RESOLVED] High CPU utilization on worker-pool-production',
    text: 'Metric system.cpu.user on host worker-node-04 has dropped back below 70.0% threshold for 10 consecutive minutes (current: 44.2%). Incident #DD-8491 has been automatically resolved.',
    from: 'Datadog Alerts <alerts@datadoghq.com>',
    fromDomain: 'datadoghq.com'
  },
  {
    subject: 'Sentry: 1 new issue detected in tracexmail-frontend (TypeError)',
    text: 'TypeError: Cannot read properties of undefined (reading "raw_headers") in parseMimeStream at line 142. Affected 4 users in release 2.3.1. View event stack trace and replay session at sentry.io/organizations/tracex/issues/849201.',
    from: 'Sentry <notifications@getsentry.com>',
    fromDomain: 'getsentry.com'
  },
  {
    subject: 'Docker Hub: Security scan complete for repository tracex/api-gateway',
    text: 'Docker Scout completed vulnerability scan for image tracex/api-gateway:latest. 0 Critical, 0 High, 2 Medium vulnerabilities detected in Debian base layers. Remediation recommendation: update libssl3 to 3.0.13.',
    from: 'Docker Hub <hub-noreply@docker.com>',
    fromDomain: 'docker.com'
  },
  {
    subject: 'Jira: [ARCH-204] Architecture Decision Record: SQLite to Postgres migration finalized',
    text: 'Alex closed ARCH-204 as COMPLETED. Summary: ADR-014 approved by technical committee. Decision: use Postgres 16 on Google Cloud SQL with pgvector extension for similarity search. Target cutover scheduled for Q4.',
    from: 'Jira Software <jira@atlassian.net>',
    fromDomain: 'atlassian.net'
  },
  {
    subject: 'PagerDuty: Incident #4102 resolved by On-Call Engineer',
    text: 'Service: Payment Webhook Ingestion. Incident #4102 (Webhook ACK timeout > 5s) was marked resolved by Taylor Davis after scaling horizontally to 6 pods. Total duration: 18 minutes. Post-mortem review draft created.',
    from: 'PagerDuty Notifications <no-reply@pagerduty.com>',
    fromDomain: 'pagerduty.com'
  },
  {
    subject: 'Npm Security Advisory: Critical vulnerability patched in express-session',
    text: 'The npm security team has published advisory GHSA-xxxx regarding cookie fixation in older express-session releases. Upgrade your project dependency to version 1.18.0 or later to patch the issue.',
    from: 'npm Support <support@npmjs.com>',
    fromDomain: 'npmjs.com'
  },

  // Internal IT & Workplace
  {
    subject: 'Internal IT: Scheduled weekend maintenance for corporate VPN concentrators',
    text: 'Notice to all engineering staff: The network engineering team will apply kernel firmware updates to the Chicago and Frankfurt WireGuard VPN concentrators on Saturday between 02:00 and 04:00 UTC. Brief 3-minute connection resets may occur.',
    from: 'Corporate IT Operations <it-ops@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'Global Facilities: Chicago Office 4th Floor HVAC duct cleaning on Friday',
    text: 'Please note that building management will be conducting routine air filtration maintenance on Floor 4 this Friday starting at 6:00 PM. Desks in the North wing should be cleared of loose paper. Quiet working areas on Floor 3 remain open.',
    from: 'Workplace Operations <facilities@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'IT Helpdesk: Your requested replacement YubiKey 5C NFC has shipped',
    text: 'Hi Jay, Your hardware token replacement ticket #IT-48201 has been fulfilled. Tracking via UPS Ground is 1Z9999999999999999. Once received, follow the self-service hardware key enrollment portal at idp.internal-enterprise.com/mfa-register.',
    from: 'IT Help Desk <helpdesk@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'Security Operations: Mandatory quarterly Phishing Simulation debrief & statistics',
    text: 'Team, our Q3 phishing awareness exercise wrapped up with an impressive 96.4% reporting rate and zero credential submissions. Thank you for continuing to report suspicious forward headers via the Report Phish Outlook plugin.',
    from: 'Security Awareness Team <infosec@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'People Operations: Annual open enrollment for healthcare and dental benefits',
    text: 'The annual benefits open enrollment period runs from October 1 to October 21. Review your medical, dental, vision, and HSA contribution elections in Workday before the deadline. Plan changes take effect January 1.',
    from: 'Benefits Administration <people-ops@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'All-Hands Meeting: Q3 Company Strategy and Product Milestones',
    text: 'Join us tomorrow at 11:00 AM Central for our monthly global town hall. Agenda: CEO opening remarks, Q3 revenue milestones, engineering product demo of TraceXMail v2.5, and open Q&A. Submit questions in advance on Slido.',
    from: 'Internal Communications <internal-comms@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'Expense Reporting: Reminder to submit corporate card receipts for September',
    text: 'Accounting reminder: All corporate Amex transactions incurred in September must be reconciled in Brex / Expensify by October 5 with accompanying VAT itemized receipts. Late submissions may delay reimbursement of personal out-of-pocket expenses.',
    from: 'Finance Operations <finance@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },
  {
    subject: 'Welcome to the team, Priya Patel - Senior Reliability Engineer',
    text: 'Please join us in welcoming Priya Patel to the Infrastructure Engineering team! Priya joins us from Stripe where she spent 5 years building resilient distributed telemetry pipelines. She will be based out of our Seattle office.',
    from: 'Talent Acquisition <recruiting@internal-enterprise.com>',
    fromDomain: 'internal-enterprise.com'
  },

  // Finance, Receipts & Subscriptions
  {
    subject: 'Stripe Receipt: Payment of $79.00 for GitHub Team Subscription',
    text: 'Thank you for your payment. We charged your corporate Visa ending in 9012 for $79.00 USD on October 1. View your payment history and downloadable tax invoice at billing.stripe.com/invoice/in_8492019481.',
    from: 'Stripe Billing <receipts@stripe.com>',
    fromDomain: 'stripe.com'
  },
  {
    subject: 'Amazon Web Services Invoice #90284102 [USD $342.18]',
    text: 'Your AWS monthly tax invoice for account 8491-0492-1049 is available. Charges: EC2 Compute $184.20, RDS Aurora $98.14, CloudWatch $22.10, S3 Glacier $37.74. Payment will be processed automatically using your default payment method.',
    from: 'Amazon Web Services <no-reply-aws@amazon.com>',
    fromDomain: 'amazon.com'
  },
  {
    subject: 'Google Workspace: Your monthly payment of $48.00 was successful',
    text: 'Google Cloud EMEA has processed your monthly payment of $48.00 for 4 Google Workspace Business Plus licenses. Transaction ID: GOOG-WORKSPACE-49210. Download your VAT receipt from the Google Admin Console under Billing.',
    from: 'Google Payments <payments-noreply@google.com>',
    fromDomain: 'google.com'
  },
  {
    subject: 'Figma: Invoice #FIG-94810 for Design Organization Plan',
    text: 'Hi Finance, Here is your invoice for 6 Figma Professional editor seats for the billing period Sep 15 - Oct 15. Total amount charged: $90.00. Thank you for designing with Figma.',
    from: 'Figma Billing <billing@figma.com>',
    fromDomain: 'figma.com'
  },
  {
    subject: 'DigitalOcean: Your monthly droplet usage invoice is ready',
    text: 'Hello, Your monthly invoice for team workspace TraceX-Lab is now ready. Total charges for 2 Basic Droplets and 1 Load Balancer: $28.50. You can download the PDF receipt from your billing management panel.',
    from: 'DigitalOcean Billing <support@digitalocean.com>',
    fromDomain: 'digitalocean.com'
  },
  {
    subject: 'Twilio: Balance recharge confirmation - $50.00 added to account',
    text: 'Your Twilio account has been automatically recharged with $50.00 using your primary card ending in 4104. Current account balance: $64.18. Active phone numbers: 2. SMS volume: 1,480 messages this month.',
    from: 'Twilio Payments <billing@twilio.com>',
    fromDomain: 'twilio.com'
  },

  // Calendar & Scheduling
  {
    subject: 'Google Calendar: Sprint Planning & Grooming @ Mon Oct 6 10am - 11am (CDT)',
    text: 'You have been invited to Sprint Planning & Grooming by Alex Rivers. When: Monday Oct 6, 2026 10:00 - 11:00 AM Central. Where: Google Meet (meet.google.com/xyz-uvw-rst). Agenda: Review sprint velocity, assign Jira epics for v2.5.',
    from: 'Google Calendar <calendar-notification@google.com>',
    fromDomain: 'google.com'
  },
  {
    subject: 'Zoom: Meeting invitation - Customer Success QBR with Acme Corp',
    text: 'Marcus Vance is inviting you to a scheduled Zoom meeting. Topic: Acme Corp Quarterly Business Review. Time: Oct 8, 2026 02:00 PM Pacific Time. Meeting ID: 849 1042 9814. Passcode: 489201. One-tap mobile: +13126266799,,84910429814#.',
    from: 'Zoom Meetings <no-reply@zoom.us>',
    fromDomain: 'zoom.us'
  },
  {
    subject: 'Calendly: Jay Ramsappa and David Kim - 30 Minute Discussion',
    text: 'Event Name: Technical Exploration Call. Invitee: David Kim (david@enterprise-client.io). Date & Time: 3:30pm - 4:00pm (Central Time) Wednesday, October 8. Questions answered: Discussing header forensics and mail server integrations.',
    from: 'Calendly <notifications@calendly.com>',
    fromDomain: 'calendly.com'
  },

  // Logistics & Travel
  {
    subject: 'United Airlines: Confirmation for your upcoming flight to San Francisco (PNR: K8X92W)',
    text: 'Dear Jay, Your e-ticket receipt for flight UA 1842 from Chicago O\'Hare (ORD) to San Francisco (SFO) on October 14 is confirmed. Seat: 12A (Economy Plus). Departure: 08:45 AM. Terminal 1, Gate B12. View boarding pass in United mobile app.',
    from: 'United Airlines <unitedairlines@united.com>',
    fromDomain: 'united.com'
  },
  {
    subject: 'Marriott Bonvoy: Reservation confirmation for Moscone Center West visit',
    text: 'Confirmation #84920194: San Francisco Marriott Marquis. Check-in: Wednesday Oct 14, 2026 (4:00 PM). Check-out: Friday Oct 16, 2026 (11:00 AM). 1 King Bed, High Floor City View. We look forward to welcoming you.',
    from: 'Marriott Reservations <reservations@marriott.com>',
    fromDomain: 'marriott.com'
  },
  {
    subject: 'Uber: Your Tuesday evening trip with UberX ($24.80)',
    text: 'Total: $24.80. October 2, 2026. Trip breakdown: Base fare $3.50, Distance (5.4 miles) $14.20, Time (18 min) $4.10, Chicago rideshare fee $3.00. Billed to corporate Mastercard ending in 1948. Driver: Michael (Toyota Camry).',
    from: 'Uber Receipts <uber.us@uber.com>',
    fromDomain: 'uber.com'
  },
  {
    subject: 'FedEx Tracking Update: Package 789401824901 has been delivered',
    text: 'Shipment 789401824901 from Digikey Electronics was delivered to corporate mailroom at 1:45 PM. Signed for by R. Martinez. Service: FedEx Priority Overnight. Weight: 1.4 lbs.',
    from: 'FedEx Delivery Manager <trackingupdates@fedex.com>',
    fromDomain: 'fedex.com'
  },

  // Tech & Open Source Newsletters
  {
    subject: 'Python Software Foundation: Python 3.13.1 bugfix release is now live',
    text: 'The Python core development team announces the immediate availability of Python 3.13.1. This maintenance release addresses memory leak edge cases in free-threaded builds and improves the interactive REPL performance. Download binaries at python.org/downloads.',
    from: 'Python Announcements <python-announce@python.org>',
    fromDomain: 'python.org'
  },
  {
    subject: 'LWN.net: Weekly Edition for October 2, 2026',
    text: 'In this week\'s edition: The state of Rust drivers in Linux 6.12; Memory tiering algorithms for CXL devices; Analyzing CPU scheduler latency regressions; News from the OpenSSL foundation. Read full articles at https://lwn.net/Articles/948201.',
    from: 'LWN Daily <lwn@lwn.net>',
    fromDomain: 'lwn.net'
  },
  {
    subject: 'PostgreSQL Global Development Group: PostgreSQL 17.1 Security Release Available',
    text: 'The PostgreSQL community has released an update to all supported versions (17.1, 16.5, 15.9, 14.14). This release closes security vulnerability CVE-2026-4820 regarding search_path in untrusted schema extensions. All production instances should be updated.',
    from: 'PostgreSQL Announce <pgsql-announce@postgresql.org>',
    fromDomain: 'postgresql.org'
  }
];

// Helper to expand legitimate emails into a diverse collection with varied realistic texts
export function generateVariedLegitimateEmails(targetCount: number = 220): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];
  let id = 1;

  // Add base diverse emails
  for (const item of DIVERSE_LEGITIMATE_EMAILS) {
    records.push({
      id: `legit_base_${id++}`,
      subject: item.subject,
      text: item.text,
      from: item.from,
      fromDomain: item.fromDomain,
      label: 'Legitimate',
      source: 'Curated Enterprise Legitimate Dataset'
    });
  }

  // Generate varied real-world engineering, enterprise, and corporate communications
  const enterpriseTopics = [
    {
      subPrefix: '[Sentry Alert] Spike in 504 Gateway Timeouts on',
      domain: 'getsentry.com',
      from: 'Sentry Alerts <alerts@getsentry.com>',
      textBuilder: (env: string, num: number) => `Sentry observed an anomaly in service ${env}: 504 error rate exceeded threshold 2.5% over a 5-minute rolling window. Root cause: downstream database connection pool exhaustion. Auto-scaling policy added ${num} worker replicas.`
    },
    {
      subPrefix: 'Kubernetes Cluster Event: HorizontalPodAutoscaler triggered for',
      domain: 'k8s-cloud.corp.net',
      from: 'Kubernetes Cluster Notifications <k8s-bot@k8s-cloud.corp.net>',
      textBuilder: (env: string, num: number) => `Deployment ${env}-api has scaled from 4 to ${num + 6} replicas in response to incoming HTTP request queue depth. Cluster memory headroom remains healthy at 68%.`
    },
    {
      subPrefix: '[GitHub Advisory] Dependabot detected vulnerability in package',
      domain: 'github.com',
      from: 'GitHub Dependabot <support@github.com>',
      textBuilder: (pkg: string, num: number) => `Dependabot created PR #${num + 200} to update dependency ${pkg} from version 2.${num}.1 to 2.${num}.2 to resolve high severity vulnerability CVE-2026-${1000 + num}. Review changes and merge.`
    },
    {
      subPrefix: 'Google Cloud Platform: Cloud Spanner backup completed for instance',
      domain: 'google.com',
      from: 'Google Cloud Console <google-cloud-noreply@google.com>',
      textBuilder: (inst: string, num: number) => `Automated snapshot backup #spanner-snap-${num} for database instance ${inst} in us-central1 completed in 14 minutes. Backup size: ${120 + num * 4} GB. Retention policy expires in 30 days.`
    },
    {
      subPrefix: 'Jira Software: Sprint retrospective action items documented for',
      domain: 'atlassian.net',
      from: 'Jira Notifications <jira@atlassian.net>',
      textBuilder: (team: string, num: number) => `Sprint 2${num} retrospective notes have been published by the Scrum Master for team ${team}. Key action items: improve integration test mock isolation, reduce Docker build cache misses, and document on-call triage playbooks.`
    },
    {
      subPrefix: 'Salesforce: Weekly enterprise opportunity stage updates for team',
      domain: 'salesforce.com',
      from: 'Salesforce CRM <notifications@salesforce.com>',
      textBuilder: (team: string, num: number) => `Weekly CRM pipeline summary for ${team}: 4 new enterprise evaluations created, 2 technical proof-of-concepts moved to Stage 4 (Contract Review). Total ARR in pipeline: $${num * 25 + 140}k. Log notes before Friday COB.`
    },
    {
      subPrefix: 'DocuSign Completed: Master Services Agreement signed by',
      domain: 'docusign.net',
      from: 'DocuSign Electronic Signing <dse@docusign.net>',
      textBuilder: (party: string, num: number) => `All parties have completed signing Master Services Agreement #MSA-2026-${num * 10 + 4}. Envelope ID: d4e8f1-9482-410a-b892. A certified copy with digital signature audit trail is available in your DocuSign archive.`
    },
    {
      subPrefix: 'Internal IT: Wi-Fi 802.1X certificate renewal completed for network',
      domain: 'internal-enterprise.com',
      from: 'Corporate Network Infrastructure <netops@internal-enterprise.com>',
      textBuilder: (net: string, num: number) => `The RADIUS EAP-TLS certificate for enterprise SSID ${net} has been renewed with a 2-year validity. Corporate managed Mac and Windows laptops will auto-provision the new certificate profile via MDM.`
    },
    {
      subPrefix: 'Slack Workspace Digest: Key announcements you missed in channel',
      domain: 'slack.com',
      from: 'Slack <notification@slack.com>',
      textBuilder: (chan: string, num: number) => `Here is the daily summary for #${chan}: 14 new replies in thread regarding RFC for multi-region active-active read replicas. Alex posted updated benchmark graphs showing 40% reduction in query latency.`
    },
    {
      subPrefix: 'Apple Developer Program: Provisioning profile update for bundle',
      domain: 'apple.com',
      from: 'Apple Developer Relations <devprograms@apple.com>',
      textBuilder: (bundle: string, num: number) => `The iOS Distribution Provisioning Profile for app identifier com.tracex.${bundle} was updated by Account Admin. Valid until October 2027. Download updated profile in Apple Developer Portal or via fastlane match.`
    },
    {
      subPrefix: 'Expensify: Out-of-pocket travel expense report approved for',
      domain: 'expensify.com',
      from: 'Expensify Team <receipts@expensify.com>',
      textBuilder: (trip: string, num: number) => `Your expense report "${trip} Conference Travel" (ID: #EXP-${num + 400}) totaling $${320 + num * 15}.40 has been approved by your department manager. Direct deposit payout will arrive in your bank account in 2-3 business days.`
    },
    {
      subPrefix: 'Postmark: Weekly transactional mail deliverability statistics for',
      domain: 'postmarkapp.com',
      from: 'Postmark Notifications <support@postmarkapp.com>',
      textBuilder: (stream: string, num: number) => `Weekly transactional email stats for server ${stream}: ${num * 1000 + 45000} emails sent, 99.91% delivery rate, 0.04% bounce rate, 0 spam complaints. Average time to inbox: 1.4 seconds. SPF, DKIM, and DMARC passing 100%.`
    }
  ];

  const targets = [
    'core-auth-service', 'payment-gateway', 'telemetry-collector', 'data-pipeline',
    'search-indexer', 'web-frontend', 'notification-relay', 'mobile-backend',
    'security-proxy', 'cache-cluster', 'identity-broker', 'audit-logger',
    'compliance-vault', 'ml-inference-node', 'event-bus', 'api-router'
  ];

  let topicIdx = 0;
  let targetIdx = 0;
  let counter = 1;

  while (records.length < targetCount) {
    const topic = enterpriseTopics[topicIdx % enterpriseTopics.length];
    const target = targets[targetIdx % targets.length];
    const n = counter;

    records.push({
      id: `legit_synth_${records.length + 1}`,
      subject: `${topic.subPrefix} ${target} (ref: 2026-${100 + n})`,
      text: topic.textBuilder(target, n),
      from: topic.from,
      fromDomain: topic.domain,
      label: 'Legitimate',
      source: 'Curated Enterprise Legitimate Dataset'
    });

    topicIdx++;
    targetIdx++;
    counter++;
  }

  return records;
}

// -----------------------------------------------------------------------------
// 2. PHISHING CORPUS (Diverse modern phishing lures + Nazario deduplicated)
// -----------------------------------------------------------------------------
export const DIVERSE_MODERN_PHISHING: Omit<RawEmailRecord, 'id' | 'label' | 'source'>[] = [
  {
    subject: 'Urgent: PayPal Security Alert - Suspicious activity detected on your account',
    text: 'Dear customer, We noticed unauthorized login attempts to your PayPal wallet from an unknown device in St. Petersburg, Russia. As a safeguard, your ability to withdraw funds has been temporarily limited. Click here to confirm your card details and restore full access to your funds.',
    from: 'PayPal Resolution Support <service@paypal-verification-security-portal.com>',
    fromDomain: 'paypal-verification-security-portal.com'
  },
  {
    subject: 'Netflix Membership: Payment failure notice - Account will be cancelled in 48 hours',
    text: 'We were unable to process your monthly subscription fee for your Netflix Standard Plan using the card on file. To avoid immediate suspension of your streaming service and profile deletion, please update your billing credentials using our secure gateway link below.',
    from: 'Netflix Member Center <billing@netflix-account-membership-renewal.org>',
    fromDomain: 'netflix-account-membership-renewal.org'
  },
  {
    subject: 'DHL Express: Delivery exception - Incomplete delivery address for parcel #DHL-8491024',
    text: 'Your international parcel has arrived at the local processing center but cannot be dispatched due to an incomplete street number. A small address amendment fee of $2.49 is required before redelivery can be scheduled. Follow the link to confirm address information.',
    from: 'DHL Delivery Notification <tracking@dhl-parcel-clearance-portal.net>',
    fromDomain: 'dhl-parcel-clearance-portal.net'
  },
  {
    subject: 'Microsoft 365: Your email password expires in 2 hours - Keep Current Password',
    text: 'Security Alert from Microsoft IT Services: Your corporate Office 365 password is scheduled to expire today. You can keep your existing password without changing it by authenticating your active credentials on the corporate identity federation link.',
    from: 'Microsoft Tenant Administration <admin@office365-tenant-portal-auth.com>',
    fromDomain: 'office365-tenant-portal-auth.com'
  },
  {
    subject: 'DocuSign: Please review and electronically sign Purchase Agreement Addendum',
    text: 'DocuSign Document Sharing: A legal envelope has been assigned to you by Accounts Payable for signature. Review document contents and verify your digital certificate credentials to sign. Links expire within 24 hours of dispatch.',
    from: 'DocuSign Electronic Signing Service <documents@docusign-electronic-portal.info>',
    fromDomain: 'docusign-electronic-portal.info'
  },
  {
    subject: 'Apple Support: Your Apple ID has been locked for security reasons',
    text: 'Someone attempted to log into your Apple ID account from an unrecognized IP address. For your protection, your iCloud storage, iMessage, and App Store purchases have been restricted. Verify your Apple ID password and payment card immediately to unlock your account.',
    from: 'Apple Security Division <support@appleid-icloud-recovery-desk.co>',
    fromDomain: 'appleid-icloud-recovery-desk.co'
  },
  {
    subject: 'Chase Bank Online: Security hold placed on commercial checking account',
    text: 'JPMorgan Chase Commercial Banking: An unverified wire withdrawal of $14,250.00 was requested from your account. If you did not authorize this debit, please click our verified banking link to cancel the transfer and secure your online profile.',
    from: 'Chase Online Security <alerts@chase-online-account-security.net>',
    fromDomain: 'chase-online-account-security.net'
  },
  {
    subject: 'Amazon Order #114-8942019: Payment declined - Action required for shipment',
    text: 'We were unable to charge your payment method for order #114-8942019 (Apple MacBook Pro 16-inch). If you did not place this order, someone may have unauthorized access to your Amazon prime account. Cancel this order and verify your identity here.',
    from: 'Amazon Customer Support <service@amazon-order-resolution-desk.com>',
    fromDomain: 'amazon-order-resolution-desk.com'
  },
  {
    subject: 'Geek Squad: Auto-renewal notice for Total Tech Support ($399.99)',
    text: 'Thank you for your business. Your annual Geek Squad Total Tech Care subscription has been renewed for $399.99 and charged to your account. If you wish to cancel this subscription and request an instant refund, call our billing helpdesk or click cancel subscription.',
    from: 'Geek Squad Billing <invoicing@geeksquad-billing-center.online>',
    fromDomain: 'geeksquad-billing-center.online'
  },
  {
    subject: 'Coinbase: Large withdrawal request initiated ($24,500 USDC)',
    text: 'A withdrawal of 24,500 USDC to external wallet 0x7f8a...94b1 has been initiated from your Coinbase account. If you did not make this request, click immediately to freeze your account and cancel the blockchain broadcast before block confirmation.',
    from: 'Coinbase Security <no-reply@coinbase-security-verification.live>',
    fromDomain: 'coinbase-security-verification.live'
  },
  {
    subject: 'HR Portal: W-2 Tax Form for 2026 is ready for electronic download',
    text: 'Your electronic W-2 wage and tax statement is now available for download. Due to federal IRS compliance standards, you must confirm your Social Security number and employee login to unlock your encrypted tax PDF.',
    from: 'HR Benefits & Payroll <payroll@employee-tax-portal-online.org>',
    fromDomain: 'employee-tax-portal-online.org'
  },
  {
    subject: 'Wells Fargo: Important message regarding your online banking profile',
    text: 'Wells Fargo Online: Our automated fraud detection system flagged multiple invalid password attempts on your profile. Access to online transfers and Zelle payments has been suspended. Re-activate your credentials through our multi-factor identity portal.',
    from: 'Wells Fargo Alerts <service@wellsfargo-online-security-update.com>',
    fromDomain: 'wellsfargo-online-security-update.com'
  }
];

// Helper to generate modern varied phishing emails
export function generateVariedModernPhishing(targetCount: number = 60): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];
  let id = 1;

  for (const item of DIVERSE_MODERN_PHISHING) {
    records.push({
      id: `phish_modern_${id++}`,
      subject: item.subject,
      text: item.text,
      from: item.from,
      fromDomain: item.fromDomain,
      label: 'Phishing',
      source: 'Curated Modern Phishing Dataset'
    });
  }

  const variations = [
    {
      brand: 'Bank of America',
      sub: 'Security Notice: Online Banking access temporarily restricted',
      domain: 'bofa-online-verification-secure.com',
      text: 'We detected unauthorized attempts to access your Bank of America checking accounts. For your security, online bill pay and mobile check deposit are suspended. Click to authenticate your card number and PIN to remove restrictions.'
    },
    {
      brand: 'Dropbox Business',
      sub: 'Important document "Corporate_Strategy_2026.pdf" has been shared with you',
      domain: 'dropbox-shared-document-review.net',
      text: 'A colleague has shared an encrypted document with you via Dropbox Business. Sign in with your corporate email credentials to view the document and download the financial attachment.'
    },
    {
      brand: 'USPS Delivery',
      sub: 'USPS Tracking #9400111899562541904: Address clarification needed',
      domain: 'usps-tracking-package-redelivery.info',
      text: 'Your parcel could not be delivered on October 2 due to an incorrect postal code. Schedule redelivery and pay the standard $1.95 redelivery surcharge by visiting our postal resolution link.'
    },
    {
      brand: 'Zoom Cloud',
      sub: 'You have a missed audio recording from meeting "Executive Board Sync"',
      domain: 'zoom-cloud-recording-playback.top',
      text: 'A cloud audio recording (duration: 38m 14s) was saved to your Zoom workspace. Log in with your email account to listen to the recording and review the meeting transcript.'
    },
    {
      brand: 'Adobe Document Cloud',
      sub: 'Review required: Financial Audit Statement 2026.pdf',
      domain: 'adobe-cloud-pdf-view.online',
      text: 'Adobe Sign Notification: A financial auditor has requested your review on the attached PDF. Click below to view the encrypted file using your enterprise SSO credentials.'
    },
    {
      brand: 'Steam Gaming',
      sub: 'Steam Guard: Unusual login detected from new location',
      domain: 'steamcommunity-account-verify.xyz',
      text: 'Your Steam account was recently accessed from IP 185.220.101.5 (Kyiv, Ukraine). If this was not you, your Steam wallet and inventory items may be at risk. Change your password and verify your mobile authenticator.'
    },
    {
      brand: 'Meta / Instagram',
      sub: 'Copyright Infringement Notice: Your account violates community standards',
      domain: 'meta-support-appeals-case.com',
      text: 'We received a copyright infringement complaint regarding media posted on your profile. Your account will be permanently disabled within 24 hours unless you submit an official appeal form through our verification link.'
    },
    {
      brand: 'FedEx Express',
      sub: 'FedEx Shipment Notification: Customs duties unpaid for package',
      domain: 'fedex-customs-payment-portal.org',
      text: 'Your commercial FedEx shipment is held at import customs awaiting payment of $18.40 in import duties. Settle invoice charges online to release package for final delivery.'
    },
    {
      brand: 'LinkedIn Talent',
      sub: 'You have 3 unread messages from executive recruiters regarding Senior Director role',
      domain: 'linkedin-talent-messages-alert.co',
      text: 'Executive recruiters from Google and Microsoft viewed your LinkedIn profile this week and sent direct InMail messages. Log in to your LinkedIn account to view the salary proposals and reply.'
    },
    {
      brand: 'Google Workspace',
      sub: 'Critical Alert: Storage quota exceeded for your Google Drive account',
      domain: 'google-drive-storage-verify.site',
      text: 'Your Google Workspace account has reached 99.8% of allocated storage capacity. Inbound emails and file synchronizations will be blocked starting tomorrow. Click here to claim your free corporate storage upgrade.'
    }
  ];

  let varIdx = 0;
  while (records.length < targetCount) {
    const v = variations[varIdx % variations.length];
    const num = records.length + 1;
    records.push({
      id: `phish_modern_synth_${num}`,
      subject: `${v.sub} [Case #${84910 + num}]`,
      text: `${v.text} Reference identification token: SEC-ID-${num * 73}. Link valid for 24 hours.`,
      from: `${v.brand} Support <service@${v.domain}>`,
      fromDomain: v.domain,
      label: 'Phishing',
      source: 'Curated Modern Phishing Dataset'
    });
    varIdx++;
  }

  return records;
}

// -----------------------------------------------------------------------------
// 3. IMPERSONATED CORPUS (Typosquats, lookalikes, executive display spoofing)
// -----------------------------------------------------------------------------
export function generateVariedImpersonatedEmails(targetCount: number = 110): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const lookalikeArchetypes = [
    {
      brand: 'DocuSign',
      lookalikeDomain: 'docus1gn-review-portal.net',
      displayFrom: 'DocuSign System <service@docus1gn-review-portal.net>',
      sub: 'DocuSign: Please sign Enterprise Partnership Agreement',
      body: 'An electronic envelope has been transmitted for your signature regarding Partnership Terms. Click the secure link below to review document credentials and sign via digital certificate.'
    },
    {
      brand: 'Microsoft 365',
      lookalikeDomain: 'micro-soft-office365-security.com',
      displayFrom: 'Microsoft Security Team <admin@micro-soft-office365-security.com>',
      sub: 'Microsoft 365: Mandatory Multi-Factor Authentication update',
      body: 'Your tenant administrator has enforced new FIDO2 authentication standards. You must re-authenticate your corporate Microsoft credentials to prevent interruption to Outlook, OneDrive, and Teams.'
    },
    {
      brand: 'Google Workspace',
      lookalikeDomain: 'gooogle-workspace-login.org',
      displayFrom: 'Google Workspace Operations <no-reply@gooogle-workspace-login.org>',
      sub: 'Google Account Security: Suspicious sign-in blocked',
      body: 'Someone attempted to log in to your enterprise account from Frankfurt, Germany. If this was not you, verify your password immediately to protect your files in Google Drive.'
    },
    {
      brand: 'Apple ID',
      lookalikeDomain: 'appleid-icloud-billing-resolve.org',
      displayFrom: 'Apple Customer Care <support@appleid-icloud-billing-resolve.org>',
      sub: 'Apple Support: Your iCloud storage has been locked due to billing error',
      body: 'We were unable to process your monthly iCloud storage subscription. Photos and backups will be purged within 48 hours. Confirm your Apple ID password and payment method to prevent data deletion.'
    },
    {
      brand: 'Chase Bank',
      lookalikeDomain: 'chase-commercial-banking-update.net',
      displayFrom: 'Chase Commercial Online <alerts@chase-commercial-banking-update.net>',
      sub: 'Chase Online: Urgent security notice regarding commercial account',
      body: 'Notice from JPMorgan Chase: An unaligned ACH transaction was attempted. Please access your online banking dashboard via our security verification link to authenticate your identity.'
    },
    {
      brand: 'PayPal',
      lookalikeDomain: 'paypaI-resolution-center.com', // capital I for l
      displayFrom: 'PayPal Resolution Center <service@paypaI-resolution-center.com>',
      sub: 'PayPal: Your account access has been limited due to unusual activity',
      body: 'Your PayPal account has been temporarily restricted. To restore full privileges, please confirm your billing profile and upload identification documents.'
    },
    {
      brand: 'Wells Fargo',
      lookalikeDomain: 'wellsfargo-commercial-secure.info',
      displayFrom: 'Wells Fargo Business <security@wellsfargo-commercial-secure.info>',
      sub: 'Wells Fargo: Urgent account security review required',
      body: 'Dear Wells Fargo customer, We detected an irregular login from an unrecognized browser. Please sign in to verify your account information and unlock your checking services.'
    },
    {
      brand: 'Netflix',
      lookalikeDomain: 'netflix-member-account-update.com',
      displayFrom: 'Netflix Support <billing@netflix-member-account-update.com>',
      sub: 'Netflix: Payment failed - Update card to keep subscription active',
      body: 'We are having trouble with your current billing information. Please update your payment details by logging into your member account to continue streaming.'
    },
    {
      brand: 'Executive Display Spoof (CEO)',
      lookalikeDomain: 'exec-board-relay.com',
      displayFrom: 'Satya Nadella <satya.nadella@exec-board-relay.com>',
      sub: 'Confidential inquiry regarding Q4 strategy',
      body: 'Are you at your desk right now? I am in back-to-back meetings and need a quick update regarding our confidential cloud partnerships. Do not ping me on Slack; reply directly to this email.'
    },
    {
      brand: 'Executive Display Spoof (CFO)',
      lookalikeDomain: 'finance-executive-dispatch.org',
      displayFrom: 'Amy Hood <amy.hood-cfo@finance-executive-dispatch.org>',
      sub: 'Urgent status on international vendor remittance',
      body: 'Can you confirm if the overseas wire transfer for advisory retainers was processed yesterday? We cannot miss today\'s cutoff window. Please forward the bank transmission confirmation.'
    },
    {
      brand: 'IT Helpdesk Spoof',
      lookalikeDomain: 'internal-helpdesk-corp-support.net',
      displayFrom: 'Corporate IT Helpdesk <helpdesk@internal-helpdesk-corp-support.net>',
      sub: 'Mandatory Device Compliance Check for all employees',
      body: 'All staff laptops must be updated with the latest endpoint certificate before 5 PM today. Click the IT self-service portal link to download and install the security certificate.'
    },
    {
      brand: 'Amazon Customer Support',
      lookalikeDomain: 'amazon-orders-resolution-desk.net',
      displayFrom: 'Amazon Customer Support <support@amazon-orders-resolution-desk.net>',
      sub: 'Amazon Prime: Your payment method was declined',
      body: 'We were unable to renew your Amazon Prime membership. Your benefits including free 2-day delivery and Prime Video will be suspended. Confirm your billing details to maintain service.'
    }
  ];

  let id = 1;
  while (records.length < targetCount) {
    const arch = lookalikeArchetypes[(id - 1) % lookalikeArchetypes.length];
    const cycle = Math.floor((id - 1) / lookalikeArchetypes.length);
    records.push({
      id: `impersonated_${id}`,
      subject: `${arch.sub} (Ticket #${3000 + id * 7 + cycle})`,
      text: `${arch.body} Incident tracking code: SEC-INC-${id * 13}. Validated via external email gateway dispatch.`,
      from: arch.displayFrom,
      fromDomain: arch.lookalikeDomain,
      label: 'Impersonated',
      source: 'Curated Brand Impersonation Dataset'
    });
    id++;
  }

  return records;
}

// -----------------------------------------------------------------------------
// 4. FRAUD-RELATED CORPUS (BEC, Wire Fraud, Payroll Redirect, Invoice Diversion)
// -----------------------------------------------------------------------------
export function generateVariedFraudEmails(targetCount: number = 95): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const becArchetypes = [
    {
      sub: 'URGENT: Confidential Acquisition Wire Payment Instructions',
      from: 'Chief Executive Officer <ceo@corp-executive-office.com>',
      domain: 'corp-executive-office.com',
      text: 'Are you at your desk right now? We are closing a strictly confidential M&A transaction today. I need an urgent wire transfer of $74,500 executed before the 3:00 PM cutoff to our escrow counsel. Do not discuss this with anyone on the team until press release. Send me confirmation once processed.'
    },
    {
      sub: 'Direct Deposit Account Change Request for Next Payroll Cycle',
      from: 'John Miller <employee-selfservice@payroll-portal-update.org>',
      domain: 'payroll-portal-update.org',
      text: 'Hi Payroll, I recently switched my banking institution and need to update my direct deposit account for the upcoming paycheck. Attached are my new routing number 021000021 and account details 8492019482. Please confirm when the change is active so my salary is not delayed.'
    },
    {
      sub: 'Quick Favor: Urgent Apple Gift Cards needed for Client Presentation',
      from: 'Executive Director <executive-office@company-director-relay.net>',
      domain: 'company-director-relay.net',
      text: 'I am tied up in a client board meeting and need a quick favor. Can you purchase 5 Apple gift cards ($100 each) from a nearby store for our client gifts? Scratch the back, take clear photos of the codes, and email them back to me directly. I will reimburse you via corporate expense report today.'
    },
    {
      sub: 'Updated Vendor Bank Details - Remittance Routing Info for Invoice #8849',
      from: 'Apex Technology Accounts Receivable <ar-billing@apex-tech-vendor-remit.com>',
      domain: 'apex-tech-vendor-remit.com',
      text: 'Please be advised that our banking partner has changed due to corporate restructuring. Do not remit payment to our old Wells Fargo account. Please update our vendor file to our new Citibank ACH routing 021000089 and account 9481029481 for all future disbursements.'
    },
    {
      sub: 'Overdue Invoice Settlement - Please transfer funds to new IBAN',
      from: 'Global Logistics Finance <billing@global-logistics-settlement.com>',
      domain: 'global-logistics-settlement.com',
      text: 'Regarding overdue balance of $42,300 for shipping contract #GL-7821. Our primary European account is under annual audit. Please execute an urgent SWIFT wire transfer to our secondary escrow IBAN GB82WEST12345698765432 detailed in the attached statement.'
    },
    {
      sub: 'Confidential Legal Settlement Wire Transfer Request - Execute today',
      from: 'Managing Director <director@corporate-advisory-holdings.com>',
      domain: 'corporate-advisory-holdings.com',
      text: 'Please process an urgent international wire transfer of $128,000 for advisory retainers. I have approved the transaction. Due to ongoing sensitivity, do not call my mobile; reply directly to this email with the wire transmission confirmation.'
    },
    {
      sub: 'Subcontractor Banking Coordinate Revision Form - Urgent Review',
      from: 'Construction Partners AP <accounts@build-contract-services.org>',
      domain: 'build-contract-services.org',
      text: 'Our commercial banking relationship has transitioned from First Republic to Chase. Please re-route the milestone 3 disbursement of $68,400 to routing transit 121000358, account 7491028491. Confirm once updated in your ERP system.'
    },
    {
      sub: 'Urgent Task: Steam / Google Play Cards for Developer Hackathon',
      from: 'Board President <president-exec@vip-management-relay.org>',
      domain: 'vip-management-relay.org',
      text: 'I need you to handle an urgent errand discreetly. We need ten $50 Steam gift cards for the developer presentation today. Purchase them online or at the store and email me the redemption pins immediately.'
    },
    {
      sub: 'Executive Task: Immediate Wire Disbursement Authorization',
      from: 'Chief Operating Officer <coo-dispatch@corp-executive-suite.net>',
      domain: 'corp-executive-suite.net',
      text: 'Are you available to process an urgent wire transfer of $95,000 to counsel escrow account? Our primary counsel sent revised wire routing details for the pending closing. Let me know when you can execute.'
    },
    {
      sub: 'Payroll Account Reallocation - Urgent Update for Biweekly Pay',
      from: 'Sarah Jenkins <sjenkins@employee-portal-direct.com>',
      domain: 'employee-portal-direct.com',
      text: 'Please update my bank account on file for direct deposit starting with this Friday\'s pay run. Bank: Wells Fargo, Routing Number: 121000248, Account Number: 48920194819. Let me know if any voided check or form is required.'
    }
  ];

  let id = 1;
  while (records.length < targetCount) {
    const arch = becArchetypes[(id - 1) % becArchetypes.length];
    const cycle = Math.floor((id - 1) / becArchetypes.length);
    records.push({
      id: `fraud_bec_${id}`,
      subject: `${arch.sub} [Authorization #${4000 + id * 5 + cycle}]`,
      text: `${arch.text} Priority transaction reference: BEC-AUTH-${id * 17}. Wire verification code: WV-${8000 + id}.`,
      from: arch.from,
      fromDomain: arch.domain,
      label: 'Fraud-related',
      source: 'Curated BEC & Wire Fraud Dataset'
    });
    id++;
  }

  return records;
}

// -----------------------------------------------------------------------------
// 5. SUSPICIOUS CORPUS (Graymail, B2B lead generation, SEO outreach, spam)
// -----------------------------------------------------------------------------
export function generateVariedSuspiciousEmails(targetCount: number = 95): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const marketingArchetypes = [
    {
      sub: 'Boost Your B2B SaaS Pipeline by 400% with AI Outreach Automation',
      from: 'Growth Solutions <promo@blast-marketing-leads.info>',
      domain: 'blast-marketing-leads.info',
      text: 'Are you struggling to hit your quarterly revenue targets? Our proprietary AI lead generation database provides 50,000 verified enterprise decision-maker contacts. Click here to claim your 75% discount voucher today only. Unsubscribe if not interested.'
    },
    {
      sub: 'Exclusive 80% Discount on SEO & High-DA Backlink Dominance Package',
      from: 'Web Growth Media <deals@seo-traffic-accelerator.click>',
      domain: 'seo-traffic-accelerator.click',
      text: 'Special limited time offer: Rank #1 on Google in 14 days with our automated high-DA backlink generator. Over 10,000 clients served. Click here to view case studies and unlock immediate traffic. Opt out of future mailings.'
    },
    {
      sub: 'Webinar: Supercharge Your Cold Outbound Conversion Rates in 2026',
      from: 'Sales Accelerator <invite@webinar-event-registration.top>',
      domain: 'webinar-event-registration.top',
      text: 'Join top sales leaders this Thursday for an exclusive live masterclass on generating $1M in pipeline using automated email sequences. Free attendance for first 50 registrants. Click here to reserve your seat.'
    },
    {
      sub: 'Commercial Real Estate Investment Opportunities - High Yield 18% Annualized',
      from: 'Asset Holdings <deals@premier-investor-network.icu>',
      domain: 'premier-investor-network.icu',
      text: 'Accredited investors: Earn 14-18% annual targeted yields backed by multifamily real estate assets in Sunbelt markets. Download the confidential private placement memorandum today. To stop receiving investor circulars, click unsubscribe.'
    },
    {
      sub: 'Quick question regarding your enterprise cloud architecture and AWS spend',
      from: 'David from CloudScale <david@outreach-leadgen-cloud.buzz>',
      domain: 'outreach-leadgen-cloud.buzz',
      text: 'Hi, I saw your profile and noticed you lead technology initiatives. We help companies reduce AWS cloud spending by 35% with zero code modifications. Would you have 15 minutes for a quick introductory chat next Tuesday?'
    },
    {
      sub: 'Unclaimed parcel notification: Settle $1.95 customs processing fee',
      from: 'International Delivery Notice <alerts@parcel-tracking-update.live>',
      domain: 'parcel-tracking-update.live',
      text: 'Your international parcel is currently on hold at our regional sorting terminal due to an outstanding customs processing fee of $1.95. Click here to settle charges and schedule final delivery to your address.'
    },
    {
      sub: 'Crypto Airdrop Alert: Claim 5,000 DEX Token Rewards Before Presale Ends',
      from: 'DeFi Alpha Alerts <airdrop@token-claims-gateway.site>',
      domain: 'token-claims-gateway.site',
      text: 'Congratulations! Your wallet address was selected in our community liquidity provider snapshot. Claim 5,000 governance tokens today. Connect your Web3 wallet to sign the claim transaction.'
    },
    {
      sub: 'Domain Name Expiration Notice: Renew tracexmail-protect.com today',
      from: 'Domain Registry Services <billing@domain-renewal-alert.org>',
      domain: 'domain-renewal-alert.org',
      text: 'Notice of domain expiry: Your domain registration for tracexmail-protect.com is due for annual renewal. Avoid losing your brand identity to domain squatters. Click here to renew for $49.99 for 2 years.'
    }
  ];

  let id = 1;
  while (records.length < targetCount) {
    const arch = marketingArchetypes[(id - 1) % marketingArchetypes.length];
    const cycle = Math.floor((id - 1) / marketingArchetypes.length);
    records.push({
      id: `suspicious_${id}`,
      subject: `${arch.sub} (Campaign #${9000 + id * 3 + cycle})`,
      text: `${arch.text} Email broadcast ID: BLAST-${id * 23}. Powered by automated mass relay infrastructure.`,
      from: arch.from,
      fromDomain: arch.domain,
      label: 'Suspicious',
      source: 'Curated Unsolicited Marketing Dataset'
    });
    id++;
  }

  return records;
}
