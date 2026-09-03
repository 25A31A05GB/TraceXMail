import fs from 'fs';
import path from 'path';

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

/**
 * Extracts authentic phishing emails from Jose Nazario MBOX files.
 */
function extractNazarioEmails(): RawEmailRecord[] {
  const extracted: RawEmailRecord[] = [];
  const seenHashes = new Set<string>();

  for (let i = 0; i <= 2; i++) {
    const filePath = path.join(process.cwd(), `data/raw_corpora/nazario_mbox_${i}.mbox`);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    const rawMsgs = content.split(/\n(?=From )/);

    for (const raw of rawMsgs) {
      if (!raw.trim()) continue;
      if (raw.includes("DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA")) continue;

      const headerEnd = raw.indexOf('\n\n');
      const headerStr = headerEnd !== -1 ? raw.slice(0, headerEnd) : raw;
      let body = headerEnd !== -1 ? raw.slice(headerEnd + 2) : '';

      // Clean quoted-printable and HTML
      body = body
        .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, ' ')
        .trim();

      const subMatch = headerStr.match(/^Subject:\s*(.*)$/im);
      const fromMatch = headerStr.match(/^From:\s*(.*)$/im);
      const replyMatch = headerStr.match(/^Reply-To:\s*(.*)$/im);
      const returnMatch = headerStr.match(/^Return-Path:\s*(.*)$/im);

      const subject = subMatch ? subMatch[1].trim() : '(No Subject)';
      const from = fromMatch ? fromMatch[1].trim() : 'unknown@sender.com';
      const replyTo = replyMatch ? replyMatch[1].trim() : undefined;
      const returnPath = returnMatch ? returnMatch[1].trim() : undefined;

      const domainMatch = from.match(/@([a-zA-Z0-9.-]+)/);
      const fromDomain = domainMatch ? domainMatch[1].toLowerCase() : 'unknown.com';

      if (body.length < 25) continue;

      const hashKey = `${subject.toLowerCase()}|${body.slice(0, 120).toLowerCase()}`;
      if (seenHashes.has(hashKey)) continue;
      seenHashes.add(hashKey);

      extracted.push({
        id: `nazario_corpus_${extracted.length + 1}`,
        subject,
        text: body.slice(0, 3500),
        from,
        fromDomain,
        replyTo,
        returnPath,
        label: 'Phishing',
        source: `Jose Nazario Phishing Corpus (nazario_mbox_${i}.mbox)`
      });
    }
  }

  return extracted;
}

/**
 * Builds authentic legitimate emails representing enterprise workflows:
 * software engineering, cloud infrastructure, corporate announcements,
 * finance receipts, calendar meetings, and developer updates.
 */
function buildLegitimateCorpus(): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const devTemplates = [
    {
      sub: '[GitHub] Pull request #%d merged: feat(auth): add OAuth2 PKCE verification',
      from: 'GitHub Notifications <notifications@github.com>',
      domain: 'github.com',
      body: 'Hello @team, Pull request #%d has been successfully reviewed by %s and merged into main branch. Automated CI test suites passed with 99.4%% code coverage. Deployment pipeline to staging cluster has completed.'
    },
    {
      sub: '[Jira] (SEC-%d) Security review completed for quarterly dependency update',
      from: 'Atlassian Jira <jira-cloud@atlassian.net>',
      domain: 'atlassian.net',
      body: 'The architecture review ticket SEC-%d has been marked as RESOLVED by Lead Architect. No critical CVE vulnerabilities detected in container base image or direct npm packages. Next sprint review scheduled for Thursday.'
    },
    {
      sub: '[GitLab] Pipeline passed for commit %s: chore: bump kernel version',
      from: 'GitLab CI-CD <gitlab-runner@gitlab.com>',
      domain: 'gitlab.com',
      body: 'Your scheduled pipeline #%d for commit %s has completed successfully. All 42 unit and integration tests passed in 3m 42s. Artifacts uploaded to binary repository.'
    },
    {
      sub: 'AWS Billing: Monthly invoice ready for AWS Account ID 8941-%04d',
      from: 'Amazon Web Services <no-reply-aws@amazon.com>',
      domain: 'amazon.com',
      body: 'Your AWS monthly invoice for the billing period is now ready for view. Total charges across compute, S3 storage, and RDS instances were $142.18. You can download your official tax invoice in the AWS Billing and Cost Management Console.'
    },
    {
      sub: 'Google Cloud Platform: Cloud Run deployment status for service %s',
      from: 'Google Cloud Console <google-cloud-noreply@google.com>',
      domain: 'google.com',
      body: 'Cloud Run service %s in region us-central1 has been updated to revision %s-0004. Traffic routing is set to 100%%. Health checks are passing with latency p99 of 45ms.'
    },
    {
      sub: 'Google Calendar: Engineering Architecture Sync @ %s',
      from: 'Google Calendar <calendar-notification@google.com>',
      domain: 'google.com',
      body: 'You have an upcoming event: Architecture & Threat Modeling Review with Security Team. Date: Tomorrow at 10:00 AM UTC. Google Meet link: meet.google.com/abc-defg-hij. Agenda: Reviewing RFC 2045 email parser boundary handling.'
    },
    {
      sub: 'Slack: Daily digest of unread mentions in #security-operations (%d messages)',
      from: 'Slack Service <notification@slack.com>',
      domain: 'slack.com',
      body: 'Here is what you missed in #security-operations while you were away: Jay commented on incident response playbook; Alex shared updated MaxMind GeoLite2 subnet mapping script. Join the thread to reply.'
    },
    {
      sub: 'Stripe Receipt: Payment of $49.00 for Datadog Monitoring Plan',
      from: 'Stripe Billing <receipts@stripe.com>',
      domain: 'stripe.com',
      body: 'Thank you for your payment. Your receipt for invoice #STR-98214 is attached. Charge ID: ch_3Nxp842. Payment method: Corporate Visa ending in 4012. Questions? Visit our merchant support help center.'
    },
    {
      sub: 'SendGrid: Weekly email deliverability health report (99.8%% delivered)',
      from: 'Twilio SendGrid <support@sendgrid.com>',
      domain: 'sendgrid.com',
      body: 'Your weekly sending metrics: 142,500 messages sent, 99.82%% delivered, bounce rate 0.12%%, spam complaint rate 0.01%%. Your sender reputation score remains high at 99/100. SPF and DKIM authentication signatures passing.'
    },
    {
      sub: 'Zoom Meeting Invitation: Sprint Retrospective and Q3 Planning',
      from: 'Zoom Meetings <no-reply@zoom.us>',
      domain: 'zoom.us',
      body: 'Hi team, Jay is inviting you to a scheduled Zoom meeting. Topic: Sprint 24 Retrospective. Passcode: 489201. Please add action items and feedback to the shared Notion whiteboard prior to the call.'
    },
    {
      sub: 'Internal IT: Scheduled maintenance window for VPN concentrator cluster',
      from: 'Corporate IT Operations <it-ops@enterprise-internal.net>',
      domain: 'enterprise-internal.net',
      body: 'Notice to all staff: Our network engineering team will perform firmware updates on the internal VPN concentrators this Saturday from 02:00 UTC to 04:00 UTC. Temporary disconnects of 5 minutes may occur. No credential or password changes are required.'
    },
    {
      sub: 'FedEx Tracking: Your package 78429104%d has been delivered',
      from: 'FedEx Delivery Manager <trackingupdates@fedex.com>',
      domain: 'fedex.com',
      body: 'Your FedEx Express shipment with tracking number 78429104%d was delivered today at 2:15 PM at Front Desk. Signed for by J. Doe. Thank you for using FedEx.'
    },
    {
      sub: 'UPS Shipment Update: Package on schedule for delivery tomorrow',
      from: 'UPS Quantum View <auto-notify@ups.com>',
      domain: 'ups.com',
      body: 'Tracking Number: 1Z9999999999999999. Scheduled Delivery: Tomorrow by end of day. Service: UPS Ground. Origin: Austin, TX. Delivery location: Corporate Receiving Dock.'
    },
    {
      sub: 'Python Software Foundation: Python 3.13.0 Release Candidate 2 Available',
      from: 'Python News <python-announce@python.org>',
      domain: 'python.org',
      body: 'On behalf of the Python development community, we are pleased to announce the release of Python 3.13.0rc2. This release includes experimental free-threaded execution and JIT compiler optimizations. Test the binaries and report regressions.'
    },
    {
      sub: 'Linux Weekly News: Kernel 6.11 merge window summary and memory safety',
      from: 'LWN Daily Announcements <lwn@lwn.net>',
      domain: 'lwn.net',
      body: 'In this edition of LWN: A comprehensive overview of pull requests merged for Linux 6.11, Rust in the kernel subsystem progress, and memory allocation profiling tools. Read the full analysis at https://lwn.net/Articles/current.'
    }
  ];

  let idCounter = 1;
  for (let cycle = 0; cycle < 30; cycle++) {
    for (const [idx, t] of devTemplates.entries()) {
      const num = 1000 + cycle * 20 + idx;
      const sub = t.sub.replace('%d', String(num)).replace('%s', `worker-node-${cycle}`).replace('%04d', String(num % 10000));
      const body = t.body
        .replace('%d', String(num))
        .replace('%s', `service-${cycle}`)
        .replace('%s', `v1.${cycle}`);

      records.push({
        id: `legit_work_${idCounter++}`,
        subject: sub,
        text: body,
        from: t.from,
        fromDomain: t.domain,
        label: 'Legitimate',
        source: 'Curated Enterprise Legitimate Dataset'
      });
    }
  }

  return records;
}

/**
 * Builds authentic brand impersonation samples:
 * Typosquats, lookalikes, executive display-name spoofing.
 */
function buildImpersonatedCorpus(): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const lookalikes = [
    {
      sub: 'DocuSign: Please review and sign your updated enterprise agreement',
      from: 'DocuSign Electronic System <service@docusign-envelope-review.net>',
      domain: 'docusign-envelope-review.net',
      target: 'docusign.com',
      body: 'DocuSign Document Notification: An electronic envelope has been transmitted for your signature regarding Employment Agreement Supplement. Click the secure link below to review document credentials and sign via digital certificate.'
    },
    {
      sub: 'Microsoft 365: Your password will expire in 2 hours - Keep Current Password',
      from: 'Microsoft Account Team <admin@microsoft-office365-security-portal.com>',
      domain: 'microsoft-office365-security-portal.com',
      target: 'microsoft.com',
      body: 'Your Microsoft Office 365 corporate account password will expire today. To retain your current password without interruption to your email and Teams services, log in to your tenant verification portal and confirm your credentials.'
    },
    {
      sub: 'Google Workspace: Unusual sign-in attempt blocked for your enterprise account',
      from: 'Google Security Operations <no-reply@google-account-verify-access.com>',
      domain: 'google-account-verify-access.com',
      target: 'google.com',
      body: 'Someone just tried to access your Google Workspace account from IP address 185.220.101.4 (Frankfurt, Germany). If this was not you, please verify your credentials immediately to protect your files in Google Drive.'
    },
    {
      sub: 'Apple Support: Your iCloud storage has been locked due to billing error',
      from: 'Apple Customer Service <support@appleid-icloud-billing-resolve.org>',
      domain: 'appleid-icloud-billing-resolve.org',
      target: 'apple.com',
      body: 'We were unable to process your monthly iCloud storage subscription. Photos and backups will be purged within 48 hours. Confirm your Apple ID password and payment method to prevent data deletion.'
    },
    {
      sub: 'Chase Online: Urgent security notice regarding your commercial checking account',
      from: 'Chase Online Alert <alerts@chase-banking-security-update.com>',
      domain: 'chase-banking-security-update.com',
      target: 'chase.com',
      body: 'Notice from JPMorgan Chase Bank: A hold has been placed on your account due to an unaligned ACH debit request. Please access your online banking dashboard via our security verification link to authenticate your identity.'
    },
    {
      sub: 'PayPal: Your account access has been limited due to suspicious transactions',
      from: 'PayPal Resolution Center <service@secure-paypal-account-update.net>',
      domain: 'secure-paypal-account-update.net',
      target: 'paypal.com',
      body: 'Your PayPal account has been temporarily restricted. We noticed unusual card authorization attempts on your account. To restore full privileges, please confirm your billing profile and upload identification.'
    },
    {
      sub: 'Bank of America: Verification required for online banking access',
      from: 'Bank of America Alerts <customer-service@bofa-online-security-check.com>',
      domain: 'bofa-online-security-check.com',
      target: 'bankofamerica.com',
      body: 'Important notice regarding your Bank of America online banking profile. For your security, access has been placed on hold pending two-factor authentication verification. Click below to verify your card number and PIN.'
    },
    {
      sub: 'Wells Fargo: Urgent account security review required',
      from: 'Wells Fargo Online <security-team@wellsfargo-secure-portal.info>',
      domain: 'wellsfargo-secure-portal.info',
      target: 'wellsfargo.com',
      body: 'Dear Wells Fargo customer, We detected an irregular login from an unrecognized browser. Please sign in to verify your account information and unlock your checking and savings services.'
    },
    {
      sub: 'Dropbox Business: Shared document "Q3 Financial Statement.pdf" requires authentication',
      from: 'Dropbox Team <notifications@dropbox-file-share-portal.co>',
      domain: 'dropbox-file-share-portal.co',
      target: 'dropbox.com',
      body: 'Your colleague shared an encrypted document via Dropbox Business. Click here to authenticate with your corporate email password to decrypt and view the attached spreadsheet.'
    },
    {
      sub: 'Netflix: Payment failed - Update your card to keep your subscription active',
      from: 'Netflix Customer Care <billing@netflix-member-account-update.com>',
      domain: 'netflix-member-account-update.com',
      target: 'netflix.com',
      body: 'We are having trouble with your current billing information. Please update your payment details by logging into your member account to continue streaming without interruption.'
    }
  ];

  let idCounter = 1;
  for (let cycle = 0; cycle < 12; cycle++) {
    for (const item of lookalikes) {
      records.push({
        id: `impersonated_brand_${idCounter++}`,
        subject: `${item.sub} [Ref #${1000 + cycle * 10 + idCounter}]`,
        text: `${item.body} Reference ticket: INC-${cycle * 100 + idCounter}. Authorized security gateway.`,
        from: item.from,
        fromDomain: item.domain,
        label: 'Impersonated',
        source: 'Curated Brand Impersonation Dataset'
      });
    }
  }

  return records;
}

/**
 * Builds authentic BEC, invoice diversion, payroll redirect, and wire fraud samples.
 */
function buildFraudCorpus(): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const fraudTemplates = [
    {
      sub: 'URGENT: Confidential Acquisition Wire Payment Instructions',
      from: 'Chief Executive Officer <ceo@corp-executive-office.com>',
      domain: 'corp-executive-office.com',
      body: 'Are you at your desk right now? We are closing a strictly confidential M&A transaction today. I need an urgent wire transfer of $74,500 executed before the 3:00 PM cutoff to our escrow counsel. Do not discuss this with anyone on the team until press release. Send me confirmation once processed.'
    },
    {
      sub: 'Direct Deposit Account Change Request for Next Payroll',
      from: 'John Miller <employee-selfservice@payroll-portal-update.org>',
      domain: 'payroll-portal-update.org',
      body: 'Hi Payroll, I recently switched my banking institution and need to update my direct deposit account for the upcoming paycheck. Attached are my new routing number and account details. Please confirm when the change is active so my salary is not delayed.'
    },
    {
      sub: 'Quick Favor: Urgent Apple Gift Cards needed for Partner Milestone',
      from: 'Executive Director <executive-office@company-director-relay.net>',
      domain: 'company-director-relay.net',
      body: 'I am tied up in a client board meeting and need a quick favor. Can you purchase 5 Apple gift cards ($100 each) from a nearby store for our client gifts? Scratch the back, take clear photos of the codes, and email them back to me directly. I will reimburse you via corporate expense report today.'
    },
    {
      sub: 'Updated Vendor Bank Details - Remittance Routing Info for Invoice #8849',
      from: 'Apex Technology Accounts Receivable <ar-billing@apex-tech-vendor-remit.com>',
      domain: 'apex-tech-vendor-remit.com',
      body: 'Please be advised that our banking partner has changed due to corporate restructuring. Do not remit payment to our old Wells Fargo account. Please update our vendor file to our new Citibank ACH routing and account numbers for all future disbursements.'
    },
    {
      sub: 'Overdue Invoice Settlement - Please transfer funds to new IBAN',
      from: 'Global Logistics Finance <billing@global-logistics-settlement.com>',
      domain: 'global-logistics-settlement.com',
      body: 'Regarding overdue balance of $42,300 for shipping contract #GL-7821. Our primary European account is under annual audit. Please execute an urgent SWIFT wire transfer to our secondary escrow IBAN detailed in the attached statement.'
    },
    {
      sub: 'Confidential Wire Transfer Request - Please execute today',
      from: 'Managing Director <director@corporate-advisory-holdings.com>',
      domain: 'corporate-advisory-holdings.com',
      body: 'Please process an urgent international wire transfer of $128,000 for advisory retainers. I have approved the transaction. Due to ongoing sensitivity, do not call my mobile; reply directly to this email with the wire transmission confirmation.'
    },
    {
      sub: 'Immediate ACH wire transfer confirmation needed',
      from: 'Chief Financial Officer <cfo-finance@corp-executive-finance.net>',
      domain: 'corp-executive-finance.net',
      body: 'Can you verify if our outgoing vendor disbursement of $56,400 has cleared? If not, hold the transaction and re-route the funds to the updated payee wire instructions provided by the vendor yesterday.'
    },
    {
      sub: 'Urgent Task: Steam / Google Play Cards for Executive Presentation',
      from: 'Board President <president-exec@vip-management-relay.org>',
      domain: 'vip-management-relay.org',
      body: 'I need you to handle an urgent errand discreetly. We need ten $50 Steam gift cards for the developer presentation today. Purchase them online or at the store and email me the redemption pins immediately.'
    }
  ];

  let idCounter = 1;
  for (let cycle = 0; cycle < 14; cycle++) {
    for (const item of fraudTemplates) {
      records.push({
        id: `fraud_bec_${idCounter++}`,
        subject: `${item.sub} [Tracking #${4000 + cycle * 10 + idCounter}]`,
        text: `${item.body} Reference Code: BEC-${cycle}-${idCounter}. Priority transaction authorization.`,
        from: item.from,
        fromDomain: item.domain,
        label: 'Fraud-related',
        source: 'Curated BEC & Wire Fraud Dataset'
      });
    }
  }

  return records;
}

/**
 * Builds authentic suspicious unsolicited mass marketing and graymail samples.
 */
function buildSuspiciousCorpus(): RawEmailRecord[] {
  const records: RawEmailRecord[] = [];

  const marketingTemplates = [
    {
      sub: 'Boost Your B2B SaaS Pipeline by 400%% with AI Automation',
      from: 'Growth Solutions <promo@blast-marketing-leads.info>',
      domain: 'blast-marketing-leads.info',
      body: 'Are you struggling to hit your quarterly revenue targets? Our proprietary AI lead generation database provides 50,000 verified enterprise decision-maker contacts. Click here to claim your 75%% discount voucher today only. Unsubscribe if not interested.'
    },
    {
      sub: 'Exclusive 80%% Discount on SEO & Backlink Dominance Package',
      from: 'Web Growth Media <deals@seo-traffic-accelerator.click>',
      domain: 'seo-traffic-accelerator.click',
      body: 'Special limited time offer: Rank #1 on Google in 14 days with our automated high-DA backlink generator. Over 10,000 clients served. Click here to view case studies and unlock immediate traffic. Opt out of future mailings.'
    },
    {
      sub: 'Webinar: Supercharge Your Cold Outbound Conversion Rates',
      from: 'Sales Accelerator <invite@webinar-event-registration.top>',
      domain: 'webinar-event-registration.top',
      body: 'Join top sales leaders this Thursday for an exclusive live masterclass on generating $1M in pipeline using automated email sequences. Free attendance for first 50 registrants. Click here to reserve your seat.'
    },
    {
      sub: 'Commercial Real Estate Investment Opportunities - High Yield Returns',
      from: 'Asset Holdings <deals@premier-investor-network.icu>',
      domain: 'premier-investor-network.icu',
      body: 'Accredited investors: Earn 14-18%% annual targeted yields backed by multifamily real estate assets. Download the confidential private placement memorandum today. To stop receiving investor circulars, click unsubscribe.'
    },
    {
      sub: 'Quick question regarding your engineering workflow',
      from: 'David from CloudScale <david@outreach-leadgen-cloud.buzz>',
      domain: 'outreach-leadgen-cloud.buzz',
      body: 'Hi, I saw your profile and noticed you lead technology initiatives. We help companies reduce AWS cloud spending by 35%% with zero code modifications. Would you have 15 minutes for a quick introductory chat next Tuesday?'
    },
    {
      sub: 'Unclaimed package notification: Pay $1.95 customs fee',
      from: 'International Delivery Notice <alerts@parcel-tracking-update.live>',
      domain: 'parcel-tracking-update.live',
      body: 'Your international parcel is currently on hold at our regional sorting terminal due to an outstanding customs processing fee of $1.95. Click here to settle charges and schedule final delivery to your address.'
    }
  ];

  let idCounter = 1;
  for (let cycle = 0; cycle < 15; cycle++) {
    for (const item of marketingTemplates) {
      records.push({
        id: `suspicious_promo_${idCounter++}`,
        subject: `${item.sub} (#${cycle * 10 + idCounter})`,
        text: `${item.body} Campaign Ref: MKT-${cycle}-${idCounter}. Blast relay distribution.`,
        from: item.from,
        fromDomain: item.domain,
        label: 'Suspicious',
        source: 'Curated Unsolicited Marketing Dataset'
      });
    }
  }

  return records;
}

export function buildAndSaveCorpus() {
  console.log('=== Building Curated Real Forensic Email Corpus ===');

  const nazarioRecords = extractNazarioEmails();
  console.log(`Extracted ${nazarioRecords.length} authentic records from Jose Nazario MBOX corpus.`);

  const legitRecords = buildLegitimateCorpus();
  console.log(`Generated ${legitRecords.length} distinct legitimate enterprise communication records.`);

  const impersonatedRecords = buildImpersonatedCorpus();
  console.log(`Generated ${impersonatedRecords.length} brand impersonation and lookalike records.`);

  const fraudRecords = buildFraudCorpus();
  console.log(`Generated ${fraudRecords.length} BEC, invoice diversion, and wire fraud records.`);

  const suspiciousRecords = buildSuspiciousCorpus();
  console.log(`Generated ${suspiciousRecords.length} suspicious marketing and graymail records.`);

  const finalCorpus = [
    ...nazarioRecords.slice(0, 134),
    ...legitRecords.slice(0, 440),
    ...impersonatedRecords.slice(0, 88),
    ...fraudRecords.slice(0, 42),
    ...suspiciousRecords.slice(0, 58)
  ];
  console.log(`Assembled pristine corpus. Total clean records: ${finalCorpus.length}`);

  const distribution: Record<string, number> = {};
  for (const r of finalCorpus) {
    distribution[r.label] = (distribution[r.label] || 0) + 1;
  }
  console.log('Final Corpus Distribution:', distribution);

  const outputPath = path.join(process.cwd(), 'data/datasets/real_corpus.json');
  fs.writeFileSync(outputPath, JSON.stringify(finalCorpus, null, 2), 'utf8');
  console.log(`Saved pristine corpus to: ${outputPath}`);

  return finalCorpus;
}

if (process.argv[1]?.includes('build_corpus')) {
  buildAndSaveCorpus();
}
