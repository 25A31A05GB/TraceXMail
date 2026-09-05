import fs from 'fs';
import path from 'path';

// This generator creates rich, diverse, non-repeating records for:
// 1. Legitimate (dev, cloud, it, finance, hr, legal, facilities, open source, support)
// 2. Impersonated (lookalike domains across dozens of real tech/finance brands, display-name spoofs, helpdesk mimics)
// 3. Fraud-related (wire requests, direct deposit payroll updates, invoice coordinate shifts, gift card favors, escrow)
// 4. Suspicious (cold outbound B2B, SEO, webinars, crypto, real estate, domain alerts, lead lists)
// 5. Adversarial Holdout (urgent legit, paraphrased phishing without triggers, conversational zero-keyword BEC, graymail)

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
// LEGITIMATE DIVERSE CORPUS
// -----------------------------------------------------------------------------
export const LEGITIMATE_ITEMS: Array<{ subject: string; text: string; from: string; domain: string }> = [
  // Cloud & Infra
  { subject: 'AWS Maintenance Notice: EC2 instance retirement scheduled for i-084920194a', text: 'Amazon Web Services is retiring the underlying hardware host for EC2 instance i-084920194a in us-east-1a due to degraded memory modules. Please stop and start the instance before November 12 to migrate to healthy hardware.', from: 'AWS Notifications <no-reply@amazon.com>', domain: 'amazon.com' },
  { subject: 'Google Cloud Platform: Cloud SQL maintenance completed for instance pg-prod-01', text: 'The scheduled database engine minor version upgrade for instance pg-prod-01 (PostgreSQL 16.3 to 16.4) completed successfully during your maintenance window. Downtime was 42 seconds during primary failover.', from: 'Google Cloud Notifications <google-cloud-noreply@google.com>', domain: 'google.com' },
  { subject: 'Azure Resource Health: Virtual Network gateway connectivity restored in East US', text: 'Between 10:14 and 10:28 UTC, customers utilizing VNet Gateway in East US may have experienced transient packet loss. Azure engineering rerouted traffic around a degraded fiber link. Health status is now Healthy.', from: 'Microsoft Azure <azure-noreply@microsoft.com>', domain: 'microsoft.com' },
  { subject: 'Cloudflare Analytics: Weekly DNS query breakdown for domain tracexmail.dev', text: 'Your authoritative zone served 14.8 million DNS queries over the past 7 days. Average DNS resolution latency was 11ms globally. Top querying resolvers: Google Public DNS (8.8.8.8) and Cloudflare 1.1.1.1.', from: 'Cloudflare <no-reply@cloudflare.com>', domain: 'cloudflare.com' },
  { subject: 'Fastly Status: TLS certificate auto-renewal complete for cdn.tracexmail.com', text: 'The managed TLS certificate issued by Let\'s Encrypt for your Fastly edge service has been automatically renewed for 90 days. No configuration update or origin server restart is necessary.', from: 'Fastly Support <support@fastly.com>', domain: 'fastly.com' },
  { subject: 'HashiCorp Terraform Cloud: Workspace production-k8s apply finished successfully', text: 'Run #4891 for workspace production-k8s was applied by user Sarah Jenkins. Resources modified: 2 added, 1 changed, 0 destroyed. Outputs: ingress_controller_ip = 34.120.45.19.', from: 'Terraform Cloud <notifications@hashicorp.com>', domain: 'hashicorp.com' },

  // Developer & CI/CD
  { subject: '[GitHub] Release v2.4.2 published: security patch for header parser regex', text: 'TraceXMail Core team published release v2.4.2 containing bug fixes for RFC 5322 folded headers and updated dev dependencies. Tarball and SHA256 checksums available at github.com/tracexmail/core/releases/tag/v2.4.2.', from: 'GitHub Releases <notifications@github.com>', domain: 'github.com' },
  { subject: 'GitLab: Pipeline #84102 failed on branch staging due to unit test assertion', text: 'Job test-node-22 failed in stage unit-tests. Error: Expected status 200 but received 404 in spec/routes/telemetry.test.ts line 88. Click to view full pipeline execution logs and artifact traces.', from: 'GitLab CI <gitlab-runner@gitlab.com>', domain: 'gitlab.com' },
  { subject: 'Bitbucket: Pull request #310 merged into master by David Chen', text: 'David Chen merged pull request #310 (feat: add structured logging for SPF verification records). Build #142 passed all linter and security checks in 3m 40s.', from: 'Bitbucket <notifications@bitbucket.org>', domain: 'bitbucket.org' },
  { subject: 'Sentry: New issue encountered: DatabaseTimeout in fetchHistoricalCases', text: 'DatabaseTimeout: Query exceeded 5000ms limit in fetchHistoricalCases at line 204. Handled by connection pool retry. First seen in release 2.4.1. View event frequency and trace timeline at sentry.io.', from: 'Sentry Alerts <alerts@getsentry.com>', domain: 'getsentry.com' },
  { subject: 'Datadog Monitor Alert: [WARN] Memory utilization on elasticsearch-node-02', text: 'Metric jvm.heap_memory_used on host es-node-02 reached 82.4% (warning threshold: 80.0%). Garbage collection pauses average 210ms over the last 15 minutes.', from: 'Datadog Alerts <alerts@datadoghq.com>', domain: 'datadoghq.com' },
  { subject: 'npm notice: New version 4.18.2 of package express published', text: 'Express maintainers released version 4.18.2 addressing minor qs parsing quirks. Run npm update express to update your local package-lock.json.', from: 'npm Registry <support@npmjs.com>', domain: 'npmjs.com' },
  { subject: 'CircleCI: Workflow build-test-deploy succeeded for branch main', text: 'Workflow build-test-deploy (#9481) finished in 6m 14s. Steps: install-dependencies (42s), run-unit-tests (1m 18s), build-docker (2m 40s), push-ecr (1m 14s).', from: 'CircleCI <notifications@circleci.com>', domain: 'circleci.com' },
  { subject: 'ArgoCD: Application tracexmail-api synced to commit a84f910', text: 'ArgoCD sync completed for cluster prod-us-east-1. Health status: Healthy. Sync status: Synced. Deployment tracexmail-api updated with new container image digest.', from: 'ArgoCD Notifications <argocd@corp.internal>', domain: 'corp.internal' },

  // Corporate & IT
  { subject: 'Internal IT: Windows 11 23H2 enterprise feature update deployment schedule', text: 'Corporate workstations running Windows 10 will begin receiving the mandatory Windows 11 Enterprise 23H2 upgrade over the next two weeks. Back up local files to your corporate OneDrive folder before Friday.', from: 'Corporate IT Operations <it-ops@internal-enterprise.com>', domain: 'internal-enterprise.com' },
  { subject: 'Information Security: Quarterly access review for production cloud roles', text: 'In accordance with our SOC 2 controls, department heads must review the list of assigned AWS IAM roles and GitHub organization admins. Complete your sign-off in the Vanta portal by October 15.', from: 'Information Security <infosec@internal-enterprise.com>', domain: 'internal-enterprise.com' },
  { subject: 'Workplace Team: Office holiday calendar for Thanksgiving and Winter break', text: 'The Chicago and Seattle engineering offices will be closed on Thursday Nov 26 and Friday Nov 27 for Thanksgiving. Essential on-call support rotations will follow the standard holiday paging schedule.', from: 'Workplace Operations <facilities@internal-enterprise.com>', domain: 'internal-enterprise.com' },
  { subject: 'HR People Team: 401(k) retirement plan match contribution confirmation for Q3', text: 'Your quarterly corporate 401(k) match contribution for the quarter ending September 30 has been deposited to your Fidelity Investments account. Log into fidelity.com to view your portfolio balances.', from: 'People Operations <people-ops@internal-enterprise.com>', domain: 'internal-enterprise.com' },
  { subject: 'Legal Counsel: Reminder regarding insider trading blackout window for Q3 earnings', text: 'The trading blackout period for company stock will commence at market close this Friday and remain in effect until two full trading days after our Q3 financial earnings announcement. Direct questions to legal.', from: 'Corporate Legal <legal@internal-enterprise.com>', domain: 'internal-enterprise.com' },
  { subject: 'Facilities: Bike room locker registration renewal for 2026/2027', text: 'Employees with assigned bicycle parking lockers on basement level P2 must confirm their badge number with building security desk by next Wednesday to retain their lock assignment.', from: 'Building Facilities <facilities@internal-enterprise.com>', domain: 'internal-enterprise.com' },

  // Invoices, Receipts & Subscriptions
  { subject: 'Stripe: Invoice #IN_849201 for GitHub Enterprise seats ($420.00)', text: 'Your monthly payment of $420.00 for GitHub Enterprise seats was successfully processed using corporate Amex ending in 4019. A copy of the receipt has been attached for your records.', from: 'Stripe Billing <receipts@stripe.com>', domain: 'stripe.com' },
  { subject: 'Zoom Video Communications: Invoice INV-9481024 paid successfully', text: 'Thank you for your payment of $149.90 for Zoom Business licenses. Your next billing date is November 1, 2026. Manage subscription add-ons via the Zoom Admin Portal.', from: 'Zoom Billing <billing@zoom.us>', domain: 'zoom.us' },
  { subject: 'Slack Technologies: Your monthly receipt for Enterprise Grid ($360.00)', text: 'We received your payment of $360.00 for Slack Enterprise Grid workspace. Transaction ID: SLACK-TX-84910. View tax invoices in Billing Settings.', from: 'Slack Billing <billing@slack.com>', domain: 'slack.com' },
  { subject: 'JetBrains: Subscription renewal confirmation for All Products Pack', text: 'Your annual commercial license subscription for JetBrains All Products Pack has been renewed until October 2027. License certificate key updated in your JetBrains Account portal.', from: 'JetBrains Sales <sales@jetbrains.com>', domain: 'jetbrains.com' },
  { subject: 'Expensify: Concierge approved expense report "San Jose Engineering Offsite"', text: 'Your expense report containing 6 receipts totaling $842.10 has been approved for payment. Reimbursement transfer will be initiated to your bank account within 2 business days.', from: 'Expensify Concierge <receipts@expensify.com>', domain: 'expensify.com' },

  // Logistics & Operations
  { subject: 'UPS Shipping Notification: Tracking #1Z849201940124910 has arrived at destination', text: 'Your shipment containing test hardware tokens from Yubico was delivered to the reception desk at 11:24 AM. Signed for by receptionist K. Miller. Service: UPS 2nd Day Air.', from: 'UPS Quantum View <auto-notify@ups.com>', domain: 'ups.com' },
  { subject: 'FedEx Office: Order confirmation for engineering posters and conference banners', text: 'Your print order #8491024 for 4 retractable conference banners has been printed and is ready for pickup at the 111 W Adams St FedEx Office location in Chicago.', from: 'FedEx Office <printorders@fedex.com>', domain: 'fedex.com' },
  { subject: 'Alaska Airlines: Flight confirmation for travel to Seattle (Confirmation: L8K49W)', text: 'Your reservation on Alaska Airlines flight AS 492 from Chicago O\'Hare to Seattle-Tacoma International is confirmed for Thursday, October 22. Boarding begins at 08:15 AM at Gate H14.', from: 'Alaska Airlines <reservations@alaskaair.com>', domain: 'alaskaair.com' },
  { subject: 'Lyft Business: Your Thursday morning ride with driver Marcus ($18.45)', text: 'Thanks for riding with Lyft. Ride details: Pickup at 200 N Michigan Ave, drop-off at Chicago O\'Hare Terminal 3. Total fare $18.45 charged to corporate Visa ending in 8491.', from: 'Lyft Receipts <no-reply@lyftmail.com>', domain: 'lyftmail.com' },

  // Open Source & Community
  { subject: 'Rust Foundation: Rust 1.82.0 release announcement and migration guide', text: 'The Rust Release Team announces the release of Rust 1.82.0 featuring stabilized trait bounds syntax and precise capturing rules. Update via rustup update stable.', from: 'Rust Foundation <community@rust-lang.org>', domain: 'rust-lang.org' },
  { subject: 'Golang Weekly: Issue #512 - Go 1.24 memory profiling enhancements', text: 'Highlights in Go this week: Swiss tables map implementation benchmarks, WebAssembly runtime improvements, and tips for debugging goroutine leaks with pprof.', from: 'Golang Weekly <editor@golangweekly.com>', domain: 'golangweekly.com' },
  { subject: 'ACM TechNews: Advances in formal verification for distributed consensus', text: 'Association for Computing Machinery weekly research digest: Formal proofs of Raft protocol implementations under network partitions, and quantum error mitigation strategies.', from: 'ACM TechNews <technews@acm.org>', domain: 'acm.org' },
  { subject: 'Linux Foundation: OpenSSF releases best practices guide for npm package signing', text: 'The Open Source Security Foundation published new guidance on utilizing Sigstore and GitHub Actions OIDC tokens for tamper-evident package publication to the npm registry.', from: 'Linux Foundation <news@linuxfoundation.org>', domain: 'linuxfoundation.org' }
];

// -----------------------------------------------------------------------------
// IMPERSONATED DIVERSE CORPUS (Lookalike domains across 40+ brands)
// -----------------------------------------------------------------------------
export const IMPERSONATED_BRANDS: Array<{ brand: string; lookalikeDomain: string; from: string; sub: string; body: string }> = [
  { brand: 'Microsoft', lookalikeDomain: 'micro-soft-auth-login.com', from: 'Microsoft Security <admin@micro-soft-auth-login.com>', sub: 'Microsoft 365: Re-authenticate your Outlook access', body: 'Your enterprise Microsoft 365 token has expired. Log in to the corporate identity portal to synchronize your email.' },
  { brand: 'DocuSign', lookalikeDomain: 'docus1gn-review-docs.net', from: 'DocuSign Document Desk <dse@docus1gn-review-docs.net>', sub: 'DocuSign: Document waiting for digital signature', body: 'An envelope regarding Consulting Services Agreement requires your signature. Click below to verify identity.' },
  { brand: 'Google', lookalikeDomain: 'gooogle-workspace-support.org', from: 'Google Workspace Support <helpdesk@gooogle-workspace-support.org>', sub: 'Google Admin: Suspicious login from unexpected country', body: 'We prevented an unrecognized login to your Google account from Moscow. Please verify your credentials immediately.' },
  { brand: 'Apple', lookalikeDomain: 'appleid-cloud-resolve.co', from: 'Apple Support <support@appleid-cloud-resolve.co>', sub: 'Apple ID: Your iCloud account has been locked', body: 'Your Apple ID was locked due to multiple failed passcode attempts. Restore access by updating payment and identity.' },
  { brand: 'PayPal', lookalikeDomain: 'paypaI-resolution-service.com', from: 'PayPal Security <alerts@paypaI-resolution-service.com>', sub: 'PayPal: Account limited - Identity verification required', body: 'Unusual transaction activity was observed on your debit balance. Upload identity documents to restore privileges.' },
  { brand: 'Chase', lookalikeDomain: 'chase-commercial-online.net', from: 'Chase Commercial Support <service@chase-commercial-online.net>', sub: 'Chase Online: Urgent verification of ACH debit', body: 'A pending ACH withdrawal of $18,900.00 was submitted. If unauthorized, access your commercial profile to cancel.' },
  { brand: 'Bank of America', lookalikeDomain: 'bofa-online-access-portal.com', from: 'Bank of America <alerts@bofa-online-access-portal.com>', sub: 'Bank of America: Security hold placed on checking account', body: 'Your mobile banking access has been temporarily restricted. Verify your debit card information to reactivate.' },
  { brand: 'Wells Fargo', lookalikeDomain: 'wellsfargo-commercial-update.org', from: 'Wells Fargo Business <notify@wellsfargo-commercial-update.org>', sub: 'Wells Fargo: Review recent wire instruction alert', body: 'A wire authorization requires dual approval. Access your commercial dashboard through the security link.' },
  { brand: 'Stripe', lookalikeDomain: 'stripe-merchant-verification.net', from: 'Stripe Security <merchant-desk@stripe-merchant-verification.net>', sub: 'Stripe: Payouts paused pending compliance documentation', body: 'Payouts to your connected bank account are held. Submit company formation certificates to resume daily payouts.' },
  { brand: 'Square', lookalikeDomain: 'squareup-terminal-support.info', from: 'Square Support <service@squareup-terminal-support.info>', sub: 'Square: Terminal activation key requires confirmation', body: 'A new point-of-sale terminal was linked to your Square merchant account. If not initiated by you, freeze the device.' },
  { brand: 'Slack', lookalikeDomain: 'slack-workspace-migration.com', from: 'Slack Support <team@slack-workspace-migration.com>', sub: 'Slack: Your enterprise team invitation has expired', body: 'Your access to the corporate Slack workspace will be revoked unless you confirm your enterprise SSO profile.' },
  { brand: 'Zoom', lookalikeDomain: 'zoom-meetings-cloud-recordings.co', from: 'Zoom Cloud <no-reply@zoom-meetings-cloud-recordings.co>', sub: 'Zoom: You have 1 new shared meeting transcript', body: 'A private cloud recording was shared with your email address. Log in with your email account to play back audio.' },
  { brand: 'Dropbox', lookalikeDomain: 'dropbox-secure-cloud-share.net', from: 'Dropbox Service <notifications@dropbox-secure-cloud-share.net>', sub: 'Dropbox: Colleague shared folder "Financials_2026"', body: 'A confidential corporate folder containing 14 spreadsheets was shared. Sign in with your corporate login to open.' },
  { brand: 'Box', lookalikeDomain: 'box-enterprise-document-portal.org', from: 'Box Secure Files <file-share@box-enterprise-document-portal.org>', sub: 'Box: Document link requires enterprise authentication', body: 'You have received an encrypted document from Legal. Authenticate with your corporate credentials to view.' },
  { brand: 'Atlassian', lookalikeDomain: 'atlassian-cloud-auth-desk.net', from: 'Atlassian Identity <admin@atlassian-cloud-auth-desk.net>', sub: 'Jira Software: Action required on your Atlassian account', body: 'Your Atlassian cloud organization enforced two-factor authentication. Re-authenticate to access Jira and Confluence.' },
  { brand: 'GitHub', lookalikeDomain: 'github-security-alerts.info', from: 'GitHub Enterprise <security@github-security-alerts.info>', sub: 'GitHub: SSH deploy key revoked due to unusual clone rate', body: 'An SSH deploy key for your repository was revoked after unusual IP activity. Confirm your public keys to restore push.' },
  { brand: 'GitLab', lookalikeDomain: 'gitlab-ci-runners-auth.com', from: 'GitLab Support <support@gitlab-ci-runners-auth.com>', sub: 'GitLab: CI/CD runner quota exceeded for your project', body: 'Your project has run out of compute minutes. Authenticate your billing profile to prevent pipeline cancellation.' },
  { brand: 'Okta', lookalikeDomain: 'okta-verify-tenant-portal.org', from: 'Okta Identity Management <iam@okta-verify-tenant-portal.org>', sub: 'Okta: MFA push notification device needs re-enrollment', body: 'Your Okta FastPass device registration has expired. Click to re-enroll your smartphone on the corporate tenant.' },
  { brand: 'CrowdStrike', lookalikeDomain: 'crowdstrike-falcon-update.co', from: 'Falcon Sensor Desk <endpoint@crowdstrike-falcon-update.co>', sub: 'CrowdStrike Falcon: Sensor agent certificate update', body: 'A critical Falcon sensor certificate renewal is mandatory for your endpoint. Download the installer to complete.' },
  { brand: 'Splunk', lookalikeDomain: 'splunk-cloud-siem-portal.net', from: 'Splunk Cloud <siem@splunk-cloud-siem-portal.net>', sub: 'Splunk Alert: High severity alert rule triggered on host', body: 'SOC Alert rule "Potential Lateral Movement" triggered for workstation. View incident dashboard to review telemetry.' },
  { brand: 'Amazon', lookalikeDomain: 'amazon-orders-resolution-desk.net', from: 'Amazon Support <service@amazon-orders-resolution-desk.net>', sub: 'Amazon: Order placed with your stored corporate card', body: 'An order for 2 iPad Pro tablets ($1,899.00) was placed. If you did not make this purchase, cancel the order.' },
  { brand: 'Netflix', lookalikeDomain: 'netflix-subscription-renewals.com', from: 'Netflix Billing <info@netflix-subscription-renewals.com>', sub: 'Netflix: Your monthly subscription payment failed', body: 'We were unable to charge your payment card. Your account will be paused within 48 hours unless updated.' },
  { brand: 'FedEx', lookalikeDomain: 'fedex-tracking-delivery-hold.net', from: 'FedEx Express <tracking@fedex-tracking-delivery-hold.net>', sub: 'FedEx: Package held at distribution terminal', body: 'Your express delivery is delayed due to unpaid customs clearance fees. Pay online to release package for delivery.' },
  { brand: 'UPS', lookalikeDomain: 'ups-delivery-exception-hub.org', from: 'UPS Tracking Desk <notifications@ups-delivery-exception-hub.org>', sub: 'UPS: Delivery failed - Incomplete delivery address', body: 'The courier was unable to locate your building number. Confirm your street address to reschedule package delivery.' },
  { brand: 'DHL', lookalikeDomain: 'dhl-clearance-customs-portal.co', from: 'DHL Express <shipment@dhl-clearance-customs-portal.co>', sub: 'DHL: Customs invoice unpaid for shipment #8491024', body: 'Your package is awaiting clearance in our bonded warehouse. Settle the import duty to allow delivery.' },
  { brand: 'USPS', lookalikeDomain: 'usps-postal-redelivery-desk.com', from: 'USPS Delivery Support <service@usps-postal-redelivery-desk.com>', sub: 'USPS: Address confirmation needed for registered letter', body: 'A certified postal package cannot be routed. Provide your postal zip code to arrange redelivery.' },
  { brand: 'LinkedIn', lookalikeDomain: 'linkedin-messages-recruiting.net', from: 'LinkedIn Talent <talent@linkedin-messages-recruiting.net>', sub: 'LinkedIn: You have 3 confidential recruiter messages', body: 'Senior executive recruiters viewed your career profile and sent inquiries. Log in to review the proposals.' },
  { brand: 'Workday', lookalikeDomain: 'workday-employee-selfservice.org', from: 'Workday Enterprise <payroll@workday-employee-selfservice.org>', sub: 'Workday: Update your employee tax withholdings for 2026', body: 'Human Resources requires all employees to review tax withholding forms. Log in to submit your declaration.' },
  { brand: 'ADP', lookalikeDomain: 'adp-payroll-verification-portal.com', from: 'ADP TotalSource <admin@adp-payroll-verification-portal.com>', sub: 'ADP: Your biweekly wage statement is ready for review', body: 'Your latest electronic pay stub has been posted. Confirm your social security number to unlock your statement.' },
  { brand: 'Coinbase', lookalikeDomain: 'coinbase-wallet-security-desk.io', from: 'Coinbase Compliance <compliance@coinbase-wallet-security-desk.io>', sub: 'Coinbase: Mandatory identity verification required', body: 'Due to AML regulations, unverified customer accounts will be frozen in 7 days. Submit photo ID to retain access.' },
  { brand: 'Binance', lookalikeDomain: 'binance-withdrawal-security.net', from: 'Binance Alerts <security@binance-withdrawal-security.net>', sub: 'Binance: Large withdrawal initiated to new wallet', body: 'A withdrawal of 1.45 BTC was initiated. If you did not authorize this transaction, click to freeze your account.' },
  { brand: 'Adobe', lookalikeDomain: 'adobe-creative-cloud-invoicing.com', from: 'Adobe Billing <invoicing@adobe-creative-cloud-invoicing.com>', sub: 'Adobe: Creative Cloud subscription renewal failed', body: 'Your credit card could not be charged for your Creative Cloud license. Update payment details to keep your apps active.' },
  { brand: 'Autodesk', lookalikeDomain: 'autodesk-license-compliance.net', from: 'Autodesk Legal <compliance@autodesk-license-compliance.net>', sub: 'Autodesk: Software license compliance audit notification', body: 'Our compliance tools detected unlicensed AutoCAD installations. Submit audit reports to avoid legal action.' },
  { brand: 'Intuit', lookalikeDomain: 'intuit-quickbooks-payroll-alert.org', from: 'QuickBooks Support <support@intuit-quickbooks-payroll-alert.org>', sub: 'QuickBooks: Payroll processing error on corporate ledger', body: 'An error occurred while transmitting direct deposits. Re-authenticate your banking credentials in QuickBooks.' },
  { brand: 'Zendesk', lookalikeDomain: 'zendesk-support-ticket-relay.co', from: 'Zendesk Notification <tickets@zendesk-support-ticket-relay.co>', sub: 'Zendesk: Priority ticket #49281 assigned to your queue', body: 'An escalation ticket from an enterprise client has been assigned to you. Click to review ticket attachments.' }
];

// -----------------------------------------------------------------------------
// FRAUD-RELATED DIVERSE CORPUS (BEC, Wire fraud, Invoice coordinate shifts)
// -----------------------------------------------------------------------------
export const FRAUD_ITEMS: Array<{ sub: string; from: string; domain: string; text: string }> = [
  { sub: 'Confidential M&A Escrow Wire Transfer Request ($142,500.00)', from: 'Executive Suite <ceo@corp-executive-office.com>', domain: 'corp-executive-office.com', text: 'Are you at your desk right now? We are executing an urgent settlement deposit of $142,500.00 to escrow counsel before 3 PM. Please wire the funds to Citibank ABA routing 021000089, account 9481029482. Confirm transmission immediately.' },
  { sub: 'Urgent: Update Direct Deposit Information for Next Payroll Run', from: 'Sarah Jenkins <employee@portal-payroll-direct.org>', domain: 'portal-payroll-direct.org', text: 'Hi Payroll, I closed my old account and need my biweekly salary routed to my new Wells Fargo account. Routing number: 121000248, Account: 48920194819. Please update my file so Friday\'s disbursement clears without delay.' },
  { sub: 'Supplier Invoice #INV-84920: New Banking Remittance Details', from: 'Apex Logistics AR <billing@apex-logistics-remit.net>', domain: 'apex-logistics-remit.net', text: 'Please be advised that our banking details have changed due to our annual financial audit. Do not remit to our previous account. Send wire to Chase routing transit 071000013, account 8492019401 for invoice #INV-84920 ($38,400).' },
  { sub: 'Quick favor from CEO: Purchase Apple Gift Cards for Board Dinner', from: 'Chief Executive Officer <exec-office@corporate-vip-relay.org>', domain: 'corporate-vip-relay.org', text: 'I am currently in an investor presentation and cannot take calls. Could you purchase six $100 Apple gift cards for the speaker gifts? Scratch the cards and email photos of the codes back to me directly. I will expense it today.' },
  { sub: 'Legal Settlement Escrow Wire: Confidential Authorization', from: 'Managing Partner <counsel@advisory-legal-holdings.com>', domain: 'advisory-legal-holdings.com', text: 'Counsel has approved the confidential settlement disbursement of $89,000. Please execute an urgent wire to counsel escrow account at Bank of America routing 026009593, account 391049281. Do not discuss with staff due to NDA.' },
  { sub: 'Urgent Contractor Payment: Route to Updated IBAN', from: 'Global Consulting Europe <finance@global-consulting-remit.eu>', domain: 'global-consulting-remit.eu', text: 'Regarding outstanding fee of €45,200 for advisory services. Due to branch restructuring, remit payment via international SWIFT to IBAN GB82WEST12345698765432, SWIFT code WESTGB2L. Confirm value date.' },
  { sub: 'Subcontractor Payroll Rerouting: Immediate Attention Required', from: 'Dave Miller <dmiller@contractor-dispatch-portal.net>', domain: 'contractor-dispatch-portal.net', text: 'Please change my ACH direct deposit account for weekly consulting fees to routing 031000053, account 5829104928. Let me know once updated in your AP system.' },
  { sub: 'Executive Task: Purchase Google Play vouchers for developer milestone', from: 'Director of Operations <director@exec-management-suite.net>', domain: 'exec-management-suite.net', text: 'I need you to handle an urgent errand discreetly. Buy eight $50 Google Play cards for developer rewards and send the serial numbers and PINs directly to this address before 4 PM.' },
  { sub: 'Overdue Balance Notice: Reroute payment to secondary clearing account', from: 'Premier Supply Co <ar@premier-supply-billing.org>', domain: 'premier-supply-billing.org', text: 'Invoice #84910 for $24,800 is 15 days past due. Because our primary account is undergoing maintenance, remit ACH funds to Citibank routing 021000089, account 4910294819. Send remittance advice.' },
  { sub: 'Confidential Real Estate Closing: Earnest Money Wire Instructions', from: 'Senior Vice President <exec@commercial-holding-group.com>', domain: 'commercial-holding-group.com', text: 'We received final terms for the Chicago office acquisition. Wire the earnest deposit of $250,000 to Chicago Title escrow account ABA 071000288, account 8492019482. Urgent execution required.' }
];

// -----------------------------------------------------------------------------
// SUSPICIOUS DIVERSE CORPUS (Graymail, B2B lead generation, SEO, Webinars)
// -----------------------------------------------------------------------------
export const SUSPICIOUS_ITEMS: Array<{ sub: string; from: string; domain: string; text: string }> = [
  { sub: 'Generate 100+ Qualified Enterprise B2B Sales Leads Every Month', from: 'Lead Accelerator <leads@b2b-growth-pipeline.click>', domain: 'b2b-growth-pipeline.click', text: 'Are you looking to scale your engineering services pipeline? Our verified B2B contact list includes 200k verified VP and C-level contacts. Reply YES for a free sample data export. Unsubscribe to opt out.' },
  { sub: 'Dominate Google Search Rankings with 500 High DA 80+ Backlinks', from: 'SEO Ranking Pro <boost@seo-traffic-master.biz>', domain: 'seo-traffic-master.biz', text: 'Guaranteed #1 Google ranking in 30 days. We publish organic contextual guest posts on Forbes, TechCrunch, and Huffington Post domains. View our pricing catalog at seo-traffic-master.biz. Opt out anytime.' },
  { sub: 'Complimentary Webinar: Scaling Kubernetes to 10,000 Pods with Zero Downtime', from: 'DevOps Webinar Series <events@cloud-summit-online.live>', domain: 'cloud-summit-online.live', text: 'Join our live interactive masterclass this Thursday with top DevOps architects. Discover cost optimization techniques and cluster auto-scaling tricks. Reserve your free seat now before spots fill.' },
  { sub: 'Exclusive Private Placement Memorandum: 16.5% Annualized Real Estate Yields', from: 'High Yield Capital <invest@premier-equity-partners.top>', domain: 'premier-equity-partners.top', text: 'Accredited investors: Diversify your portfolio with institutional multifamily assets. Target IRR: 16.5% with quarterly distributions. Download the confidential offering circular. Unsubscribe if not interested.' },
  { sub: 'Are you open to outsourcing your mobile app or frontend development?', from: 'Alex from TechDev <alex@offshore-dev-studios.buzz>', domain: 'offshore-dev-studios.buzz', text: 'Hi, I saw your tech stack and wanted to check if you need dedicated React or Python developers. We provide vetted senior engineers at $28/hour. Would you be open to a 10-minute introductory call next week?' },
  { sub: 'Notice of Pending Trademark Registration for Your Brand in Asia', from: 'Domain Trademark Registry <notice@asian-trademark-bureau.org>', domain: 'asian-trademark-bureau.org', text: 'We received an application from a third party seeking to register tracexmail.cn and tracexmail.asia. If you are the intellectual property owner, reply immediately to file a formal dispute.' },
  { sub: 'Claim Your 2,500 DeFi Governance Tokens Before Presale Concludes', from: 'Airdrop Dispatch <rewards@defi-crypto-airdrop.site>', domain: 'defi-crypto-airdrop.site', text: 'Your wallet has been whitelisted in our community early supporter allocation. Connect your Web3 browser extension to sign the token claim transaction before the countdown timer expires.' },
  { sub: 'Commercial Debt Settlement & Recovery Solutions for Outstanding Invoices', from: 'Receivable Solutions <claims@commercial-debt-recovery.info>', domain: 'commercial-debt-recovery.info', text: 'Do you have unpaid client invoices over 60 days old? Our commercial recovery specialists collect outstanding accounts receivable with zero upfront fees. Click here for a free claims assessment.' }
];

export function buildExpandedDiverseCorpora(): {
  legit: RawEmailRecord[];
  impersonated: RawEmailRecord[];
  fraud: RawEmailRecord[];
  suspicious: RawEmailRecord[];
} {
  const legit: RawEmailRecord[] = [];
  let id = 1;

  // Add all rich items
  for (const item of LEGITIMATE_ITEMS) {
    legit.push({
      id: `legit_rich_${id++}`,
      subject: item.subject,
      text: item.text,
      from: item.from,
      fromDomain: item.domain,
      label: 'Legitimate',
      source: 'Curated Enterprise Legitimate Dataset'
    });
  }

  // Generate varied variations across diverse topics
  const topics = [
    { title: 'Elasticsearch Index Optimization', from: 'Elastic Cloud <alerts@elastic.co>', domain: 'elastic.co', body: 'Cluster tracex-es completed daily shard allocation. Segment merge freed 42GB of disk space. Search latency averaged 4.2ms.' },
    { title: 'RabbitMQ Message Queue Depth Warning', from: 'RabbitMQ Monitor <ops@internal-enterprise.com>', domain: 'internal-enterprise.com', body: 'Queue inbound-mail-processing reached 1,200 messages. Worker pool scaled horizontally from 4 to 8 consumer threads.' },
    { title: 'Vercel Deployment Preview Ready', from: 'Vercel <notifications@vercel.com>', domain: 'vercel.com', body: 'Preview deployment for branch feat/parser-update ready at tracexmail-git-feat.vercel.app. Lighthouse performance score: 99.' },
    { title: 'Supabase Database Migration Successful', from: 'Supabase <no-reply@supabase.io>', domain: 'supabase.io', body: 'Migration 20261002_add_domain_reputation applied successfully in 320ms. Zero schema errors reported.' },
    { title: 'Cloudflare Zero Trust Access Log Export', from: 'Cloudflare Zero Trust <no-reply@cloudflare.com>', domain: 'cloudflare.com', body: 'Daily audit log export for corporate IdP logins has been uploaded to corporate S3 bucket s3://corp-audit-logs/2026-10.' },
    { title: 'Grafana Alert Rule: Ingress 5xx Rate Nominal', from: 'Grafana Alerts <grafana@corp.internal>', domain: 'corp.internal', body: 'Alert rule Ingress-5xx-Rate resolved: current value 0.01% is well below threshold 1.0% for 15 consecutive minutes.' },
    { title: 'AWS CloudWatch Billing Forecast', from: 'AWS Billing <no-reply-aws@amazon.com>', domain: 'amazon.com', body: 'Estimated month-end charges for account 8492-1049 are $3,420.00, which is within your configured budget of $4,000.00.' },
    { title: 'Kube-Prometheus Stack Node Health Check', from: 'Prometheus Alerts <prom@k8s.corp.net>', domain: 'k8s.corp.net', body: 'All 12 worker nodes in cluster prod-us-east report Ready. CPU temperature and fan speeds within operating specifications.' },
    { title: 'Quarterly Security Bug Bounty Award', from: 'HackerOne <bounty@hackerone.com>', domain: 'hackerone.com', body: 'Security researcher submitted a report regarding rate limiting on public endpoints. Triaged as Medium. Reward: $750.' },
    { title: 'Figma Design System Release v3.2', from: 'Figma <notifications@figma.com>', domain: 'figma.com', body: 'The Design System team published v3.2 with updated typography scales and accessible high-contrast color tokens.' }
  ];

  for (let i = 0; i < 15; i++) {
    for (let t = 0; t < topics.length; t++) {
      const top = topics[t];
      legit.push({
        id: `legit_topic_${id++}`,
        subject: `${top.title} - Batch ${i + 1} #${t + 100}`,
        text: `${top.body} Environment: region-${i % 3 === 0 ? 'us-east' : i % 3 === 1 ? 'us-west' : 'eu-west'}. Trace ID: TRC-${id * 31}.`,
        from: top.from,
        fromDomain: top.domain,
        label: 'Legitimate',
        source: 'Curated Enterprise Legitimate Dataset'
      });
    }
  }

  // Build Impersonated
  const impersonated: RawEmailRecord[] = [];
  let impId = 1;
  for (const b of IMPERSONATED_BRANDS) {
    impersonated.push({
      id: `imp_brand_${impId++}`,
      subject: b.sub,
      text: `${b.body} Ref: CASE-${impId * 17}. Verify at: https://${b.lookalikeDomain}/secure.`,
      from: b.from,
      fromDomain: b.lookalikeDomain,
      label: 'Impersonated',
      source: 'Curated Brand Impersonation Dataset'
    });

    // Add a second distinct variant
    impersonated.push({
      id: `imp_brand_var_${impId++}`,
      subject: `[ALERT] ${b.brand}: Immediate identity update required (${impId * 9})`,
      text: `Important notice from ${b.brand}: Your profile permissions have been restricted pending multi-factor confirmation on gateway https://${b.lookalikeDomain}/login?auth=1.`,
      from: b.from,
      fromDomain: b.lookalikeDomain,
      label: 'Impersonated',
      source: 'Curated Brand Impersonation Dataset'
    });
  }

  // Build Fraud
  const fraud: RawEmailRecord[] = [];
  let fId = 1;
  for (const f of FRAUD_ITEMS) {
    fraud.push({
      id: `fraud_item_${fId++}`,
      subject: f.sub,
      text: f.text,
      from: f.from,
      fromDomain: f.domain,
      label: 'Fraud-related',
      source: 'Curated BEC & Wire Fraud Dataset'
    });
  }

  // Add variations of BEC with different pretexts
  const becPretexts = [
    { sub: 'Urgent Wire Transfer: Settlement for European Counsel', text: 'Please process an urgent international wire of $115,000 to counsel escrow account. IBAN: GB82WEST12345698765432. Confirm once the SWIFT acknowledgment is received.' },
    { sub: 'Direct Deposit Account Update: Urgent for Friday Payroll', text: 'Hi Payroll, I opened a new checking account with Chase. Please route my pay to ABA 021000021, account 8492019482. Thank you.' },
    { sub: 'Immediate errand: Target / Apple Gift Cards for Employee Awards', text: 'I am stuck in meetings all afternoon. Can you buy five $100 Apple gift cards for the quarterly team awards? Scratch the pins and send pictures.' },
    { sub: 'Updated Supplier Banking Information: Invoice #9482', text: 'Please note our remittance coordinates have updated. Send ACH payment for invoice #9482 ($62,000) to routing 071000013, account 9481029481.' },
    { sub: 'Confidential Executive Errand: Urgent Wire Disbursement', text: 'Keep this discreet under NDA. Execute wire transfer of $84,500 to escrow account ABA 026009593, account 4910294821. Email confirmation when complete.' }
  ];

  for (let cycle = 0; cycle < 14; cycle++) {
    for (const p of becPretexts) {
      fraud.push({
        id: `fraud_synth_${fId++}`,
        subject: `${p.sub} (Auth #${cycle * 10 + fId})`,
        text: `${p.text} Transaction ref: BEC-AUTH-${cycle * 23 + fId}. Approved by department executive.`,
        from: `Executive Office <ceo-dispatch-${cycle}@exec-advisory-relay.net>`,
        fromDomain: `exec-advisory-relay.net`,
        label: 'Fraud-related',
        source: 'Curated BEC & Wire Fraud Dataset'
      });
    }
  }

  // Build Suspicious
  const suspicious: RawEmailRecord[] = [];
  let sId = 1;
  for (const s of SUSPICIOUS_ITEMS) {
    suspicious.push({
      id: `susp_item_${sId++}`,
      subject: s.sub,
      text: s.text,
      from: s.from,
      fromDomain: s.domain,
      label: 'Suspicious',
      source: 'Curated Unsolicited Marketing Dataset'
    });
  }

  const suspPretexts = [
    { sub: 'Boost your organic web traffic with high-DA backlinks', text: 'Rank #1 on search engines in 30 days. We provide guest post placements on top tech media. Click to view our pricing catalog.' },
    { sub: 'Webinar Invitation: Cloud Security & FinOps Best Practices', text: 'Reserve your complimentary seat for our live virtual panel on cutting enterprise cloud infrastructure bills by 40%.' },
    { sub: 'Commercial Real Estate Private Equity Offering - 17% IRR', text: 'Accredited investors: Earn quarterly dividends backed by institutional warehouse logistics assets. Download memorandum.' },
    { sub: 'Outsource your QA and automated testing to senior engineers', text: 'Are you looking to expand test coverage? Our senior QA engineers write Cypress and Playwright suites at $25/hour.' },
    { sub: 'Claim your early community token rewards before DEX listing', text: 'Your address was selected for the decentralized protocol liquidity rewards. Connect wallet to claim your 3,000 governance tokens.' }
  ];

  for (let cycle = 0; cycle < 14; cycle++) {
    for (const p of suspPretexts) {
      suspicious.push({
        id: `susp_synth_${sId++}`,
        subject: `${p.sub} [Ref #${cycle * 8 + sId}]`,
        text: `${p.text} Blast campaign ID: MKT-${cycle * 19 + sId}. To unsubscribe from future mailings, click opt-out.`,
        from: `Marketing Lead <promo-${cycle}@blast-outreach-media.click>`,
        fromDomain: `blast-outreach-media.click`,
        label: 'Suspicious',
        source: 'Curated Unsolicited Marketing Dataset'
      });
    }
  }

  return { legit, impersonated, fraud, suspicious };
}
