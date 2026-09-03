import type { ReactNode } from 'react';
import { ShieldCheck, ArrowLeft } from 'lucide-react';

type LegalPageProps = {
  type: 'privacy' | 'terms';
};

export function LegalPage({ type }: LegalPageProps) {
  const isPrivacy = type === 'privacy';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="border-b border-slate-800 bg-slate-950/95">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-5">
          <a href="/" className="flex items-center gap-3">
            <ShieldCheck className="h-6 w-6 text-blue-400" />
            <span className="text-lg font-semibold tracking-tight text-white">
              TraceXMail
            </span>
          </a>

          <a
            href="/"
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-white"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to TraceXMail
          </a>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-12 sm:py-16">
        <p className="mb-2 font-mono text-xs uppercase tracking-widest text-blue-400">
          TraceXMail Legal
        </p>

        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          {isPrivacy ? 'Privacy Policy' : 'Terms of Service'}
        </h1>

        <p className="mt-3 text-sm text-slate-500">
          Effective date: August 30, 2026
        </p>

        <div className="mt-12">
          {isPrivacy ? <PrivacyContent /> : <TermsContent />}
        </div>
      </main>

      <footer className="border-t border-slate-800 bg-slate-950">
        <div className="mx-auto flex max-w-5xl flex-col gap-3 px-6 py-6 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <span>© 2026 TraceXMail. All rights reserved.</span>

          <div className="flex gap-5">
            <a href="/privacy" className="hover:text-white">
              Privacy Policy
            </a>
            <a href="/terms" className="hover:text-white">
              Terms of Service
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="mb-10">
      <h2 className="mb-3 text-xl font-semibold text-white">{title}</h2>
      <div className="space-y-3 text-sm leading-7 text-slate-400">
        {children}
      </div>
    </section>
  );
}

function PrivacyContent() {
  return (
    <>
      <Section title="1. Overview">
        <p>
          TraceXMail is an email security and threat-analysis application
          designed to help users investigate potentially malicious or
          suspicious email messages. This Privacy Policy explains what
          information TraceXMail may access, how that information is used,
          and the choices available to users.
        </p>
      </Section>

      <Section title="2. Email Ingestion & Gmail Integration Status [Feature Not Enabled in This Release]">
        <div className="p-3 bg-slate-900/60 border border-amber-500/30 rounded text-xs text-amber-300 mb-3">
          <strong>Notice:</strong> Direct Gmail and Google OAuth mailbox synchronization is currently <em>not enabled in this release</em>. TraceXMail currently ingests and analyzes email artifacts solely through direct RFC 822 EML file uploads, raw headers, and user-provided forensic artifacts.
        </div>
        <p>
          In future releases with Google OAuth integration enabled, TraceXMail will request
          permission through standard Google OAuth consent scopes strictly to access email headers,
          sender and recipient information, message dates, subjects, and security-relevant metadata.
        </p>
        <p>
          TraceXMail will not obtain access to any external mailbox without explicit user authorization through the appropriate OAuth consent process.
        </p>
      </Section>

      <Section title="3. Purpose of Forensic Email Processing">
        <p>
          Email data is processed solely to provide TraceXMail's email
          security, forensic investigation, threat detection, and analysis
          features.
        </p>
        <p>
          Analysis includes identifying suspicious senders, authentication
          anomalies (SPF/DKIM/DMARC/ARC), malicious links, indicators of compromise, phishing
          characteristics, and suspicious infrastructure.
        </p>
      </Section>

      <Section title="4. How Ingested Data Is Handled">
        <p>
          Data submitted for analysis is used to process and evaluate email
          security events, generate threat assessments, display investigation
          results, and provide related forensic reporting.
        </p>
        <p>
          User data is never sold for advertising purposes. TraceXMail
          does not build advertising profiles or sell forensic telemetry to third-party data brokers.
        </p>
      </Section>

      <Section title="5. External Mailbox Connections [Feature Not Enabled in This Release]">
        <p>
          Because direct Gmail and external mailbox OAuth connectors are not active in this release, no persistent background mailbox connections are maintained.
        </p>
        <p>
          In future updates supporting active mailbox connections, users will maintain complete controls to disconnect accounts or revoke tokens at any time through standard application and identity provider security settings.
        </p>
      </Section>

      <Section title="6. Data Security">
        <p>
          TraceXMail uses reasonable technical and organizational safeguards
          intended to protect information processed by the service.
        </p>
        <p>
          No internet-based service can guarantee absolute security. Users
          should maintain appropriate security controls for their Google
          account and connected devices.
        </p>
      </Section>

      <Section title="7. Data Retention">
        <p>
          TraceXMail may retain email analysis results, security findings,
          cases, and related technical information for as long as reasonably
          necessary to provide the service, maintain investigation history,
          improve reliability, comply with legal obligations, or protect the
          service.
        </p>
        <p>
          Retention periods may vary depending on the type of information and
          operational requirements of the service.
        </p>
      </Section>

      <Section title="8. Contact and Support">
        <p>
          For privacy questions, account-access concerns, or support requests,
          please contact the TraceXMail support team through the support
          channel provided with your TraceXMail deployment.
        </p>
      </Section>

      <Section title="9. Changes to This Policy">
        <p>
          TraceXMail may update this Privacy Policy when the service,
          applicable requirements, or data practices change. Updated versions
          will be made available on this page.
        </p>
      </Section>
    </>
  );
}

function TermsContent() {
  return (
    <>
      <Section title="1. About TraceXMail">
        <p>
          TraceXMail is an email security and threat-analysis application
          designed to help users inspect email messages, investigate security
          indicators, and identify characteristics associated with phishing,
          malicious activity, and other email-based threats.
        </p>
      </Section>

      <Section title="2. Acceptable Use">
        <p>
          You may use TraceXMail only for lawful purposes and in accordance
          with these Terms. You must not use the service to gain unauthorized
          access to accounts, systems, networks, communications, or data.
        </p>
        <p>
          You must not use TraceXMail to distribute malware, conduct
          unauthorized surveillance, interfere with other users or systems,
          circumvent security controls, or otherwise violate applicable law.
        </p>
      </Section>

      <Section title="3. External Integrations & Authorization [Feature Not Enabled in This Release]">
        <div className="p-3 bg-slate-900/60 border border-amber-500/30 rounded text-xs text-amber-300 mb-3">
          <strong>Notice:</strong> Direct Gmail and Google OAuth authorization flows are <em>not enabled in this release</em>. All forensic analysis is conducted on user-submitted RFC 822 EML files and headers.
        </div>
        <p>
          In future updates enabling direct mailbox integration, connecting third-party mailboxes will require explicit authorization through the provider's OAuth
          authorization process.
        </p>
        <p>
          Users are responsible for ensuring that they possess legitimate forensic authority to
          submit and inspect any email artifacts, headers, or messages processed within TraceXMail.
        </p>
      </Section>

      <Section title="4. Security Analysis Limitations">
        <p>
          TraceXMail provides security analysis and threat indicators as an
          assistive security tool. Its results are not guaranteed to be
          complete, accurate, or error-free.
        </p>
        <p>
          Security analysis may produce false positives, where legitimate
          email is identified as suspicious, and false negatives, where
          malicious or suspicious activity is not detected.
        </p>
        <p>
          Users should consider TraceXMail findings together with other
          security controls, investigation methods, and appropriate human
          judgment before taking consequential action.
        </p>
      </Section>

      <Section title="5. User Responsibilities">
        <p>
          You are responsible for maintaining the security of your Google
          account, credentials, devices, and access to TraceXMail.
        </p>
        <p>
          You are also responsible for reviewing security findings before
          making decisions that could affect users, accounts, systems, or
          business operations.
        </p>
      </Section>

      <Section title="6. Service Availability">
        <p>
          TraceXMail is provided on an availability basis and may occasionally
          be unavailable because of maintenance, infrastructure failures,
          third-party services, network problems, or other circumstances.
        </p>
        <p>
          TraceXMail does not guarantee uninterrupted or error-free operation
          of the service or third-party integrations such as Google Gmail.
        </p>
      </Section>

      <Section title="7. Privacy">
        <p>
          Your use of TraceXMail is also governed by the TraceXMail{' '}
          <a href="/privacy" className="text-blue-400 hover:text-blue-300">
            Privacy Policy
          </a>
          , which explains how information and Gmail data are handled.
        </p>
      </Section>

      <Section title="8. Changes to These Terms">
        <p>
          TraceXMail may update these Terms when necessary to reflect changes
          to the service, legal requirements, or operational practices.
          Updated Terms will be made available on this page.
        </p>
      </Section>

      <Section title="9. Contact and Support">
        <p>
          Questions regarding these Terms or TraceXMail support should be
          directed through the support channel provided with your TraceXMail
          deployment.
        </p>
      </Section>
    </>
  );
}
