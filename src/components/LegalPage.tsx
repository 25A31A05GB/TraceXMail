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

      <Section title="2. Gmail and Google Data We Access">
        <p>
          When you choose to connect a Gmail account, TraceXMail requests
          permission through Google OAuth. TraceXMail may access Gmail
          messages and related metadata necessary to perform email security
          analysis.
        </p>
        <p>
          This may include email headers, sender and recipient information,
          message dates, subjects, message content, attachments or attachment
          metadata, links, and other technical information contained in an
          email that is relevant to security analysis.
        </p>
        <p>
          TraceXMail does not obtain access to your Gmail account without your
          authorization through Google's OAuth consent process.
        </p>
      </Section>

      <Section title="3. Why We Access Gmail Data">
        <p>
          Gmail data is accessed solely to provide TraceXMail's email
          security, forensic investigation, threat detection, and analysis
          features.
        </p>
        <p>
          Analysis may include identifying suspicious senders, authentication
          anomalies, malicious links, indicators of compromise, phishing
          characteristics, suspicious infrastructure, and other security
          signals.
        </p>
      </Section>

      <Section title="4. How Gmail Data Is Used">
        <p>
          Data obtained through Gmail is used to process and analyze email
          security events, generate threat assessments, display investigation
          results, and provide related security functionality requested by
          the user.
        </p>
        <p>
          Google user data is not sold for advertising purposes. TraceXMail
          does not use Gmail content obtained through Google OAuth to build
          advertising profiles or sell such information to advertisers.
        </p>
      </Section>

      <Section title="5. Disconnecting Gmail">
        <p>
          You may disconnect your Gmail account at any time using the Gmail
          connection controls provided by the application. You may also revoke
          TraceXMail's access through your Google Account security settings.
        </p>
        <p>
          After access is revoked or the connection is disconnected,
          TraceXMail will no longer use the OAuth connection to retrieve new
          Gmail data.
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

      <Section title="3. Gmail and Google Authorization">
        <p>
          Connecting Gmail requires authorization through Google's OAuth
          authorization process. By connecting an account, you authorize
          TraceXMail to access the Gmail information permitted by the OAuth
          scopes presented during authorization.
        </p>
        <p>
          You are responsible for ensuring that you have the authority to
          connect and analyze the Gmail account and messages you submit or
          make available to TraceXMail.
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
