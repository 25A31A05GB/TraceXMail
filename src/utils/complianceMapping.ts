import { EmailAnalysis } from '../types';
import { getStandardizedVerdict } from './verdict';

export interface ComplianceFlag {
  regime: string;
  reason: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  color: string;
}

/**
 * Pure rule-based compliance mapping function for SOC analysts.
 * Evaluates forensic telemetry against key regulatory regimes:
 * - CERT-In Directions 2022 (Mandatory 6-Hour Reporting / Incident Logging)
 * - RBI Cyber Security Framework (Payment Diversion / Financial Fraud)
 * - IT Act Section 43A & Digital Personal Data Protection (DPDP) Act (PII & Credential Theft)
 * - NCIIPC Threat Advisory (Critical Infrastructure & Anonymized Origin Routing)
 */
export function mapComplianceFlags(analysis: Partial<EmailAnalysis> | null | undefined): ComplianceFlag[] {
  if (!analysis) {
    return [];
  }

  const stdVerdict = getStandardizedVerdict(analysis);
  const threatScore = stdVerdict.score;

  // Clean / Legitimate emails have no regulatory breach flags
  if (stdVerdict.isSafe || threatScore < 35) {
    return [];
  }

  const flags: ComplianceFlag[] = [];
  const subject = (analysis.headers?.subject || analysis.subject || '').toLowerCase();
  const rawBody = (analysis.summary || analysis.rawEml || '').toLowerCase();
  const classification = (analysis.classification || stdVerdict.rawVerdict || '').toLowerCase();

  const heuristicsText = (analysis.heuristics || analysis.heuristicSignals || [])
    .filter(h => h.triggered)
    .map(h => `${h.title} ${h.description}`.toLowerCase())
    .join(' ');

  const combinedText = `${subject} ${rawBody} ${heuristicsText} ${classification}`;

  // 1. Detect Financial & Wire Transfer language
  const hasFinancialIndicators =
    combinedText.includes('wire transfer') ||
    combinedText.includes('wire') ||
    combinedText.includes('invoice') ||
    combinedText.includes('refund') ||
    combinedText.includes('bank account') ||
    combinedText.includes('payment') ||
    combinedText.includes('remittance') ||
    combinedText.includes('direct deposit') ||
    combinedText.includes('cfo') ||
    combinedText.includes('escrow') ||
    classification.includes('fraud');

  // 2. Detect Credential Harvesting & PII extraction
  const hasPiiCredentialTheft =
    combinedText.includes('password') ||
    combinedText.includes('ssn') ||
    combinedText.includes('social security') ||
    combinedText.includes('signin') ||
    combinedText.includes('login') ||
    combinedText.includes('credential') ||
    combinedText.includes('personal access token') ||
    combinedText.includes('restriction') ||
    classification.includes('phish') ||
    (analysis.urls || []).some(u => u.status === 'MALICIOUS' || (u.category && u.category.toLowerCase().includes('credential')));

  // 3. Detect Tor / Bulletproof Hosting
  const firstHop = analysis.hops && analysis.hops.length > 0 ? (analysis.hops.find(h => h.isOrigin) || analysis.hops[0]) : undefined;
  const isTor = Boolean(firstHop?.is_tor || firstHop?.isTorExitNode || firstHop?.reverseDns?.toLowerCase().includes('tor'));
  const isHighAbuse = (firstHop?.abuseScore ?? 0) >= 80;

  // Rule 1: CERT-In Mandatory 6-Hour Reporting for High-Severity Financial/BEC Incidents
  if (threatScore >= 80 && (hasFinancialIndicators || classification.includes('fraud') || classification.includes('impersonat'))) {
    flags.push({
      regime: 'CERT-In (Reportable within 6 hrs)',
      reason: 'High-severity fraudulent financial/BEC cyber incident subject to mandatory 6-hour reporting under CERT-In Directions 2022.',
      severity: 'critical',
      color: 'bg-rose-950/80 text-rose-300 border-rose-700/70'
    });
  } else if (threatScore >= 70) {
    // Rule 1b: CERT-In Mandatory Incident Logging
    flags.push({
      regime: 'CERT-In Incident Logging',
      reason: 'Targeted brand impersonation and credential phishing telemetry requiring institutional incident recording.',
      severity: 'high',
      color: 'bg-orange-950/80 text-orange-300 border-orange-700/70'
    });
  }

  // Rule 2: RBI Cyber Security Framework for Payment/Banking Pretexts
  if (hasFinancialIndicators) {
    flags.push({
      regime: 'RBI Cyber Security Framework',
      reason: 'Unsanctioned financial transaction lure or payment diversion pretext identified in corporate email flow.',
      severity: 'high',
      color: 'bg-amber-950/80 text-amber-300 border-amber-700/70'
    });
  }

  // Rule 3: IT Act Section 43A & DPDP Act for PII / Credential Exfiltration
  if (hasPiiCredentialTheft) {
    flags.push({
      regime: 'IT Act §43A / DPDP Act',
      reason: 'Deceptive credential harvesting vector attempting illicit acquisition of authentication tokens and PII.',
      severity: 'medium',
      color: 'bg-purple-950/80 text-purple-300 border-purple-700/70'
    });
  }

  // Rule 4: NCIIPC Threat Advisory for High-Abuse / Tor Origin Infrastructure
  if (isTor || isHighAbuse) {
    flags.push({
      regime: 'NCIIPC Threat Advisory',
      reason: `Inbound relay traversed ${isTor ? 'an anonymized Tor exit node' : `high-abuse bulletproof infrastructure (${firstHop?.abuseScore}% abuse confidence)`}.`,
      severity: 'medium',
      color: 'bg-cyan-950/80 text-cyan-300 border-cyan-700/70'
    });
  }

  return flags;
}
