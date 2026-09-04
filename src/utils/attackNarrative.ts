import { EmailAnalysis } from '../types';
import { getStandardizedVerdict } from './verdict';

/**
 * Pure function that generates a 2-4 sentence plain-English attack narrative
 * from verifiable forensic evidence present in EmailAnalysis.
 * Uses strict string-template composition — zero LLM/ML calls, deterministic and unit-testable.
 */
export function generateAttackNarrative(analysis: EmailAnalysis | Partial<EmailAnalysis> | null | undefined): string {
  if (!analysis) {
    return 'No forensic telemetry available for narrative synthesis.';
  }

  const stdVerdict = getStandardizedVerdict(analysis);
  const isClean = stdVerdict.isSafe || stdVerdict.score < 35;

  // Extract identity fields
  const fromDisplay = analysis.headers?.from || analysis.from || 'an external sender';
  const fromEmail = analysis.headers?.fromEmail || analysis.from || '';
  const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1].replace(/[<>]/g, '').trim() : '';

  const returnPath = analysis.headers?.returnPath || analysis.returnPath || '';
  const returnPathDomain = returnPath.includes('@') ? returnPath.split('@')[1].replace(/[<>]/g, '').trim() : '';
  const returnPathMismatch = Boolean(
    returnPath && fromDomain && returnPathDomain &&
    !returnPathDomain.toLowerCase().includes(fromDomain.toLowerCase()) &&
    !fromDomain.toLowerCase().includes(returnPathDomain.toLowerCase())
  );

  const replyTo = analysis.headers?.replyTo || analysis.replyTo || '';
  const replyToDomain = replyTo.includes('@') ? replyTo.split('@')[1].replace(/[<>]/g, '').trim() : '';
  const replyToMismatch = Boolean(
    replyTo && fromDomain && replyToDomain &&
    !replyToDomain.toLowerCase().includes(fromDomain.toLowerCase()) &&
    !fromDomain.toLowerCase().includes(replyToDomain.toLowerCase())
  );

  // Authentication statuses
  const spfStatus = (analysis.auth?.spf?.status || analysis.authResults?.spf?.status || 'UNKNOWN').toUpperCase();
  const dkimStatus = (analysis.auth?.dkim?.status || analysis.authResults?.dkim?.status || 'UNKNOWN').toUpperCase();
  const dmarcStatus = (analysis.auth?.dmarc?.status || analysis.authResults?.dmarc?.status || 'UNKNOWN').toUpperCase();
  const authPassed = spfStatus === 'PASS' && dkimStatus === 'PASS' && (dmarcStatus === 'PASS' || dmarcStatus === 'NONE');

  // Origin Hop / Infrastructure
  const firstHop = analysis.hops && analysis.hops.length > 0
    ? (analysis.hops.find(h => h.isOrigin) || analysis.hops[0])
    : undefined;
  const originAsn = firstHop?.asn;
  const originOrg = firstHop?.org || firstHop?.isp;
  const originCountry = firstHop?.country || firstHop?.countryCode;
  const isTor = Boolean(firstHop?.is_tor || firstHop?.isTorExitNode || firstHop?.reverseDns?.toLowerCase().includes('tor'));

  // Domain Intelligence
  const domIntel = analysis.domain_intelligence || analysis.domainIntelligence;
  const domainAgeDays = domIntel?.domain_age_days;
  const typosquatTarget = domIntel?.typosquat_matched_brand || domIntel?.typosquatting?.target_brand;

  // Artifacts & Heuristics
  const maliciousUrls = (analysis.urls || []).filter(u => u.status === 'MALICIOUS');
  const maliciousAttachments = (analysis.attachments || []).filter(a => a.status === 'MALICIOUS');
  const totalThreatScore = stdVerdict.score;

  // Clean / Legitimate Narrative
  if (isClean) {
    const originDesc = originOrg && originAsn
      ? `verified ${originOrg} (${originAsn}) infrastructure`
      : fromDomain
      ? `authorized ${fromDomain} mail infrastructure`
      : 'authorized mail servers';

    const authDesc = authPassed
      ? `Cryptographic validation succeeded (SPF: ${spfStatus}, DKIM: ${dkimStatus}, DMARC: ${dmarcStatus})`
      : `Authentication telemetry evaluated (SPF: ${spfStatus}, DKIM: ${dkimStatus})`;

    return `This communication originated from ${originDesc} with consistent envelope alignment. ${authDesc} with no detected brand spoofing, reply redirection, or malicious payloads. The message evaluated to a clean composite risk score of ${totalThreatScore}/100.`;
  }

  // Malicious / Suspicious Attack Narrative Generation
  const sentences: string[] = [];

  // Sentence 1: Identity & Spoofing
  let s1 = `An inbound transmission claiming to represent ${fromDisplay}`;
  if (typosquatTarget) {
    s1 += ` utilized a lookalike domain targeting ${typosquatTarget}`;
  } else if (returnPathMismatch && returnPathDomain) {
    s1 += ` routed envelope bounces to an unaligned return-path domain (${returnPathDomain})`;
  } else if (replyToMismatch && replyToDomain) {
    s1 += ` attempted to divert victim replies to an external domain (${replyToDomain})`;
  } else {
    s1 += ` exhibited suspicious identity and delivery characteristics`;
  }

  if (replyToMismatch && returnPathMismatch && replyToDomain && !s1.includes(replyToDomain)) {
    s1 += `, while diverting responses to ${replyToDomain}`;
  }
  s1 += '.';
  sentences.push(s1);

  // Sentence 2: Origin & Authentication Failure
  let s2 = 'The message ';
  if (isTor) {
    s2 += `was routed through an anonymized Tor exit node${originCountry ? ` in ${originCountry}` : ''}`;
  } else if (originOrg && originCountry) {
    s2 += `originated from ${originOrg}${originAsn ? ` (${originAsn})` : ''} in ${originCountry}`;
  } else if (originAsn) {
    s2 += `originated from Autonomous System ${originAsn}`;
  } else {
    s2 += `was delivered across untrusted relay hops`;
  }

  s2 += `, failing cryptographic policy alignment (SPF: ${spfStatus}, DKIM: ${dkimStatus}, DMARC: ${dmarcStatus}).`;
  sentences.push(s2);

  // Sentence 3: Domain & Payload Threat Vectors
  const payloadParts: string[] = [];
  if (typeof domainAgeDays === 'number' && domainAgeDays <= 60) {
    payloadParts.push(`was sent from a newly registered domain (${domainAgeDays} days old)`);
  }
  if (maliciousUrls.length > 0) {
    payloadParts.push(`contained ${maliciousUrls.length} malicious credential-harvesting/phishing URL${maliciousUrls.length > 1 ? 's' : ''}`);
  }
  if (maliciousAttachments.length > 0) {
    payloadParts.push(`embedded ${maliciousAttachments.length} flagged attachment payload${maliciousAttachments.length > 1 ? 's' : ''}`);
  }

  if (payloadParts.length > 0) {
    sentences.push(`The vector ${payloadParts.join(' and ')}.`);
  }

  // Sentence 4: Summary Risk Verdict
  sentences.push(
    `Forensic correlation assigned an elevated threat score of ${totalThreatScore}/100, recommending immediate SOC isolation and perimeter blocking.`
  );

  return sentences.join(' ');
}
