import { EmailAnalysis } from '../types';
import { getStandardizedVerdict } from './verdict';

export interface CounterfactualFactor {
  factor: string;
  categoryKey: string;
  currentContribution: number;
  maxPossible: number;
  scoreIfFlipped: number;
  verdictIfFlipped: string;
  delta: number;
  actionText: string;
  isDecisive?: boolean;
}

/**
 * Derives the verdict string corresponding to a hypothetical numerical score.
 */
function getHypotheticalVerdict(hypotheticalScore: number, baseVerdict: string): string {
  const score = Math.max(0, Math.min(100, Math.round(hypotheticalScore)));
  if (score >= 70) {
    if (baseVerdict.includes('FRAUD')) return 'FRAUD-RELATED';
    if (baseVerdict.includes('IMPERSONAT')) return 'IMPERSONATED';
    return 'MALICIOUS PHISH';
  }
  if (score >= 35) {
    return 'SUSPICIOUS';
  }
  return 'LEGITIMATE';
}

/**
 * Pure function that computes counterfactual "what-if" score flips across the 5 forensic pillars:
 * 1. Authentication (25 pts)
 * 2. Domain Intelligence (25 pts)
 * 3. Infrastructure & Routing (20 pts)
 * 4. ML Content Classification (20 pts)
 * 5. Rule Heuristics (10 pts)
 */
export function computeCounterfactuals(analysis: Partial<EmailAnalysis> | null | undefined): CounterfactualFactor[] {
  if (!analysis) {
    return [];
  }

  const stdVerdict = getStandardizedVerdict(analysis);
  const currentTotal = stdVerdict.score;

  // Extract component scores from breakdown or derive from forensic telemetry
  const breakdown = analysis.threatScoreBreakdown?.components;

  // 1. Authentication (max 25)
  let authScore = breakdown?.authentication?.score;
  if (typeof authScore !== 'number') {
    const spfFail = analysis.auth?.spf?.status === 'FAIL' || analysis.authResults?.spf?.status === 'FAIL';
    const dkimFail = analysis.auth?.dkim?.status === 'FAIL' || analysis.authResults?.dkim?.status === 'FAIL';
    const dmarcFail = analysis.auth?.dmarc?.status === 'FAIL' || analysis.auth?.dmarc?.status === 'REJECT' || analysis.authResults?.dmarc?.status === 'REJECT';
    authScore = (dmarcFail ? 15 : 0) + (spfFail ? 5 : 0) + (dkimFail ? 5 : 0);
  }

  // 2. Domain Risk (max 25)
  let domainScore = breakdown?.domainRisk?.score;
  if (typeof domainScore !== 'number') {
    const domIntel = analysis.domain_intelligence || analysis.domainIntelligence;
    const isTypo = Boolean(domIntel?.is_typosquat || domIntel?.typosquatting?.is_typosquat);
    const isNew = Boolean(domIntel?.is_newly_registered || (typeof domIntel?.domain_age_days === 'number' && domIntel.domain_age_days <= 30));
    domainScore = (isTypo ? 15 : 0) + (isNew ? 10 : 0);
  }

  // 3. Infrastructure Risk (max 20)
  let infraScore = breakdown?.infrastructureRisk?.score;
  if (typeof infraScore !== 'number') {
    const firstHop = analysis.hops && analysis.hops.length > 0 ? (analysis.hops.find(h => h.isOrigin) || analysis.hops[0]) : undefined;
    const isTor = Boolean(firstHop?.is_tor || firstHop?.isTorExitNode || firstHop?.reverseDns?.includes('tor'));
    const abuseHigh = (firstHop?.abuseScore ?? 0) > 50;
    infraScore = isTor ? 20 : abuseHigh ? 15 : 0;
  }

  // 4. ML Classification (max 20)
  let mlScore = breakdown?.mlClassification?.score;
  if (typeof mlScore !== 'number') {
    const prob = analysis.mlConfidence ?? analysis.phishingProbability ?? (currentTotal >= 70 ? 0.95 : 0.1);
    mlScore = Math.round(prob * 20);
  }

  // 5. Heuristics & Signals (max 10)
  let heurScore = breakdown?.heuristics?.score;
  if (typeof heurScore !== 'number') {
    const trigCount = (analysis.heuristics || analysis.heuristicSignals || []).filter(h => h.triggered).length;
    heurScore = Math.min(10, trigCount * 3);
  }

  const rawPillars = [
    {
      factor: 'Authentication (SPF / DKIM / DMARC)',
      categoryKey: 'authentication',
      currentContribution: Math.min(25, Math.max(0, authScore)),
      maxPossible: 25,
      cleanAction: 'If cryptographic signatures & DMARC aligned (Passed)',
      failAction: 'If SPF, DKIM, and DMARC failed strict alignment'
    },
    {
      factor: 'Domain Intelligence & Age',
      categoryKey: 'domainRisk',
      currentContribution: Math.min(25, Math.max(0, domainScore)),
      maxPossible: 25,
      cleanAction: 'If sending domain had established age & zero lookalike traits',
      failAction: 'If sending domain was newly registered lookalike typosquat'
    },
    {
      factor: 'Infrastructure & Routing',
      categoryKey: 'infrastructureRisk',
      currentContribution: Math.min(20, Math.max(0, infraScore)),
      maxPossible: 20,
      cleanAction: 'If origin IP had clean IP reputation with zero Tor/proxy hops',
      failAction: 'If origin IP was high-abuse blacklist host or Tor exit relay'
    },
    {
      factor: 'ML Content Classification',
      categoryKey: 'mlClassification',
      currentContribution: Math.min(20, Math.max(0, mlScore)),
      maxPossible: 20,
      cleanAction: 'If ML semantic model evaluated text body as neutral/benign',
      failAction: 'If ML semantic model detected critical phishing lures'
    },
    {
      factor: 'Linguistic & Rule Heuristics',
      categoryKey: 'heuristics',
      currentContribution: Math.min(10, Math.max(0, heurScore)),
      maxPossible: 10,
      cleanAction: 'If zero social engineering or identity diversion rules fired',
      failAction: 'If urgency, wire pretext, and double-extension rules fired'
    }
  ];

  const results: CounterfactualFactor[] = rawPillars.map(p => {
    let scoreIfFlipped: number;
    let actionText: string;

    if (p.currentContribution > 0) {
      // Risk points were added by this factor: what if it was clean?
      scoreIfFlipped = Math.max(0, currentTotal - p.currentContribution);
      actionText = p.cleanAction;
    } else {
      // Currently 0 risk points: what if this factor completely failed?
      scoreIfFlipped = Math.min(100, currentTotal + p.maxPossible);
      actionText = p.failAction;
    }

    const delta = scoreIfFlipped - currentTotal;
    const verdictIfFlipped = getHypotheticalVerdict(scoreIfFlipped, stdVerdict.rawVerdict);

    return {
      factor: p.factor,
      categoryKey: p.categoryKey,
      currentContribution: p.currentContribution,
      maxPossible: p.maxPossible,
      scoreIfFlipped,
      verdictIfFlipped,
      delta,
      actionText
    };
  });

  // Identify the single most decisive factor (greatest swing magnitude)
  let maxSwing = -1;
  let decisiveIdx = 0;
  results.forEach((r, idx) => {
    const swing = Math.abs(r.delta);
    if (swing > maxSwing) {
      maxSwing = swing;
      decisiveIdx = idx;
    }
  });

  if (results[decisiveIdx]) {
    results[decisiveIdx].isDecisive = true;
  }

  // Sort with most decisive first, followed by descending swing magnitude
  return results.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
}
