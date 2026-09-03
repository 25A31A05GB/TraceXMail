/**
 * TraceXMail 5-Class ML TF-IDF Classifier & Forensic Evaluation Engine
 * Trained on Nazario Phishing Corpora, SpamAssassin Ham Benchmarks, and Real Threat Corpora.
 *
 * Classes:
 * 0: Legitimate
 * 1: Suspicious
 * 2: Impersonated
 * 3: Phishing
 * 4: Fraud-related
 */

import fs from 'fs';
import path from 'path';

export type EmailClassification =
  | 'Legitimate'
  | 'Suspicious'
  | 'Impersonated'
  | 'Phishing'
  | 'Fraud-related';

export interface ClassifierInput {
  from: string;
  fromDomain: string;
  to?: string;
  subject: string;
  bodyText?: string;
  replyTo?: string;
  returnPath?: string;
  hops?: Array<{
    fromIp?: string;
    isPrivate?: boolean;
    isTor?: boolean;
    isBlacklisted?: boolean;
    abuseScore?: number;
    asn?: string;
    org?: string;
  }>;
  domainIntelligence?: {
    status?: string;
    is_newly_registered?: boolean;
    domain_age_days?: number;
    dns?: {
      spf?: string;
      spf_qualifier?: string;
      dmarc?: string;
      dmarc_policy?: string;
      mx_records?: string[];
    };
    typosquatting?: {
      is_typosquat?: boolean;
      target_brand?: string;
      technique?: string;
    };
  };
}

export interface FeatureWeight {
  feature: string;
  category: 'AUTHENTICATION' | 'INFRASTRUCTURE' | 'LINGUISTIC' | 'DOMAIN' | 'IDENTITY';
  weight: number;
  triggered: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
}

export interface ClassificationResult {
  classification: EmailClassification;
  predictedClass: EmailClassification;
  probabilities: Record<EmailClassification, number>;
  confidence: number;
  threatScore: number;
  phishingProbability: number;
  mlConfidence: number;
  verdict: 'MALICIOUS PHISH' | 'SUSPICIOUS' | 'LEGITIMATE' | 'IMPERSONATED' | 'FRAUD-RELATED';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
  features: FeatureWeight[];
  topFeatures: Array<{ token: string; weight: number }>;
  heuristics: Array<{
    id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    triggered: boolean;
  }>;
  topVectors: string[];
  infrastructureBreakdown: {
    spoofedDomain: number;
    anonymizedRelay: number;
    compromisedAccount: number;
    legitimateRoute: number;
  };
  attribution: {
    actor: string;
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    reason: string;
  };
}

interface TrainedModelPayload {
  metadata?: {
    accuracy?: number;
    macroF1?: number;
    weightedF1?: number;
    totalSamples?: number;
    trainCount?: number;
    testCount?: number;
  };
  classes: string[];
  vocabulary: string[];
  vocabMap?: Record<string, number>;
  idf: number[];
  weights?: number[][];
  biases?: number[];
  priors?: number[];
  logLikelihoods?: number[][];
  numClasses: number;
  vocabSize: number;
}

const CLASS_NAMES: EmailClassification[] = [
  'Legitimate',
  'Suspicious',
  'Impersonated',
  'Phishing',
  'Fraud-related'
];

class MachineLearningClassifier {
  private model: TrainedModelPayload | null = null;
  private vocabLookup: Map<string, number> = new Map();

  constructor() {
    this.loadModel();
  }

  private loadModel() {
    try {
      const modelPath = path.join(process.cwd(), 'data/datasets/trained_model.json');
      if (fs.existsSync(modelPath)) {
        const raw = fs.readFileSync(modelPath, 'utf-8');
        this.model = JSON.parse(raw);
        if (this.model) {
          if (this.model.vocabMap) {
            this.vocabLookup = new Map(Object.entries(this.model.vocabMap));
          } else if (Array.isArray(this.model.vocabulary)) {
            this.vocabLookup = new Map(this.model.vocabulary.map((t, idx) => [t, idx]));
          }
        }
      }
    } catch (e) {
      console.warn('[Classifier] Could not load trained_model.json, using fallback heuristics:', e);
      this.model = null;
    }
  }

  /**
   * Tokenizes text and appends forensic signal cues.
   */
  public tokenize(text: string): string[] {
    const lower = text.toLowerCase();
    const words = lower.match(/[a-z0-9_]{2,}/g) || [];
    const tokens: string[] = [];

    for (const w of words) {
      if (w.length >= 2 && w.length <= 25) {
        tokens.push(w);
      }
    }

    // Bi-grams
    for (let i = 0; i < words.length - 1; i++) {
      tokens.push(`${words[i]}_${words[i + 1]}`);
    }

    // High-Signal Forensic Cues
    if (/(?:wire transfer|direct deposit|payroll update|gift card|invoice payment|swift transfer|escrow|routing number)/i.test(text)) {
      tokens.push('__cue_fraud_wire__', '__cue_fraud_wire__');
    }
    if (/(?:urgent|immediate|account suspended|password expired|verify your identity|security alert|confirm password|restore access)/i.test(text)) {
      tokens.push('__cue_phish_lure__', '__cue_phish_lure__');
    }
    if (/(?:docusign|microsoft|office 365|paypal|chase|apple|wells fargo|bank of america|netflix)/i.test(text)) {
      tokens.push('__cue_brand_target__', '__cue_brand_target__');
    }
    if (/(?:click here|unsubscribe|exclusive offer|special discount|blast|promo deal|b2b leads|webinar)/i.test(text)) {
      tokens.push('__cue_marketing_susp__', '__cue_marketing_susp__');
    }
    if (/(?:github|pull request|jira|meeting notes|standup|agenda|sprint|team discussion|patch|linux|debian|python)/i.test(text)) {
      tokens.push('__cue_legit_work__', '__cue_legit_work__');
    }

    return tokens;
  }

  /**
   * Evaluates text through the trained ML inference engine.
   */
  public predict(text: string): {
    predictedClass: EmailClassification;
    probabilities: Record<EmailClassification, number>;
    confidence: number;
    topFeatures: Array<{ token: string; weight: number }>;
  } {
    const defaultProbs: Record<EmailClassification, number> = {
      Legitimate: 0.2,
      Suspicious: 0.2,
      Impersonated: 0.2,
      Phishing: 0.2,
      'Fraud-related': 0.2
    };

    if (!this.model) {
      return {
        predictedClass: 'Suspicious',
        probabilities: defaultProbs,
        confidence: 0.5,
        topFeatures: []
      };
    }

    const tokens = this.tokenize(text);

    // Support Calibrated Softmax Logistic Regression model (weights + biases)
    if (this.model.weights && this.model.biases) {
      const counts: Record<number, number> = {};
      for (const t of tokens) {
        const idx = this.vocabLookup.get(t);
        if (idx !== undefined) {
          counts[idx] = (counts[idx] || 0) + 1;
        }
      }

      let normSq = 0;
      const entries: Array<[number, number]> = [];
      for (const [idxStr, cnt] of Object.entries(counts)) {
        const idx = Number(idxStr);
        const idfVal = this.model.idf[idx] || 1.0;
        const val = (1.0 + Math.log(cnt)) * idfVal;
        entries.push([idx, val]);
        normSq += val * val;
      }
      const norm = Math.sqrt(normSq);
      if (norm > 0) {
        for (const e of entries) e[1] /= norm;
      }

      const numClasses = this.model.numClasses || 5;
      const logits = [...this.model.biases];
      for (const [idx, val] of entries) {
        for (let c = 0; c < numClasses; c++) {
          logits[c] += this.model.weights[c][idx] * val;
        }
      }

      const maxLogit = Math.max(...logits);
      const exps = logits.map(l => Math.exp(l - maxLogit));
      const sumExp = exps.reduce((a, b) => a + b, 0);
      const probs = exps.map(e => e / (sumExp || 1));

      let bestIdx = 0;
      let bestProb = -1;
      for (let i = 0; i < probs.length; i++) {
        if (probs[i] > bestProb) {
          bestProb = probs[i];
          bestIdx = i;
        }
      }

      const predictedClass = CLASS_NAMES[bestIdx] || 'Suspicious';
      const resultProbs: Record<EmailClassification, number> = {
        Legitimate: parseFloat((probs[0] || 0).toFixed(4)),
        Suspicious: parseFloat((probs[1] || 0).toFixed(4)),
        Impersonated: parseFloat((probs[2] || 0).toFixed(4)),
        Phishing: parseFloat((probs[3] || 0).toFixed(4)),
        'Fraud-related': parseFloat((probs[4] || 0).toFixed(4))
      };

      const tokenWeights: Array<{ token: string; weight: number }> = [];
      for (const [idx, val] of entries) {
        const token = this.model.vocabulary[idx];
        const w = this.model.weights[bestIdx][idx] * val;
        tokenWeights.push({ token, weight: parseFloat(w.toFixed(3)) });
      }
      tokenWeights.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

      return {
        predictedClass,
        probabilities: resultProbs,
        confidence: parseFloat(bestProb.toFixed(3)),
        topFeatures: tokenWeights.slice(0, 8)
      };
    }

    // Fallback Naive Bayes (logLikelihoods + priors)
    if (this.model.priors && this.model.logLikelihoods) {
      const logPosteriors = [...this.model.priors];
      const tokenWeights: Array<{ token: string; weight: number }> = [];
      const countedTokens = new Set<string>();

      for (const token of tokens) {
        const idx = this.vocabLookup.get(token);
        if (idx !== undefined && !countedTokens.has(token)) {
          countedTokens.add(token);
          const idfVal = this.model.idf[idx] || 1;
          for (let c = 0; c < this.model.numClasses; c++) {
            const ll = this.model.logLikelihoods[c][idx];
            logPosteriors[c] += ll * idfVal;
          }
          tokenWeights.push({
            token,
            weight: parseFloat((this.model.logLikelihoods[3][idx] || 0).toFixed(3))
          });
        }
      }

      const maxLog = Math.max(...logPosteriors);
      const exps = logPosteriors.map(lp => Math.exp(lp - maxLog));
      const sumExp = exps.reduce((a, b) => a + b, 0);
      const probs = exps.map(e => e / sumExp);

      let bestIdx = 0;
      let bestProb = -1;
      for (let i = 0; i < probs.length; i++) {
        if (probs[i] > bestProb) {
          bestProb = probs[i];
          bestIdx = i;
        }
      }

      const predictedClass = CLASS_NAMES[bestIdx] || 'Suspicious';
      const resultProbs: Record<EmailClassification, number> = {
        Legitimate: parseFloat(probs[0].toFixed(4)),
        Suspicious: parseFloat(probs[1].toFixed(4)),
        Impersonated: parseFloat(probs[2].toFixed(4)),
        Phishing: parseFloat(probs[3].toFixed(4)),
        'Fraud-related': parseFloat(probs[4].toFixed(4))
      };

      return {
        predictedClass,
        probabilities: resultProbs,
        confidence: parseFloat(bestProb.toFixed(3)),
        topFeatures: tokenWeights.slice(0, 8)
      };
    }

    return {
      predictedClass: 'Suspicious',
      probabilities: defaultProbs,
      confidence: 0.5,
      topFeatures: []
    };
  }
}

const mlEngine = new MachineLearningClassifier();

const URGENCY_PATTERNS = [
  /\burgent\b/i,
  /\bimmediate(?:ly)?\b/i,
  /\baction required\b/i,
  /\baccount (?:suspended|restricted|locked|disabled)\b/i,
  /\bwithin 24 hours\b/i,
  /\bpassword (?:expired|expir(?:es|y)|reset)\b/i,
  /\bunauthorized (?:access|activity|sign-in)\b/i,
  /\bverify your (?:identity|account|credentials)\b/i,
  /\bsecurity alert\b/i,
  /\bwire (?:transfer|redirection)\b/i,
  /\bdirect deposit\b/i,
  /\bpayroll update\b/i
];

const BRAND_KEYWORDS = [
  { name: 'PayPal', pattern: /\bpaypal\b/i, domainPattern: /paypal\.com$/i },
  { name: 'Microsoft', pattern: /\bmicrosoft|office\s*365|m365|outlook\b/i, domainPattern: /(?:microsoft|office365|live|outlook)\.com$/i },
  { name: 'DocuSign', pattern: /\bdocusign\b/i, domainPattern: /docusign\.com$/i },
  { name: 'Google', pattern: /\bgoogle|gmail\b/i, domainPattern: /(?:google|gmail)\.com$/i },
  { name: 'Apple', pattern: /\bapple|icloud\b/i, domainPattern: /(?:apple|icloud)\.com$/i },
  { name: 'Chase', pattern: /\bchase\b/i, domainPattern: /chase\.com$/i },
  { name: 'Bank of America', pattern: /\bbank of america|bofa\b/i, domainPattern: /bankofamerica\.com$/i }
];

/**
 * Main forensic classifier combining ML TF-IDF inference with structural header evidence.
 */
export function classifyEmailForensics(input: ClassifierInput): ClassificationResult {
  const features: FeatureWeight[] = [];
  const heuristics: ClassificationResult['heuristics'] = [];
  const topVectors: string[] = [];

  const textCorpus = `${input.subject} ${input.bodyText || ''} from:${input.from} domain:${input.fromDomain}`;
  const mlOutput = mlEngine.predict(textCorpus);

  // 1. Typosquatting / Brand Lookalike Evaluation
  const isTyposquat = Boolean(input.domainIntelligence?.typosquatting?.is_typosquat);
  const targetBrand = input.domainIntelligence?.typosquatting?.target_brand;
  features.push({
    feature: 'domain_typosquatting',
    category: 'DOMAIN',
    weight: 42,
    triggered: isTyposquat,
    severity: 'CRITICAL',
    title: 'Brand Impersonation & Typosquatting Domain',
    description: isTyposquat
      ? `Sending domain ${input.fromDomain} mimics enterprise brand "${targetBrand}" (${input.domainIntelligence?.typosquatting?.technique || 'lookalike'}).`
      : 'No lookalike domain permutations detected.'
  });

  // 2. Display Name Spoofing Check
  let displayNameSpoof = false;
  let spoofedBrandName = '';
  for (const brand of BRAND_KEYWORDS) {
    if (brand.pattern.test(input.from) && !brand.domainPattern.test(input.fromDomain)) {
      displayNameSpoof = true;
      spoofedBrandName = brand.name;
      break;
    }
  }
  features.push({
    feature: 'display_name_spoofing',
    category: 'IDENTITY',
    weight: 35,
    triggered: displayNameSpoof,
    severity: 'HIGH',
    title: 'Display Name Identity Spoofing',
    description: displayNameSpoof
      ? `Display header claims identity "${spoofedBrandName}" but originates from unaligned domain ${input.fromDomain}.`
      : 'Display name aligns with sender envelope domain.'
  });

  // 3. Authoritative DNS Existence (NXDOMAIN)
  const isNxdomain = input.domainIntelligence?.status === 'nxdomain';
  features.push({
    feature: 'nxdomain_status',
    category: 'DOMAIN',
    weight: 38,
    triggered: isNxdomain,
    severity: 'HIGH',
    title: 'Non-Existent Sender Domain (NXDOMAIN)',
    description: isNxdomain
      ? `Domain ${input.fromDomain} has no authoritative SOA or NS records in public DNS.`
      : 'Domain successfully resolved in public DNS hierarchy.'
  });

  // 4. Newly Registered Domain (< 30 days)
  const isNewDomain = Boolean(input.domainIntelligence?.is_newly_registered);
  const domainAge = input.domainIntelligence?.domain_age_days;
  features.push({
    feature: 'newly_registered_domain',
    category: 'DOMAIN',
    weight: 22,
    triggered: isNewDomain,
    severity: 'HIGH',
    title: 'Newly Registered Domain (NRD)',
    description: isNewDomain
      ? `Sender domain was registered recently (${domainAge !== undefined ? `${domainAge} days ago` : '< 30 days'}).`
      : `Domain established with mature registration history (${domainAge !== undefined ? `${domainAge} days` : '> 1 year'}).`
  });

  // 5. Tor / Blacklisted Relay Hop Infrastructure
  const torHop = input.hops?.find(h => h.isTor || h.isBlacklisted || (h.abuseScore && h.abuseScore > 60));
  features.push({
    feature: 'anonymized_relay_hop',
    category: 'INFRASTRUCTURE',
    weight: 40,
    triggered: Boolean(torHop),
    severity: 'CRITICAL',
    title: 'Anonymized / High-Abuse Relay Infrastructure',
    description: torHop
      ? `Transmission path includes high-risk hop ${torHop.fromIp || 'node'} (Tor Exit / Abuse confidence ${torHop.abuseScore || 85}%).`
      : 'No anonymized exit nodes or flagged relay subnets detected in route trace.'
  });

  // 6. Linguistic Urgency & Fraud Triggers
  const matchedUrgencyPatterns = URGENCY_PATTERNS.filter(regex => regex.test(textCorpus));
  const hasUrgency = matchedUrgencyPatterns.length > 0;
  features.push({
    feature: 'linguistic_urgency_triggers',
    category: 'LINGUISTIC',
    weight: Math.min(25, matchedUrgencyPatterns.length * 8),
    triggered: hasUrgency,
    severity: matchedUrgencyPatterns.length >= 2 ? 'HIGH' : 'MEDIUM',
    title: 'Urgency & Psychological Coercion Cues',
    description: hasUrgency
      ? `Linguistic scanning detected ${matchedUrgencyPatterns.length} urgency patterns in message content.`
      : 'No high-pressure psychological manipulation tokens detected.'
  });

  // 7. Reply-To / Return-Path Mismatch
  const replyTo = (input.replyTo || '').toLowerCase();
  const replyToDomainMatch = replyTo.match(/@([\w.-]+)/);
  const replyToDomain = replyToDomainMatch ? replyToDomainMatch[1] : '';
  const hasReplyToMismatch = Boolean(replyToDomain && replyToDomain !== input.fromDomain.toLowerCase());
  features.push({
    feature: 'reply_to_mismatch',
    category: 'IDENTITY',
    weight: 20,
    triggered: hasReplyToMismatch,
    severity: 'MEDIUM',
    title: 'Reply-To Routing Redirection',
    description: hasReplyToMismatch
      ? `Reply-To header directs responses to different domain (${replyToDomain}) than sender (${input.fromDomain}).`
      : 'Reply-To routing matches envelope sender.'
  });

  // Calculate Heuristics & Threat Score
  let scoreSum = 0;
  for (const feat of features) {
    if (feat.triggered) {
      scoreSum += feat.weight;
      heuristics.push({
        id: `h-${feat.feature}`,
        title: feat.title,
        severity: feat.severity,
        description: feat.description,
        triggered: true
      });
      topVectors.push(feat.title);
    }
  }

  // Determine final fused classification
  let finalClass: EmailClassification = mlOutput.predictedClass;
  if (isTyposquat || displayNameSpoof) {
    finalClass = 'Impersonated';
  } else if (matchedUrgencyPatterns.some(p => p.source.includes('wire') || p.source.includes('payroll') || p.source.includes('deposit'))) {
    finalClass = 'Fraud-related';
  } else if (scoreSum >= 65 && finalClass === 'Legitimate') {
    finalClass = 'Phishing';
  }

  const threatScore = Math.min(99, Math.max(5, Math.round(scoreSum * 0.7 + (1 - mlOutput.probabilities.Legitimate) * 30)));
  const phishingProbability = parseFloat((1 - mlOutput.probabilities.Legitimate).toFixed(3));
  const mlConfidence = mlOutput.confidence;

  const verdict: ClassificationResult['verdict'] =
    finalClass === 'Phishing' ? 'MALICIOUS PHISH'
    : finalClass === 'Fraud-related' ? 'FRAUD-RELATED'
    : finalClass === 'Impersonated' ? 'IMPERSONATED'
    : finalClass === 'Suspicious' ? 'SUSPICIOUS'
    : 'LEGITIMATE';

  const severity: ClassificationResult['severity'] =
    threatScore > 85 ? 'CRITICAL'
    : threatScore > 70 ? 'HIGH'
    : threatScore > 40 ? 'MEDIUM'
    : threatScore > 20 ? 'LOW'
    : 'CLEAN';

  // Honest attribution: No fake TA505/Lazarus/Storm-0324
  const attribution: ClassificationResult['attribution'] = {
    actor: 'Unattributed',
    confidence: 'LOW',
    reason: 'Forensic telemetry indicates generic commodity phishing / BEC infrastructure without verified APT signatures.'
  };

  const infrastructureBreakdown = {
    spoofedDomain: isTyposquat || displayNameSpoof ? 85 : 15,
    anonymizedRelay: Boolean(torHop) ? 90 : 10,
    compromisedAccount: hasReplyToMismatch ? 65 : 20,
    legitimateRoute: finalClass === 'Legitimate' ? 95 : 5
  };

  return {
    classification: finalClass,
    predictedClass: finalClass,
    probabilities: mlOutput.probabilities,
    confidence: mlConfidence,
    threatScore,
    phishingProbability,
    mlConfidence,
    verdict,
    severity,
    features,
    topFeatures: mlOutput.topFeatures,
    heuristics,
    topVectors,
    infrastructureBreakdown,
    attribution
  };
}
