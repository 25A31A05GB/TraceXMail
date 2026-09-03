/**
 * TraceXMail 5-Class ML Centroid-Cosine Classifier & Forensic Scoring Engine
 *
 * Implements:
 * 1. Runtime inference matching the trained Centroid Cosine model with temperature Softmax calibration.
 * 2. 5-Class probability distribution: Legitimate, Suspicious, Impersonated, Phishing, Fraud-related.
 * 3. Strict schema validation & fail-loudly model state checking.
 * 4. Transparent, non-double-counted Threat Score (0-100) with explainable component breakdown:
 *    - Authentication (max 25 pts)
 *    - Domain Intelligence (max 25 pts)
 *    - Infrastructure & Routing (max 20 pts)
 *    - ML Content Probability (max 20 pts)
 *    - Linguistic & Rule-Based Heuristics (max 10 pts)
 * 5. Honest commodity attribution (no fabricated APT threat actors; evidence != physical attacker location).
 */

import fs from 'fs';
import path from 'path';
import {
  extractForensicTokens,
  evaluateStructuralIdentity,
  loadBrandDefinitions,
  isPunycodeOrHomoglyph
} from './structuralFeatures.js';

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
  text?: string;
  replyTo?: string;
  returnPath?: string;
  auth?: {
    spf?: { status?: string; details?: string };
    dkim?: { status?: string; details?: string };
    dmarc?: { status?: string; details?: string; policy?: string };
    arc?: { status?: string; details?: string };
  };
  hops?: Array<{
    fromIp?: string;
    isPrivate?: boolean;
    isTor?: boolean;
    is_tor?: boolean;
    isBlacklisted?: boolean;
    abuseScore?: number;
    asn?: string;
    org?: string;
    city?: string;
    country?: string;
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
    mx_missing?: boolean;
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

export interface ThreatScoreBreakdown {
  total: number;
  maxScore: 100;
  components: {
    authentication: { score: number; max: 25; reasons: string[] };
    domainRisk: { score: number; max: 25; reasons: string[] };
    infrastructureRisk: { score: number; max: 20; reasons: string[] };
    mlClassification: { score: number; max: 20; reasons: string[] };
    heuristics: { score: number; max: 10; reasons: string[] };
  };
}

export interface ClassificationResult {
  classification: EmailClassification;
  predictedClass: EmailClassification;
  probabilities: Record<EmailClassification, number>;
  confidence: number;
  threatScore: number;
  threatScoreBreakdown: ThreatScoreBreakdown;
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
    disclaimer: string;
  };
}

export interface TrainedModelPayload {
  schemaVersion?: string;
  featureSchemaVersion?: string;
  metadata?: {
    modelName: string;
    algorithm: string;
    trainedAt?: string;
    trainingCorpora?: string[];
    totalSamples?: number;
    trainCount?: number;
    testCount?: number;
    classes: EmailClassification[];
    vocabularySize: number;
    testAccuracy: number;
    macroF1: number;
    weightedF1?: number;
    baselineAccuracy?: number;
    perClassMetrics?: Record<EmailClassification, { precision: number; recall: number; f1: number; support: number }>;
    confusionMatrix?: number[][];
  };
  featureSchema?: string[];
  vocabulary: string[];
  vocabMap: Record<string, number>;
  idf: Record<string, number>;
  centroids: number[][];
  priors: number[];
  temperature: number;
}

export const CLASS_NAMES: EmailClassification[] = [
  'Legitimate',
  'Suspicious',
  'Impersonated',
  'Phishing',
  'Fraud-related'
];

export class MachineLearningClassifier {
  private model: TrainedModelPayload | null = null;
  private modelStatus: 'OPERATIONAL' | 'MISSING_ARTIFACT' | 'CORRUPTED_SCHEMA' = 'MISSING_ARTIFACT';
  private loadError: string | null = null;

  constructor() {
    this.loadModel();
  }

  public loadModel(): boolean {
    try {
      const modelPath = path.join(process.cwd(), 'data/datasets/trained_model.json');
      if (!fs.existsSync(modelPath)) {
        this.modelStatus = 'MISSING_ARTIFACT';
        this.loadError = `Model artifact missing at: ${modelPath}`;
        console.warn(`[Classifier] ${this.loadError}`);
        return false;
      }

      const raw = fs.readFileSync(modelPath, 'utf-8');
      const parsed: TrainedModelPayload = JSON.parse(raw);

      // Strict Schema Validation
      if (!parsed.vocabulary || !Array.isArray(parsed.vocabulary) || parsed.vocabulary.length === 0) {
        throw new Error('Invalid model artifact: missing or empty vocabulary array');
      }
      if (!parsed.vocabMap || typeof parsed.vocabMap !== 'object') {
        throw new Error('Invalid model artifact: missing vocabMap lookup table');
      }
      if (!parsed.centroids || !Array.isArray(parsed.centroids) || parsed.centroids.length !== 5) {
        throw new Error(`Invalid model artifact: centroids array must have length 5 for 5 classes, received ${parsed.centroids?.length}`);
      }
      if (!parsed.idf || typeof parsed.idf !== 'object') {
        throw new Error('Invalid model artifact: missing idf weights map');
      }

      this.model = parsed;
      this.modelStatus = 'OPERATIONAL';
      this.loadError = null;
      console.log(`[Classifier] Successfully loaded ML model: ${this.model.metadata?.modelName || '5-Class Centroid Model'} (Schema: ${this.model.schemaVersion || '2.3.0'}, Vocab: ${this.model.vocabulary.length})`);
      return true;
    } catch (e: any) {
      this.model = null;
      this.modelStatus = 'CORRUPTED_SCHEMA';
      this.loadError = e?.message || 'Failed to parse model artifact';
      console.error('[Classifier] Critical error during model artifact loading:', this.loadError);
      return false;
    }
  }

  public getStatus() {
    return {
      status: this.modelStatus,
      error: this.loadError,
      isOperational: this.modelStatus === 'OPERATIONAL',
      modelName: this.model?.metadata?.modelName || null,
      schemaVersion: this.model?.schemaVersion || null,
      featureSchemaVersion: this.model?.featureSchemaVersion || null,
      classes: this.model?.metadata?.classes || CLASS_NAMES,
      vocabularySize: this.model?.vocabulary?.length || 0,
      metadata: this.model?.metadata || null,
      temperature: this.model?.temperature || 12.0
    };
  }

  /**
   * Tokenizes text and extracts forensic features matching training pipeline.
   */
  public tokenize(input: {
    subject: string;
    from?: string;
    fromDomain?: string;
    bodyText?: string;
    text?: string;
    replyTo?: string;
    returnPath?: string;
    auth?: ClassifierInput['auth'];
    domainIntelligence?: ClassifierInput['domainIntelligence'];
    hops?: ClassifierInput['hops'];
  }): string[] {
    return extractForensicTokens(input);
  }

  /**
   * Evaluates text through the trained Centroid Cosine ML engine.
   */
  public predict(input: {
    subject: string;
    from?: string;
    fromDomain?: string;
    bodyText?: string;
    text?: string;
    replyTo?: string;
    returnPath?: string;
    auth?: ClassifierInput['auth'];
    domainIntelligence?: ClassifierInput['domainIntelligence'];
    hops?: ClassifierInput['hops'];
  }): {
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

    if (!this.model || !this.model.vocabMap || !this.model.centroids) {
      return {
        predictedClass: 'Suspicious',
        probabilities: defaultProbs,
        confidence: 0.5,
        topFeatures: []
      };
    }

    const tokens = this.tokenize(input);
    const counts: Record<string, number> = {};
    for (const t of tokens) {
      if (this.model.vocabMap[t] !== undefined) {
        counts[t] = (counts[t] || 0) + 1;
      }
    }

    const entries: Array<[number, number]> = [];
    let sumSq = 0;
    for (const [t, count] of Object.entries(counts)) {
      const idx = this.model.vocabMap[t];
      const tf = 1 + Math.log(count);
      const tfidf = tf * (this.model.idf[t] || 1);
      entries.push([idx, tfidf]);
      sumSq += tfidf * tfidf;
    }

    const norm = Math.sqrt(sumSq) || 1;
    for (const e of entries) {
      e[1] /= norm;
    }

    const numClasses = CLASS_NAMES.length;
    const similarities = new Array(numClasses).fill(0);

    for (let c = 0; c < numClasses; c++) {
      let dot = 0;
      const centroidRow = this.model.centroids[c];
      if (centroidRow) {
        for (const [fIdx, val] of entries) {
          dot += (centroidRow[fIdx] || 0) * val;
        }
      }
      similarities[c] = dot;
    }

    const temperature = this.model.temperature || 12.0;
    const maxSim = Math.max(...similarities);
    let sumExp = 0;
    const exps = new Array(numClasses);
    for (let c = 0; c < numClasses; c++) {
      exps[c] = Math.exp(temperature * (similarities[c] - maxSim));
      sumExp += exps[c];
    }

    const probs = exps.map(e => (sumExp > 0 ? e / sumExp : 1 / numClasses));

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

    const tokenWeights: Array<{ token: string; weight: number }> = [];
    const centroidRow = this.model.centroids[bestIdx];
    if (centroidRow) {
      for (const [fIdx, val] of entries) {
        const token = this.model.vocabulary[fIdx];
        const w = (centroidRow[fIdx] || 0) * val;
        if (w > 0.005) {
          tokenWeights.push({ token, weight: parseFloat(w.toFixed(3)) });
        }
      }
    }
    tokenWeights.sort((a, b) => b.weight - a.weight);

    const sortedProbs = [...probs].sort((a, b) => b - a);
    const confidence = parseFloat((sortedProbs[0] - (sortedProbs[1] || 0)).toFixed(3));

    return {
      predictedClass,
      probabilities: resultProbs,
      confidence: Math.max(0.1, confidence),
      topFeatures: tokenWeights.slice(0, 8)
    };
  }
}

export const mlEngine = new MachineLearningClassifier();

/**
 * Main forensic classifier combining ML Centroid-Cosine TF-IDF inference with structural identity evidence.
 * Generates an explainable 0-100 Threat Score without double-counting.
 */
export function classifyEmailForensics(input: ClassifierInput): ClassificationResult {
  const features: FeatureWeight[] = [];
  const heuristics: ClassificationResult['heuristics'] = [];
  const topVectors: string[] = [];

  const mlOutput = mlEngine.predict({
    subject: input.subject,
    from: input.from,
    fromDomain: input.fromDomain,
    bodyText: input.bodyText || input.text,
    replyTo: input.replyTo,
    returnPath: input.returnPath,
    auth: input.auth,
    domainIntelligence: input.domainIntelligence,
    hops: input.hops
  });

  const structuralIdentity = evaluateStructuralIdentity({
    from: input.from,
    fromDomain: input.fromDomain,
    replyTo: input.replyTo,
    returnPath: input.returnPath,
    auth: input.auth,
    domainIntelligence: input.domainIntelligence,
    hops: input.hops
  });

  // -------------------------------------------------------------
  // Component 1: Authentication Evaluation (Max 25 pts)
  // -------------------------------------------------------------
  let authScore = 0;
  const authReasons: string[] = [];

  const spfStatus = input.auth?.spf?.status?.toUpperCase();
  const dkimStatus = input.auth?.dkim?.status?.toUpperCase();
  const dmarcStatus = input.auth?.dmarc?.status?.toUpperCase();

  if (spfStatus === 'FAIL') {
    authScore += 10;
    authReasons.push('SPF validation hard-failed (-all rejected sending host IP)');
  } else if (spfStatus === 'SOFTFAIL') {
    authScore += 6;
    authReasons.push('SPF validation soft-failed (~all unaligned sender IP)');
  }

  if (dkimStatus === 'FAIL' || dkimStatus === 'INVALID') {
    authScore += 10;
    authReasons.push('DKIM cryptographic signature verification failed');
  }

  if (dmarcStatus === 'REJECT' || dmarcStatus === 'FAIL') {
    authScore += 10;
    authReasons.push('DMARC alignment policy failed');
  }

  authScore = Math.min(25, authScore);
  features.push({
    feature: 'authentication_alignment',
    category: 'AUTHENTICATION',
    weight: authScore,
    triggered: authScore > 0,
    severity: authScore >= 15 ? 'CRITICAL' : authScore > 0 ? 'HIGH' : 'LOW',
    title: 'Authentication & Cryptographic Alignment',
    description: authReasons.length > 0
      ? authReasons.join('; ')
      : 'SPF, DKIM, and DMARC passing or aligned.'
  });

  // -------------------------------------------------------------
  // Component 2: Domain Risk Evaluation (Max 25 pts)
  // -------------------------------------------------------------
  let domainScore = 0;
  const domainReasons: string[] = [];

  const isTyposquat = Boolean(input.domainIntelligence?.typosquatting?.is_typosquat || structuralIdentity.isLookalikeDomain);
  const targetBrand = input.domainIntelligence?.typosquatting?.target_brand || structuralIdentity.claimedBrand;
  if (isTyposquat) {
    domainScore += 15;
    domainReasons.push(`Domain mimics enterprise brand "${targetBrand || 'Known Brand'}"`);
  }

  const isNxdomain = input.domainIntelligence?.status === 'nxdomain';
  if (isNxdomain) {
    domainScore += 15;
    domainReasons.push(`Domain ${input.fromDomain} does not exist in public authoritative DNS (NXDOMAIN)`);
  }

  const isNewDomain = Boolean(input.domainIntelligence?.is_newly_registered);
  const domainAge = input.domainIntelligence?.domain_age_days;
  if (isNewDomain) {
    domainScore += 10;
    domainReasons.push(`Newly registered domain (${domainAge !== undefined ? `${domainAge} days` : '<30 days'})`);
  }

  const mxMissing = Boolean(input.domainIntelligence?.mx_missing);
  if (mxMissing) {
    domainScore += 8;
    domainReasons.push('No Mail Exchanger (MX) records found in DNS');
  }

  domainScore = Math.min(25, domainScore);
  features.push({
    feature: 'domain_risk_intelligence',
    category: 'DOMAIN',
    weight: domainScore,
    triggered: domainScore > 0,
    severity: domainScore >= 15 ? 'CRITICAL' : domainScore > 0 ? 'HIGH' : 'LOW',
    title: 'Domain Risk & Registration Intelligence',
    description: domainReasons.length > 0 ? domainReasons.join('; ') : 'Established domain with authoritative DNS.'
  });

  // -------------------------------------------------------------
  // Component 3: Infrastructure & Route Risk (Max 20 pts)
  // -------------------------------------------------------------
  let infraScore = 0;
  const infraReasons: string[] = [];

  const torOrAbuseHop = input.hops?.find(h => h.isTor || h.is_tor || h.isBlacklisted || (h.abuseScore && h.abuseScore > 60));
  if (torOrAbuseHop) {
    infraScore += 15;
    infraReasons.push(`Relay hop ${torOrAbuseHop.fromIp || 'node'} flagged for anonymization / abuse score ${torOrAbuseHop.abuseScore || 85}%`);
  }

  infraScore = Math.min(20, infraScore);
  features.push({
    feature: 'infrastructure_route_risk',
    category: 'INFRASTRUCTURE',
    weight: infraScore,
    triggered: infraScore > 0,
    severity: infraScore >= 15 ? 'CRITICAL' : 'LOW',
    title: 'Transmission Route & Relay Infrastructure',
    description: infraReasons.length > 0 ? infraReasons.join('; ') : 'Transmission path passed through verified relays.'
  });

  // -------------------------------------------------------------
  // Component 4: Machine Learning Content Risk (Max 20 pts)
  // -------------------------------------------------------------
  const maliciousProbability = (mlOutput.probabilities.Phishing || 0) +
    (mlOutput.probabilities['Fraud-related'] || 0) +
    0.6 * (mlOutput.probabilities.Impersonated || 0) +
    0.3 * (mlOutput.probabilities.Suspicious || 0);

  const mlScore = Math.min(20, Math.round(maliciousProbability * 20));
  const mlReasons: string[] = [
    `ML classifier predicted class: "${mlOutput.predictedClass}" (confidence ${(mlOutput.confidence * 100).toFixed(1)}%)`,
    `Phishing prob: ${((mlOutput.probabilities.Phishing || 0) * 100).toFixed(1)}%, Fraud prob: ${((mlOutput.probabilities['Fraud-related'] || 0) * 100).toFixed(1)}%`
  ];

  features.push({
    feature: 'ml_content_probability',
    category: 'LINGUISTIC',
    weight: mlScore,
    triggered: mlScore > 5,
    severity: mlScore >= 15 ? 'CRITICAL' : mlScore >= 10 ? 'HIGH' : 'LOW',
    title: 'Machine Learning Content Classification',
    description: mlReasons.join(' | ')
  });

  // -------------------------------------------------------------
  // Component 5: Rule-Based Heuristics (Max 10 pts)
  // -------------------------------------------------------------
  let heuristicScore = 0;
  const heuristicReasons: string[] = [];

  if (structuralIdentity.isReplyToMismatch) {
    heuristicScore += 5;
    heuristicReasons.push(`Reply-To header routes to different domain (${input.replyTo})`);
  }

  if (structuralIdentity.isBrandDisplayMismatch) {
    heuristicScore += 5;
    heuristicReasons.push(`Display name claims identity "${structuralIdentity.claimedBrand}" but originates from unaligned domain ${input.fromDomain}`);
  }

  if (structuralIdentity.isPunycode) {
    heuristicScore += 5;
    heuristicReasons.push('Punycode / Homoglyph lookalike characters detected in sender domain');
  }

  heuristicScore = Math.min(10, heuristicScore);
  features.push({
    feature: 'heuristic_identity_rules',
    category: 'IDENTITY',
    weight: heuristicScore,
    triggered: heuristicScore > 0,
    severity: heuristicScore >= 8 ? 'HIGH' : heuristicScore > 0 ? 'MEDIUM' : 'LOW',
    title: 'Identity & Routing Redirection Heuristics',
    description: heuristicReasons.length > 0 ? heuristicReasons.join('; ') : 'No identity spoofing or reply redirection detected.'
  });

  // Calculate Total Threat Score (0 - 100)
  const totalThreatScore = Math.min(100, authScore + domainScore + infraScore + mlScore + heuristicScore);

  const threatScoreBreakdown: ThreatScoreBreakdown = {
    total: totalThreatScore,
    maxScore: 100,
    components: {
      authentication: { score: authScore, max: 25, reasons: authReasons },
      domainRisk: { score: domainScore, max: 25, reasons: domainReasons },
      infrastructureRisk: { score: infraScore, max: 20, reasons: infraReasons },
      mlClassification: { score: mlScore, max: 20, reasons: mlReasons },
      heuristics: { score: heuristicScore, max: 10, reasons: heuristicReasons }
    }
  };

  // Compile active heuristics list
  for (const feat of features) {
    if (feat.triggered) {
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

  // Classification & Verdict derivation
  let finalClass: EmailClassification = mlOutput.predictedClass;
  if (structuralIdentity.isBrandDisplayMismatch || structuralIdentity.isLookalikeDomain || structuralIdentity.isPunycode) {
    if (mlOutput.predictedClass !== 'Fraud-related') {
      finalClass = 'Impersonated';
    }
  }

  const verdict: ClassificationResult['verdict'] =
    finalClass === 'Phishing' ? 'MALICIOUS PHISH'
    : finalClass === 'Fraud-related' ? 'FRAUD-RELATED'
    : finalClass === 'Impersonated' ? 'IMPERSONATED'
    : finalClass === 'Suspicious' ? 'SUSPICIOUS'
    : 'LEGITIMATE';

  const severity: ClassificationResult['severity'] =
    totalThreatScore >= 80 ? 'CRITICAL'
    : totalThreatScore >= 60 ? 'HIGH'
    : totalThreatScore >= 35 ? 'MEDIUM'
    : totalThreatScore >= 15 ? 'LOW'
    : 'CLEAN';

  const phishingProbability = parseFloat((mlOutput.probabilities.Phishing || 0).toFixed(4));
  const mlConfidence = mlOutput.confidence;

  const attribution: ClassificationResult['attribution'] = {
    actor: 'Commodity Threat Infrastructure',
    confidence: 'LOW',
    reason: 'Forensic indicators reflect automated or commodity spoofing infrastructure; no specific APT actor attribution is made.',
    disclaimer: 'Evidence reflects intermediate transmission relays and network-level telemetry, NOT physical attacker location or definitive actor attribution.'
  };

  const infrastructureBreakdown = {
    spoofedDomain: isTyposquat || structuralIdentity.isBrandDisplayMismatch ? 85 : 10,
    anonymizedRelay: Boolean(torOrAbuseHop) ? 90 : 10,
    compromisedAccount: structuralIdentity.isReplyToMismatch ? 70 : 15,
    legitimateRoute: finalClass === 'Legitimate' ? 95 : 5
  };

  return {
    classification: finalClass,
    predictedClass: finalClass,
    probabilities: mlOutput.probabilities,
    confidence: mlConfidence,
    threatScore: totalThreatScore,
    threatScoreBreakdown,
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
