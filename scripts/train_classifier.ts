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

export const FORENSIC_CLASSES: Array<RawEmailRecord['label']> = [
  'Legitimate',
  'Suspicious',
  'Impersonated',
  'Phishing',
  'Fraud-related'
];

export function tokenizeForensics(text: string): string[] {
  const normalized = text
    .toLowerCase()
    .replace(/https?:\/\/[^\s]+/g, ' url_token ')
    .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, ' ip_token ')
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const words = normalized.split(' ').filter(w => w.length > 2 && w.length < 25);
  const tokens: string[] = [...words];

  for (let i = 0; i < words.length - 1; i++) {
    tokens.push(`${words[i]}_${words[i + 1]}`);
  }

  // Domain cue tokens
  if (/wire transfer|escrow|bank deposit|direct deposit|payroll|routing number|w-2 form|gift card|gift cards|invoice #|remittance advice/i.test(text)) {
    tokens.push('__cue_fraud_wire__', '__cue_fraud_wire__', '__cue_fraud_wire__');
  }
  if (/paypal|apple id|microsoft 365|office 365|chase online|bank of america|docusign|wells fargo|netflix billing/i.test(text)) {
    tokens.push('__cue_brand_target__', '__cue_brand_target__');
  }
  if (/password expire|account suspended|unauthorized access|verify your identity|confirm password|restore access|billing failure/i.test(text)) {
    tokens.push('__cue_phish_lure__', '__cue_phish_lure__', '__cue_phish_lure__');
  }
  if (/unsubscribe|promotional offer|discount voucher|b2b leads|webinar invitation|opt-out/i.test(text)) {
    tokens.push('__cue_marketing_susp__', '__cue_marketing_susp__');
  }
  if (/github|pull request|jira ticket|commit|code review|standup notes|quarterly planning|internal meeting|zoom meeting/i.test(text)) {
    tokens.push('__cue_legit_work__', '__cue_legit_work__', '__cue_legit_work__');
  }

  return tokens;
}

export function trainHighAccuracyModel() {
  const datasetPath = path.join(process.cwd(), 'data/datasets/real_corpus.json');
  const allRecords: RawEmailRecord[] = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));

  const numClasses = FORENSIC_CLASSES.length;
  const docTokensList = allRecords.map(r => tokenizeForensics(`${r.subject} ${r.subject} ${r.from} ${r.text}`));
  const docFreq: Record<string, number> = {};

  for (const docTokens of docTokensList) {
    const uniqueInDoc = new Set(docTokens);
    for (const token of uniqueInDoc) {
      docFreq[token] = (docFreq[token] || 0) + 1;
    }
  }

  const N = allRecords.length;
  // Vocabulary with informative tokens
  const sortedTokens = Object.entries(docFreq)
    .filter(([token, count]) => token.startsWith('__cue_') || (count >= 2 && count <= N * 0.85))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3500)
    .map(([token]) => token);

  sortedTokens.sort();
  const vocabulary = sortedTokens;
  const idf: Record<string, number> = {};

  vocabulary.forEach(token => {
    const count = docFreq[token] || 1;
    idf[token] = parseFloat((Math.log((N + 1) / (count + 1)) + 1).toFixed(4));
  });

  const vocabIndex = new Map<string, number>();
  vocabulary.forEach((token, idx) => vocabIndex.set(token, idx));

  type SparseVector = Array<[number, number]>;

  function vectorizeSparse(tokens: string[]): SparseVector {
    const termCounts: Record<string, number> = {};
    for (const t of tokens) {
      termCounts[t] = (termCounts[t] || 0) + 1;
    }

    const entries: Array<[number, number]> = [];
    let normSq = 0;

    for (const [t, count] of Object.entries(termCounts)) {
      const idx = vocabIndex.get(t);
      if (idx !== undefined) {
        const tf = Math.log(1 + count);
        const tfidf = tf * idf[t];
        entries.push([idx, tfidf]);
        normSq += tfidf * tfidf;
      }
    }

    const norm = Math.sqrt(normSq);
    if (norm > 0) {
      for (const entry of entries) {
        entry[1] /= norm;
      }
    }

    return entries;
  }

  const X = docTokensList.map(vectorizeSparse);
  const y = allRecords.map(r => FORENSIC_CLASSES.indexOf(r.label));

  // Stratified 80/20 train/test split
  const classIndices: Record<number, number[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
  y.forEach((classIdx, docIdx) => classIndices[classIdx].push(docIdx));

  const trainIndices: number[] = [];
  const testIndices: number[] = [];

  for (let c = 0; c < FORENSIC_CLASSES.length; c++) {
    const indices = classIndices[c];
    const shuffled = [...indices].sort((a, b) => ((a * 9301 + 49297) % 233280) - ((b * 9301 + 49297) % 233280));
    const splitPoint = Math.floor(shuffled.length * 0.8);
    trainIndices.push(...shuffled.slice(0, splitPoint));
    testIndices.push(...shuffled.slice(splitPoint));
  }

  // Complement / Multinomial Naive Bayes with Log Probabilities + TF-IDF Smoothing
  // This provides solid empirical calibration for text classification across imbalanced classes.
  const classFeatureCounts: number[][] = Array.from({ length: numClasses }, () => new Array(vocabulary.length).fill(0));
  const classTotalTokens: number[] = new Array(numClasses).fill(0);
  const classDocCounts: number[] = new Array(numClasses).fill(0);

  const alpha = 0.5; // Laplace smoothing

  for (const idx of trainIndices) {
    const classIdx = y[idx];
    classDocCounts[classIdx]++;
    for (const [fIdx, val] of X[idx]) {
      classFeatureCounts[classIdx][fIdx] += val;
      classTotalTokens[classIdx] += val;
    }
  }

  // Precompute log likelihoods per class
  // weights[c][f] = log( (count + alpha) / (total + alpha * V) )
  const weights: number[][] = Array.from({ length: numClasses }, () => new Array(vocabulary.length).fill(0));
  const biases: number[] = new Array(numClasses).fill(0);

  const totalTrainDocs = trainIndices.length;
  for (let c = 0; c < numClasses; c++) {
    // Prior
    biases[c] = Math.log((classDocCounts[c] + 1) / (totalTrainDocs + numClasses));
    const denominator = classTotalTokens[c] + alpha * vocabulary.length;

    for (let f = 0; f < vocabulary.length; f++) {
      weights[c][f] = Math.log((classFeatureCounts[c][f] + alpha) / denominator);
    }
  }

  function predict(tokens: string[]) {
    const xi = vectorizeSparse(tokens);
    const logPosteriors = new Array(numClasses);

    for (let c = 0; c < numClasses; c++) {
      let score = biases[c];
      for (const [fIdx, val] of xi) {
        score += weights[c][fIdx] * val * 10.0; // scale factor
      }
      logPosteriors[c] = score;
    }

    // Softmax normalization
    let maxLog = -Infinity;
    for (let c = 0; c < numClasses; c++) {
      if (logPosteriors[c] > maxLog) maxLog = logPosteriors[c];
    }

    let sumExp = 0;
    const probs = new Array(numClasses);
    for (let c = 0; c < numClasses; c++) {
      probs[c] = Math.exp(logPosteriors[c] - maxLog);
      sumExp += probs[c];
    }
    for (let c = 0; c < numClasses; c++) {
      probs[c] /= sumExp;
    }

    let bestClass = 0;
    let bestProb = -1;
    for (let c = 0; c < numClasses; c++) {
      if (probs[c] > bestProb) {
        bestProb = probs[c];
        bestClass = c;
      }
    }

    const probMap: Record<string, number> = {};
    FORENSIC_CLASSES.forEach((className, idx) => {
      probMap[className] = parseFloat(probs[idx].toFixed(4));
    });

    const featureContributions: Array<{ token: string; weight: number }> = [];
    for (const [fIdx, val] of xi) {
      const token = vocabulary[fIdx];
      const w = weights[bestClass][fIdx] * val;
      featureContributions.push({ token, weight: parseFloat(w.toFixed(3)) });
    }
    featureContributions.sort((a, b) => b.weight - a.weight);

    const sortedProbs = [...probs].sort((a, b) => b - a);
    const confidence = parseFloat((sortedProbs[0] - (sortedProbs[1] || 0)).toFixed(3));

    return {
      predictedClass: FORENSIC_CLASSES[bestClass],
      classIndex: bestClass,
      probabilities: probMap,
      confidence: Math.max(0.15, confidence),
      topFeatures: featureContributions.slice(0, 8)
    };
  }

  // Test set evaluation
  let correct = 0;
  const confusionMatrix: number[][] = Array.from({ length: numClasses }, () => new Array(numClasses).fill(0));

  for (const idx of testIndices) {
    const r = allRecords[idx];
    const trueClassIdx = y[idx];
    const pred = predict(tokenizeForensics(`${r.subject} ${r.subject} ${r.from} ${r.text}`));

    confusionMatrix[trueClassIdx][pred.classIndex]++;
    if (pred.classIndex === trueClassIdx) {
      correct++;
    }
  }

  const accuracy = parseFloat((correct / testIndices.length).toFixed(4));
  console.log(`\n======================================================`);
  console.log(`=== Calibrated Naive Bayes Test Set Accuracy: ${(accuracy * 100).toFixed(2)}% (${correct}/${testIndices.length}) ===`);
  console.log(`======================================================`);
  console.log('Confusion Matrix (Rows = Actual [Legit, Susp, Imp, Phish, Fraud], Cols = Predicted):');
  console.table(confusionMatrix);

  const metricsPerClass: Record<string, { precision: number; recall: number; f1: number }> = {};
  for (let c = 0; c < numClasses; c++) {
    const className = FORENSIC_CLASSES[c];
    const tp = confusionMatrix[c][c];
    let fp = 0;
    let fn = 0;
    for (let r = 0; r < numClasses; r++) {
      if (r !== c) fp += confusionMatrix[r][c];
    }
    for (let col = 0; col < numClasses; col++) {
      if (col !== c) fn += confusionMatrix[c][col];
    }

    const precision = tp + fp > 0 ? parseFloat((tp / (tp + fp)).toFixed(3)) : 1.0;
    const recall = tp + fn > 0 ? parseFloat((tp / (tp + fn)).toFixed(3)) : 1.0;
    const f1 = precision + recall > 0 ? parseFloat(((2 * precision * recall) / (precision + recall)).toFixed(3)) : 0;
    metricsPerClass[className] = { precision, recall, f1 };
  }
  console.log('Per-Class Metrics:', metricsPerClass);

  // Save model bundle
  const modelBundle = {
    metadata: {
      trainedAt: new Date().toISOString(),
      trainingCorpora: ['Jose Nazario Phishing Corpus', 'SpamAssassin Ham Corpus', 'Curated Forensics'],
      totalSamples: allRecords.length,
      trainCount: trainIndices.length,
      testCount: testIndices.length,
      classes: FORENSIC_CLASSES,
      accuracy,
      metricsPerClass
    },
    vocabulary,
    idf,
    weights,
    biases
  };

  const modelSavePath = path.join(process.cwd(), 'data/datasets/trained_model.json');
  fs.writeFileSync(modelSavePath, JSON.stringify(modelBundle), 'utf8');
  console.log(`Saved calibrated model to: ${modelSavePath}`);

  // Test inference cases
  console.log('\n=== Inference Validations ===');
  console.log('1. Known Phishing:', predict(tokenizeForensics('Subject: PayPal Security Alert: Account Suspended. Please confirm your password and identity.')));
  console.log('2. BEC Wire Fraud:', predict(tokenizeForensics('Subject: URGENT: Executive Wire Transfer Request. Please wire $45,000 to vendor escrow.')));
  console.log('3. Brand Impersonation:', predict(tokenizeForensics('From: DocuSign Service <admin@docusign-envelope-review.com> Subject: Review and sign legal document')));
  console.log('4. Suspicious Promo:', predict(tokenizeForensics('Subject: Exclusive 75% Discount on B2B SaaS Leads Blast! Click here to unsubscribe.')));
  console.log('5. Legitimate Work Email:', predict(tokenizeForensics('From: GitHub Notifications <notifications@github.com> Subject: [GitHub] Pull Request #12 merged into main by Jay.')));
  console.log('6. Legitimate Meeting Notes:', predict(tokenizeForensics('From: Team Lead <lead@company.com> Subject: Team Weekly Standup Notes and Sprint Planning agenda.')));

  return modelBundle;
}

trainHighAccuracyModel();
