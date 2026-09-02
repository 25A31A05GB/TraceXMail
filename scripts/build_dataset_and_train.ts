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

  // Domain & structural bigrams
  for (let i = 0; i < words.length - 1; i++) {
    tokens.push(`${words[i]}_${words[i + 1]}`);
  }

  // Domain cues
  if (/wire|deposit|payroll|w-2|gift card|invoice|remittance|bank transfer|escrow/i.test(text)) {
    tokens.push('__cue_financial_wire__', '__cue_financial_wire__');
  }
  if (/password|verify|suspend|restore|unauthorized|credential|login to|security alert/i.test(text)) {
    tokens.push('__cue_credential_urgency__', '__cue_credential_urgency__');
  }
  if (/unsubscribe|newsletter|discount|promo|deal|leads|summit|opt-out/i.test(text)) {
    tokens.push('__cue_marketing_promo__', '__cue_marketing_promo__');
  }
  if (/paypal|microsoft|docusign|apple|chase|wellsfargo|netflix|google workspace/i.test(text)) {
    tokens.push('__cue_brand_name__', '__cue_brand_name__');
  }
  if (/github|commit|pull request|issue|patch|linux|standup|agenda|meeting|sprint/i.test(text)) {
    tokens.push('__cue_legitimate_dev__', '__cue_legitimate_dev__');
  }

  return tokens;
}

export function trainAndEvaluate() {
  const datasetPath = path.join(process.cwd(), 'data/datasets/real_corpus.json');
  if (!fs.existsSync(datasetPath)) {
    throw new Error('Dataset file real_corpus.json not found!');
  }

  const allRecords: RawEmailRecord[] = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
  console.log(`Loaded ${allRecords.length} validated forensic records.`);

  const distribution: Record<string, number> = {};
  for (const r of allRecords) {
    distribution[r.label] = (distribution[r.label] || 0) + 1;
  }
  console.log('Class Distribution:', distribution);

  // === Step 1: Vocabulary & TF-IDF Feature Selection ===
  const docTokensList = allRecords.map(r => tokenizeForensics(`${r.subject} ${r.subject} ${r.from} ${r.text}`));
  const docFreq: Record<string, number> = {};

  for (const docTokens of docTokensList) {
    const uniqueInDoc = new Set(docTokens);
    for (const token of uniqueInDoc) {
      docFreq[token] = (docFreq[token] || 0) + 1;
    }
  }

  const N = allRecords.length;
  const sortedTokens = Object.entries(docFreq)
    .filter(([token, count]) => token.startsWith('__cue_') || (count >= 2 && count <= N * 0.9))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3000)
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
  console.log(`Vocabulary Size: ${vocabulary.length}`);

  // Sparse vector: [featureIndex, tfidfValue]
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

  // Stratified Split
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

  console.log(`Training Samples: ${trainIndices.length}, Testing Samples: ${testIndices.length}`);

  // Train Softmax Multi-Class Classifier with calibrated feature updates
  const numClasses = FORENSIC_CLASSES.length;
  const numFeatures = vocabulary.length;

  const weights: number[][] = Array.from({ length: numClasses }, () => new Array(numFeatures).fill(0));
  const biases: number[] = new Array(numClasses).fill(0);

  const epochs = 250;
  const learningRate = 0.5;
  const l2Lambda = 0.00002;

  // Initialize class biases with class prior logs
  for (let c = 0; c < numClasses; c++) {
    const prior = (classIndices[c].length || 1) / allRecords.length;
    biases[c] = Math.log(prior);
  }

  for (let epoch = 0; epoch < epochs; epoch++) {
    const currentLr = learningRate / (1 + 0.002 * epoch);

    for (const idx of trainIndices) {
      const xi = X[idx];
      const yi = y[idx];

      const logits = new Array(numClasses);
      let maxLogit = -Infinity;

      for (let c = 0; c < numClasses; c++) {
        let dot = biases[c];
        for (const [fIdx, val] of xi) {
          dot += weights[c][fIdx] * val;
        }
        logits[c] = dot;
        if (dot > maxLogit) maxLogit = dot;
      }

      let sumExp = 0;
      const probs = new Array(numClasses);
      for (let c = 0; c < numClasses; c++) {
        probs[c] = Math.exp(logits[c] - maxLogit);
        sumExp += probs[c];
      }
      for (let c = 0; c < numClasses; c++) {
        probs[c] /= sumExp;
      }

      for (let c = 0; c < numClasses; c++) {
        const target = c === yi ? 1.0 : 0.0;
        const grad = probs[c] - target;

        biases[c] -= currentLr * grad;
        for (const [fIdx, val] of xi) {
          weights[c][fIdx] -= currentLr * (grad * val + l2Lambda * weights[c][fIdx]);
        }
      }
    }
  }

  // Evaluation on Test Set
  let correct = 0;
  const confusionMatrix: number[][] = Array.from({ length: numClasses }, () => new Array(numClasses).fill(0));

  function predict(tokens: string[]) {
    const xi = vectorizeSparse(tokens);
    const logits = new Array(numClasses);
    let maxLogit = -Infinity;

    for (let c = 0; c < numClasses; c++) {
      let dot = biases[c];
      for (const [fIdx, val] of xi) {
        dot += weights[c][fIdx] * val;
      }
      logits[c] = dot;
      if (dot > maxLogit) maxLogit = dot;
    }

    let sumExp = 0;
    const probs = new Array(numClasses);
    for (let c = 0; c < numClasses; c++) {
      probs[c] = Math.exp(logits[c] - maxLogit);
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
      if (Math.abs(w) > 0.05) {
        featureContributions.push({ token, weight: parseFloat(w.toFixed(3)) });
      }
    }
    featureContributions.sort((a, b) => b.weight - a.weight);

    const sortedProbs = [...probs].sort((a, b) => b - a);
    const confidence = parseFloat((sortedProbs[0] - (sortedProbs[1] || 0)).toFixed(3));

    return {
      predictedClass: FORENSIC_CLASSES[bestClass],
      classIndex: bestClass,
      probabilities: probMap,
      confidence: Math.max(0.1, confidence),
      topFeatures: featureContributions.slice(0, 8)
    };
  }

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
  console.log(`\n=== Test Set Accuracy: ${(accuracy * 100).toFixed(2)}% (${correct}/${testIndices.length}) ===`);
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
  console.log(`Saved trained model to: ${modelSavePath}`);

  console.log('\n=== Inference Validations ===');
  console.log('1. Known Phishing:', predict(tokenizeForensics('Subject: PayPal Security Alert: Account Suspended. Please confirm your password and identity.')));
  console.log('2. BEC Wire Fraud:', predict(tokenizeForensics('Subject: URGENT: Executive Wire Transfer Request. Please wire $45,000 to vendor escrow.')));
  console.log('3. Brand Impersonation:', predict(tokenizeForensics('From: DocuSign Service <admin@docusign-envelope-review.com> Subject: Review and sign legal document')));
  console.log('4. Suspicious Promo:', predict(tokenizeForensics('Subject: Exclusive 75% Discount on B2B SaaS Leads Blast! Click here to unsubscribe.')));
  console.log('5. Legitimate Email:', predict(tokenizeForensics('From: GitHub <notifications@github.com> Subject: [GitHub] Pull Request #12 merged by Jay.')));
}

trainAndEvaluate();
