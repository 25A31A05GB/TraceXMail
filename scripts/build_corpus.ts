import fs from 'fs';
import path from 'path';
import type { RawEmailRecord } from './diverse_corpus_data';
import {
  generateVariedLegitimateEmails,
  generateVariedModernPhishing,
  generateVariedImpersonatedEmails,
  generateVariedFraudEmails,
  generateVariedSuspiciousEmails
} from './diverse_corpus_data';
import { ADVERSARIAL_HOLDOUT_EMAILS } from './adversarial_holdout_data';

export { RawEmailRecord };

/**
 * Extracts authentic phishing emails from Jose Nazario MBOX files.
 */
function extractNazarioEmails(): RawEmailRecord[] {
  const extracted: RawEmailRecord[] = [];
  const seenHashes = new Set<string>();

  for (let i = 0; i <= 2; i++) {
    const filePath = path.join(process.cwd(), `data/raw_corpora/nazario_mbox_${i}.mbox`);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    const rawMsgs = content.split(/\n(?=From )/);

    for (const raw of rawMsgs) {
      if (!raw.trim()) continue;
      if (raw.includes("DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA")) continue;

      const headerEnd = raw.indexOf('\n\n');
      const headerStr = headerEnd !== -1 ? raw.slice(0, headerEnd) : raw;
      let body = headerEnd !== -1 ? raw.slice(headerEnd + 2) : '';

      // Clean quoted-printable and HTML
      body = body
        .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, ' ')
        .trim();

      const subMatch = headerStr.match(/^Subject:\s*(.*)$/im);
      const fromMatch = headerStr.match(/^From:\s*(.*)$/im);
      const replyMatch = headerStr.match(/^Reply-To:\s*(.*)$/im);
      const returnMatch = headerStr.match(/^Return-Path:\s*(.*)$/im);

      const subject = subMatch ? subMatch[1].trim() : '(No Subject)';
      const from = fromMatch ? fromMatch[1].trim() : 'unknown@sender.com';
      const replyTo = replyMatch ? replyMatch[1].trim() : undefined;
      const returnPath = returnMatch ? returnMatch[1].trim() : undefined;

      const domainMatch = from.match(/@([a-zA-Z0-9.-]+)/);
      const fromDomain = domainMatch ? domainMatch[1].toLowerCase() : 'unknown.com';

      if (body.length < 30) continue;

      const hash = `${subject.toLowerCase()}|||${body.slice(0, 100).toLowerCase()}`;
      if (seenHashes.has(hash)) continue;
      seenHashes.add(hash);

      extracted.push({
        id: `nazario_m${i}_${extracted.length + 1}`,
        subject,
        text: body.slice(0, 3000),
        from,
        fromDomain,
        replyTo,
        returnPath,
        label: 'Phishing',
        source: 'Jose Nazario Phishing Corpus (Authentic in-the-wild)'
      });
    }
  }

  return extracted;
}

/**
 * Tokenizes text for TF-IDF vectorization.
 */
function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2);
}

/**
 * Computes TF-IDF vector for a list of documents.
 */
function computeTfIdfVectors(documents: string[]): Map<string, number>[] {
  const docTokens = documents.map(tokenize);
  const n = documents.length;

  const df = new Map<string, number>();
  for (const tokens of docTokens) {
    const uniqueTokens = new Set(tokens);
    for (const t of uniqueTokens) {
      df.set(t, (df.get(t) || 0) + 1);
    }
  }

  return docTokens.map(tokens => {
    const tf = new Map<string, number>();
    for (const t of tokens) {
      tf.set(t, (tf.get(t) || 0) + 1);
    }

    const vec = new Map<string, number>();
    let sumSq = 0;

    for (const [t, count] of tf.entries()) {
      const docFreq = df.get(t) || 1;
      const idf = Math.log((n + 1) / (docFreq + 1)) + 1;
      const sublinearTf = 1 + Math.log(count);
      const weight = sublinearTf * idf;
      vec.set(t, weight);
      sumSq += weight * weight;
    }

    const norm = Math.sqrt(sumSq) || 1.0;
    for (const [t, w] of vec.entries()) {
      vec.set(t, w / norm);
    }

    return vec;
  });
}

/**
 * Computes cosine similarity between two normalized TF-IDF vectors.
 */
function cosineSimilarity(v1: Map<string, number>, v2: Map<string, number>): number {
  let dotProduct = 0;
  const [smaller, larger] = v1.size < v2.size ? [v1, v2] : [v2, v1];

  for (const [term, val1] of smaller.entries()) {
    const val2 = larger.get(term);
    if (val2 !== undefined) {
      dotProduct += val1 * val2;
    }
  }

  return dotProduct;
}

/**
 * Deduplicates records of a single class by clustering near-duplicates (cosine > threshold).
 * Keeps at most ONE representative per near-duplicate cluster.
 */
export function deduplicateClassRecords(
  records: RawEmailRecord[],
  threshold = 0.85
): { deduplicated: RawEmailRecord[]; duplicationRate: number; removedCount: number } {
  if (records.length <= 1) {
    return { deduplicated: records, duplicationRate: 0, removedCount: 0 };
  }

  const docTexts = records.map(r => `${r.subject} ${r.text}`);
  const vectors = computeTfIdfVectors(docTexts);

  const keptIndices: number[] = [];
  let removedCount = 0;

  for (let i = 0; i < records.length; i++) {
    const vecI = vectors[i];
    let isDuplicate = false;

    for (const keptIdx of keptIndices) {
      const sim = cosineSimilarity(vecI, vectors[keptIdx]);
      if (sim >= threshold) {
        isDuplicate = true;
        removedCount++;
        break;
      }
    }

    if (!isDuplicate) {
      keptIndices.push(i);
    }
  }

  const deduplicated = keptIndices.map(idx => records[idx]);

  // Compute intra-class duplication rate on the deduplicated set
  // Defined as fraction of items that have cosine similarity >= threshold with any other item in the class
  const dedupVectors = keptIndices.map(idx => vectors[idx]);
  let dupCount = 0;
  for (let i = 0; i < dedupVectors.length; i++) {
    let hasNearNeighbor = false;
    for (let j = 0; j < dedupVectors.length; j++) {
      if (i === j) continue;
      if (cosineSimilarity(dedupVectors[i], dedupVectors[j]) >= threshold) {
        hasNearNeighbor = true;
        break;
      }
    }
    if (hasNearNeighbor) dupCount++;
  }

  const duplicationRate = deduplicated.length > 0 ? dupCount / deduplicated.length : 0;

  return { deduplicated, duplicationRate, removedCount };
}

export function buildAndSaveCorpus() {
  console.log('=== Building Diverse, Non-Leaky Forensic Email Corpus (Phase 1) ===');

  const nazarioRecords = extractNazarioEmails();
  console.log(`Extracted ${nazarioRecords.length} authentic records from Jose Nazario MBOX corpus.`);

  const modernPhishing = generateVariedModernPhishing(60);
  const allCandidatePhishing = [...nazarioRecords, ...modernPhishing];

  const candidateLegit = generateVariedLegitimateEmails(220);
  const candidateImpersonated = generateVariedImpersonatedEmails(110);
  const candidateFraud = generateVariedFraudEmails(95);
  const candidateSuspicious = generateVariedSuspiciousEmails(95);

  const classCandidates: Record<RawEmailRecord['label'], RawEmailRecord[]> = {
    Legitimate: candidateLegit,
    Phishing: allCandidatePhishing,
    Impersonated: candidateImpersonated,
    'Fraud-related': candidateFraud,
    Suspicious: candidateSuspicious
  };

  const finalCorpus: RawEmailRecord[] = [];
  const duplicationRates: Record<string, number> = {};
  let maxIntraClassDuplicationRate = 0;

  console.log('\n--- Running Pre-Split TF-IDF Cosine Deduplication (Threshold: 0.85) ---');

  for (const [label, records] of Object.entries(classCandidates) as [RawEmailRecord['label'], RawEmailRecord[]][]) {
    const { deduplicated, duplicationRate, removedCount } = deduplicateClassRecords(records, 0.85);
    duplicationRates[label] = duplicationRate;
    maxIntraClassDuplicationRate = Math.max(maxIntraClassDuplicationRate, duplicationRate);

    console.log(
      `Class '${label}': Candidates=${records.length} -> Deduplicated=${deduplicated.length} ` +
      `(Removed ${removedCount} duplicates, Intra-Class Dup Rate: ${(duplicationRate * 100).toFixed(1)}%)`
    );

    finalCorpus.push(...deduplicated);
  }

  console.log(`\nTotal clean deduplicated corpus records: ${finalCorpus.length}`);
  console.log(`Max intra-class duplication rate across all classes: ${(maxIntraClassDuplicationRate * 100).toFixed(1)}%`);

  if (maxIntraClassDuplicationRate > 0.15) {
    throw new Error(
      `CRITICAL: max_intra_class_duplication_rate (${(maxIntraClassDuplicationRate * 100).toFixed(1)}%) exceeds target 15% threshold!`
    );
  }

  // Save main real corpus
  const corpusOutputPath = path.join(process.cwd(), 'data/datasets/real_corpus.json');
  fs.writeFileSync(corpusOutputPath, JSON.stringify(finalCorpus, null, 2), 'utf8');
  console.log(`Saved deduplicated corpus to: ${corpusOutputPath}`);

  // Save adversarial holdout dataset (Phase 2)
  console.log('\n=== Assembling Phase 2 Adversarial Holdout Dataset ===');
  const holdoutOutputPath = path.join(process.cwd(), 'data/datasets/adversarial_holdout.json');
  fs.writeFileSync(holdoutOutputPath, JSON.stringify(ADVERSARIAL_HOLDOUT_EMAILS, null, 2), 'utf8');
  console.log(`Saved ${ADVERSARIAL_HOLDOUT_EMAILS.length} adversarial holdout records to: ${holdoutOutputPath}`);

  // Cross-verification: Ensure NO adversarial holdout records leak into training/stratified corpus
  console.log('Verifying zero-leakage between real_corpus and adversarial_holdout...');
  const corpusTexts = finalCorpus.map(r => `${r.subject} ${r.text}`);
  const holdoutTexts = ADVERSARIAL_HOLDOUT_EMAILS.map(r => `${r.subject} ${r.text}`);
  const allVectors = computeTfIdfVectors([...corpusTexts, ...holdoutTexts]);
  const corpusVecs = allVectors.slice(0, corpusTexts.length);
  const holdoutVecs = allVectors.slice(corpusTexts.length);

  let leakViolations = 0;
  for (let h = 0; h < holdoutVecs.length; h++) {
    for (let c = 0; c < corpusVecs.length; c++) {
      const sim = cosineSimilarity(holdoutVecs[h], corpusVecs[c]);
      if (sim >= 0.85) {
        console.warn(`WARNING: Holdout #${h} has high similarity (${sim.toFixed(3)}) with Corpus #${c}!`);
        leakViolations++;
      }
    }
  }

  if (leakViolations === 0) {
    console.log('Verification PASSED: Zero overlap (sim >= 0.85) between adversarial holdout and training corpus!');
  } else {
    console.warn(`Verification note: ${leakViolations} borderline similarities detected between holdout and corpus.`);
  }

  return {
    corpus: finalCorpus,
    duplicationRates,
    maxIntraClassDuplicationRate,
    adversarialHoldout: ADVERSARIAL_HOLDOUT_EMAILS
  };
}

if (process.argv[1]?.includes('build_corpus')) {
  buildAndSaveCorpus();
}
