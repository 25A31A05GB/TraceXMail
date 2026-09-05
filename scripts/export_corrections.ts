/**
 * TraceXMail Analyst-Feedback Dataset Export Script (C4)
 * Exports reviewed human analyst corrections from data/datasets/classifier_corrections.json
 * into normalized training samples ready for retraining or fine-tuning.
 *
 * Usage:
 *   npx tsx scripts/export_corrections.ts [--approved-only] [--all] [--out <filepath>]
 */

import fs from 'fs';
import path from 'path';
import { loadCorrections, type ClassifierCorrection, normalizeVerdictLabel } from '../src/server/classifierFeedback.js';

export const FORENSIC_CLASSES = [
  'Legitimate',
  'Suspicious',
  'Impersonated',
  'Phishing',
  'Fraud-related'
] as const;

export type ForensicClass = typeof FORENSIC_CLASSES[number];

export interface ExportedCorrectionRecord {
  id: string;
  subject: string;
  text: string;
  from: string;
  fromDomain: string;
  label: ForensicClass;
  source: string;
  analyst_notes: string;
  analyst_email: string;
  original_model_prediction: string;
  model_confidence: number;
  status: string;
  created_at: string;
  reviewed_at?: string;
}

function parseCliArgs() {
  const args = process.argv.slice(2);
  let approvedOnly = true;
  let outputPath = path.join(process.cwd(), 'data/datasets/reviewed_corrections.json');

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--all') {
      approvedOnly = false;
    } else if (args[i] === '--approved-only') {
      approvedOnly = true;
    } else if (args[i] === '--out' && args[i + 1]) {
      outputPath = path.resolve(process.cwd(), args[i + 1]);
      i++;
    }
  }

  return { approvedOnly, outputPath };
}

export function exportCorrections(options?: { approvedOnly?: boolean; outputPath?: string }) {
  const approvedOnly = options?.approvedOnly ?? true;
  const outputPath = options?.outputPath ?? path.join(process.cwd(), 'data/datasets/reviewed_corrections.json');

  const corrections: ClassifierCorrection[] = loadCorrections();

  console.log('================================================================');
  console.log('TRACEXMAIL ANALYST FEEDBACK EXPORT PIPELINE (C4)');
  console.log('================================================================');
  console.log(`Total Feedback Records in Store: ${corrections.length}`);
  console.log(`Filter Mode:                     ${approvedOnly ? 'Approved Only' : 'All (Including Pending & Reviewed)'}`);
  console.log(`Target Output Path:              ${outputPath}`);

  const filtered = approvedOnly
    ? corrections.filter(c => c.status === 'approved')
    : corrections.filter(c => c.status !== 'rejected');

  const classCounts: Record<ForensicClass, number> = {
    Legitimate: 0,
    Suspicious: 0,
    Impersonated: 0,
    Phishing: 0,
    'Fraud-related': 0
  };

  const exportedRecords: ExportedCorrectionRecord[] = [];

  for (const item of filtered) {
    const normVerdict = normalizeVerdictLabel(item.analyst_verdict) as ForensicClass;
    if (!FORENSIC_CLASSES.includes(normVerdict)) {
      continue;
    }

    classCounts[normVerdict] = (classCounts[normVerdict] || 0) + 1;

    exportedRecords.push({
      id: `feedback_${item.id}`,
      subject: item.subject || 'Investigated Communication',
      text: item.body_snippet || item.analyst_notes || item.subject || '',
      from: item.from || (item.from_domain ? `analyst-case@${item.from_domain}` : 'analyst-case@unknown.net'),
      fromDomain: item.from_domain || 'unknown.net',
      label: normVerdict,
      source: 'analyst_feedback',
      analyst_notes: item.analyst_notes || 'Analyst verdict override',
      analyst_email: item.analyst_email || 'soc-analyst@enterprise.internal',
      original_model_prediction: item.model_prediction,
      model_confidence: item.model_confidence,
      status: item.status,
      created_at: item.created_at,
      reviewed_at: item.reviewed_at
    });
  }

  // Ensure output directory exists
  const outDir = path.dirname(outputPath);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  fs.writeFileSync(outputPath, JSON.stringify(exportedRecords, null, 2), 'utf8');

  console.log('\n--- Export Breakdown by Ground-Truth Forensic Class ---');
  console.table(
    FORENSIC_CLASSES.map(cls => ({
      'Forensic Class': cls,
      'Exported Count': classCounts[cls]
    }))
  );

  console.log(`\nSuccessfully exported ${exportedRecords.length} records to ${outputPath}`);
  return {
    exportedCount: exportedRecords.length,
    perClass: classCounts,
    outputPath,
    records: exportedRecords
  };
}

// Direct execution
if (process.argv[1]?.endsWith('export_corrections.ts')) {
  const opts = parseCliArgs();
  exportCorrections(opts);
}
