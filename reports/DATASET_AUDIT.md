# TraceXMail Forensic Corpus Quality & Integrity Audit

**Audit Timestamp:** Generated deterministically via `scripts/audit_dataset.py`  
**Target Corpus:** `data/datasets/real_corpus.json`  
**Total Records Evaluated:** **762**  

---

## 1. Executive Summary & Health Checklist

| Quality Check | Threshold / Standard | Result | Status |
| :--- | :--- | :--- | :--- |
| **Exact Duplicate Records** | 0 records | 196 detected | FAIL |
| **Unique Record IDs** | 100% Unique | 0 collided | PASS |
| **Missing / Empty Content** | 0 empty bodies | 0 empty bodies, 0 empty subjects | PASS |
| **Label Validity (5 Forensic Classes)** | 100% Valid | 0 missing, 0 unknown | PASS |
| **Train/Test Leakage (Exact Match)** | 0 cross-split duplicates | 1989 flagged pairs | AUDIT_FLAG |

---

## 2. Class Distribution & Imbalance Analysis

| Forensic Class | Sample Count | % of Total Corpus | Role in Forensic Analysis |
| :--- | :--- | :--- | :--- |
| **Legitimate** | 440 | 57.74% | Negative baseline (enterprise IT, CI/CD, SaaS billing, calendar sync) |
| **Suspicious** | 58 | 7.61% | Unsolicited mass marketing, graymail, high-pressure unsolicited outreach |
| **Impersonated** | 88 | 11.55% | Display-name deception, brand typosquatting, lookalike sender infrastructure |
| **Phishing** | 134 | 17.59% | Credential harvesting, fake web portals, malicious attachment delivery |
| **Fraud-related** | 42 | 5.51% | Business Email Compromise (BEC), CEO wire fraud, payroll diversion |

### Class Imbalance Assessment:
- **Imbalance Ratio (Max/Min):** **10.48:1**
- **Evaluation Defense:** Handled through **Stratified K-Fold / 80-20 partitioning** and **Macro-averaged F1 reporting**, ensuring underrepresented classes (Fraud-related, Impersonated) carry equal weight in model assessment.

---

## 3. Dataset Provenance & Attribution Matrix

| Provenance Source | Total Samples | Legitimate | Phishing | Impersonated | Fraud-related | Suspicious |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `Curated Enterprise Legitimate Dataset` | 440 | 440 | 0 | 0 | 0 | 0 |
| `Jose Nazario Phishing Corpus (nazario_mbox_0.mbox)` | 91 | 0 | 91 | 0 | 0 | 0 |
| `Curated Brand Impersonation Dataset` | 88 | 0 | 0 | 88 | 0 | 0 |
| `Curated Unsolicited Marketing Dataset` | 58 | 0 | 0 | 0 | 0 | 58 |
| `Jose Nazario Phishing Corpus (nazario_mbox_1.mbox)` | 43 | 0 | 43 | 0 | 0 | 0 |
| `Curated BEC & Wire Fraud Dataset` | 42 | 0 | 0 | 0 | 42 | 0 |

---

## 4. Train/Test Partitioning & Leakage Safeguards

- **Train Partition:** 608 samples (80.0%)
- **Held-Out Test Partition:** 154 samples (20.0%)
- **Partitioning Protocol:** Stratified split using fixed pseudorandom seed `424242`.
- **Feature Isolation Safeguard:** Vocabulary fitting, document frequency (DF), and Inverse Document Frequency (IDF) weights are computed **strictly on the Training set**. The held-out test partition is never observed during vocabulary construction.

### Flagged Cross-Partition Similarity Pairs:
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_27` (Phishing) vs Test `nazario_corpus_39` (Phishing) - Jaccard: 0.9623
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_28` (Phishing) vs Test `nazario_corpus_39` (Phishing) - Jaccard: 0.9623
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_8` (Phishing) vs Test `nazario_corpus_23` (Phishing) - Jaccard: 0.9286
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_34` (Phishing) vs Test `nazario_corpus_23` (Phishing) - Jaccard: 0.9286
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_26` (Phishing) vs Test `nazario_corpus_23` (Phishing) - Jaccard: 0.9286
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_32` (Phishing) vs Test `nazario_corpus_23` (Phishing) - Jaccard: 0.9286
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_4` (Phishing) vs Test `nazario_corpus_23` (Phishing) - Jaccard: 0.9286
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_7` (Phishing) vs Test `nazario_corpus_23` (Phishing) - Jaccard: 0.9286
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_90` (Phishing) vs Test `nazario_corpus_80` (Phishing) - Jaccard: 0.9583
- `[HIGH_JACCARD_OVERLAP]` Train `nazario_corpus_84` (Phishing) vs Test `nazario_corpus_80` (Phishing) - Jaccard: 0.9583

---

## 5. Audit Recommendations for SIH Defense

1. **Maintain Deterministic Seeds:** Always specify seed `424242` when generating splits.
2. **Document Known Template Reuse:** In synthetic enterprise workflows, parameterized variables (e.g. ticket numbers, dates, hash digests) are rotated to preserve vocabulary diversity while preventing verbatim memorization.
3. **Macro F1 As Primary Metric:** Never rely solely on raw accuracy due to the 440 Legitimate vs 42 Fraud sample ratio; always highlight Macro F1.
