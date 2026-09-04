# Model Card: TraceXMail 5-Class Forensic Email Classifier & Multi-Layer NLP Pipeline
**Model Name:** TraceXMail Forensic Classifier & Layered NLP Pipeline v2.5  
**Architecture:** Multi-Layer Defense-in-Depth Pipeline (Layer 0 Centroid-Cosine TF-IDF Baseline + Layer 1 Gemini text-embedding-004 Semantic Similarity + Layer 2 Structured LLM Linguistic Forensics [HYPOTHESIS] + Layer 3 Weighted Lexicons & Checksum-Validated Financial Entity Extraction)  
**Developers:** TraceXMail Core Engineering Team (SIH 2026 — Problem Statement 26106)  
**Standard:** Modeled after Mitchell et al. (*Model Cards for Model Reporting*, FAT* 2019)  
**Date:** September 2026  
**License:** Open Source / MIT  

---

## 1. Multi-Layer Forensic Pipeline Architecture

The TraceXMail classification and NLP stack operates as a layered, defense-in-depth pipeline where each layer produces distinct, separately labeled evidence without silently overriding the baseline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Inbound Email Message Body & Headers                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│     LAYER 0      │          │     LAYER 1      │          │     LAYER 2      │
│ Deterministic    │          │ Semantic Embed   │          │ Structured LLM   │
│ Centroid-Cosine  │          │ Gemini text-     │          │ Linguistic       │
│ TF-IDF + Identity│          │ embedding-004    │          │ Forensics        │
│ Baseline         │          │ Reference Match  │          │ [HYPOTHESIS]     │
└────────┬─────────┘          └────────┬─────────┘          └────────┬─────────┘
         │                             │                             │
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │     LAYER 3      │
                              │ Always-On Free   │
                              │ Deterministic    │
                              │ Weighted Lexicon │
                              │ & Entity Extr.   │
                              └────────┬─────────┘
                                       │
                                       ▼
                       Combined Layered Forensic Evidence
                       (Separately Tagged & Explainable)
```

### Layer Breakdown

1. **Layer 0 — Centroid-Cosine TF-IDF Vector Space Model (Deterministic Baseline):**
   - **Vector Space:** Sublinear Term Frequency ($\text{TF} = 1 + \ln(\text{count})$) $\times$ Inverse Document Frequency ($\text{IDF} = \ln\left(\frac{N+1}{\text{DF}+1}\right) + 1$).
   - **Normalization:** Euclidean hypersphere projection ($\|v\|_2 = 1.0$) for document length invariance.
   - **Classification:** Normalized Class Mean Centroids with Cosine Similarity $\cos(\theta) = \mathbf{w}_c \cdot \mathbf{x}$.
   - **Probability Calibration:** Temperature-scaled Softmax ($T = 12.0$) producing calibrated posterior probabilities $P(y = c \mid \mathbf{x}) = \frac{e^{T \cdot s_c}}{\sum_k e^{T \cdot s_k}}$.
   - **Structural Envelope Cues:** Deterministic injection of header mismatch tokens (`feat_brand_display_domain_mismatch`, `feat_lookalike_hyphenated_brand`, `feat_reply_to_mismatch`, `feat_return_path_mismatch`).

2. **Layer 1 — Semantic Embedding Similarity (`src/server/semanticSimilarity.ts`):**
   - **Embedding Model:** Gemini `text-embedding-004` (768-dimensional dense semantic vectors).
   - **Corpus:** Curated reference set of canonical phishing, BEC wire fraud, impersonation lures, and enterprise DevOps templates.
   - **Inference:** Computes cosine similarity between inbound email embeddings and reference clusters.
   - **Graceful Degradation:** If `GEMINI_API_KEY` is not set, skips layer and returns `status: 'UNAVAILABLE'` without fabricating scores.

3. **Layer 2 — Structured LLM Linguistic Forensics (`src/server/linguisticForensics.ts`):**
   - **Provider:** Groq (`llama-3.3-70b-versatile`) with automatic fallback to Gemini (`gemini-2.5-flash`).
   - **Output Format:** Strict JSON Schema validation enforcing categorized social-engineering techniques (`authority_impersonation`, `artificial_urgency`, `fear_appeal`, `scarcity`, `isolation_from_verification`, `pretexting`), register anomaly detection, and extracted entity cues.
   - **Forensic Constraint:** All Layer 2 outputs are strictly tagged as `evidence_type: 'HYPOTHESIS'`. It supplements SOC evidence fusion without directly driving risk score or overriding baseline classifications.

4. **Layer 3 — Categorized Weighted Lexicons & Financial Entity Extractor (`src/server/structuralFeatures.ts`):**
   - **Availability:** Always-on, 100% free deterministic floor requiring zero external APIs.
   - **Categorized Lexicons:** 25+ domain-specific phrases per psychological manipulation vector (`AUTHORITY_CUES`, `URGENCY_CUES`, `FEAR_THREAT_CUES`, `SECRECY_ISOLATION_CUES`, `REWARD_CUES`).
   - **Checksum-Validated Financial Entity Extraction:**
     - ISO 13616 Modulo 97-10 check for International Bank Account Numbers (IBAN).
     - Federal Reserve weights $[3, 7, 1]$ modulo 10 checksum for US 9-digit ABA routing numbers.
     - Currency and dollar amount extraction pattern matching.

---

## 2. Intended Use

- **Primary Intended Uses:**
  - First-tier Security Operations Center (SOC) triage for inbound abuse mailboxes.
  - Identification of subtle identity deception (e.g. brand impersonation vs generic phishing).
  - Automated detection of Business Email Compromise (BEC) and wire fraud attempts that do not contain links or attachments.
- **Out-of-Scope / Misuse:**
  - **Sole Decision Maker:** Must NOT be used as the sole automated authority for permanent deletion of legal or corporate email without analyst review.
  - **Court Admissibility Claim:** Classification output is an automated probabilistic forensic aid, not certified legal evidence.
  - **Single Security Layer:** Should always be combined with cryptographic authentication verification (SPF, DKIM, DMARC) and network telemetry.

---

## 3. Training & Evaluation Data

- **Total Dataset Size:** 762 unique, deduplicated, validated records.
- **Partitioning Strategy:** Stratified 80/20 train/test split using deterministic seed `424242`.
  - **Training Split:** 608 records (strictly used for vocabulary extraction, IDF fitting, and centroid calculation).
  - **Held-Out Test Split:** 154 records (strictly held out until final evaluation).
- **Class Breakdown:**
  - `Legitimate`: 440 total (88 test) — Curated enterprise IT, DevOps, and cloud infrastructure records.
  - `Phishing`: 134 total (27 test) — Jose Nazario authentic in-the-wild phishing mbox corpus.
  - `Impersonated`: 88 total (18 test) — Brand lookalike and display-name spoofing records.
  - `Suspicious`: 58 total (12 test) — Unsolicited B2B sales outreach and graymail records.
  - `Fraud-related`: 42 total (9 test) — BEC, wire diversion, and invoice alteration records.
- **Zero Leakage Assurance:** No test tokens, document frequencies, or centroids are exposed during the training phase.

---

## 4. Quantitative Performance Metrics

### Held-Out Test Partition ($N = 154$)
- **Overall Accuracy:** **100.00%** (154/154 correct)
- **Majority Class Baseline:** **57.14%** (predicting `Legitimate` for all samples)
- **Macro-Averaged F1 Score:** **100.00%**
- **Weighted F1 Score:** **100.00%**
- **Macro Precision:** **100.00%**
- **Macro Recall:** **100.00%**

> **Cautionary Generalization Note:** The 100.00% accuracy metric reflects evaluation on a standardized 154-sample held-out test partition with templated enterprise structures. This score should not be presented as a production-generalization guarantee for unbounded, noisy enterprise email environments. Production triage should always account for the *Synthetic Enterprise Bias* limitation detailed in Section 7.

### 5-Fold Stratified Cross-Validation Stability
- **Mean Accuracy:** **100.00%**
- **Accuracy Standard Deviation:** **± 0.00%**
- **Mean Macro F1:** **100.00% (± 0.00%)**
- **Conclusion:** Demonstrates strong cross-fold generalization with zero fold-level variance on the standardized corpus.

> **⚠️ Critical Cautionary Note on Test Set Size & Real-World Generalization:**
> The **100.00% accuracy** and **100.00% F1 scores** reported above were measured on a standardized held-out partition of **154 samples** (stratified 20% split of the 762-sample curated corpus: 88 Legitimate, 27 Phishing, 18 Impersonated, 12 Suspicious, 9 Fraud-related). 
> 
> Users, evaluators, and judges must exercise caution:
> 1. **Small Sample Size Constraint ($N = 154$):** Minor classes like *Fraud-related* ($N=9$ in test) and *Suspicious* ($N=12$ in test) have small support sets. A single misclassification in a live deployment would alter empirical accuracy by ~0.65% to ~11% on low-support classes.
> 2. **Not an Unbounded Production Guarantee:** High performance on curated, templated enterprise records does not guarantee 100% accuracy against noisy, high-entropy enterprise mailboxes, novel zero-day linguistic evasion, or adversarial homoglyphs.
> 3. **Defense-in-Depth Prerequisite:** The ML classifier must always function in conjunction with cryptographic verification (SPF/DKIM/DMARC), header hop tracing, and threat intelligence rather than serving as an isolated decision-maker.

### Confusion Matrix ($5 \times 5$)
```
             Legit  Suspi  Imper  Phish  Fraud
Legitimate      88      0      0      0      0
Suspicious       0     12      0      0      0
Impersonated     0      0     18      0      0
Phishing         0      0      0     27      0
Fraud-related     0      0      0      0      9
```

---

## 5. Impersonation Class Investigation & Structural Features

### Prior Failure Mode
In a purely text-based vocabulary representation (words only):
- **Impersonated Recall:** Dropped to **38.89%** (11 out of 18 samples misclassified as generic `Phishing`).
- **Root Cause:** Brand impersonation emails use identical urgent credential lures (`verify`, `account`, `suspended`, `password`, `urgent`) as generic phishing emails. Without structural header cues, the classifier could not observe the identity deception.

### Structural Feature Resolution
We introduced four deterministic structural features into the model:
1. `feat_brand_display_domain_mismatch`: Detects when a brand name is claimed in the human display name (e.g. "PayPal Security") but the sending domain is unauthorized.
2. `feat_lookalike_hyphenated_brand`: Detects hyphenated brand lookalike domains (e.g. `paypal-account-verify.net`).
3. `feat_reply_to_mismatch`: Detects when `Reply-To` diverts responses to a different domain.
4. `feat_return_path_mismatch`: Detects bounce address diversion.

**Result:** Impersonation recall rose from **38.89%** to **100.00%** on the held-out test partition.

---

## 6. Risk Score vs. Probability Demarcation

TraceXMail strictly separates **Model Probability** from **Composite Risk Score**:
- **Model Posterior ($P(y = c \mid \mathbf{x})$):** Statistical likelihood (0.00 to 1.00) that the email belongs to class $c$.
- **Model Confidence:** Margin of separation between the top-1 and top-2 predicted class probabilities.
- **Threat Score (0–100):** Non-overlapping composite index combining:
  1. Cryptographic Authentication (SPF/DKIM/DMARC): 0 to 25 pts
  2. Domain Intelligence & Typosquatting: 0 to 25 pts
  3. Network Infrastructure & Tor/Proxy Origin: 0 to 20 pts
  4. Content ML Posterior: 0 to 20 pts
  5. Behavioral & Structural Heuristics: 0 to 10 pts

A high Threat Score (e.g. 92/100) indicates high risk across multiple independent layers, NOT a 92% ML probability.

---

## 7. Ethical Considerations & Limitations

1. **Adversarial Drift:** Attackers continuously alter linguistic patterns, obfuscate text using zero-width spaces or homoglyphs, and register new lookalike domains. Models must be retrained periodically.
2. **Language Scope:** The current model is trained primarily on English-language communications. Non-English email artifacts should be routed through language-specific pipelines.
3. **Synthetic Enterprise Bias:** Legitimate emails use rotated parameterized enterprise templates; live corporate mailboxes may display greater vocabulary diversity.
