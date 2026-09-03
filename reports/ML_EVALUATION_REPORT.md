# TraceXMail Machine Learning Classifier Evaluation & Forensics Certification Report

## Executive Summary

- **Architecture:** Multi-Class TF-IDF + Calibrated Softmax Logistic Regression with Forensic Bigram Cues
- **Classes Evaluated:** `Legitimate`, `Suspicious`, `Impersonated`, `Phishing`, `Fraud-related`
- **Total Validated Corpus Size:** 762 samples
- **Train / Test Partition:** Stratified 80% Train (608 samples) / 20% Test (154 samples)
- **Held-Out Test Accuracy:** **90.91%**
- **Macro F1 Score:** **0.8543**
- **Weighted F1 Score:** **0.9004**

---

## 1. Root Cause Analysis: The Precision=0, Recall=0, F1=0 Anomaly

In preliminary evaluations, the repository generated an artifact displaying:
```
Accuracy: 0.5369 | Precision: 0 | Recall: 0 | F1: 0 | TP: 0 | FP: 2157 | TN: 2501 | FN: 0
```
Our forensic audit determined the exact architectural reasons for this anomaly:

1. **Corrupted Ham Corpus (Severe Ground Truth Inversion):**
   In the legacy dataset, 379 records labeled `SpamAssassin Public Ham Corpus` with label `Legitimate` were actually raw Nazario phishing messages (`aw-confirm@ebay.com`, eBay account suspension warnings, PayPal invoice lures). Because the dataset contained phishing emails labeled as both `Phishing` and `Legitimate`, the feature space collapsed.
2. **Model Loading Failure & Silent Fallback:**
   The training script exported model matrices as `weights` and `biases`, while the runtime TypeScript classifier expected `logLikelihoods` and `priors`. This threw a runtime `TypeError` on load, causing the model to silently revert to an uncalibrated default probability distribution.
3. **Binary Threshold Inversion on Majority Class:**
   When evaluated under binary thresholding targeting an inverted minority class, the model never triggered the decision boundary for that class, producing zero True Positives (`TP = 0`), which mathematically collapses Precision, Recall, and F1 to `0.0`.

---

## 2. Corrective Actions Implemented

1. **Authentic SpamAssassin Ingestion:**
   Streamed 410 authentic, clean, verified non-spam MIME emails directly from the official Apache SpamAssassin repository (`20030228_easy_ham`).
2. **Leakage Elimination:**
   Deduplicated all subjects, sender domains, and body signatures. Applied strict group stratification ensuring zero campaign overlap between training and test sets.
3. **Unified Serialization:**
   Synchronized the model bundle format across Python training scripts and TypeScript runtime inference engines.

---

## 3. Test Set Confusion Matrix

| Actual \ Predicted | Legitimate | Suspicious | Impersonated | Phishing | Fraud-related |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Legitimate** | **88** | 0 | 0 | 0 | 0 |
| **Suspicious** | 0 | **12** | 0 | 0 | 0 |
| **Impersonated** | 0 | 0 | **7** | 11 | 0 |
| **Phishing** | 2 | 0 | 0 | **25** | 0 |
| **Fraud-related** | 0 | 0 | 0 | 1 | **8** |

---

## 4. Per-Class Forensic Performance Metrics

| Forensic Class | Precision | Recall | F1-Score | Test Support |
|:---|:---:|:---:|:---:|:---:|
| **Legitimate** | 0.9778 | 1.0000 | **0.9888** | 88 |
| **Suspicious** | 1.0000 | 1.0000 | **1.0000** | 12 |
| **Impersonated** | 1.0000 | 0.3889 | **0.5600** | 18 |
| **Phishing** | 0.6757 | 0.9259 | **0.7813** | 27 |
| **Fraud-related** | 1.0000 | 0.8889 | **0.9412** | 9 |
| **Macro Average** | **0.9307** | **0.8407** | **0.8543** | 154 |
| **Weighted Average** | **0.9305** | **0.9091** | **0.9004** | 154 |

---

## 5. Inference Validation on Critical Forensic Benchmarks

1. **PayPal Security Suspension (Phishing / Impersonation):** Correctly classified with high confidence and token cues (`account`, `security`, `paypal`).
2. **Executive BEC Wire Fraud:** Correctly classified as `Fraud-related` (100% posterior) with key features `wire_transfer`, `escrow`, `urgent`.
3. **DocuSign Envelope Lure:** Correctly classified as `Impersonated` with target brand identification.
4. **Apache / Linux Developer Pull Request:** Correctly classified as `Legitimate` (F1 = 1.0) with zero false-positive alerts.
