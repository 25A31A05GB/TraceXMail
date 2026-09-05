# TraceXMail Scientific ML Model Evaluation Report (v2.4)

**Generated:** 2026-09-05T19:47:14.747Z  
**Corpus Size:** 433 clean deduplicated records  
**Adversarial Holdout:** 60 zero-leakage records  
**Max Intra-Class Duplication Rate:** 0.00% (Target: < 15.0%)  

---

## 1. Cross-Validation Stability (5-Fold Stratified)
*Strict train-only vocabulary and IDF fit preventing data leakage.*

| Fold | Accuracy | Macro F1 | Weighted F1 | Brier Score |
|------|----------|----------|-------------|-------------|
| Fold 1 | 93.02% | 91.47% | 93.13% | 0.2841 |
| Fold 2 | 85.06% | 81.50% | 84.65% | 0.3174 |
| Fold 3 | 87.21% | 86.11% | 87.32% | 0.3004 |
| Fold 4 | 93.10% | 92.06% | 93.01% | 0.2049 |
| Fold 5 | 83.91% | 82.91% | 84.57% | 0.3657 |
| **Mean ± Std** | **88.46% ± 3.90%** | **86.81% ± 4.32%** | **88.54% ± 3.83%** | **0.2945 ± 0.0525** |

---

## 2. Held-out Test Set Performance (80/20 Stratified Partition)
- **Overall Accuracy:** 88.51% (77/87)
- **Majority Class Baseline:** 37.93%
- **Macro-averaged F1 Score:** 89.94%
- **Weighted F1 Score:** 88.42%

### Per-Class Performance
| Class | Precision | Recall | F1 Score | Support |
|-------|-----------|--------|----------|---------|
| Legitimate | 79.2% | 90.5% | 84.5% | 21 |
| Suspicious | 75.0% | 100.0% | 85.7% | 6 |
| Impersonated | 87.5% | 100.0% | 93.3% | 21 |
| Phishing | 100.0% | 75.8% | 86.2% | 33 |
| Fraud-related | 100.0% | 100.0% | 100.0% | 6 |

---

## 3. Probability Calibration (Phase 4)
- **Multi-Class Brier Score:** `0.2921`
- **Expected Calibration Error (ECE):** `28.68%`
- **Calibration Temperature:** `12`

### 10-Bin Reliability Curve
| Bin Range | Samples | Mean Confidence | Empirical Accuracy | Calibration Gap |
|-----------|---------|-----------------|--------------------|-----------------|
| [0.0, 0.1) | 0 | 5.0% | 0.0% | 5.0% |
| [0.1, 0.2) | 0 | 15.0% | 0.0% | 15.0% |
| [0.2, 0.3) | 3 | 27.0% | 0.0% | 27.0% |
| [0.3, 0.4) | 14 | 34.9% | 64.3% | 29.4% |
| [0.4, 0.5) | 16 | 45.7% | 93.8% | 48.0% |
| [0.5, 0.6) | 18 | 55.7% | 94.4% | 38.7% |
| [0.6, 0.7) | 9 | 63.4% | 100.0% | 36.6% |
| [0.7, 0.8) | 6 | 73.6% | 100.0% | 26.4% |
| [0.8, 0.9) | 1 | 85.7% | 100.0% | 14.3% |
| [0.9, 1.0) | 20 | 98.2% | 100.0% | 1.8% |

---

## 4. Phase 3 Learned BEC Model vs Heuristic Fallback
- **Algorithm:** Supervised Logistic Regression with L2 Regularization
- **Engineered Features:** 15 forensic signals (urgency density, executive titles, payment diversion, payroll rerouting, gift cards, IBAN/ABA checksums, benign devops counter-signals)
- **Learned Model Accuracy:** 88.68%
- **Learned Model F1:** 50.50%
- **Legacy Static Heuristic F1:** `0.768`
- *Note: `data/bec_weights.json` is documented as a heuristic fallback layer, not an ML model.*

---

## 5. Phase 5 Learned Meta-Classifier (Stacking Ensemble)
- **Algorithm:** Stacked Supervised Logistic Regression
- **Stacked Dimensions:** 20 forensic signals across Base ML probabilities, SPF/DKIM/DMARC auth flags, domain age, typosquatting, brand display mismatch, Tor/abuse relays, and BEC scores.
- **Accuracy:** 93.76%
- **Brier Score:** `0.0193`
- **ROC-AUC:** `0.996`

---

## 6. Adversarial Holdout Evaluation (60 Challenging Samples)
- **Zero-Leakage Verified:** Cosine similarity < 0.85 against all corpus samples.
- **Overall Holdout Accuracy:** 56.67%
- **Holdout Macro-F1:** 51.50%

| Category | Total | Correct | Accuracy |
|----------|-------|---------|----------|
| paraphrased_phishing | 21 | 4 | 19.1% |
| high_urgency_legitimate | 20 | 19 | 95.0% |
| conversational_bec | 15 | 9 | 60.0% |
| brand_impersonation_display | 4 | 2 | 50.0% |
