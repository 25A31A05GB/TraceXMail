# TraceXMail Scientific ML Model Evaluation Report (v2.4)

**Generated:** 2026-09-05T14:25:38.090Z  
**Corpus Size:** 433 clean deduplicated records  
**Adversarial Holdout:** 60 zero-leakage records  
**Max Intra-Class Duplication Rate:** 0.00% (Target: < 15.0%)  

---

## 1. Cross-Validation Stability (5-Fold Stratified)
*Strict train-only vocabulary and IDF fit preventing data leakage.*

| Fold | Validation Samples | Accuracy | Macro F1 |
|------|--------------------|----------|----------|
| Fold 1 | 86 | 97.67% | 96.92% |
| Fold 2 | 87 | 88.51% | 85.56% |
| Fold 3 | 86 | 93.02% | 93.98% |
| Fold 4 | 87 | 96.55% | 97.68% |
| Fold 5 | 87 | 90.80% | 90.59% |
| **Mean ± Std** | **433 Total** | **93.31% ± 3.43%** | **92.95% ± 4.46%** |

---

## 2. Held-out Test Set Performance (80/20 Stratified Partition)
- **Overall Accuracy:** 91.95% (80/87)
- **Majority Class Baseline:** 37.93%
- **Macro-averaged F1 Score:** 92.41%
- **Weighted F1 Score:** 91.93%

### Per-Class Performance
| Class | Precision | Recall | F1 Score | Support |
|-------|-----------|--------|----------|---------|
| Legitimate | 90.9% | 95.2% | 93.0% | 21 |
| Suspicious | 75.0% | 100.0% | 85.7% | 6 |
| Impersonated | 87.5% | 100.0% | 93.3% | 21 |
| Phishing | 100.0% | 81.8% | 90.0% | 33 |
| Fraud-related | 100.0% | 100.0% | 100.0% | 6 |

---

## 3. Probability Calibration (Phase 4)
- **Multi-Class Brier Score:** `0.2435`
- **Expected Calibration Error (ECE):** `26.09%`
- **Calibration Temperature:** `12`

### 10-Bin Reliability Curve
| Bin Range | Samples | Mean Confidence | Empirical Accuracy | Calibration Gap |
|-----------|---------|-----------------|--------------------|-----------------|
| [0.0, 0.1) | 0 | 5.0% | 0.0% | 5.0% |
| [0.1, 0.2) | 0 | 15.0% | 0.0% | 15.0% |
| [0.2, 0.3) | 3 | 27.9% | 66.7% | 38.8% |
| [0.3, 0.4) | 8 | 35.4% | 50.0% | 14.6% |
| [0.4, 0.5) | 11 | 46.7% | 90.9% | 44.3% |
| [0.5, 0.6) | 20 | 54.5% | 95.0% | 40.5% |
| [0.6, 0.7) | 14 | 62.3% | 100.0% | 37.7% |
| [0.7, 0.8) | 3 | 74.6% | 100.0% | 25.4% |
| [0.8, 0.9) | 5 | 85.0% | 100.0% | 15.0% |
| [0.9, 1.0) | 23 | 97.3% | 100.0% | 2.7% |

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
- **Accuracy:** 93.53%
- **Brier Score:** `0.0184`
- **ROC-AUC:** `0.996`

---

## 6. Adversarial Holdout Evaluation (60 Challenging Samples)
- **Zero-Leakage Verified:** Cosine similarity < 0.85 against all corpus samples.
- **Overall Holdout Accuracy:** 70.00%
- **Holdout Macro-F1:** 61.53%

| Category | Total | Correct | Accuracy |
|----------|-------|---------|----------|
| paraphrased_phishing | 21 | 5 | 23.8% |
| high_urgency_legitimate | 20 | 19 | 95.0% |
| conversational_bec | 15 | 15 | 100.0% |
| brand_impersonation_display | 4 | 3 | 75.0% |
