#!/usr/bin/env python3
"""
TraceXMail Machine Learning Classifier Training Pipeline (Python)
Smart India Hackathon 2026 — Problem Statement 26106

Performs end-to-end training and evaluation:
1. Stratified 80/20 train/test partition (deterministic seed: 424242)
2. Sublinear TF-IDF + Structural Impersonation Feature Extraction (fitted strictly on train set)
3. Centroid Cosine representation with temperature-scaled Softmax
4. Serialization of trained model artifact to: data/datasets/trained_model.json
5. Generation of comprehensive evaluation reports:
   - reports/MODEL_EVALUATION.md
   - reports/ML_EVALUATION_REPORT.md
   - docs/model_evaluation_report.json
"""

import os
import sys
import json
import math
import shutil
from evaluate_classifier import (
    main as eval_main,
    NearestCentroidModel,
    tokenize_email,
    CLASSES,
    CORPUS_PATH,
    REPORT_JSON_PATH,
    REPORT_MD_PATH
)

TRAINED_MODEL_PATH = os.path.join(os.getcwd(), 'data/datasets/trained_model.json')
ALT_REPORT_MD_PATH = os.path.join(os.getcwd(), 'reports/ML_EVALUATION_REPORT.md')

def train_and_export():
    print("=" * 64)
    print("Training TraceXMail 5-Class Forensic Model & Exporting Artifacts")
    print("=" * 64)

    if not os.path.exists(CORPUS_PATH):
        print(f"Error: Corpus not found at {CORPUS_PATH}")
        sys.exit(1)

    with open(CORPUS_PATH, 'r', encoding='utf-8') as f:
        records = json.load(f)

    print(f"Loaded {len(records)} samples from {CORPUS_PATH}")

    # Stratified 80/20 split
    class_doc_indices = {c: [] for c in range(len(CLASSES))}
    for idx, r in enumerate(records):
        c_idx = CLASSES.index(r['label'])
        class_doc_indices[c_idx].append(idx)

    train_indices = []
    test_indices = []

    for c in range(len(CLASSES)):
        lst = list(class_doc_indices[c])
        seed = 424242 + c * 10007
        for i in range(len(lst) - 1, 0, -1):
            seed = (seed * 16807) % 2147483647
            j = seed % (i + 1)
            lst[i], lst[j] = lst[j], lst[i]
        split_idx = int(len(lst) * 0.8)
        train_indices.extend(lst[:split_idx])
        test_indices.extend(lst[split_idx:])

    train_records = [records[i] for i in train_indices]
    test_records = [records[i] for i in test_indices]

    # Train model
    model = NearestCentroidModel(max_features=3500, temperature=12.0)
    model.fit(train_records, include_structural=True)

    # Evaluate on held-out test set
    from evaluate_classifier import evaluate_split
    test_res = evaluate_split(model, test_records, include_structural=True)

    # Export model payload matching TypeScript / Python runtime format
    payload = {
        "schemaVersion": "2.3.0",
        "featureSchemaVersion": "1.2.0",
        "metadata": {
            "modelName": "TraceXMail 5-Class Forensic Classifier v2.3",
            "algorithm": "Nearest Centroid Cosine Classifier with Temperature-Scaled Softmax Calibration",
            "trainedAt": "2026-09-03T12:00:00Z",
            "trainingCorpora": [
                "Jose Nazario Phishing Corpus (nazario_mbox_0, nazario_mbox_1, nazario_mbox_2)",
                "Curated Enterprise Legitimate Dataset",
                "Curated Brand Impersonation Dataset",
                "Curated BEC & Wire Fraud Dataset",
                "Curated Unsolicited Marketing Dataset"
            ],
            "totalSamples": len(records),
            "trainCount": len(train_records),
            "testCount": len(test_records),
            "classes": CLASSES,
            "vocabularySize": len(model.vocab),
            "testAccuracy": test_res["accuracy"],
            "macroF1": test_res["macro_f1"],
            "weightedF1": test_res["weighted_f1"],
            "baselineAccuracy": test_res["majority_baseline"],
            "perClassMetrics": test_res["per_class_metrics"],
            "confusionMatrix": test_res["confusion_matrix"]
        },
        "featureSchema": [
            "subject_body_tokens",
            "word_bigrams",
            "sender_domain_token",
            "brand_display_domain_signals",
            "lookalike_brand_hyphenation",
            "reply_to_mismatch",
            "return_path_mismatch",
            "cryptographic_auth_signals",
            "domain_intelligence_dns_signals",
            "semantic_linguistic_cues"
        ],
        "vocabulary": model.vocab,
        "vocabMap": model.vmap,
        "idf": model.idf,
        "centroids": model.centroids,
        "priors": model.priors,
        "temperature": model.temperature
    }

    os.makedirs(os.path.dirname(TRAINED_MODEL_PATH), exist_ok=True)
    with open(TRAINED_MODEL_PATH, 'w', encoding='utf-8') as f:
        json.dump(payload, f)
    print(f"Serialized model artifact to: {TRAINED_MODEL_PATH}")

    # Run full evaluator and copy markdown report to both locations
    eval_main()
    if os.path.exists(REPORT_MD_PATH):
        shutil.copyfile(REPORT_MD_PATH, ALT_REPORT_MD_PATH)
        print(f"Mirrored report to: {ALT_REPORT_MD_PATH}")

if __name__ == '__main__':
    train_and_export()
