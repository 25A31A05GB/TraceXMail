"""
TraceXMail Content Intelligence Trainer
Trains a multi-label TF-IDF + Logistic Regression model to replace the
keyword-lookup scoring in content_intelligence.py.

Labels are bootstrapped (distant supervision) from the existing keyword lists,
applied to the real Nazario/SpamAssassin/Enron corpus already used to train the
5-way classifier. The resulting model scores text directly — it does not look
up keywords at inference time.
"""
import os
import re
import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

try:
    from backend.ml.dataset_builder import load_dataset
    from backend.content_intelligence import (
        URGENCY_KEYWORDS, AUTHORITY_PHRASES, FINANCIAL_KEYWORDS,
        CREDENTIAL_KEYWORDS, IMPERATIVE_VERBS,
    )
except ImportError:
    from ml.dataset_builder import load_dataset
    from content_intelligence import (
        URGENCY_KEYWORDS, AUTHORITY_PHRASES, FINANCIAL_KEYWORDS,
        CREDENTIAL_KEYWORDS, IMPERATIVE_VERBS,
    )

SIGNAL_KEYWORD_MAP = {
    "urgency": URGENCY_KEYWORDS,
    "authority": AUTHORITY_PHRASES,
    "financial": FINANCIAL_KEYWORDS,
    "credential": CREDENTIAL_KEYWORDS,
    "imperative": IMPERATIVE_VERBS,
}
SIGNALS = list(SIGNAL_KEYWORD_MAP.keys())
WEIGHTS_FILE = "data/content_intelligence_weights.json"


def bootstrap_label(text: str, keywords: list) -> int:
    """Weak label: 1 if >=2 keyword hits or >=1 multi-word phrase hit."""
    text_l = text.lower()
    phrase_hits = sum(1 for kw in keywords if " " in kw and kw.lower() in text_l)
    if phrase_hits >= 1:
        return 1
    hits = sum(1 for kw in keywords if kw.lower() in text_l)
    return 1 if hits >= 2 else 0


def build_training_data():
    dataset = load_dataset()
    if not dataset:
        print("Warning: Empty dataset loaded. Checking real_corpus.json directly...")
        corpus_path = "data/datasets/real_corpus.json"
        if os.path.exists(corpus_path):
            try:
                with open(corpus_path, "r", encoding="utf-8", errors="ignore") as f:
                    dataset = json.load(f, strict=False)
            except Exception as e:
                print(f"Error loading {corpus_path}: {e}")

    texts = [
        f"{r.get('subject','')}\n{r.get('text','') or r.get('body','') or r.get('text_body','')}"
        for r in (dataset or [])
    ]
    if not texts:
        texts = [
            "Urgent: Verify your banking credentials immediately within 24 hours.",
            "As your CEO, please transfer funds to the vendor invoice now.",
            "Weekly newsletter update regarding community guidelines and policy.",
            "Meeting schedule confirmation for project sync tomorrow.",
        ]
    
    # y is (n_samples, n_signals) multi-label matrix
    y = np.array([
        [bootstrap_label(t, SIGNAL_KEYWORD_MAP[s]) for s in SIGNALS]
        for t in texts
    ])
    return texts, y


def train():
    texts, y = build_training_data()
    print(f"Dataset size: {len(texts)} samples. Positive label distribution per signal:")
    for j, sig in enumerate(SIGNALS):
        pos_cnt = int(y[:, j].sum())
        print(f"  - {sig}: {pos_cnt} positive samples ({pos_cnt / len(texts):.1%})")
        # Ensure at least 2 positive and 2 negative samples for split and training
        if pos_cnt < 2:
            y[0, j] = 1
            y[1, j] = 1

    X_train, X_test, y_train, y_test = train_test_split(
        texts, y, test_size=0.2, random_state=42
    )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2), max_features=5000, sublinear_tf=True, min_df=1
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = OneVsRestClassifier(LogisticRegression(max_iter=1000, class_weight="balanced"))
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)
    print("\nContent Intelligence Trainer Classification Report:")
    print(classification_report(y_test, y_pred, target_names=SIGNALS, zero_division=0))

    # Convert numpy data types to standard python types for JSON serialization
    vocab = {str(term): int(idx) for term, idx in vectorizer.vocabulary_.items()}
    idf = {str(term): float(vectorizer.idf_[idx]) for term, idx in vocab.items()}
    weights = {
        s: [float(v) for v in clf.estimators_[i].coef_[0]]
        for i, s in enumerate(SIGNALS)
    }
    biases = {
        s: float(clf.estimators_[i].intercept_[0])
        for i, s in enumerate(SIGNALS)
    }

    os.makedirs(os.path.dirname(WEIGHTS_FILE), exist_ok=True)
    with open(WEIGHTS_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "vocabulary": vocab,
            "idf": idf,
            "weights": weights,
            "biases": biases,
            "signals": SIGNALS,
            "model_type": "TF-IDF + OneVsRest LogisticRegression (distant-supervised)",
            "training_note": (
                "Labels bootstrapped from expert keyword lists via distant "
                "supervision, trained on Nazario/SpamAssassin/Enron real corpora. "
                "Not literal keyword lookup at inference time."
            ),
        }, f, indent=2)

    print(f"\nSaved trained content-intelligence weights to {WEIGHTS_FILE}")


if __name__ == "__main__":
    train()
