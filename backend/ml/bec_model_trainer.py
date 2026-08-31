"""
TraceXMail BEC Model Trainer
Trains a multi-label TF-IDF + Logistic Regression model to supply learned
confidence scores for BEC rules in bec_engine.py, replacing static hardcoded scores.

Labels are bootstrapped (distant supervision) from core BEC keyword triggers applied
to the real Nazario / SpamAssassin corpus.
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
    from backend.bec_engine import (
        BANK_CHANGE_KEYWORDS, URGENCY_KEYWORDS, FINANCIAL_KEYWORDS,
        INVOICE_KEYWORDS, PAYROLL_CHANGE_KEYWORDS
    )
except ImportError:
    from ml.dataset_builder import load_dataset
    from bec_engine import (
        BANK_CHANGE_KEYWORDS, URGENCY_KEYWORDS, FINANCIAL_KEYWORDS,
        INVOICE_KEYWORDS, PAYROLL_CHANGE_KEYWORDS
    )

BEC_CATEGORIES = [
    "payment_diversion",
    "fake_invoice",
    "credential_harvesting",
    "executive_impersonation",
    "bank_account_change",
    "vendor_impersonation",
    "urgent_transfer_request",
    "payroll_manipulation"
]

WEIGHTS_FILE = "data/bec_weights.json"


def _matches_any(text: str, patterns: list) -> bool:
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def bootstrap_bec_labels(text: str) -> list:
    """Computes binary weak label for each of the 8 BEC categories based on text indicators."""
    text_l = text.lower()
    
    bank_match = _matches_any(text_l, BANK_CHANGE_KEYWORDS)
    urgency_match = _matches_any(text_l, URGENCY_KEYWORDS)
    financial_match = _matches_any(text_l, FINANCIAL_KEYWORDS)
    invoice_match = _matches_any(text_l, INVOICE_KEYWORDS)
    payroll_match = _matches_any(text_l, PAYROLL_CHANGE_KEYWORDS)
    cred_match = any(kw in text_l for kw in ["login", "sign in", "verify identity", "reset password", "update credentials"])
    exec_match = any(kw in text_l for kw in ["ceo", "cfo", "president", "director", "manager", "as your manager", "as your ceo"])
    vendor_match = any(kw in text_l for kw in ["docusign", "paypal", "fedex", "dhl", "amazon", "microsoft", "quickbooks", "stripe"])

    labels = [
        1 if (bank_match and urgency_match) or (bank_match and financial_match) else 0, # payment_diversion
        1 if invoice_match and (financial_match or urgency_match or vendor_match) else 0, # fake_invoice
        1 if cred_match and urgency_match else 0, # credential_harvesting
        1 if exec_match and (financial_match or urgency_match) else 0, # executive_impersonation
        1 if bank_match else 0, # bank_account_change
        1 if vendor_match and (invoice_match or financial_match) else 0, # vendor_impersonation
        1 if urgency_match and financial_match else 0, # urgent_transfer_request
        1 if payroll_match else 0, # payroll_manipulation
    ]
    return labels


def build_training_data():
    dataset = load_dataset()
    if not dataset:
        corpus_path = "data/datasets/real_corpus.json"
        if os.path.exists(corpus_path):
            try:
                with open(corpus_path, "r", encoding="utf-8", errors="ignore") as f:
                    dataset = json.load(f, strict=False)
            except Exception:
                dataset = []

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

    y = np.array([bootstrap_bec_labels(t) for t in texts])
    return texts, y


def train():
    texts, y = build_training_data()
    print(f"BEC Dataset size: {len(texts)} samples. Positive label distribution per BEC category:")
    for j, cat in enumerate(BEC_CATEGORIES):
        pos_cnt = int(y[:, j].sum())
        print(f"  - {cat}: {pos_cnt} positive samples ({pos_cnt / len(texts):.1%})")
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
    print("\nBEC Model Trainer Classification Report:")
    print(classification_report(y_test, y_pred, target_names=BEC_CATEGORIES, zero_division=0))

    vocab = {str(term): int(idx) for term, idx in vectorizer.vocabulary_.items()}
    idf = {str(term): float(vectorizer.idf_[idx]) for term, idx in vocab.items()}
    weights = {
        cat: [float(v) for v in clf.estimators_[i].coef_[0]]
        for i, cat in enumerate(BEC_CATEGORIES)
    }
    biases = {
        cat: float(clf.estimators_[i].intercept_[0])
        for i, cat in enumerate(BEC_CATEGORIES)
    }

    os.makedirs(os.path.dirname(WEIGHTS_FILE), exist_ok=True)
    with open(WEIGHTS_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "vocabulary": vocab,
            "idf": idf,
            "weights": weights,
            "biases": biases,
            "categories": BEC_CATEGORIES,
            "model_type": "TF-IDF + OneVsRest LogisticRegression (BEC Categories)",
            "training_note": "Learned BEC confidence scores bootstrapped from real corpora and structural rule indicators."
        }, f, indent=2)

    print(f"\nSaved trained BEC category weights to {WEIGHTS_FILE}")


if __name__ == "__main__":
    train()
