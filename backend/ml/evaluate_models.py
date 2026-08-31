"""
TraceXMail Model Evaluation Script
Evaluates all trained ML models against a gold validation set constructed from authentic email samples
and writes metrics (precision, recall, F1, accuracy) to docs/model_evaluation_report.json.
"""
import os
import json
import numpy as np

try:
    from backend.ml.model import predict_email_threat
    from backend.ml.content_intelligence_model import predict_content_signals
    from backend.ml.bec_model import predict_bec_category_scores
    from backend.ml.dataset_builder import load_dataset
except ImportError:
    from ml.model import predict_email_threat
    from ml.content_intelligence_model import predict_content_signals
    from ml.bec_model import predict_bec_category_scores
    from ml.dataset_builder import load_dataset


REPORT_PATH = "docs/model_evaluation_report.json"


def evaluate_models():
    dataset = load_dataset()
    if not dataset:
        corpus_path = "data/datasets/real_corpus.json"
        if os.path.exists(corpus_path):
            with open(corpus_path, "r", encoding="utf-8", errors="ignore") as f:
                dataset = json.load(f, strict=False)

    if not dataset:
        print("Error: No evaluation dataset available.")
        return

    print(f"Evaluating models on Gold Validation Set of {len(dataset)} real email records...")

    # 1. Main Phishing Classifier Evaluation
    phish_tp, phish_fp, phish_tn, phish_fn = 0, 0, 0, 0
    for record in dataset:
        subj = record.get('subject', '')
        text = record.get('text', '') or record.get('body', '') or record.get('text_body', '')
        
        # Ground truth: 0 if legitimate, 1 if any threat category
        cat = record.get("category", "")
        if not cat:
            true_label = 1 if record.get("is_phishing") else 0
        else:
            true_label = 0 if cat == "legitimate" else 1
        
        pred = predict_email_threat({"subject": subj, "text_body": text})
        p_prob = pred.get("phishing_probability", 0.0)
        p_verdict = pred.get("five_way_verdict", "legitimate")
        pred_label = 1 if (p_prob >= 0.5 or p_verdict != "legitimate") else 0

        if true_label == 1 and pred_label == 1:
            phish_tp += 1
        elif true_label == 0 and pred_label == 1:
            phish_fp += 1
        elif true_label == 0 and pred_label == 0:
            phish_tn += 1
        else:
            phish_fn += 1

    phish_prec = phish_tp / (phish_tp + phish_fp) if (phish_tp + phish_fp) > 0 else 0.0
    phish_rec = phish_tp / (phish_tp + phish_fn) if (phish_tp + phish_fn) > 0 else 0.0
    phish_f1 = (2 * phish_prec * phish_rec) / (phish_prec + phish_rec) if (phish_prec + phish_rec) > 0 else 0.0
    phish_acc = (phish_tp + phish_tn) / len(dataset) if dataset else 0.0

    # 2. Content Intelligence Signals Evaluation
    signal_results = {}
    for sig in ["urgency", "authority", "financial", "credential", "imperative"]:
        s_tp, s_fp, s_tn, s_fn = 0, 0, 0, 0
        for record in dataset:
            text = f"{record.get('subject','')}\n{record.get('text','') or record.get('body','') or record.get('text_body','')}"
            preds = predict_content_signals(text) or {}
            sig_pred = 1 if preds.get(sig, 0.0) >= 0.5 else 0
            
            # True label heuristic matching signal definition
            sig_true = 1 if sig in record.get("signals", []) else (
                1 if (
                    (sig == "urgency" and any(w in text.lower() for w in ["urgent", "immediately", "24 hours", "asap"])) or
                    (sig == "authority" and any(w in text.lower() for w in ["ceo", "cfo", "director", "manager", "admin"])) or
                    (sig == "financial" and any(w in text.lower() for w in ["payment", "invoice", "bank", "wire", "transfer", "dollar", "$"])) or
                    (sig == "credential" and any(w in text.lower() for w in ["password", "login", "verify your account", "credentials"])) or
                    (sig == "imperative" and any(w in text.lower() for w in ["click here", "please verify", "action required", "kindly update"]))
                ) else 0
            )
            
            if sig_true == 1 and sig_pred == 1:
                s_tp += 1
            elif sig_true == 0 and sig_pred == 1:
                s_fp += 1
            elif sig_true == 0 and sig_pred == 0:
                s_tn += 1
            else:
                s_fn += 1

        prec = s_tp / (s_tp + s_fp) if (s_tp + s_fp) > 0 else 0.0
        rec = s_tp / (s_tp + s_fn) if (s_tp + s_fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        acc = (s_tp + s_tn) / len(dataset)
        signal_results[sig] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "true_positives": s_tp,
            "false_positives": s_fp,
            "true_negatives": s_tn,
            "false_negatives": s_fn
        }

    # 3. BEC Category Model Evaluation
    bec_categories = ["payment_diversion", "fake_invoice", "credential_harvesting", "executive_impersonation", "bank_account_change", "vendor_impersonation", "urgent_transfer_request", "payroll_manipulation"]
    bec_results = {}
    for cat in bec_categories:
        b_tp, b_fp, b_tn, b_fn = 0, 0, 0, 0
        for record in dataset:
            text = f"{record.get('subject','')}\n{record.get('text','') or record.get('body','') or record.get('text_body','')}"
            preds = predict_bec_category_scores(text) or {}
            cat_pred = 1 if preds.get(cat, 0.0) >= 0.5 else 0
            
            cat_true = 1 if cat in record.get("bec_categories", []) else (
                1 if cat.replace("_", " ") in text.lower() or (
                    (cat == "payment_diversion" and "bank" in text.lower() and "urgent" in text.lower()) or
                    (cat == "fake_invoice" and "invoice" in text.lower()) or
                    (cat == "credential_harvesting" and "login" in text.lower()) or
                    (cat == "executive_impersonation" and "ceo" in text.lower())
                ) else 0
            )
            
            if cat_true == 1 and cat_pred == 1:
                b_tp += 1
            elif cat_true == 0 and cat_pred == 1:
                b_fp += 1
            elif cat_true == 0 and cat_pred == 0:
                b_tn += 1
            else:
                b_fn += 1

        prec = b_tp / (b_tp + b_fp) if (b_tp + b_fp) > 0 else 0.0
        rec = b_tp / (b_tp + b_fn) if (b_tp + b_fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        acc = (b_tp + b_tn) / len(dataset)
        bec_results[cat] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "true_positives": b_tp,
            "false_positives": b_fp,
            "true_negatives": b_tn,
            "false_negatives": b_fn
        }

    report = {
        "gold_validation_size": len(dataset),
        "methodology": "Distant supervision multi-label evaluation against authentic email corpora (Nazario Phishing, SpamAssassin, Enron)",
        "main_phishing_classifier": {
            "accuracy": round(phish_acc, 4),
            "precision": round(phish_prec, 4),
            "recall": round(phish_rec, 4),
            "f1_score": round(phish_f1, 4),
            "confusion_matrix": {
                "true_positives": phish_tp,
                "false_positives": phish_fp,
                "true_negatives": phish_tn,
                "false_negatives": phish_fn
            }
        },
        "content_intelligence_signals": signal_results,
        "bec_category_models": bec_results
    }

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\nSaved evaluation report to {REPORT_PATH}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    evaluate_models()
