#!/usr/bin/env python3
"""
TraceXMail Standalone ML Forensics Model Evaluator
Allows security researchers, SIH judges, and engineers to evaluate the trained model
directly via Python CLI without external dependencies.
"""

import json
import os
import re
import math
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'data/datasets/trained_model.json')
DATASET_PATH = os.path.join(BASE_DIR, 'data/datasets/real_corpus.json')

def tokenize_forensics(text):
    text_lower = text.lower()
    cleaned = re.sub(r'https?://\S+', ' url_token ', text_lower)
    cleaned = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ' ip_token ', cleaned)
    cleaned = re.sub(r'[^\w\s]', ' ', cleaned)
    
    words = [w for w in cleaned.split() if 2 < len(w) < 25]
    tokens = list(words)
    for i in range(len(words) - 1):
        tokens.append(f'{words[i]}_{words[i+1]}')
        
    if re.search(r'wire transfer|escrow|bank deposit|direct deposit|payroll|routing number|w-2 form|gift card|gift cards|invoice remittance|swift transfer', text_lower):
        tokens.extend(['__cue_fraud_wire__', '__cue_fraud_wire__'])
    if re.search(r'paypal|apple id|microsoft 365|office 365|chase online|bank of america|docusign|wells fargo|netflix', text_lower):
        tokens.extend(['__cue_brand_target__', '__cue_brand_target__'])
    if re.search(r'password expire|account suspended|unauthorized access|verify your identity|confirm password|restore access|billing failure|security alert', text_lower):
        tokens.extend(['__cue_phish_lure__', '__cue_phish_lure__'])
    if re.search(r'unsubscribe|promotional offer|discount voucher|b2b leads|webinar|opt-out|marketing blast', text_lower):
        tokens.extend(['__cue_marketing_susp__', '__cue_marketing_susp__'])
    if re.search(r'github|pull request|jira ticket|commit|code review|standup|sprint|agenda|linux|debian|python|meeting recap|colleagues', text_lower):
        tokens.extend(['__cue_legit_work__', '__cue_legit_work__'])
        
    return tokens

def run_evaluation():
    if not os.path.exists(MODEL_PATH):
        print(f"[Error] Model file {MODEL_PATH} not found. Please run train_forensics_classifier.py first.")
        return
        
    with open(MODEL_PATH, 'r', encoding='utf-8') as f:
        model = json.load(f)
        
    meta = model.get('metadata', {})
    classes = model['classes']
    vocab_map = model['vocabMap']
    idf = model['idf']
    weights = model['weights']
    biases = model['biases']
    num_classes = len(classes)
    
    print("==========================================================================")
    print("       TRACEXMAIL PRODUCTION FORENSICS ML CLASSIFIER EVALUATION          ")
    print("==========================================================================")
    print(f"Engine          : {meta.get('engine', 'Multi-Class Calibrated Logistic Regression')}")
    print(f"Corpus Size     : {meta.get('totalSamples', 'N/A')} samples across 5 forensic classes")
    print(f"Train / Test    : {meta.get('trainCount', 'N/A')} Train / {meta.get('testCount', 'N/A')} Test (Stratified 80/20)")
    print(f"Test Accuracy   : {meta.get('accuracy', 0) * 100:.2f}%")
    print(f"Macro F1 Score  : {meta.get('macroF1', 0):.4f}")
    print(f"Weighted F1     : {meta.get('weightedF1', 0):.4f}")
    print("--------------------------------------------------------------------------")
    
    print("\n[Per-Class Metrics on Held-Out Test Set]")
    print(f"{'Class':16s} | {'Precision':10s} | {'Recall':10s} | {'F1-Score':10s} | {'Support':8s}")
    print("-" * 65)
    for c_name in classes:
        m = meta.get('metricsPerClass', {}).get(c_name, {})
        print(f"{c_name:16s} | {m.get('precision', 0):10.4f} | {m.get('recall', 0):10.4f} | {m.get('f1', 0):10.4f} | {m.get('support', 0):8d}")
        
    cm = meta.get('confusionMatrix', [])
    if cm:
        print("\n[Confusion Matrix (Rows: Actual Class, Columns: Predicted Class)]")
        header_str = "Actual \\ Pred"
        print(f"{header_str:16s} " + " ".join(f"{c[:8]:>8s}" for c in classes))
        for i, row in enumerate(cm):
            print(f"{classes[i]:16s} " + " ".join(f"{val:8d}" for val in row))
            
    # Predictor function
    def predict(text):
        tokens = tokenize_forensics(text)
        counts = Counter(tokens)
        vec = {}
        norm_sq = 0.0
        for t, cnt in counts.items():
            if t in vocab_map:
                idx = vocab_map[t]
                val = (1.0 + math.log(cnt)) * idf[idx]
                vec[idx] = val
                norm_sq += val * val
        norm = math.sqrt(norm_sq)
        if norm > 0:
            for idx in vec:
                vec[idx] /= norm
                
        logits = [biases[c] for c in range(num_classes)]
        for f_idx, val in vec.items():
            for c in range(num_classes):
                logits[c] += weights[c][f_idx] * val
                
        max_l = max(logits)
        exps = [math.exp(l - max_l) for l in logits]
        sum_e = sum(exps)
        probs = [e / sum_e for e in exps]
        pred_idx = logits.index(max_l)
        
        # Top contributing features for predicted class
        token_contributions = []
        for t, cnt in counts.items():
            if t in vocab_map:
                idx = vocab_map[t]
                w = weights[pred_idx][idx] * vec[idx]
                token_contributions.append((t, w))
        token_contributions.sort(key=lambda x: x[1], reverse=True)
        
        return classes[pred_idx], probs, token_contributions[:5]

    print("\n--------------------------------------------------------------------------")
    print("                      SAMPLE INFERENCE BENCHMARKS                         ")
    print("--------------------------------------------------------------------------")
    test_cases = [
        ("PayPal Phishing Lure", "Subject: Urgent: PayPal Account Suspended! Verify your identity and billing password immediately."),
        ("BEC Executive Wire Fraud", "Subject: Wire Transfer Remittance. Please execute urgent vendor escrow wire of $65,000 before 4 PM."),
        ("DocuSign Impersonation", "From: DocuSign Service <notifications@docusign-envelope-review.com> Subject: Please sign urgent legal NDA."),
        ("Unsolicited Marketing", "Subject: Exclusive 50% discount on B2B SaaS marketing leads database! Click here to unsubscribe."),
        ("Legitimate Open-Source Work", "From: Linus Torvalds <torvalds@linux-foundation.org> Subject: Linux kernel 6.12 patch review and merge pull request.")
    ]
    
    for label, email_text in test_cases:
        pred_class, probs, top_feats = predict(email_text)
        print(f"\nTest Case : {label}")
        print(f"Snippet   : {email_text[:80]}...")
        print(f"Predicted : >> {pred_class.upper()} << (Confidence: {max(probs)*100:.1f}%)")
        print(f"Posteriors: " + ", ".join(f"{c}: {p*100:.1f}%" for c, p in zip(classes, probs)))
        print(f"Key Cues  : " + ", ".join(f"{t} ({w:+.2f})" for t, w in top_feats))
    print("\n==========================================================================")

if __name__ == '__main__':
    run_evaluation()
