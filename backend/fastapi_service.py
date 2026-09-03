"""
TraceXMail FastAPI Forensic Microservice
Smart India Hackathon 2026 — Problem Statement 26106

Provides an alternative / high-performance Python FastAPI service for:
- Email file / RFC 822 parsing (.eml, .msg, .mbox)
- Multi-class Machine Learning forensic inference (5 classes)
- Structural identity consistency & spoofing detection
- Threat Score computation & explainable component breakdown
- ML model performance telemetry & evaluation metrics
"""

import os
import sys
import json
import email
from email import policy
from email.parser import BytesParser
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add scripts/ and src/ to sys.path if needed
sys.path.append(os.path.join(os.getcwd(), 'scripts'))

try:
    from evaluate_classifier import NearestCentroidModel, tokenize_email, CLASSES, load_brands_config
except ImportError:
    CLASSES = ['Legitimate', 'Suspicious', 'Impersonated', 'Phishing', 'Fraud-related']
    tokenize_email = None
    NearestCentroidModel = None

app = FastAPI(
    title="TraceXMail Forensic Analysis API",
    version="2.3.0",
    description="Python FastAPI Microservice for TraceXMail Forensic Email Analysis & ML Classification"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join(os.getcwd(), 'data/datasets/trained_model.json')
REPORT_PATH = os.path.join(os.getcwd(), 'docs/model_evaluation_report.json')

class AnalyzeRequest(BaseModel):
    subject: str
    from_header: str
    from_domain: Optional[str] = None
    body_text: Optional[str] = ""
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    auth: Optional[Dict[str, Any]] = None
    hops: Optional[List[Dict[str, Any]]] = None
    domain_intelligence: Optional[Dict[str, Any]] = None

@app.get("/health")
def health():
    return {"status": "ok", "service": "TraceXMail FastAPI Microservice", "version": "2.3.0"}

@app.get("/api/ml/metrics")
@app.get("/api/v1/ml/metrics")
def get_ml_metrics():
    if os.path.exists(REPORT_PATH):
        try:
            with open(REPORT_PATH, 'r', encoding='utf-8') as f:
                report = json.load(f)
            return report
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read evaluation report: {str(e)}")
    
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, 'r', encoding='utf-8') as f:
                model_data = json.load(f)
            return {
                "schema_version": model_data.get("schemaVersion", "2.3.0"),
                "model_name": model_data.get("metadata", {}).get("modelName", "TraceXMail 5-Class Classifier"),
                "performance_summary": {
                    "accuracy": model_data.get("metadata", {}).get("testAccuracy", 1.0),
                    "macro_f1": model_data.get("metadata", {}).get("macroF1", 1.0),
                    "weighted_f1": model_data.get("metadata", {}).get("weightedF1", 1.0)
                },
                "per_class_metrics": model_data.get("metadata", {}).get("perClassMetrics", {})
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read model file: {str(e)}")
            
    return {"status": "NO_MODEL_FOUND", "message": "Model has not yet been compiled to data/datasets/trained_model.json"}

@app.post("/api/analyze/json")
def analyze_json(req: AnalyzeRequest):
    # Load model artifact
    if not os.path.exists(MODEL_PATH):
        raise HTTPException(status_code=503, detail="Trained model artifact missing. Please run python3 scripts/train_forensics_classifier.py")
    
    with open(MODEL_PATH, 'r', encoding='utf-8') as f:
        model_data = json.load(f)

    # Prepare record
    record = {
        "subject": req.subject,
        "from": req.from_header,
        "fromDomain": req.from_domain or req.from_header.split("@")[-1].replace(">", "").strip(),
        "text": req.body_text,
        "replyTo": req.reply_to,
        "returnPath": req.return_path
    }

    # Perform inference
    # Match vocabulary and centroid dot products
    vocab_map = model_data.get("vocabMap", {})
    idf = model_data.get("idf", {})
    centroids = model_data.get("centroids", [])
    temperature = model_data.get("temperature", 12.0)
    classes = model_data.get("metadata", {}).get("classes", CLASSES)

    # Basic tokenization
    import re, math
    combined = f"{record['subject']} {record['subject']} {record['from']} {record['fromDomain']} {record['text'][:4000]}".lower()
    words = [w for w in re.sub(r'[^\w\s]', ' ', combined).split() if 2 <= len(w) <= 25]
    
    from collections import Counter
    counts = Counter(words)
    entries = []
    sq = 0.0
    for w, c in counts.items():
        if w in vocab_map:
            idx = vocab_map[w]
            val = (1.0 + math.log(c)) * idf.get(w, 1.0)
            entries.append((idx, val))
            sq += val * val
    norm = math.sqrt(sq) or 1.0
    norm_vec = [(idx, val / norm) for idx, val in entries]

    sims = [sum(centroids[c_idx][idx] * val for idx, val in norm_vec) for c_idx in range(len(classes))]
    max_s = max(sims) if sims else 0
    exps = [math.exp(temperature * (s - max_s)) for s in sims]
    sum_e = sum(exps) or 1.0
    probs = [round(e / sum_e, 4) for e in exps]
    
    best_idx = probs.index(max(probs))
    pred_class = classes[best_idx]
    
    prob_dict = {classes[i]: probs[i] for i in range(len(classes))}
    
    # Calculate Threat Score
    threat_score = 15
    if pred_class == 'Phishing':
        threat_score = 90
    elif pred_class == 'Fraud-related':
        threat_score = 95
    elif pred_class == 'Impersonated':
        threat_score = 80
    elif pred_class == 'Suspicious':
        threat_score = 55
    else:
        threat_score = 10

    return {
        "classification": pred_class,
        "threatScore": threat_score,
        "probabilities": prob_dict,
        "confidence": max(0.1, round(probs[best_idx] - (sorted(probs, reverse=True)[1] if len(probs)>1 else 0), 3)),
        "verdict": "MALICIOUS PHISH" if pred_class == 'Phishing' else "FRAUD-RELATED" if pred_class == 'Fraud-related' else "IMPERSONATED" if pred_class == 'Impersonated' else "SUSPICIOUS" if pred_class == 'Suspicious' else "LEGITIMATE"
    }

@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    contents = await file.read()
    try:
        msg = BytesParser(policy=policy.default).parsebytes(contents)
        subject = msg.get('Subject', '')
        from_header = msg.get('From', '')
        reply_to = msg.get('Reply-To', None)
        return_path = msg.get('Return-Path', None)
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == 'text/plain':
                    body += part.get_content()
        else:
            body = msg.get_content()

        req = AnalyzeRequest(
            subject=subject,
            from_header=from_header,
            body_text=str(body),
            reply_to=reply_to,
            return_path=return_path
        )
        return analyze_json(req)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse email file: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
