"""Inference for the trained content-intelligence signal model."""
import os
import re
import json
import math
from collections import Counter
from typing import Dict, Optional

WEIGHTS_FILE = "data/content_intelligence_weights.json"
_CACHED = None


def _load():
    global _CACHED
    if _CACHED is not None:
        return _CACHED
    if os.path.exists(WEIGHTS_FILE):
        try:
            with open(WEIGHTS_FILE, "r", encoding="utf-8") as f:
                _CACHED = json.load(f)
        except Exception:
            _CACHED = None
    return _CACHED


def _tokens(text: str):
    if not text:
        return []
    no_html = re.sub(r"<[^>]+>", " ", text)
    words = re.findall(r"\b[a-zA-Z0-9$€£'-]{2,}\b", no_html.lower())
    return words + [f"{words[i]}_{words[i+1]}" for i in range(len(words) - 1)]


def predict_content_signals(text: str) -> Optional[Dict[str, float]]:
    """
    Returns a trained probability (0.0-1.0) per signal — urgency, authority,
    financial, credential, imperative — replacing the old keyword-density scores.
    Falls back to None (caller should fall back to rule-based) if weights aren't trained yet.
    """
    data = _load()
    if not data:
        return None

    vocab, idf = data["vocabulary"], data["idf"]
    tf = Counter(_tokens(text))
    vec, norm_sq = {}, 0.0
    for term, count in tf.items():
        if term in vocab:
            idx = vocab[term]
            w = (1.0 + math.log(count)) * idf.get(term, 1.0)
            vec[idx] = w
            norm_sq += w * w
    norm = math.sqrt(norm_sq) if norm_sq > 0 else 1.0
    normalized = {idx: v / norm for idx, v in vec.items()}

    results = {}
    for signal in data["signals"]:
        coef = data["weights"][signal]
        bias = data["biases"][signal]
        logit = bias + sum(coef[idx] * v for idx, v in normalized.items() if idx < len(coef))
        results[signal] = round(1.0 / (1.0 + math.exp(-logit)), 4)  # sigmoid
    return results
