"""
TraceXMail Real Dataset Engine
Loads and prepares training samples from real public email corpora:
1. Jose Nazario Phishing Corpus (phishing0-3 mboxes)
2. SpamAssassin Public Ham & Spam Corpus (easy_ham & spam archives)
"""

import os
import json
import csv
from typing import List, Dict, Any, Tuple

DATASET_DIR = "data/datasets"
REAL_CORPUS_JSON = os.path.join(DATASET_DIR, "real_corpus.json")
REAL_CORPUS_CSV = os.path.join(DATASET_DIR, "nazario_enron_phishing_corpus.csv")

os.makedirs(DATASET_DIR, exist_ok=True)


def ensure_real_corpus_exists() -> str:
    """Ensures real corpus exists on disk; runs fetch script if not yet generated."""
    if os.path.exists(REAL_CORPUS_JSON) and os.path.getsize(REAL_CORPUS_JSON) > 1024:
        return REAL_CORPUS_JSON

    # Run fetch script dynamically
    from scripts.fetch_real_corpus import build_and_save_real_corpus
    return build_and_save_real_corpus()


def export_dataset_to_csv() -> str:
    """Exports loaded real corpus to CSV for external inspection and training."""
    records = load_dataset()
    if not records:
        return ""
    keys = records[0].keys()
    with open(REAL_CORPUS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(records)
    return REAL_CORPUS_CSV


def load_dataset() -> List[Dict[str, Any]]:
    """Loads all real email records from real_corpus.json."""
    json_path = ensure_real_corpus_exists()
    if not os.path.exists(json_path):
        return []

    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            records = json.load(f, strict=False)
        return records
    except Exception as e:
        # Fallback: line-by-line or script regeneration if corpus JSON was corrupted
        try:
            with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # sanitize control chars
                content_clean = re.sub(r'[\x00-\x1F\x7F]', ' ', content)
                return json.loads(content_clean, strict=False)
        except Exception:
            return []



def load_5way_dataset() -> List[Dict[str, Any]]:
    """Loads 5-way classification dataset records (legitimate, suspicious, impersonated, phishing, fraud_related)."""
    records = load_dataset()
    return [r for r in records if "five_way_label" in r]
