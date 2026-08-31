"""
TraceXMail AI Reasoner — Groq-backed narrative synthesis
Module: backend/ai_reasoner.py

Takes the ALREADY-COMPUTED, structured evidence (fusion output, attribution
hypotheses, contradictions, BEC findings) and asks an LLM to write a concise,
analyst-readable case narrative. The LLM never re-scores or re-classifies —
it only explains what the deterministic engines already found, and must cite
the evidence IDs it references. If no API key is set, or the call fails, this
degrades to returning None — callers must treat it as optional enrichment.
"""
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("TraceXMail.AIReasoner")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

SYSTEM_PROMPT = (
    "You are a SOC forensic analyst assistant. You are given structured, "
    "already-computed evidence from a deterministic email forensics pipeline "
    "(authentication results, header anomalies, threat intel, BEC signals, "
    "attribution hypotheses, contradictions). Write a concise (150-250 word) "
    "investigator narrative summarizing what the evidence shows. "
    "Rules: (1) Only reference facts present in the evidence JSON — never "
    "invent IPs, domains, names, or scores. (2) Explicitly separate FACT vs "
    "FINDING vs HYPOTHESIS, matching the labels already present in the input. "
    "(3) If the evidence is inconclusive, say so plainly — do not manufacture "
    "certainty. (4) Never state a physical attacker location as fact; only "
    "infrastructure geolocation, per the evidence's own framing."
)


def is_available() -> bool:
    return bool(os.environ.get("GROQ_API_KEY", "").strip())


def synthesize_case_narrative(evidence_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    model_name = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile").strip() or "llama-3.3-70b-versatile"
    
    if not api_key:
        return None
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(evidence_payload, default=str)},
            ],
            temperature=0.2,
            max_tokens=500,
        )
        narrative = resp.choices[0].message.content
        return {
            "narrative": narrative,
            "model": model_name,
            "source": "groq_ai_reasoner",
            "disclaimer": "AI-generated synthesis of deterministic evidence below — not an independent finding.",
        }
    except Exception as e:
        logger.warning(f"Groq synthesis failed: {e}")
        return None
