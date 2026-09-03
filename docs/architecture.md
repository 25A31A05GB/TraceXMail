# TraceXMail Architecture Specification

## 1. System Overview
TraceXMail is an AI-powered email threat detection, geolocation, and forensic intelligence platform engineered for SIH 2026 (Problem Statement 26106).

```
React 18 + Vite (Tailwind CSS, Lucide Icons)
                   │
                   ▼
  Node.js / Express Application Gateway (Port 3000)
  ├── RFC 822 EML Raw Ingestion & Bit-Level Evidence Vault (SHA-256)
  ├── 5-Class Forensic ML Classifier (Trained Nearest Centroid / Cosine)
  ├── Header & Received-Hop Demarcator (RFC 1918 / 1122 Boundary Analysis)
  ├── Cryptographic Auth Verifier (SPF, DKIM, DMARC)
  ├── Intelligence Enrichment Subsystem:
  │    ├── MaxMind GeoLite2 Offline City & ASN Resolver
  │    ├── Live DNS & RDAP Registrar Resolver (with timeouts & caching)
  │    ├── VirusTotal v3 Reputation Gateway (Real API or UNCONFIGURED)
  │    └── AbuseIPDB v2 Reputation Gateway (Real API or UNCONFIGURED)
  ├── Multi-Signal BEC & Threat Scoring Engine [0-100]
  ├── Multi-Case Campaign Correlation & Graph Engine
  └── Tenant Isolation & RBAC Controller (Admin, Analyst, Viewer)
                   │
                   ▼
  PostgreSQL / Supabase Persistent Store & SQLite Fallback
```

## 2. Core Subsystems

### 2.1 Raw Ingestion & Evidence Vault
- **Input:** RFC 822 `.eml`, `.msg`, `.mbox` files and raw MIME streams.
- **Immutability:** The raw uploaded byte array is saved unmodified.
- **Hashing:** A cryptographic SHA-256 digest is computed instantly upon reception.
- **Verification:** The `/api/evidence/:evidenceId/verify` endpoint recalculates the SHA-256 hash of the stored raw file and compares it with the database index, outputting `MATCH` or `INTEGRITY_FAILURE`.

### 2.2 Header Forensics & Received Chain Demarcation
- Parses every RFC 5322 `Received:` header sequentially from recipient MTA (hop #1) to sender origin (hop #N).
- Demarcates private non-routable IP ranges (RFC 1918 Class A/B/C, Loopback RFC 1122, CGNAT RFC 6598, Link-Local RFC 3927) from public internet relays.
- Computes the **Earliest Verifiable Node** rather than asserting an unverified "attacker IP".

### 2.3 Machine Learning Inference Subsystem
- **Model Type:** 5-Class Nearest Centroid Classifier with Cosine Similarity and TF-IDF Normalized Lexical Features (3,500 vocabulary size).
- **Target Classes:** `Legitimate`, `Suspicious`, `Impersonated`, `Phishing`, `Fraud-related`.
- **Explainability:** Emits posterior class probabilities, confidence margins, and human-interpretable linguistic/structural signals.

### 2.4 Enrichment & Anti-Fabrication Principles
- If MaxMind lacks a CIDR match for an IP, the system outputs `city: null`, `country: null`, `lookupStatus: "unavailable"`.
- If VirusTotal or AbuseIPDB API keys are not supplied in `.env`, the system marks the service as `UNCONFIGURED` / `UNKNOWN` and explains why.
- Under zero circumstances are fake coordinates, fake scores (e.g. "28/88 Engines"), or fake threat actor names generated.
