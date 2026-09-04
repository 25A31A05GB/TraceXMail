# TraceXMail Architecture Specification

## 1. System Overview
TraceXMail is an AI-powered email threat detection, geolocation, and forensic intelligence platform engineered for SIH 2026 (Problem Statement 26106).

```
React 18 + Vite (Tailwind CSS, Lucide Icons)
                   │
                   ▼
  Node.js / Express Application Gateway (Port 3000)
  ├── RFC 822 EML Raw Ingestion & Bit-Level Evidence Vault (SHA-256)
  ├── Real-Time Ingestion Subsystem (Cloud Pub/Sub watch() & Polling Fallback)
  ├── Pre-Delivery Quarantine / Hold Gate (Threshold Filtering & Admin Webhooks)
  ├── Layered NLP & Forensic Classifier:
  │    ├── Layer 0: Nearest Centroid / Cosine Similarity (TF-IDF Lexical Baseline)
  │    ├── Layer 1: Gemini text-embedding-004 Semantic Vector Cosine Similarity
  │    ├── Layer 2: LLM Deep Linguistic Forensics (Gemini / Groq)
  │    └── Layer 3: Weighted Social Engineering Lexicons & Financial Entity Scanner
  ├── Header & Received-Hop Demarcator (RFC 1918 / 1122 Boundary Analysis)
  ├── Cryptographic Auth Verifier (SPF, DKIM, DMARC, ARC via mailauth)
  ├── Intelligence Enrichment Subsystem:
  │    ├── MaxMind GeoLite2 City & ASN Resolver (MMDB / CSV / Web Service)
  │    ├── Authoritative Tor Project Directory & Exit Node Resolver (torExitNodes.ts)
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

---

## 2. Core Subsystems

### 2.1 Raw Ingestion & Evidence Vault
- **Input:** RFC 822 `.eml`, `.msg`, `.mbox` files, MIME streams, and real-time Gmail mailbox push streams.
- **Immutability:** The raw uploaded byte array is saved unmodified.
- **Hashing:** A cryptographic SHA-256 digest is computed instantly upon reception.
- **Verification:** The `/api/evidence/:evidenceId/verify` endpoint recalculates the SHA-256 hash of the stored raw file and compares it with the database index, outputting `MATCH` or `INTEGRITY_FAILURE`.

### 2.2 Ingestion Modes: Real-Time Cloud Pub/Sub `watch()` vs. Polling Fallback
TraceXMail supports two ingestion modes to ensure zero-latency threat detection:
1. **Real-Time Push Notifications (Cloud Pub/Sub `watch()`):**
   - TraceXMail establishes a Google Cloud Pub/Sub subscription via the Gmail `users.watch()` API.
   - When a new message arrives at the mail server, Google Cloud Pub/Sub instantly posts a webhook to `/api/gmail/pubsub/push`.
   - The message is analyzed within milliseconds **prior to regular inbox display**, enabling automated pre-delivery quarantine holding.
2. **Polling Sync Loop (Fallback):**
   - For restricted network perimeters or air-gapped environments where inbound webhooks cannot be received from Cloud Pub/Sub, TraceXMail provides a configurable polling loop (`/api/gmail/poll-now`) executing at user-specified intervals (default: 20 seconds).

### 2.3 Automated Pre-Delivery Quarantine Gate & Delivery Stages
TraceXMail categorizes every analyzed message into an authoritative `deliveryStage`:
- **`pre-delivery-hold`**: Email intercepted via real-time push before reaching the recipient's view. If the calculated threat score exceeds the configurable quarantine threshold (default: ≥ 70/100), TraceXMail automatically:
  1. Applies the holding label (`TraceXMail-Quarantine`) and removes `INBOX`.
  2. Dispatches an instant HTTP POST webhook to the SOC Admin Webhook URL.
  3. Records an immutable entry in the Quarantine Audit Trail.
  4. Requires explicit SOC analyst approval before release.
- **`post-delivery-alert`**: Messages uploaded post-delivery or audited after arriving in an unprotected inbox, raising SIEM alerts and real-time WebSocket notifications.

### 2.4 Header Forensics & Received Chain Demarcation
- Parses every RFC 5322 `Received:` header sequentially from recipient MTA (hop #1) to sender origin (hop #N).
- Demarcates private non-routable IP ranges (RFC 1918 Class A/B/C, Loopback RFC 1122, CGNAT RFC 6598, Link-Local RFC 3927) from public internet relays.
- Identifies the **Earliest Verifiable Node** rather than asserting an unverified "attacker IP".

### 2.5 Authoritative Tor Exit Node Intelligence Subsystem
- Located in `src/server/intelligence/torExitNodes.ts`.
- Periodically fetches and caches the official Tor Project bulk exit-list (`https://check.torproject.org/torbulkexitlist`) with a 6-hour TTL in `IntelligenceCache` and disk fallback.
- Enriches every IP in the GeoIP pipeline with `isTorExitNode: boolean`.
- Visualized distinctly across `MapView.tsx` (animated badges) and `HopTracerouteView.tsx` (timeline and inspector markers).

### 2.6 Layered NLP & Linguistic Analysis Pipeline
TraceXMail employs a multi-tiered forensic NLP architecture:
1. **Deterministic Lexical Baseline:** 5-Class Nearest Centroid with Cosine Similarity and TF-IDF Normalized Lexical Features (3,500 vocabulary size).
2. **Layer 1 (Semantic Embedding Similarity):** Generates high-dimensional vector embeddings using Google's `text-embedding-004` model via Gemini API, evaluating cosine similarity against clustered reference threat templates.
3. **Layer 2 (LLM Deep Linguistic Forensics):** Analyzes cognitive urgency, authority pressure, grammatical anomalies, and deceptive intent via Gemini 2.5 Flash / Groq.
4. **Layer 3 (Weighted Entity Lexicons):** Scans for financial keywords, SWIFT/IBAN/crypto wallet addresses, invoice lures, and social engineering vectors.

### 2.7 Multi-Tiered Geolocation & Anti-Fabrication Principles
- **Setup & Automated Pipeline:**
  - Run `npm run setup:maxmind` and add your free MaxMind license key (`MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`) to `.env` before first run.
  - Sign up for a free MaxMind account at https://www.maxmind.com/en/geolite2/signup.
  - Periodic weekly database updates can be executed via `npm run refresh:maxmind` or automated server background tasks.
- **Multi-Tier Resolution Flow:**
  - **Tier 1 (Sub-millisecond Binary MMDB):** Local `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` parsed via official `maxmind` binary search tree reader (`O(log N)` search).
  - **Tier 2 (ip-api.com Live Fallback):** High-speed live lookup (no API key required), protected by an in-process sliding-window rate limiter (capped at 45 requests/minute).
  - **Tier 3 (ipwho.is Live Fallback):** Secondary free live API fallback with regional/ASN enrichment.
  - **Tier 4 (ipgeolocation.io Live Fallback):** Optional third-tier API fallback when `IPGEO_API_KEY` is provided.
- **Strict Anti-Fabrication Rule:**
  - If an IP is not mapped across local databases and live fallback providers, the system outputs `city: null`, `country: null`, `source: "unavailable"`, and `lookupStatus: "unavailable"`.
  - Under zero circumstances are fake coordinates or guessed city names fabricated.
- **RFC 1918 Private Demarcation:**
  - Private non-routable subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16) are immediately classified with zero network overhead as `Internal Subnet / Private Network (RFC 1918)`.
- If VirusTotal or AbuseIPDB API keys are not supplied in `.env`, the system marks the service as `UNCONFIGURED` / `UNKNOWN` and explains why.

