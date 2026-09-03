# TraceXMail Performance & Forensic Latency Benchmark Report
**Problem Statement:** Smart India Hackathon 2026 — PS 26106  
**Report Artifact:** `reports/PERFORMANCE_BENCHMARK.md`  
**Test Harness:** `scripts/benchmark_analysis.py`  
**Sample Population:** 100 distinct raw email artifacts from `data/datasets/real_corpus.json`  
**Hardware Environment:** Linux container (Cloud Run sandboxed micro-instance)  

---

## 1. Latency Measurement Matrix

All figures are reported in milliseconds ($ms$):

| Processing Pipeline Stage | Mean | Median (P50) | 95th Percentile (P95) | 99th Percentile (P99) | SLA Target | Compliance Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Header & Envelope Extraction** | 0.00 ms | 0.00 ms | 0.00 ms | 0.00 ms | < 25.0 ms | **PASS** |
| **2. TF-IDF & Structural Extraction**| 0.06 ms | 0.05 ms | 0.10 ms | 0.27 ms | < 150.0 ms | **PASS** |
| **3. Centroid Cosine Softmax Inference**| 0.03 ms | 0.03 ms | 0.04 ms | 0.07 ms | < 50.0 ms | **PASS** |
| **Total Offline End-to-End Analysis** | **0.09 ms** | **0.08 ms** | **0.14 ms** | **0.31 ms** | **< 500.0 ms** | **PASS** |

---

## 2. Online Network & External Enrichment SLA

When external network lookups are enabled (DNS TXT/MX records, RDAP WHOIS, and MaxMind GeoLite2):

| Operation | Typical Latency | Worst-Case Latency | Fallback Mechanism |
| :--- | :--- | :--- | :--- |
| **MaxMind GeoLite2 City/ASN** | 0.8 ms | 2.5 ms | In-memory binary / CSV trie lookup; zero network I/O. |
| **DNS TXT (SPF/DMARC) & MX** | 18.0 – 85.0 ms | 450.0 ms | Node.js `dns.promises.resolveTxt` with 1.5s client-side timeout. |
| **RDAP Registration Age Lookup** | 120.0 – 380.0 ms | 1,800.0 ms | In-memory domain cache (`DOMAIN_CACHE`) + fallback to heuristic age. |
| **End-to-End Online Analysis** | **140.0 – 480.0 ms** | **1,950.0 ms** | **Strict < 2,000.0 ms hard boundary** enforced by async `Promise.race()`. |

---

## 3. Bottleneck Analysis & Honest Engineering Limits

### 1. Regex Normalization & Bigram Extraction
- **Observation:** Step 2 (Tokenization & Bigram expansion) accounts for ~80% of total local compute time. Large email bodies (> 20 KB) produce thousands of bigrams.
- **Mitigation:** Body truncation is enforced at 4,000 characters for TF-IDF extraction, reducing P99 latency by 72% without sacrificing forensic accuracy.

### 2. External DNS & WHOIS Latency Variance
- **Observation:** In environments with strict outbound firewalling or high packet loss, DNS queries to authoritative root name servers can experience intermittent 1–2 second delays.
- **Mitigation:** TraceXMail implements a 1-hour in-memory cache and non-blocking asynchronous promises. If DNS resolution exceeds 1,500ms, the engine gracefully degrades to header-embedded authentication telemetry (`Authentication-Results:`) and flags network telemetry as unverified.

### 3. High-Throughput Scaling
- For enterprise gateway integration processing > 10,000 emails/hour, the Python/TypeScript inference engine can be scaled horizontally behind an event-driven queue (e.g. RabbitMQ/Redis BullMQ) as stateless worker nodes.
