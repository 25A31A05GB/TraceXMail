# TraceXMail REST API Reference

All endpoints bind to port `3000` via Express application gateway.

## 1. Core Endpoints

### 1.1 Ingestion & Analysis
- `POST /api/analyze/eml`: Multipart form upload of `.eml` or RFC 822 MIME raw email.
  - **Returns:** Full JSON `EmailAnalysis` object containing SHA-256 hash, evidence ID, parsed headers, auth results, hops, domain intelligence, ML probabilities, BEC signals, and risk score.
- `POST /api/analyze/text`: JSON payload containing raw email text headers and body.
  - **Returns:** Structured forensic analysis.

### 1.2 Case Management
- `GET /api/cases`: Retrieve case list. Supports query parameters `exclude_demo=true`, `severity`, `status`, `search`.
- `GET /api/cases/:id`: Retrieve detailed forensic case data.
- `POST /api/cases`: Create a new forensic case.
- `PATCH /api/cases/:id`: Update case status, severity, notes, tags.
- `DELETE /api/cases/:id`: Delete a case (Admin only).

### 1.3 Evidence Management
- `GET /api/evidence/:evidenceId`: Retrieve evidence metadata and custody record.
- `GET /api/evidence/:evidenceId/raw`: Download preserved unmodified original `.eml` bytes.
- `POST /api/evidence/:evidenceId/verify`: Verify SHA-256 hash against preserved disk/db bytes.
  - **Returns:** `{"status": "MATCH", "recorded_hash": "...", "calculated_hash": "..."}` or `{"status": "INTEGRITY_FAILURE"}`.

### 1.4 Intelligence & Enrichment
- `GET /api/intelligence/ip/:ip`: MaxMind GeoLite2 & ASN lookup for an IP.
- `GET /api/intelligence/domain/:domain`: Live DNS (MX, SPF, DMARC) and RDAP registration lookup.
- `GET /api/ml/metrics`: Telemetry and performance metrics for the active ML classifier.

### 1.5 System & Health
- `GET /api/health`: Health status and active component readiness.
- `GET /api/audit-logs`: Chronological log of all analyst actions and evidence accesses.

## 2. Network Intelligence & Analyst Telemetry

### 2.1 Telemetry Endpoints
- `GET /api/network-info`: Retrieves public IP, IP version (IPv4/IPv6), approximate location, network organization/ISP, ASN, and hosting server location.
  - **Query Params:** `force_refresh=true` (bypasses 10-minute in-memory cache).
  - **Returns:** Structured JSON with `isApproximate: true` and disclaimer.
- `GET /api/network/ping`: Lightweight round-trip latency endpoint with zero-cache headers.
  - **Returns:** `{"status": "ok", "timestamp": 1788538543227}`.
- `GET /api/network/bandwidth-payload`: Controlled 512 KB payload for on-demand download throughput measurement.
  - **Returns:** 524,288 raw bytes with `application/octet-stream` and no-cache directives.

See `docs/NETWORK_INTELLIGENCE.md` for methodology, privacy safeguards, and rate limits.
