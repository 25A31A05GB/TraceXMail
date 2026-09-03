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
