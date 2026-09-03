# TraceXMail Security & Privacy Architecture

## 1. Zero Trust Ingestion & Safe Parsing
- **No Remote Code Execution:** Email payloads (HTML, attachments, scripts) are never executed or evaluated in browser or server contexts.
- **Attachment Quarantine:** Attachments are extracted purely as metadata (filename, MIME type, size, SHA-256 hash). Binary payloads are hashed without running.
- **URL Disarming & Sanitization:** URLs are extracted, normalized, and disarmed. Outbound connections are only initiated to standard DNS resolvers or official reputation APIs (VirusTotal/AbuseIPDB) if explicitly configured with keys.

## 2. PII Protection & Data Privacy Compliance
- **Masking Modes:** Supports Full Masking, Partial Masking, and Unmasked views based on analyst permissions.
- **Retention & Auto-Purge:** Implements retention policy schedules (7, 30, 90, 365 days) with auditable purge tracking.
- **GDPR / HIPAA Alignment:** Strict role-based redaction of employee email addresses and proprietary internal header strings.

## 3. Multi-Tenancy & Role-Based Access Control (RBAC)
- **Tenancy Boundary:** All database records enforce `organization_id`.
- **Roles:**
  - `Admin`: Full permissions (user management, policy configuration, hard deletion, evidence audit).
  - `Analyst`: Ingestion, case investigation, tagging, report generation, evidence verification.
  - `Viewer / Auditor`: Read-only access to anonymized cases and compliance reports.
