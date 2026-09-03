# Digital Evidence Preservation & Chain of Custody

## 1. Evidentiary Standards
TraceXMail adheres to RFC 3161 digital timestamping and NIST SP 800-86 guide for integrating forensic techniques into incident response.

## 2. Ingestion & Preservation Lifecycle
1. **Raw Reception:** Ingested `.eml` or RFC 822 payload is buffered into memory.
2. **Instant Digest Calculation:** SHA-256 hash is computed immediately over the raw byte buffer.
3. **Preservation Vaulting:** The byte buffer is written to the evidence vault storage without any text decoding, stripping, or header modification.
4. **Metadata Indexing:** A record is created containing:
   - `evidence_id`: UUIDv4 identifier
   - `case_id`: Associated forensic case
   - `organization_id`: Tenant boundary
   - `original_filename`: Sanitized original upload name
   - `mime_type`: `message/rfc822`
   - `byte_size`: Integer byte count
   - `sha256_hash`: 64-character lowercase hex digest
   - `ingestion_timestamp`: ISO 8601 UTC timestamp
   - `uploader_id`: Identity of ingesting analyst/system
   - `preservation_status`: `PRESERVED`

## 3. Cryptographic Verification Procedure
The `/api/evidence/:evidenceId/verify` endpoint loads the physical bytes from storage, recomputes the SHA-256 digest, and compares it bit-for-bit with `sha256_hash`:
- **MATCH:** Cryptographic integrity verified.
- **INTEGRITY_FAILURE:** Evidence has been modified or corrupted post-ingestion.

## 4. Chain of Custody Audit Log
Every view, download, analysis run, or report export produces an immutable audit log record in `audit_logs` tracking timestamp, actor, IP, action, and target evidence ID.
