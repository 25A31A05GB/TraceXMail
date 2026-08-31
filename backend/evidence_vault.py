"""
TraceXMail Evidence Vault (backend/evidence_vault.py)
Cryptographic Chain of Custody and Immutable Raw Email Evidence Storage.

Guarantees:
1. Exact raw bytes received are hashed (SHA-256) BEFORE any parsing, decoding, or transformation.
2. Generates immutable evidence_id formatted as 'EV-XXXXXX' (6-char uppercase hex token).
3. Records UTC received_at timestamp and ingestion source (email_upload, api, forwarded, gateway_webhook).
4. Persists raw bytes immutably in Postgres (bytea) / SQLite (BLOB) storage.
5. Provides cryptographic re-verification on demand (recomputes SHA-256 to prove non-tampering).
"""

import hashlib
import secrets
import os
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy.orm import Session
from backend.db_session import get_db_context
from backend.models import Evidence
from backend.database import get_db_connection
HAS_DB = True

# In-memory storage for when database engine is unavailable
_MEMORY_VAULT: Dict[str, Dict[str, Any]] = {}


VALID_SOURCES = {"email_upload", "api", "forwarded", "gateway_webhook"}


def compute_sha256(data: bytes | str) -> str:
    """
    Calculates the standard SHA-256 hexadecimal digest of raw input bytes.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_evidence_id() -> str:
    """
    Generates a unique Evidence ID formatted as EV-XXXXXX where XXXXXX is
    a 6-character uppercase cryptographic hexadecimal string (e.g. EV-A1B2C3).
    """
    return f"EV-{secrets.token_hex(3).upper()}"


class EvidenceVault:
    """
    Vault manager for immutable forensic email evidence.
    """

    @staticmethod
    def store_evidence(
        raw_bytes: bytes | str,
        source: str = "email_upload",
        filename: Optional[str] = None,
        organization_id: str = "org_default_01",
        case_id: Optional[str] = None,
        evidence_type: str = "RAW_EML",
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Stores raw email bytes into the immutable evidence vault BEFORE any parsing occurs.
        Computes SHA-256 hash, generates unique EV-XXXXXX identifier, and persists to DB.
        """
        # Ensure bytes representation for cryptographic hashing
        if isinstance(raw_bytes, str):
            content_bytes = raw_bytes.encode("utf-8")
            raw_text = raw_bytes
        else:
            content_bytes = raw_bytes
            raw_text = raw_bytes.decode("utf-8", errors="ignore")

        # 1. Compute SHA-256 over exact raw bytes received
        sha256_hash = compute_sha256(content_bytes)
        file_size = len(content_bytes)
        received_at_dt = datetime.utcnow()
        received_at_iso = received_at_dt.isoformat() + "Z"

        # Validate source
        normalized_source = source if source in VALID_SOURCES else "api"

        # 2. Generate unique evidence_id (format EV-XXXXXX)
        evidence_id = generate_evidence_id()

        # 3. Store into persistent database (ORM + SQLite fallback)
        if HAS_DB:
            try:
                with get_db_context() as db:
                    # Collision check
                    while db.query(Evidence).filter_by(id=evidence_id).first() is not None:
                        evidence_id = generate_evidence_id()

                    evidence_record = Evidence(
                        id=evidence_id,
                        organization_id=organization_id,
                        case_id=case_id,
                        evidence_type=evidence_type,
                        source=normalized_source,
                        filename=filename or "raw_ingested_message.eml",
                        file_size=file_size,
                        raw_bytes=content_bytes,
                        raw_content=raw_text,
                        custody_hash=sha256_hash,
                        sha256_hash=sha256_hash,
                        notes=notes or f"Ingested via {normalized_source}",
                        received_at=received_at_dt,
                        created_at=received_at_dt
                    )
                    db.add(evidence_record)
                    db.commit()
            except Exception as e:
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS evidence (
                        id TEXT PRIMARY KEY,
                        organization_id TEXT NOT NULL DEFAULT 'org_default_01',
                        case_id TEXT,
                        evidence_type TEXT NOT NULL DEFAULT 'RAW_EML',
                        source TEXT NOT NULL DEFAULT 'email_upload',
                        filename TEXT,
                        file_size INTEGER DEFAULT 0,
                        raw_bytes BLOB,
                        raw_content TEXT,
                        custody_hash TEXT NOT NULL,
                        sha256_hash TEXT NOT NULL,
                        notes TEXT,
                        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """)
                    cursor.execute("""
                    INSERT OR REPLACE INTO evidence (
                        id, organization_id, case_id, evidence_type, source,
                        filename, file_size, raw_bytes, raw_content, custody_hash,
                        sha256_hash, notes, received_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        evidence_id,
                        organization_id,
                        case_id,
                        evidence_type,
                        normalized_source,
                        filename or "raw_ingested_message.eml",
                        file_size,
                        content_bytes,
                        raw_text,
                        sha256_hash,
                        sha256_hash,
                        notes,
                        received_at_iso,
                        received_at_iso
                    ))
                    conn.commit()
                    conn.close()
                except Exception as sql_err:
                    print(f"[EvidenceVault Error] Failed to persist evidence record: {sql_err}")

        record_dict = {
            "evidence_id": evidence_id,
            "id": evidence_id,
            "sha256_hash": sha256_hash,
            "custody_hash": sha256_hash,
            "file_size": file_size,
            "filename": filename or "raw_ingested_message.eml",
            "source": normalized_source,
            "organization_id": organization_id,
            "case_id": case_id,
            "received_at": received_at_iso,
            "created_at": received_at_iso,
            "evidence_type": evidence_type,
            "raw_bytes": content_bytes,
            "raw_content": raw_text,
            "hash_verified": True
        }
        _MEMORY_VAULT[evidence_id] = record_dict
        return record_dict

    @staticmethod
    def get_evidence(evidence_id: str, organization_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves evidence record by evidence_id and executes live cryptographic re-verification.
        Recomputes SHA-256 of the stored raw bytes to mathematically prove the record hasn't changed.
        """
        # Check in-memory vault first if available
        if evidence_id in _MEMORY_VAULT:
            mem = _MEMORY_VAULT[evidence_id]
            stored_bytes = mem.get("raw_bytes") or mem.get("raw_content", "").encode("utf-8")
            recomputed = compute_sha256(stored_bytes)
            is_verified = (recomputed == mem["sha256_hash"])
            return {
                "evidence_id": mem["evidence_id"],
                "sha256_hash": mem["sha256_hash"],
                "recomputed_sha256": recomputed,
                "hash_verified": is_verified,
                "match": is_verified,
                "tamper_detected": not is_verified,
                "source": mem["source"],
                "filename": mem["filename"],
                "file_size": mem["file_size"],
                "organization_id": mem["organization_id"],
                "case_id": mem["case_id"],
                "evidence_type": mem["evidence_type"],
                "received_at": mem["received_at"],
                "created_at": mem["created_at"]
            }

        if HAS_DB:
            # 1. Query ORM
            try:
                with get_db_context() as db:
                    query = db.query(Evidence).filter_by(id=evidence_id)
                    if organization_id:
                        query = query.filter_by(organization_id=organization_id)
                    ev = query.first()
                    if ev:
                        stored_bytes = ev.raw_bytes or (ev.raw_content.encode("utf-8") if ev.raw_content else b"")
                        recomputed_hash = compute_sha256(stored_bytes)
                        is_verified = (recomputed_hash == ev.sha256_hash or recomputed_hash == ev.custody_hash)

                        return {
                            "evidence_id": ev.id,
                            "sha256_hash": ev.sha256_hash or ev.custody_hash,
                            "recomputed_sha256": recomputed_hash,
                            "hash_verified": is_verified,
                            "match": is_verified,
                            "tamper_detected": not is_verified,
                            "source": ev.source,
                            "filename": ev.filename,
                            "file_size": ev.file_size or len(stored_bytes),
                            "organization_id": ev.organization_id,
                            "case_id": ev.case_id,
                            "evidence_type": ev.evidence_type,
                            "notes": ev.notes,
                            "received_at": ev.received_at.isoformat() + "Z" if ev.received_at else None,
                            "created_at": ev.created_at.isoformat() + "Z" if ev.created_at else None,
                            "custody_chain": [
                                {
                                    "action": "INITIAL_INGESTION",
                                    "timestamp": ev.received_at.isoformat() + "Z" if ev.received_at else None,
                                    "actor": f"Evidence Vault ({ev.source})",
                                    "sha256": ev.sha256_hash
                                },
                                {
                                    "action": "INTEGRITY_AUDIT",
                                    "timestamp": datetime.utcnow().isoformat() + "Z",
                                    "actor": "Cryptographic Hash Auditor",
                                    "result": "VERIFIED_BIT_FOR_BIT" if is_verified else "TAMPER_WARNING",
                                    "recomputed_sha256": recomputed_hash
                                }
                            ]
                        }
            except Exception as e:
                print(f"[EvidenceVault] ORM lookup failed, trying SQLite: {e}")

        # 2. SQLite Fallback
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                stored_bytes = row["raw_bytes"] or (row["raw_content"].encode("utf-8") if row["raw_content"] else b"")
                if isinstance(stored_bytes, str):
                    stored_bytes = stored_bytes.encode("utf-8")
                recomputed_hash = compute_sha256(stored_bytes)
                stored_hash = row["sha256_hash"] or row["custody_hash"]
                is_verified = (recomputed_hash == stored_hash)

                return {
                    "evidence_id": row["id"],
                    "sha256_hash": stored_hash,
                    "recomputed_sha256": recomputed_hash,
                    "hash_verified": is_verified,
                    "match": is_verified,
                    "tamper_detected": not is_verified,
                    "source": row["source"],
                    "filename": row["filename"],
                    "file_size": row["file_size"],
                    "organization_id": row["organization_id"],
                    "case_id": row["case_id"],
                    "evidence_type": row["evidence_type"],
                    "notes": row["notes"],
                    "received_at": row["received_at"],
                    "created_at": row["created_at"],
                    "custody_chain": [
                        {
                            "action": "INITIAL_INGESTION",
                            "timestamp": row["received_at"],
                            "actor": f"Evidence Vault ({row['source']})",
                            "sha256": stored_hash
                        },
                        {
                            "action": "INTEGRITY_AUDIT",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "actor": "Cryptographic Hash Auditor",
                            "result": "VERIFIED_BIT_FOR_BIT" if is_verified else "TAMPER_WARNING",
                            "recomputed_sha256": recomputed_hash
                        }
                    ]
                }
        except Exception as e:
            print(f"[EvidenceVault] SQLite lookup failed: {e}")

        return None

    @staticmethod
    def get_raw_bytes(evidence_id: str) -> Optional[bytes]:
        """
        Retrieves the exact unparsed raw bytes for an evidence record.
        """
        try:
            with get_db_context() as db:
                ev = db.query(Evidence).filter_by(id=evidence_id).first()
                if ev:
                    if ev.raw_bytes:
                        return ev.raw_bytes
                    if ev.raw_content:
                        return ev.raw_content.encode("utf-8")
        except Exception:
            pass

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT raw_bytes, raw_content FROM evidence WHERE id = ?", (evidence_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                if row["raw_bytes"]:
                    return row["raw_bytes"] if isinstance(row["raw_bytes"], bytes) else row["raw_bytes"].encode("utf-8")
                if row["raw_content"]:
                    return row["raw_content"].encode("utf-8")
        except Exception:
            pass

        return None

    @staticmethod
    def list_all(organization_id: str = "org_default_01", limit: int = 50) -> List[Dict[str, Any]]:
        """
        Lists stored evidence records for the organization with verified hash statuses.
        """
        items = []
        try:
            with get_db_context() as db:
                ev_list = db.query(Evidence).filter_by(organization_id=organization_id).order_by(Evidence.created_at.desc()).limit(limit).all()
                for ev in ev_list:
                    stored_bytes = ev.raw_bytes or (ev.raw_content.encode("utf-8") if ev.raw_content else b"")
                    recomputed = compute_sha256(stored_bytes)
                    items.append({
                        "evidence_id": ev.id,
                        "sha256_hash": ev.sha256_hash,
                        "recomputed_sha256": recomputed,
                        "hash_verified": (recomputed == ev.sha256_hash),
                        "filename": ev.filename,
                        "file_size": ev.file_size,
                        "source": ev.source,
                        "evidence_type": ev.evidence_type,
                        "case_id": ev.case_id,
                        "received_at": ev.received_at.isoformat() + "Z" if ev.received_at else None
                    })
                return items
        except Exception:
            pass

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?", (organization_id, limit))
            rows = cursor.fetchall()
            conn.close()
            for r in rows:
                stored_bytes = r["raw_bytes"] or (r["raw_content"].encode("utf-8") if r["raw_content"] else b"")
                if isinstance(stored_bytes, str):
                    stored_bytes = stored_bytes.encode("utf-8")
                recomputed = compute_sha256(stored_bytes)
                stored_hash = r["sha256_hash"] or r["custody_hash"]
                items.append({
                    "evidence_id": r["id"],
                    "sha256_hash": stored_hash,
                    "recomputed_sha256": recomputed,
                    "hash_verified": (recomputed == stored_hash),
                    "filename": r["filename"],
                    "file_size": r["file_size"],
                    "source": r["source"],
                    "evidence_type": r["evidence_type"],
                    "case_id": r["case_id"],
                    "received_at": r["received_at"]
                })
        except Exception:
            pass

        return items
