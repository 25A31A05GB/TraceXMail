"""
TraceXMail Database Module
SQLite persistent storage for forensics cases, threat telemetry, IOCs, and ML metrics.
"""

import sqlite3
import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
import numpy as np

class NumpySafeEncoder(json.JSONEncoder):
    """JSON Encoder that gracefully handles NumPy scalar types and arrays."""
    def default(self, obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if hasattr(obj, "item"):
            return obj.item()
        return super().default(obj)

from backend.db_session import engine, IS_SQLITE, DB_URL

if IS_SQLITE:
    DB_FILE = DB_URL.replace("sqlite:///", "")
    os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)
else:
    DB_FILE = "data/tracexmail.db"


def _reset_corrupted_db():
    """Removes malformed or corrupted SQLite database file and WAL logs."""
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
            print(f"[Database] Successfully removed malformed database file: {DB_FILE}")
        except Exception as e:
            print(f"[Database Error] Could not remove malformed database file: {e}")
    for ext in ["-wal", "-shm", "-journal"]:
        f_path = DB_FILE + ext
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except Exception:
                pass


class PostgresRowAdapter(dict):
    """Allows dict-like and index-like access to database rows."""
    def __init__(self, colnames, values):
        data = dict(zip(colnames, values))
        super().__init__(data)
        self._colnames = colnames
        self._values = list(values)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class PostgresCursorAdapter:
    def __init__(self, cursor):
        self.cursor = cursor
        self.rowcount = getattr(cursor, "rowcount", -1)

    def execute(self, sql: str, params=None):
        converted_sql = sql.replace("?", "%s")
        if "INSERT OR REPLACE INTO" in converted_sql:
            match = re.search(r"INSERT\s+OR\s+REPLACE\s+INTO\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)", converted_sql, re.IGNORECASE)
            if match:
                table_name = match.group(1)
                cols = [c.strip() for c in match.group(2).split(",")]
                pk = cols[0]
                update_cols = [f"{c} = EXCLUDED.{c}" for c in cols if c != pk]
                if update_cols:
                    conflict_clause = f" ON CONFLICT ({pk}) DO UPDATE SET " + ", ".join(update_cols)
                else:
                    conflict_clause = f" ON CONFLICT ({pk}) DO NOTHING"
                converted_sql = re.sub(
                    r"INSERT\s+OR\s+REPLACE\s+INTO",
                    "INSERT INTO",
                    converted_sql,
                    flags=re.IGNORECASE
                ).rstrip().rstrip(";") + conflict_clause

        elif "INSERT OR IGNORE INTO" in converted_sql:
            match = re.search(r"INSERT\s+OR\s+IGNORE\s+INTO\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)", converted_sql, re.IGNORECASE)
            if match:
                cols = [c.strip() for c in match.group(2).split(",")]
                pk = cols[0]
                conflict_clause = f" ON CONFLICT ({pk}) DO NOTHING"
                converted_sql = re.sub(
                    r"INSERT\s+OR\s+IGNORE\s+INTO",
                    "INSERT INTO",
                    converted_sql,
                    flags=re.IGNORECASE
                ).rstrip().rstrip(";") + conflict_clause

        if params is None:
            self.cursor.execute(converted_sql)
        else:
            self.cursor.execute(converted_sql, params)
        self.rowcount = getattr(self.cursor, "rowcount", -1)
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        if hasattr(self.cursor, "description") and self.cursor.description:
            colnames = [col[0] for col in self.cursor.description]
            return PostgresRowAdapter(colnames, row)
        return row

    def fetchall(self):
        rows = self.cursor.fetchall()
        if not rows:
            return []
        if hasattr(self.cursor, "description") and self.cursor.description:
            colnames = [col[0] for col in self.cursor.description]
            return [PostgresRowAdapter(colnames, r) for r in rows]
        return rows


class PostgresConnAdapter:
    def __init__(self, raw_conn):
        self.raw_conn = raw_conn

    def cursor(self):
        return PostgresCursorAdapter(self.raw_conn.cursor())

    def execute(self, sql: str, params=None):
        cursor = self.cursor()
        cursor.execute(sql, params)
        return cursor

    def commit(self):
        self.raw_conn.commit()

    def rollback(self):
        self.raw_conn.rollback()

    def close(self):
        self.raw_conn.close()


def get_db_connection():
    if not IS_SQLITE:
        return PostgresConnAdapter(engine.raw_connection())
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        if IS_SQLITE:
            conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA quick_check;")
        return conn
    except sqlite3.DatabaseError as e:
        print(f"[Database Warning] Malformed SQLite database detected ({e}). Resetting database...")
        _reset_corrupted_db()
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn


def init_db():
    try:
        _do_init_db()
    except sqlite3.DatabaseError as e:
        print(f"[Database Warning] init_db failed due to malformed SQLite database ({e}). Re-creating database...")
        _reset_corrupted_db()
        _do_init_db()


def _do_init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ingested emails table storing raw content & extracted metadata
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id TEXT PRIMARY KEY,
        filename TEXT,
        file_size INTEGER DEFAULT 0,
        subject TEXT,
        from_header TEXT,
        to_header TEXT,
        reply_to TEXT,
        return_path TEXT,
        date_header TEXT,
        message_id TEXT,
        received_headers TEXT,
        body_text TEXT,
        body_html TEXT,
        raw_content TEXT,
        parsed_metadata TEXT,
        threat_verdict TEXT DEFAULT 'PENDING',
        threat_score REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()
         # Safe column migrations for emails table in SQLite
    # (models.Email/SQLAlchemy ORM needs these columns which the hand-written
    # table above lacks — same drift pattern as cases/alerts/evidence below)
    for col_def in [
        ("case_id", "TEXT"),
        ("evidence_id", "TEXT"),
        ("sender", "TEXT"),
        ("recipient", "TEXT"),
        ("raw_eml", "TEXT"),
        ("file_name", "TEXT")
    ]:
        try:
            cursor.execute(f"ALTER TABLE emails ADD COLUMN IF NOT EXISTS {col_def[0]} {col_def[1]}")
            conn.commit()
        except Exception as e:
            conn.rollback()
    # Evidence Vault Table (Immutable Chain of Custody)
    try:
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
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Safe column migrations for evidence table in SQLite
    # (models.Evidence has reference_id which the hand-written table above lacks)
    for col_def in [
        ("reference_id", "TEXT")
    ]:
        try:
            cursor.execute(f"ALTER TABLE evidence ADD COLUMN IF NOT EXISTS {col_def[0]} {col_def[1]}")
            conn.commit()
        except Exception as e:
            conn.rollback()

    # Analyzed emails and forensic campaign cases table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        organization_id TEXT DEFAULT 'org_default_01',
        title TEXT,
        filename TEXT,
        subject TEXT,
        sender TEXT,
        recipient TEXT,
        return_path TEXT,
        date_header TEXT,
        status TEXT DEFAULT 'open',
        severity TEXT DEFAULT 'MEDIUM',
        threat_verdict TEXT DEFAULT 'PENDING',
        threat_score REAL DEFAULT 0.0,
        confidence REAL DEFAULT 0.0,
        spf_status TEXT,
        dkim_status TEXT,
        dmarc_status TEXT,
        hop_count INTEGER DEFAULT 0,
        link_count INTEGER DEFAULT 0,
        suspicious_links INTEGER DEFAULT 0,
        anomalies_detected INTEGER DEFAULT 0,
        analyst_notes TEXT,
        full_analysis_json TEXT,
        tags TEXT DEFAULT '[]',
        analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Safe column migrations for SQLite
    # NOTE: these must stay in sync with backend/models.py's SQLAlchemy `Case`
    # model — Base.metadata.create_all() in seed.py is a no-op for tables that
    # already exist (as this one does, created above), so any ORM-only column
    # added to models.py has to be added here too or ORM queries against this
    # legacy-created table will fail with "no such column".
    for col_def in [
        ("title", "TEXT"),
        ("status", "TEXT DEFAULT 'open'"),
        ("severity", "TEXT DEFAULT 'MEDIUM'"),
        ("filename", "TEXT"),
        ("analyst_notes", "TEXT"),
        ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("user_id", "TEXT"),
        ("description", "TEXT"),
        ("tags", "TEXT DEFAULT '[]'"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    ]:
        try:
            cursor.execute(f"ALTER TABLE cases ADD COLUMN IF NOT EXISTS {col_def[0]} {col_def[1]}")
            conn.commit()
        except Exception as e:
            conn.rollback()

    # Alerts table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        case_id TEXT,
        severity TEXT,
        category TEXT,
        title TEXT,
        description TEXT,
        evidence TEXT,
        channel TEXT DEFAULT 'in_app_websocket',
        delivery_status TEXT DEFAULT 'delivered',
        delivery_details TEXT,
        recipient TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Safe column migrations for alerts table in SQLite
    # (see note above cases' migration list — same drift risk applies here)
    for col_def in [
        ("channel", "TEXT DEFAULT 'in_app_websocket'"),
        ("delivery_status", "TEXT DEFAULT 'delivered'"),
        ("delivery_details", "TEXT"),
        ("recipient", "TEXT"),
        ("status", "TEXT DEFAULT 'OPEN'"),
        ("email_id", "TEXT"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    ]:
        try:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN IF NOT EXISTS {col_def[0]} {col_def[1]}")
            conn.commit()
        except Exception as e:
            conn.rollback()

    # IOCs table (Indicators of Compromise)
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY,
        case_id TEXT,
        ioc_type TEXT,
        ioc_value TEXT,
        threat_level TEXT,
        source TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(case_id) REFERENCES cases(id)
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # ML Training runs table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS ml_runs (
        id TEXT PRIMARY KEY,
        trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        samples_count INTEGER,
        phishing_count INTEGER,
        ham_count INTEGER,
        accuracy REAL,
        precision_score REAL,
        recall_score REAL,
        f1_score REAL,
        model_type TEXT
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Organizations Tenant Settings Table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        pii_masking_enabled BOOLEAN DEFAULT 1,
        retention_days INTEGER DEFAULT 90,
        settings TEXT DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Seed default organization if not exists
    try:
        cursor.execute("""
    INSERT OR IGNORE INTO organizations (id, name, slug, pii_masking_enabled, retention_days, settings)
    VALUES ('org_default_01', 'Default Enterprise SOC', 'default-soc', 1, 90, '{"log_level": "INFO"}');
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on default seed: {e}")
        conn.rollback()

    # Audit Logs Table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT 'org_default_01',
        user_id TEXT,
        actor TEXT,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT,
        details TEXT DEFAULT '{}',
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Retention Jobs Table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS retention_jobs (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT 'org_default_01',
        job_name TEXT NOT NULL,
        retention_days INTEGER DEFAULT 90,
        last_run_at TIMESTAMP,
        records_purged INTEGER DEFAULT 0,
        records_skipped INTEGER DEFAULT 0,
        status TEXT DEFAULT 'IDLE',
        details TEXT DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    # Safe column migrations for retention_jobs table in SQLite
    # (models.RetentionJob has next_run_at which the hand-written table above lacks)
    for col_def in [
        ("next_run_at", "TIMESTAMP")
    ]:
        try:
            cursor.execute(f"ALTER TABLE retention_jobs ADD COLUMN IF NOT EXISTS {col_def[0]} {col_def[1]}")
            conn.commit()
        except Exception as e:
            conn.rollback()

    # Gmail OAuth Connections Table
    try:
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS gmail_connections (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL DEFAULT 'org_default_01',
        email_address TEXT NOT NULL,
        encrypted_access_token TEXT NOT NULL,
        encrypted_refresh_token TEXT,
        token_expiry TIMESTAMP,
        history_id TEXT,
        watch_expiry TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        last_polled_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {e}")
        conn.rollback()

    conn.commit()
    conn.close()



def save_case(case_data: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()

    title = case_data.get("title") or case_data.get("name") or case_data.get("subject", "No Subject")
    status = case_data.get("status", "open")
    severity = case_data.get("severity", "MEDIUM")
    org_id = case_data.get("organization_id", "org_default_01")
    analyst_notes = case_data.get("analyst_notes") or case_data.get("notes") or case_data.get("description", "")

    # Ensure status, title, analyst_notes are in the dictionary for JSON serialization
    case_data["title"] = title
    case_data["status"] = status
    case_data["severity"] = severity
    case_data["organization_id"] = org_id
    case_data["analyst_notes"] = analyst_notes

    cursor.execute("""
    INSERT OR REPLACE INTO cases (
        id, organization_id, title, filename, subject, sender, recipient, return_path, date_header,
        status, severity, threat_verdict, threat_score, confidence, spf_status, dkim_status, dmarc_status,
        hop_count, link_count, suspicious_links, anomalies_detected, analyst_notes, full_analysis_json, tags,
        analyzed_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """, (
        case_data["id"],
        org_id,
        title,
        case_data.get("filename", "email.eml"),
        case_data.get("subject", "No Subject"),
        case_data.get("from", "") or case_data.get("sender", ""),
        case_data.get("to", "") or case_data.get("recipient", ""),
        case_data.get("return_path", ""),
        case_data.get("date", "") or case_data.get("date_header", ""),
        status,
        severity,
        case_data.get("verdict", "UNKNOWN") or case_data.get("threat_verdict", "UNKNOWN"),
        float(case_data.get("threat_score", 0.0) or 0.0),
        float(case_data.get("confidence", 0.0) or 0.0),
        case_data.get("dns_auth", {}).get("spf", {}).get("status", "none") if isinstance(case_data.get("dns_auth"), dict) else "none",
        case_data.get("dns_auth", {}).get("dkim", {}).get("status", "none") if isinstance(case_data.get("dns_auth"), dict) else "none",
        case_data.get("dns_auth", {}).get("dmarc", {}).get("status", "none") if isinstance(case_data.get("dns_auth"), dict) else "none",
        len(case_data.get("hops", [])) if isinstance(case_data.get("hops"), list) else 0,
        len(case_data.get("links", [])) if isinstance(case_data.get("links"), list) else 0,
        len([l for l in case_data.get("links", []) if isinstance(l, dict) and l.get("is_suspicious")]) if isinstance(case_data.get("links"), list) else 0,
        len(case_data.get("anomalies", [])) if isinstance(case_data.get("anomalies"), list) else 0,
        analyst_notes,
        json.dumps(case_data, cls=NumpySafeEncoder),
        json.dumps(case_data.get("tags", []))
    ))

    # Save alerts
    for alert in case_data.get("alerts", []):
        cursor.execute("""
        INSERT OR REPLACE INTO alerts (
            id, case_id, severity, category, title, description, evidence,
            channel, delivery_status, delivery_details, recipient, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            alert.get("id"),
            case_data["id"],
            alert.get("severity", "LOW"),
            alert.get("category", "GENERAL"),
            alert.get("title", ""),
            alert.get("description", ""),
            json.dumps(alert.get("evidence", {}), cls=NumpySafeEncoder),
            alert.get("channel", "in_app_websocket"),
            alert.get("delivery_status", "delivered"),
            json.dumps(alert.get("delivery_details", {}), cls=NumpySafeEncoder) if isinstance(alert.get("delivery_details"), (dict, list)) else alert.get("delivery_details", ""),
            alert.get("recipient", "")
        ))

    # Save IOCs
    for ioc in case_data.get("iocs", []):
        cursor.execute("""
        INSERT OR REPLACE INTO iocs (
            id, case_id, ioc_type, ioc_value, threat_level, source, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ioc.get("id"),
            case_data["id"],
            ioc.get("type", "UNKNOWN"),
            ioc.get("value", ""),
            ioc.get("threat_level", "SUSPICIOUS"),
            ioc.get("source", "Forensic Pipeline"),
            ioc.get("notes", "")
        ))

    conn.commit()
    conn.close()


def delete_case(case_id: str) -> bool:
    """Deletes a case and its linked alerts and IOCs from SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    cursor.execute("DELETE FROM alerts WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM iocs WHERE case_id = ?", (case_id,))
    conn.commit()
    conn.close()
    return True


def update_case(case_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Updates status, analyst_notes, title, severity, threat_score or members of a case.
    """
    existing = get_case_by_id(case_id)
    if not existing:
        return None

    # Merge updates into existing object
    for k, v in updates.items():
        if v is not None:
            existing[k] = v

    if "analyst_notes" in updates and updates["analyst_notes"] is not None:
        existing["analyst_notes"] = updates["analyst_notes"]
        existing["description"] = updates["analyst_notes"]

    if "status" in updates and updates["status"] is not None:
        existing["status"] = updates["status"]

    if "title" in updates and updates["title"] is not None:
        existing["title"] = updates["title"]
        existing["name"] = updates["title"]

    if "name" in updates and updates["name"] is not None:
        existing["title"] = updates["name"]
        existing["name"] = updates["name"]

    existing["updated_at"] = datetime.utcnow().isoformat() + "Z"

    # Save back to SQLite
    save_case(existing)
    return existing


def get_all_cases(limit: int = 50, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("SELECT * FROM cases WHERE organization_id = ? ORDER BY updated_at DESC LIMIT ?", (organization_id, limit))
    else:
        cursor.execute("SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = []
    for row in rows:
        r = dict(row)
        if r.get("tags"):
            try:
                r["tags"] = json.loads(r["tags"])
            except:
                r["tags"] = []
        else:
            r["tags"] = []
        if r.get("full_analysis_json"):
            try:
                full = json.loads(r["full_analysis_json"])
                # Ensure top-level fields match row
                for key in ["status", "severity", "title", "analyst_notes", "organization_id", "analyzed_at", "updated_at", "tags"]:
                    if key in r and r[key] is not None:
                        full[key] = r[key]
                results.append(full)
                continue
            except Exception:
                pass
        results.append(r)
    conn.close()
    return results


def get_case_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    row_dict = dict(row)
    if row_dict.get("tags"):
        try:
            row_dict["tags"] = json.loads(row_dict["tags"])
        except:
            row_dict["tags"] = []
    else:
        row_dict["tags"] = []

    if row_dict.get("full_analysis_json"):
        try:
            full = json.loads(row_dict["full_analysis_json"])
            # Synchronize top-level database columns
            if "status" in row_dict and row_dict["status"]:
                full["status"] = row_dict["status"]
            if "analyst_notes" in row_dict and row_dict["analyst_notes"]:
                full["analyst_notes"] = row_dict["analyst_notes"]
                full["description"] = row_dict["analyst_notes"]
            if "title" in row_dict and row_dict["title"]:
                full["title"] = row_dict["title"]
                full["name"] = row_dict["title"]
            if "severity" in row_dict and row_dict["severity"]:
                full["severity"] = row_dict["severity"]
            if "organization_id" in row_dict and row_dict["organization_id"]:
                full["organization_id"] = row_dict["organization_id"]
            if "updated_at" in row_dict and row_dict["updated_at"]:
                full["updated_at"] = str(row_dict["updated_at"])
            if "tags" in row_dict:
                full["tags"] = row_dict["tags"]
            return full
        except Exception:
            pass
    return row_dict


def save_ingested_email(email_record: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO emails (
        id, filename, file_size, subject, from_header, to_header, reply_to, return_path,
        date_header, message_id, received_headers, body_text, body_html, raw_content,
        parsed_metadata, threat_verdict, threat_score, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_record["id"],
        email_record.get("filename", "unknown.eml"),
        email_record.get("file_size", 0),
        email_record.get("subject", "(No Subject)"),
        email_record.get("from_header", ""),
        email_record.get("to_header", ""),
        email_record.get("reply_to", ""),
        email_record.get("return_path", ""),
        email_record.get("date_header", ""),
        email_record.get("message_id", ""),
        json.dumps(email_record.get("received_headers", [])),
        email_record.get("body_text", ""),
        email_record.get("body_html", ""),
        email_record.get("raw_content", ""),
        json.dumps(email_record.get("parsed_metadata", {})),
        email_record.get("threat_verdict", "PENDING"),
        email_record.get("threat_score", 0.0),
        email_record.get("created_at", datetime.utcnow().isoformat() + "Z")
    ))
    conn.commit()
    conn.close()


def get_all_ingested_emails(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, file_size, subject, from_header, to_header, date_header, threat_verdict, threat_score, created_at FROM emails ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results


def get_ingested_email_by_id(email_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        res = dict(row)
        if res.get("received_headers"):
            try:
                res["received_headers"] = json.loads(res["received_headers"])
            except Exception:
                pass
        if res.get("parsed_metadata"):
            try:
                res["parsed_metadata"] = json.loads(res["parsed_metadata"])
            except Exception:
                pass
        return res
    return None


def get_recent_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT a.*, c.subject as case_subject, c.sender as case_sender
    FROM alerts a
    LEFT JOIN cases c ON a.case_id = c.id
    ORDER BY a.timestamp DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results


def save_alert_record(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Saves or logs an alert dispatch attempt with delivery channel and status to SQLite.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    alert_id = alert.get("id") or f"ALT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    case_id = alert.get("case_id") or alert.get("email_id")
    severity = (alert.get("severity") or "HIGH").upper()
    category = alert.get("category") or "SECURITY_ALERT"
    title = alert.get("title") or "High Risk Phishing Email Detected"
    description = alert.get("description") or ""
    evidence = alert.get("evidence", {})
    channel = alert.get("channel") or "multi_channel"
    delivery_status = alert.get("delivery_status") or "delivered"
    delivery_details = alert.get("delivery_details") or {}
    recipient = alert.get("recipient") or ""
    timestamp = alert.get("timestamp") or (datetime.utcnow().isoformat() + "Z")

    cursor.execute("""
    INSERT OR REPLACE INTO alerts (
        id, case_id, severity, category, title, description, evidence,
        channel, delivery_status, delivery_details, recipient, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        case_id,
        severity,
        category,
        title,
        description,
        json.dumps(evidence) if isinstance(evidence, (dict, list)) else str(evidence),
        channel,
        delivery_status,
        json.dumps(delivery_details) if isinstance(delivery_details, (dict, list)) else str(delivery_details),
        recipient,
        timestamp
    ))

    conn.commit()
    conn.close()
    return {
        "id": alert_id,
        "case_id": case_id,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "channel": channel,
        "delivery_status": delivery_status,
        "delivery_details": delivery_details,
        "recipient": recipient,
        "timestamp": timestamp
    }


def get_organization_settings(org_id: str = "org_default_01") -> Dict[str, Any]:
    """
    Retrieves organization settings including pii_masking_enabled and retention_days.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, name, slug, pii_masking_enabled, retention_days, settings, created_at, updated_at
    FROM organizations
    WHERE id = ? OR slug = ?
    LIMIT 1
    """, (org_id, org_id))
    row = cursor.fetchone()
    conn.close()

    if row:
        settings_dict = {}
        if row["settings"]:
            try:
                settings_dict = json.loads(row["settings"]) if isinstance(row["settings"], str) else row["settings"]
            except Exception:
                pass
        return {
            "id": row["id"],
            "name": row["name"],
            "slug": row["slug"],
            "pii_masking_enabled": bool(row["pii_masking_enabled"]),
            "retention_days": int(row["retention_days"] or 90),
            "settings": settings_dict,
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"])
        }

    return {
        "id": org_id,
        "name": "Default Enterprise SOC",
        "slug": "default-soc",
        "pii_masking_enabled": True,
        "retention_days": 90,
        "settings": {"log_level": "INFO"},
        "created_at": datetime.utcnow().isoformat() + "Z",
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }


def update_organization_settings(org_id: str = "org_default_01", updates: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Updates organization compliance configuration (pii_masking_enabled, retention_days, etc.).
    """
    if updates is None:
        updates = {}

    current = get_organization_settings(org_id)
    new_pii = updates.get("pii_masking_enabled", current["pii_masking_enabled"])
    new_retention = updates.get("retention_days", current["retention_days"])
    new_name = updates.get("name", current["name"])
    new_settings = updates.get("settings", current["settings"])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO organizations (id, name, slug, pii_masking_enabled, retention_days, settings, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        pii_masking_enabled = excluded.pii_masking_enabled,
        retention_days = excluded.retention_days,
        settings = excluded.settings,
        updated_at = CURRENT_TIMESTAMP
    """, (
        org_id,
        new_name,
        current["slug"],
        1 if new_pii else 0,
        int(new_retention),
        json.dumps(new_settings) if isinstance(new_settings, dict) else str(new_settings)
    ))
    conn.commit()
    conn.close()

    return get_organization_settings(org_id)


def save_gmail_connection(conn_data: Dict[str, Any]) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO gmail_connections (
        id, organization_id, email_address, encrypted_access_token, encrypted_refresh_token,
        token_expiry, history_id, watch_expiry, is_active, last_polled_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET
        email_address = excluded.email_address,
        encrypted_access_token = excluded.encrypted_access_token,
        encrypted_refresh_token = COALESCE(excluded.encrypted_refresh_token, gmail_connections.encrypted_refresh_token),
        token_expiry = excluded.token_expiry,
        history_id = COALESCE(excluded.history_id, gmail_connections.history_id),
        watch_expiry = excluded.watch_expiry,
        is_active = excluded.is_active,
        last_polled_at = excluded.last_polled_at,
        updated_at = CURRENT_TIMESTAMP
    """, (
        conn_data["id"],
        conn_data.get("organization_id", "org_default_01"),
        conn_data["email_address"],
        conn_data["encrypted_access_token"],
        conn_data.get("encrypted_refresh_token"),
        conn_data.get("token_expiry"),
        conn_data.get("history_id"),
        conn_data.get("watch_expiry"),
        1 if conn_data.get("is_active", True) else 0,
        conn_data.get("last_polled_at")
    ))
    conn.commit()
    conn.close()
    return conn_data



def gmail_message_exists(
    message_id: str,
    organization_id: str = "org_default_01"
) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    filename = f"gmail_{message_id}.eml"
    cursor.execute("""
        SELECT 1
        FROM cases
        WHERE filename = ?
          AND organization_id = ?
        LIMIT 1
    """, (filename, organization_id))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def get_gmail_connection_by_org(organization_id: str = "org_default_01") -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM gmail_connections
    WHERE organization_id = ? AND is_active = TRUE
    ORDER BY updated_at DESC LIMIT 1
    """, (organization_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def get_active_gmail_connections() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM gmail_connections WHERE is_active = TRUE
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def delete_gmail_connection(organization_id: str = "org_default_01") -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    DELETE FROM gmail_connections WHERE organization_id = ?
    """, (organization_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted
