"""
TraceXMail Database Seeder (backend/seed.py)
Seeds default organization ('org_default_01') and default user ('usr_default_01')
along with initial baseline forensic data and parsed sample emails for local development.
"""

import os
import sys
import uuid
import json
from datetime import datetime, timezone

# Ensure project root is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.parser import parse_email_message
from backend.normalizer import normalize_url, normalize_domain, validate_ip
from backend.ioc_extractor import extract_iocs
from backend.evidence_vault import EvidenceVault

from backend.db_session import get_db_context, engine, Base
from backend.models import (
    Organization,
    User,
    Case,
    Email,
    EmailHeader,
    RelayNode,
    URL,
    Attachment,
    AnalysisResult,
    BECResult,
    AttributionResult,
    Campaign,
    Alert
)
from backend.rls_manager import apply_row_level_security
from backend.ioc_extractor import persist_email_artifacts
HAS_SQLALCHEMY = True


def seed_database():
    """
    Initializes tables, applies RLS, seeds default organization, user,
    and populates sample email forensic records into relational tables.
    """
    samples_dir = os.path.join(PROJECT_ROOT, "data", "samples")

    if not HAS_SQLALCHEMY:
        print("[Seed] SQLAlchemy not available in current Python environment. Running in-memory forensic verification parser...")
        if os.path.exists(samples_dir):
            for sample_file in sorted(os.listdir(samples_dir)):
                if not sample_file.endswith(".eml"):
                    continue
                file_path = os.path.join(samples_dir, sample_file)
                with open(file_path, "rb") as f:
                    raw_bytes = f.read()

                vault_rec = EvidenceVault.store_evidence(
                    raw_bytes=raw_bytes,
                    source="email_upload",
                    filename=sample_file,
                    organization_id="org_default_01"
                )

                parsed_data = parse_email_message(raw_bytes, filename=sample_file)
                iocs_data = extract_iocs(parsed_data)

                print(f"[Seed] Parsed & Verified '{sample_file}':")
                print(f"       -> Subject: {parsed_data['subject'][:45]}")
                print(f"       -> Evidence ID: {vault_rec['evidence_id']} (SHA-256: {vault_rec['sha256_hash'][:16]}...)")
                print(f"       -> Hops: {len(parsed_data['received_hops'])} | URLs: {len(iocs_data['urls'])} | Domains: {len(iocs_data['domains'])} | Attachments: {len(iocs_data['attachment_hashes'])}")
                if parsed_data['attachments']:
                    for att in parsed_data['attachments']:
                        print(f"          Attachment: {att['filename']} (SHA-256: {att['sha256'][:16]}...)")
        print("[Seed] In-memory verification completed successfully.")
        return

    # 1. Create all tables
    Base.metadata.create_all(bind=engine)
    print("[Seed] All 19 database tables ensured.")

    # 2. Apply RLS policies
    apply_row_level_security()

    # 3. Seed Default Organization and User
    with get_db_context() as db:
        # Check if default org already exists
        existing_org = db.query(Organization).filter_by(id="org_default_01").first()
        if not existing_org:
            default_org = Organization(
                id="org_default_01",
                name="Acme Cyber Defense SOC",
                slug="acme-soc",
                settings={
                    "default_retention_days": 180,
                    "auto_mitre_mapping": True,
                    "ml_confidence_threshold": 0.85,
                    "alert_channels": ["websocket", "webhook"]
                },
                created_at=datetime.now(timezone.utc)
            )
            db.add(default_org)
            db.flush()
            print("[Seed] Created default organization: Acme Cyber Defense SOC (org_default_01)")
        else:
            default_org = existing_org

        # Check if default user exists
        existing_user = db.query(User).filter_by(id="usr_default_01").first()
        if not existing_user:
            default_user = User(
                id="usr_default_01",
                organization_id=default_org.id,
                email="investigator@acmedefense.internal",
                full_name="Lead Cyber Forensics Investigator",
                role="admin",
                is_active=True,
                created_at=datetime.now(timezone.utc)
            )
            db.add(default_user)
            db.flush()
            print("[Seed] Created default user: Lead Cyber Forensics Investigator (usr_default_01)")

        # Check if default campaign exists
        existing_campaign = db.query(Campaign).filter_by(name="Operation GhostWire Spearphish").first()
        if not existing_campaign:
            sample_campaign = Campaign(
                id="camp_default_01",
                organization_id=default_org.id,
                name="Operation GhostWire Spearphish",
                threat_actor="TA505 / FIN7 Syndicate",
                target_industry="Financial Services & Supply Chain",
                status="ACTIVE",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                total_emails=14,
                notes="Coordinated impersonation and SVG attachment malicious macro lures targeting corporate finance teams."
            )
            db.add(sample_campaign)

        # Seed sample incident case
        existing_case = db.query(Case).filter_by(id="case_default_01").first()
        if not existing_case:
            sample_case = Case(
                id="case_default_01",
                organization_id=default_org.id,
                user_id="usr_default_01",
                title="Critical CEO Wire Transfer Fraud Impersonation",
                description="High-confidence BEC attack with spoofed display name and typo-squatted sender domain requesting immediate wire dispatch.",
                status="INVESTIGATING",
                severity="CRITICAL",
                threat_score=94.5,
                created_at=datetime.now(timezone.utc)
            )
            db.add(sample_case)

        # Seed sample emails from data/samples directory
        if os.path.exists(samples_dir):
            for sample_file in os.listdir(samples_dir):
                if not sample_file.endswith(".eml"):
                    continue
                file_path = os.path.join(samples_dir, sample_file)
                try:
                    with open(file_path, "rb") as f:
                        raw_bytes = f.read()

                    # 1. Check if email already exists before creating new evidence
                    existing_eml = db.query(Email).filter_by(file_name=sample_file).first()
                    if existing_eml:
                        continue

                    # 2. Store in Evidence Vault
                    vault_rec = EvidenceVault.store_evidence(
                        raw_bytes=raw_bytes,
                        source="email_upload",
                        filename=sample_file,
                        organization_id="org_default_01"
                    )

                    # 3. Parse using Python email library
                    parsed_data = parse_email_message(raw_bytes, filename=sample_file)
                    iocs_data = extract_iocs(parsed_data)


                    email_id = f"eml_{sample_file.replace('.eml', '').replace('-', '_')}"
                    email_rec = Email(
                        id=email_id,
                        organization_id="org_default_01",
                        case_id="case_default_01" if "paypal" in sample_file else None,
                        evidence_id=vault_rec["evidence_id"],
                        message_id=parsed_data.get("message_id") or f"<{email_id}@tracexmail.local>",
                        subject=parsed_data.get("subject", "No Subject"),
                        sender=parsed_data.get("from", "Unknown"),
                        recipient=parsed_data.get("to", ""),
                        reply_to=parsed_data.get("reply_to", ""),
                        return_path=parsed_data.get("return_path", ""),
                        date_header=parsed_data.get("date", datetime.now(timezone.utc).isoformat()),
                        body_text=parsed_data.get("body_text", ""),
                        body_html=parsed_data.get("body_html", ""),
                        raw_eml=parsed_data.get("raw_content", ""),
                        file_name=sample_file,
                        file_size=len(raw_bytes),
                        created_at=datetime.now(timezone.utc)
                    )
                    db.add(email_rec)
                    db.flush()

                    # Persist headers, relay hops, urls, attachments
                    persist_email_artifacts(
                        db=db,
                        email_id=email_rec.id,
                        organization_id="org_default_01",
                        parsed_email_data=parsed_data,
                        iocs_data=iocs_data
                    )
                    print(f"[Seed] Parsed & Persisted '{sample_file}' -> ID: {email_id} (Hops: {len(parsed_data['received_hops'])}, URLs: {len(iocs_data['urls'])}, Atts: {len(iocs_data['attachment_hashes'])})")
                except Exception as e:
                    db.rollback()
                    print(f"[Seed] Warning: Failed to seed sample {sample_file}: {e}")

        db.commit()
        print("[Seed] Database successfully seeded with default records and parsed samples.")


if __name__ == "__main__":
    seed_database()
