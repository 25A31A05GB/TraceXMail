"""
TraceXMail Relational Database Schema Models (SQLAlchemy ORM)
Full schema containing 19 tables with multi-tenant organization isolation (organization_id).
Compatible with Supabase PostgreSQL (with Row Level Security) and local SQLite fallback.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    Index,
    LargeBinary
)
from sqlalchemy.orm import relationship
from backend.db_session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


# ==========================================
# 1. ORGANIZATIONS (Tenant Root)
# ==========================================
class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    pii_masking_enabled = Column(Boolean, default=True)  # Enterprise PII masking toggle
    retention_days = Column(Integer, default=90)  # Organization data retention window
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    cases = relationship("Case", back_populates="organization", cascade="all, delete-orphan")
    campaigns = relationship("Campaign", back_populates="organization", cascade="all, delete-orphan")


# ==========================================
# 2. USERS (SOC Analysts & Investigators)
# ==========================================
class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="analyst")  # admin, senior_analyst, analyst, auditor
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    assigned_cases = relationship("Case", back_populates="assigned_user")


# ==========================================
# 3. CASES (Forensic Investigations)
# ==========================================
class Case(Base):
    __tablename__ = "cases"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list, nullable=True)
    status = Column(String(50), default="OPEN", index=True)  # OPEN, INVESTIGATING, ESCALATED, CLOSED
    severity = Column(String(50), default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    threat_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="cases")
    assigned_user = relationship("User", back_populates="assigned_cases")
    emails = relationship("Email", back_populates="case")
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="case")


# ==========================================
# 4. EMAILS (Raw & Normalized Messages)
# ==========================================
class Email(Base):
    __tablename__ = "emails"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(String(64), nullable=True, index=True)
    message_id = Column(String(512), nullable=True, index=True)
    subject = Column(String(1000), nullable=True)
    sender = Column(String(512), nullable=True, index=True)
    recipient = Column(String(512), nullable=True, index=True)
    reply_to = Column(String(512), nullable=True)
    return_path = Column(String(512), nullable=True)
    date_header = Column(String(255), nullable=True)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    raw_eml = Column(Text, nullable=True)
    file_name = Column(String(255), nullable=True)
    file_size = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="emails")
    headers = relationship("EmailHeader", back_populates="email", cascade="all, delete-orphan")
    relay_nodes = relationship("RelayNode", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("URL", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResult", back_populates="email", cascade="all, delete-orphan")
    bec_results = relationship("BECResult", back_populates="email", cascade="all, delete-orphan")
    attribution_results = relationship("AttributionResult", back_populates="email", cascade="all, delete-orphan")


# ==========================================
# 5. EMAIL_HEADERS (RFC 5322 Headers)
# ==========================================
class EmailHeader(Base):
    __tablename__ = "email_headers"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    value = Column(Text, nullable=False)
    order_index = Column(Integer, default=0)

    # Relationships
    email = relationship("Email", back_populates="headers")


# ==========================================
# 6. RELAY_NODES (MTA Hop Traceroute)
# ==========================================
class RelayNode(Base):
    __tablename__ = "relay_nodes"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    hop_number = Column(Integer, nullable=False)
    ip_address = Column(String(128), nullable=True, index=True)
    hostname = Column(String(512), nullable=True)
    by_host = Column(String(512), nullable=True)
    protocol = Column(String(100), default="ESMTPS")
    delay_seconds = Column(Float, default=0.0)
    timestamp = Column(DateTime, nullable=True)
    raw_line = Column(Text, nullable=True)
    auth_results = Column(JSON, default=dict)
    is_suspicious = Column(Boolean, default=False)

    # Relationships
    email = relationship("Email", back_populates="relay_nodes")


# ==========================================
# 7. URLS (Extracted Links & Redirects)
# ==========================================
class URL(Base):
    __tablename__ = "urls"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    raw_url = Column(Text, nullable=False)
    canonical_url = Column(Text, nullable=True)
    domain = Column(String(512), nullable=True, index=True)
    scheme = Column(String(20), default="https")
    is_defanged = Column(Boolean, default=False)
    reputation_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    resolved_ip = Column(String(128), nullable=True)

    # Relationships
    email = relationship("Email", back_populates="urls")


# ==========================================
# 8. ATTACHMENTS (File Artifacts & Hashes)
# ==========================================
class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)
    mime_type = Column(String(255), nullable=True)
    sha256 = Column(String(64), nullable=True, index=True)
    md5 = Column(String(32), nullable=True)
    is_suspicious = Column(Boolean, default=False)
    verdict = Column(String(50), default="CLEAN")

    # Relationships
    email = relationship("Email", back_populates="attachments")


# ==========================================
# 9. IP_INTELLIGENCE (Geo & Threat Intel)
# ==========================================
class IPIntelligence(Base):
    __tablename__ = "ip_intelligence"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address = Column(String(128), nullable=False, index=True)
    country_code = Column(String(10), nullable=True)
    city = Column(String(255), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    abuse_score = Column(Float, default=0.0)
    is_vpn_tor = Column(Boolean, default=False)
    last_queried = Column(DateTime, default=datetime.utcnow)


# ==========================================
# 10. DOMAIN_INTELLIGENCE (RDAP / WHOIS / DNS)
# ==========================================
class DomainIntelligence(Base):
    __tablename__ = "domain_intelligence"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    domain_name = Column(String(512), nullable=False, index=True)
    registrar = Column(String(255), nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    domain_age_days = Column(Integer, default=0)
    is_typosquat = Column(Boolean, default=False)
    dmarc_record = Column(Text, nullable=True)
    spf_record = Column(Text, nullable=True)
    dkim_record = Column(Text, nullable=True)


# ==========================================
# 10b. IOC_CACHE (Intelligence API Cache & Circuit Breaker)
# ==========================================
class IOCCache(Base):
    __tablename__ = "ioc_cache"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True, default="org_default_01")
    source = Column(String(64), nullable=False, index=True)  # virustotal, abuseipdb, rdap, dns, etc.
    lookup_key = Column(String(512), nullable=False, index=True)  # IP, Domain, Hash, URL
    result_json = Column(JSON, default=dict)
    checked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    status = Column(String(50), default="ok", index=True)  # ok, api_error, rate_limited, circuit_open


# ==========================================
# 11. ANALYSIS_RESULTS (Forensic Engine Output)
# ==========================================
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    verdict = Column(String(50), default="SUSPICIOUS")
    overall_risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    ml_score = Column(Float, default=0.0)
    rules_score = Column(Float, default=0.0)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    email = relationship("Email", back_populates="analysis_results")


# ==========================================
# 12. BEC_RESULTS (Business Email Compromise)
# ==========================================
class BECResult(Base):
    __tablename__ = "bec_results"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    impersonation_target = Column(String(255), nullable=True)
    display_name_spoof = Column(Boolean, default=False)
    lookalike_domain_score = Column(Float, default=0.0)
    urgency_score = Column(Float, default=0.0)
    financial_lure_detected = Column(Boolean, default=False)
    risk_level = Column(String(50), default="LOW")

    # Relationships
    email = relationship("Email", back_populates="bec_results")


# ==========================================
# 13. ATTRIBUTION_RESULTS (Threat Actor Clues)
# ==========================================
class AttributionResult(Base):
    __tablename__ = "attribution_results"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_actor_name = Column(String(255), nullable=True, index=True)
    campaign_name = Column(String(255), nullable=True, index=True)
    mitre_tactics = Column(JSON, default=list)
    ioc_overlap_count = Column(Integer, default=0)
    confidence_score = Column(Float, default=0.0)

    # Relationships
    email = relationship("Email", back_populates="attribution_results")


# ==========================================
# 14. CAMPAIGNS (Coordinated Phishing Clusters)
# ==========================================
class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    threat_actor = Column(String(255), nullable=True)
    target_industry = Column(String(255), nullable=True)
    status = Column(String(50), default="ACTIVE", index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    total_emails = Column(Integer, default=1)
    notes = Column(Text, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="campaigns")
    relationships = relationship("CampaignRelationship", back_populates="campaign", cascade="all, delete-orphan")


# ==========================================
# 15. CAMPAIGN_RELATIONSHIPS (Cluster Links)
# ==========================================
class CampaignRelationship(Base):
    __tablename__ = "campaign_relationships"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    campaign_id = Column(String(64), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_strength = Column(String(32), default="STRONG", index=True)  # STRONG, MEDIUM, WEAK
    similarity_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    is_auto_merged = Column(Boolean, default=False)
    shared_evidence = Column(JSON, default=list)
    linked_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    campaign = relationship("Campaign", back_populates="relationships")


# ==========================================
# 16. EVIDENCE (Chain of Custody & Hashes)
# ==========================================
class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True, default="org_default_01")
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_type = Column(String(100), nullable=False, default="RAW_EML")  # RAW_EML, PCAP, SCREENSHOT, MEMORY_DUMP
    source = Column(String(100), nullable=False, default="email_upload")  # email_upload, api, forwarded, gateway_webhook
    reference_id = Column(String(255), nullable=True)
    filename = Column(String(255), nullable=True)
    file_size = Column(Integer, default=0)
    raw_bytes = Column(LargeBinary, nullable=True)
    raw_content = Column(Text, nullable=True)
    custody_hash = Column(String(64), nullable=False, index=True)
    sha256_hash = Column(String(64), nullable=False, index=True)
    notes = Column(Text, nullable=True)
    received_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="evidence_items")


# ==========================================
# 17. AUDIT_LOGS (SOC Operations Audit Trail)
# ==========================================
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False)  # INGEST, CASE_CREATE, CASE_STATUS_UPDATE, EVIDENCE_ACCESS, REPORT_EXPORT, REVEAL_PII, RETENTION_CLEANUP
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ==========================================
# 18. ALERTS (Security Operations Incident Alerts)
# ==========================================
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(String(64), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    email_id = Column(String(64), ForeignKey("emails.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), default="HIGH", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status = Column(String(50), default="NEW")  # NEW, ACKNOWLEDGED, RESOLVED
    category = Column(String(100), default="THREAT_DETECTION")
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    case = relationship("Case", back_populates="alerts")


# ==========================================
# 19. RETENTION_JOBS (Compliance & Data Purge)
# ==========================================
class RetentionJob(Base):
    __tablename__ = "retention_jobs"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    job_name = Column(String(255), nullable=False)
    retention_days = Column(Integer, default=90)
    last_run_at = Column(DateTime, nullable=True)
    records_purged = Column(Integer, default=0)
    records_skipped = Column(Integer, default=0)
    status = Column(String(50), default="IDLE")
    details = Column(JSON, default=dict)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ==========================================
# 20. GMAIL_CONNECTIONS (OAuth Real-time Mailbox Integration)
# ==========================================
class GmailConnection(Base):
    __tablename__ = "gmail_connections"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    organization_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True, default="org_default_01")
    email_address = Column(String(255), nullable=False, index=True)
    encrypted_access_token = Column(Text, nullable=False)
    encrypted_refresh_token = Column(Text, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    history_id = Column(String(128), nullable=True)
    watch_expiry = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    last_polled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
