"""
TraceXMail Database Engine & Session Configuration
Supports Supabase Postgres via DATABASE_URL / SUPABASE_DB_URL, with local SQLite fallback.
Handles Tenant Organization Context for Row Level Security (RLS).
"""

import os
from typing import Optional
from contextlib import contextmanager
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

def is_valid_db_url(url: Optional[str]) -> bool:
    if not url:
        return False
    if "[YOUR-" in url or "YOUR-PASSWORD" in url or "YOUR-PROJECT" in url:
        return False
    return url.startswith("postgres") or url.startswith("sqlite")

# 1. Resolve Database Connection String
# Priority: DATABASE_URL -> SUPABASE_DB_URL -> Local SQLite fallback
db_url = os.getenv("DATABASE_URL")
if not is_valid_db_url(db_url):
    db_url = os.getenv("SUPABASE_DB_URL")
    if not is_valid_db_url(db_url):
        db_url = "sqlite:///data/tracexmail.db"

RAW_DB_URL = db_url

# Convert postgres:// to postgresql:// for SQLAlchemy compatibility if needed
if RAW_DB_URL.startswith("postgres://"):
    DB_URL = RAW_DB_URL.replace("postgres://", "postgresql://", 1)
else:
    DB_URL = RAW_DB_URL

IS_SQLITE = DB_URL.startswith("sqlite")

# Ensure local data directory exists if SQLite is used
if IS_SQLITE:
    db_file_path = DB_URL.replace("sqlite:///", "")
    dir_name = os.path.dirname(db_file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    
    engine = create_engine(
        DB_URL,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True
    )
else:
    # Postgres / Supabase connection pooling
    engine = create_engine(
        DB_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    FastAPI dependency that yields a database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Standard context manager for background tasks and scripts.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def set_tenant_context(session: Session, organization_id: str, is_admin: bool = False):
    """
    Sets the current session tenant context for PostgreSQL Row Level Security (RLS).
    Executes 'SET LOCAL app.current_organization_id = ...'
    """
    if not IS_SQLITE:
        try:
            session.execute(
                text("SET LOCAL app.current_organization_id = :org_id"),
                {"org_id": organization_id}
            )
            session.execute(
                text("SET LOCAL app.is_admin = :is_admin"),
                {"is_admin": "true" if is_admin else "false"}
            )
        except Exception as e:
            # Non-blocking if setting fails on certain dev engines
            pass
