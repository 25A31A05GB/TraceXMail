# Database session and connection manager
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tracexmail.db")
