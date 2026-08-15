"""Database connection setup, reading configuration from the DATABASE_URL environment variable."""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://forensix:forensix_dev_password@localhost:5432/forensix"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def get_session() -> Session:
    """Return a new database session."""
    return SessionLocal()
