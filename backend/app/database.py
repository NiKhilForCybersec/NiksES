"""
NiksES Database Configuration

SQLite database setup using SQLAlchemy async.
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Float
from typing import AsyncGenerator
import logging

from .config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


# =============================================================================
# DATABASE TABLES
# =============================================================================

class AnalysisRecord(Base):
    """Store complete analysis results."""
    __tablename__ = "analyses"
    
    id = Column(String, primary_key=True)
    created_at = Column(DateTime)
    subject = Column(Text)
    sender_email = Column(String)
    sender_domain = Column(String)
    risk_score = Column(Integer)
    risk_level = Column(String)
    classification = Column(String)
    result_json = Column(Text)
    has_attachments = Column(Boolean, default=False)
    has_urls = Column(Boolean, default=False)
    attachment_count = Column(Integer, default=0)
    url_count = Column(Integer, default=0)
    ai_summary = Column(Text)


class IOCRecord(Base):
    """Store extracted IOCs for correlation."""
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String)
    ioc_type = Column(String)
    ioc_value = Column(Text)
    verdict = Column(String)
    first_seen = Column(DateTime)


class APIKeyRecord(Base):
    """Store encrypted API keys."""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String, unique=True)
    encrypted_key = Column(Text)
    is_enabled = Column(Boolean, default=True)
    last_tested = Column(DateTime)
    last_test_result = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)


class SettingsRecord(Base):
    """Store user settings."""
    __tablename__ = "settings"
    
    key = Column(String, primary_key=True)
    value = Column(Text)
    value_type = Column(String, default="string")
    category = Column(String, default="general")
    description = Column(Text)
    is_secret = Column(Boolean, default=False)
    updated_at = Column(DateTime)


# =============================================================================
# DATABASE ENGINE & SESSION
# =============================================================================

# Engine will be created on first access
_engine = None
_async_session_factory = None


def get_engine():
    """Get or create database engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        # Convert sqlite:/// to sqlite+aiosqlite:///
        db_url = settings.database_url.replace("sqlite:///", "sqlite+aiosqlite:///")
        _engine = create_async_engine(
            db_url,
            echo=settings.debug,
            future=True
        )
    return _engine


def get_session_factory():
    """Get or create session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False
        )
    return _async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that provides database session.
    
    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """
    Initialize database, creating tables if they don't exist.
    
    Call this on application startup.
    """
    logger.info("Initializing database...")
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized successfully")


async def close_db() -> None:
    """
    Close database connections.
    
    Call this on application shutdown.
    """
    global _engine, _async_session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
        logger.info("Database connections closed")
