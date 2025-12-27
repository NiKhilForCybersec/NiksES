"""
NiksES API Dependencies

FastAPI dependency injection for settings, stores, etc.
"""

import logging
from typing import Optional, Dict, TYPE_CHECKING
from functools import lru_cache

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from app.models.analysis import AnalysisResult

logger = logging.getLogger(__name__)


class Settings(BaseModel):
    """Application settings - all API keys from Railway environment."""
    
    # Feature flags
    enrichment_enabled: bool = True
    ai_enabled: bool = True  # Default to true
    
    # AI Configuration
    ai_provider: str = "openai"  # Default to openai since user has it
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    
    # Threat Intelligence API Keys
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    phishtank_api_key: Optional[str] = None
    mxtoolbox_api_key: Optional[str] = None
    ipqualityscore_api_key: Optional[str] = None
    google_safebrowsing_api_key: Optional[str] = None
    
    # Sandbox API Keys
    hybrid_analysis_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    
    # Storage
    storage_type: str = "memory"  # memory, sqlite, postgres
    database_url: Optional[str] = None
    
    # Limits
    max_file_size_mb: int = 50
    analysis_timeout_seconds: int = 120
    
    class Config:
        # NO env_prefix - read directly from env vars like IPQUALITYSCORE_API_KEY
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields


# Global settings instance
_settings: Optional[Settings] = None


def _load_settings_from_env() -> Settings:
    """Load settings directly from environment variables."""
    import os
    return Settings(
        # Feature flags
        enrichment_enabled=os.getenv("ENRICHMENT_ENABLED", "true").lower() == "true",
        ai_enabled=os.getenv("AI_ENABLED", "true").lower() == "true",
        ai_provider=os.getenv("AI_PROVIDER", "openai"),
        
        # AI Keys
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        
        # TI Keys
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        phishtank_api_key=os.getenv("PHISHTANK_API_KEY"),
        mxtoolbox_api_key=os.getenv("MXTOOLBOX_API_KEY"),
        ipqualityscore_api_key=os.getenv("IPQUALITYSCORE_API_KEY"),
        google_safebrowsing_api_key=os.getenv("GOOGLE_SAFEBROWSING_API_KEY"),
        
        # Sandbox Keys
        hybrid_analysis_api_key=os.getenv("HYBRID_ANALYSIS_API_KEY"),
        urlscan_api_key=os.getenv("URLSCAN_API_KEY"),
        
        # Storage
        storage_type=os.getenv("STORAGE_TYPE", "sqlite"),
        database_url=os.getenv("DATABASE_URL"),
    )


def init_settings(**kwargs) -> Settings:
    """Initialize global settings."""
    global _settings
    _settings = _load_settings_from_env()
    # Override with any provided kwargs
    for key, value in kwargs.items():
        if hasattr(_settings, key):
            setattr(_settings, key, value)
    return _settings


def get_settings() -> Settings:
    """Get current settings, loading from env if not initialized."""
    global _settings
    if _settings is None:
        _settings = _load_settings_from_env()
    return _settings


def get_mutable_settings() -> Settings:
    """Get mutable settings (same as get_settings for in-memory)."""
    return get_settings()


# Analysis store interface
class AnalysisStore:
    """Interface for analysis storage."""
    
    async def save(self, analysis):
        """Save an analysis."""
        raise NotImplementedError
    
    async def get(self, analysis_id: str):
        """Get an analysis by ID."""
        raise NotImplementedError
    
    async def list(self, **kwargs):
        """List analyses with filters."""
        raise NotImplementedError
    
    async def delete(self, analysis_id: str) -> bool:
        """Delete an analysis."""
        raise NotImplementedError
    
    async def get_stats(self, days: int = 7):
        """Get statistics."""
        raise NotImplementedError
    
    async def get_timeline(self, days: int = 7):
        """Get timeline data."""
        raise NotImplementedError


class InMemoryAnalysisStore(AnalysisStore):
    """In-memory analysis storage."""
    
    def __init__(self):
        self._analyses = {}
    
    async def save(self, analysis):
        self._analyses[analysis.analysis_id] = analysis
    
    async def get(self, analysis_id: str):
        return self._analyses.get(analysis_id)
    
    async def list(self, page=1, page_size=20, **kwargs):
        analyses = list(self._analyses.values())
        
        # Sort by date descending
        analyses.sort(key=lambda a: a.analyzed_at, reverse=True)
        
        # Paginate
        start = (page - 1) * page_size
        end = start + page_size
        
        return analyses[start:end], len(analyses)
    
    async def delete(self, analysis_id: str) -> bool:
        if analysis_id in self._analyses:
            del self._analyses[analysis_id]
            return True
        return False
    
    async def get_stats(self, days: int = 7):
        from collections import Counter
        from datetime import datetime, timedelta
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent = [a for a in self._analyses.values() if a.analyzed_at >= cutoff]
        
        risk_dist = Counter(a.detection.risk_level.value for a in recent)
        class_dist = Counter(a.detection.primary_classification.value for a in recent)
        
        avg_score = sum(a.detection.risk_score for a in recent) / len(recent) if recent else 0
        
        return {
            "total_analyses": len(recent),
            "risk_distribution": dict(risk_dist),
            "classification_distribution": dict(class_dist),
            "average_risk_score": round(avg_score, 1),
        }
    
    async def get_timeline(self, days: int = 7):
        from datetime import datetime, timedelta
        from collections import defaultdict
        
        timeline = defaultdict(lambda: {"count": 0, "avg_risk": 0, "scores": []})
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        for analysis in self._analyses.values():
            if analysis.analyzed_at >= cutoff:
                date_key = analysis.analyzed_at.strftime("%Y-%m-%d")
                timeline[date_key]["count"] += 1
                timeline[date_key]["scores"].append(analysis.detection.risk_score)
        
        result = []
        for date_key in sorted(timeline.keys()):
            data = timeline[date_key]
            avg = sum(data["scores"]) / len(data["scores"]) if data["scores"] else 0
            result.append({
                "date": date_key,
                "count": data["count"],
                "average_risk_score": round(avg, 1),
            })
        
        return result


# Global store instance
_analysis_store: Optional[AnalysisStore] = None


def init_analysis_store(store_type: str = "sqlite") -> AnalysisStore:
    """Initialize analysis store."""
    global _analysis_store
    
    if store_type == "sqlite":
        from app.services.storage import get_sqlite_store
        _analysis_store = get_sqlite_store()
        logger.info("Using SQLite analysis store")
    elif store_type == "memory":
        _analysis_store = InMemoryAnalysisStore()
        logger.info("Using in-memory analysis store")
    else:
        _analysis_store = InMemoryAnalysisStore()  # Default to memory
    
    return _analysis_store


def get_analysis_store() -> Optional[AnalysisStore]:
    """Get the analysis store."""
    global _analysis_store
    if _analysis_store is None:
        # Default to SQLite for persistence
        from app.services.storage import get_sqlite_store
        _analysis_store = get_sqlite_store()
    return _analysis_store


# =============================================================================
# SHARED IN-MEMORY CACHE FOR RECENT ANALYSES
# =============================================================================
# This provides immediate access to analyses for export without database round-trip

from app.models.analysis import AnalysisResult

_analysis_cache: Dict[str, 'AnalysisResult'] = {}
_cache_max_size = 100


def cache_analysis(analysis_id: str, analysis: 'AnalysisResult') -> None:
    """Store analysis in the shared cache."""
    global _analysis_cache
    _analysis_cache[analysis_id] = analysis
    
    # Limit cache size
    if len(_analysis_cache) > _cache_max_size:
        oldest_key = next(iter(_analysis_cache))
        del _analysis_cache[oldest_key]
    
    logger.info(f"Cached analysis {analysis_id} (cache size: {len(_analysis_cache)})")


def get_cached_analysis(analysis_id: str) -> Optional['AnalysisResult']:
    """Get analysis from cache."""
    result = _analysis_cache.get(analysis_id)
    if result:
        logger.debug(f"Cache hit for analysis {analysis_id}")
    else:
        logger.debug(f"Cache miss for analysis {analysis_id}")
    return result


def get_cache_size() -> int:
    """Get current cache size."""
    return len(_analysis_cache)
