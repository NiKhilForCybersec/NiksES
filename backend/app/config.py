"""
NiksES Application Configuration

Configuration management using pydantic-settings.
All configuration values are loaded from environment variables.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    Values can be set via:
    1. Environment variables
    2. .env file
    3. Default values defined here
    """
    
    # =========================================================================
    # Application
    # =========================================================================
    app_name: str = "NiksES"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # =========================================================================
    # Server
    # =========================================================================
    host: str = "0.0.0.0"
    port: int = 8000
    
    # =========================================================================
    # Database
    # =========================================================================
    database_url: str = "sqlite:///./data/nikses.db"
    
    # =========================================================================
    # Security
    # =========================================================================
    secret_key: str = Field(..., description="Secret key for encryption - REQUIRED")
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    
    # =========================================================================
    # API Keys (optional - can be set via UI)
    # =========================================================================
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    
    # =========================================================================
    # Feature Flags
    # =========================================================================
    enable_ai_triage: bool = True
    enable_enrichment: bool = True
    follow_redirects: bool = False
    max_redirect_depth: int = 3
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Settings are cached to avoid re-reading environment on every access.
    Use get_settings.cache_clear() to reload settings.
    """
    return Settings()
