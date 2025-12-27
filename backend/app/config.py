"""
NiksES Application Configuration

Configuration management using pydantic-settings.
All configuration values are loaded from environment variables (Railway compatible).
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Optional
from functools import lru_cache
import os


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    Railway Deployment:
    - All API keys are read from Railway environment variables
    - Set them in Railway Dashboard > Variables
    
    Values can be set via:
    1. Environment variables (Railway)
    2. .env file (local development)
    3. Default values defined here
    """
    
    # =========================================================================
    # Application
    # =========================================================================
    app_name: str = "NiksES"
    app_version: str = "3.1.0"
    debug: bool = False
    
    # =========================================================================
    # Server
    # =========================================================================
    host: str = "0.0.0.0"
    port: int = Field(default=8000, description="Port - Railway sets PORT env var")
    
    # =========================================================================
    # Database
    # =========================================================================
    database_url: str = "sqlite:///./data/nikses.db"
    
    # =========================================================================
    # Security
    # =========================================================================
    secret_key: str = Field(default="change-me-in-production-use-railway-env", description="Secret key for encryption")
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173", "*"]
    
    # =========================================================================
    # Threat Intelligence API Keys (Set in Railway Dashboard > Variables)
    # =========================================================================
    # URL/Domain Reputation
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key")
    ipqualityscore_api_key: Optional[str] = Field(default=None, description="IPQualityScore API key")
    google_safebrowsing_api_key: Optional[str] = Field(default=None, description="Google Safe Browsing API key")
    phishtank_api_key: Optional[str] = Field(default=None, description="PhishTank API key")
    
    # IP Reputation
    abuseipdb_api_key: Optional[str] = Field(default=None, description="AbuseIPDB API key")
    
    # Email/DNS
    mxtoolbox_api_key: Optional[str] = Field(default=None, description="MXToolbox API key")
    
    # Sandbox Analysis
    hybrid_analysis_api_key: Optional[str] = Field(default=None, description="Hybrid Analysis API key")
    
    # =========================================================================
    # AI Analysis API Keys (Set in Railway Dashboard > Variables)
    # =========================================================================
    anthropic_api_key: Optional[str] = Field(default=None, description="Anthropic Claude API key")
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API key")
    
    # =========================================================================
    # Additional APIs (Optional)
    # =========================================================================
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    greynoise_api_key: Optional[str] = Field(default=None, description="GreyNoise API key")
    
    # =========================================================================
    # Feature Flags
    # =========================================================================
    enable_ai_triage: bool = True
    enable_enrichment: bool = True
    enrichment_enabled: bool = True
    ai_enabled: bool = True
    ai_provider: str = "anthropic"
    follow_redirects: bool = False
    max_redirect_depth: int = 3
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Railway sets PORT environment variable
        railway_port = os.environ.get("PORT")
        if railway_port:
            self.port = int(railway_port)


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Settings are cached to avoid re-reading environment on every access.
    Use get_settings.cache_clear() to reload settings.
    """
    return Settings()
