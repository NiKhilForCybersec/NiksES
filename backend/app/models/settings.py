"""
NiksES Settings Data Models

Pydantic models for application settings and API key management.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class APIService(str, Enum):
    """Supported API services."""
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    URLHAUS = "urlhaus"
    PHISHTANK = "phishtank"
    MXTOOLBOX = "mxtoolbox"
    SHODAN = "shodan"
    GREYNOISE = "greynoise"
    OPENAI = "openai"


class APIKeyStatus(BaseModel):
    """Status of an API key configuration."""
    service: APIService = Field(..., description="Service name")
    service_display_name: str = Field(..., description="Human-readable service name")
    is_configured: bool = Field(..., description="Whether key is configured")
    is_enabled: bool = Field(True, description="Whether service is enabled")
    is_free: bool = Field(False, description="Whether service is free (no key needed)")
    masked_key: Optional[str] = Field(None, description="Masked API key for display")
    last_tested: Optional[datetime] = Field(None)
    last_test_result: Optional[str] = Field(None, description="success, failed, rate_limited")


class APIKeyCreate(BaseModel):
    """Request to create/update an API key."""
    service: APIService = Field(..., description="Service name")
    key: str = Field(..., min_length=1, description="API key value")


class APIKeyTest(BaseModel):
    """Result of API key test."""
    service: APIService
    success: bool
    message: str
    response_time_ms: Optional[int] = None


class SettingValue(BaseModel):
    """Single setting value."""
    key: str = Field(..., description="Setting key")
    value: str = Field(..., description="Setting value")
    value_type: str = Field("string", description="Value type: string, int, float, bool, json")
    category: str = Field("general", description="Setting category")
    description: Optional[str] = Field(None)
    is_secret: bool = Field(False)
    updated_at: Optional[datetime] = None


class SettingsUpdate(BaseModel):
    """Request to update settings."""
    settings: List[SettingValue] = Field(..., description="Settings to update")


class DynamicDetectionConfig(BaseModel):
    """Dynamic configuration for detection rules - user customizable."""
    
    # Custom suspicious TLDs (added to defaults)
    custom_suspicious_tlds: List[str] = Field(
        default_factory=list,
        description="Additional suspicious TLDs to detect (e.g., .lol, .dating)"
    )
    
    # Custom spam keywords
    custom_spam_keywords: List[str] = Field(
        default_factory=list,
        description="Additional spam keywords to detect"
    )
    
    # Custom romance/dating scam keywords
    custom_romance_keywords: List[str] = Field(
        default_factory=list,
        description="Additional romance scam keywords"
    )
    
    # Custom freemail domains
    custom_freemail_domains: List[str] = Field(
        default_factory=list,
        description="Additional freemail domains"
    )
    
    # Whitelisted domains (skip detection)
    whitelisted_domains: List[str] = Field(
        default_factory=list,
        description="Domains to skip in detection"
    )
    
    # Whitelisted sender emails
    whitelisted_senders: List[str] = Field(
        default_factory=list,
        description="Sender emails to whitelist"
    )
    
    # Custom legitimate financial domains (added to defaults)
    custom_financial_domains: List[str] = Field(
        default_factory=list,
        description="Additional legitimate bank/financial domains to whitelist"
    )
    
    # High-risk countries for GeoIP
    high_risk_countries: List[str] = Field(
        default_factory=lambda: ["RU", "CN", "KP", "IR", "NG", "RO", "UA", "BY"],
        description="Country codes considered high risk"
    )
    
    # Risk score thresholds
    risk_threshold_high: int = Field(60, ge=0, le=100)
    risk_threshold_critical: int = Field(80, ge=0, le=100)
    
    # Feature toggles
    enable_geoip: bool = Field(True, description="Enable GeoIP lookups")
    enable_whois: bool = Field(True, description="Enable WHOIS lookups")
    enable_ai_description: bool = Field(True, description="Generate detailed AI description")


class SettingsResponse(BaseModel):
    """Response containing all settings."""
    settings: List[SettingValue] = Field(default_factory=list)
    api_keys: List[APIKeyStatus] = Field(default_factory=list)
    detection_config: Optional[DynamicDetectionConfig] = Field(None)


class AnalysisOptions(BaseModel):
    """Options for analysis request."""
    skip_enrichment: bool = Field(False, description="Skip threat intel enrichment")
    skip_ai: bool = Field(False, description="Skip AI triage")
    skip_geoip: bool = Field(False, description="Skip GeoIP lookup")
    follow_redirects: bool = Field(False, description="Follow URL redirects")
    max_redirect_depth: int = Field(3, ge=0, le=10, description="Max redirect depth")
    generate_ai_description: bool = Field(True, description="Generate detailed AI description")
