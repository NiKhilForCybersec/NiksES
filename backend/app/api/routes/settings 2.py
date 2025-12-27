"""
NiksES Settings API Routes

API configuration and settings management.
"""

import logging
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.api.dependencies import get_settings, get_mutable_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["settings"])


class APIKeyConfig(BaseModel):
    """API key configuration."""
    virustotal_api_key: Optional[str] = Field(None, description="VirusTotal API key")
    abuseipdb_api_key: Optional[str] = Field(None, description="AbuseIPDB API key")
    phishtank_api_key: Optional[str] = Field(None, description="PhishTank API key")
    mxtoolbox_api_key: Optional[str] = Field(None, description="MXToolbox API key")
    ipqualityscore_api_key: Optional[str] = Field(None, description="IPQualityScore API key")
    google_safebrowsing_api_key: Optional[str] = Field(None, description="Google Safe Browsing API key")
    anthropic_api_key: Optional[str] = Field(None, description="Anthropic API key")
    openai_api_key: Optional[str] = Field(None, description="OpenAI API key")
    hybrid_analysis_api_key: Optional[str] = Field(None, description="Hybrid Analysis API key")


class SettingsUpdate(BaseModel):
    """Settings update request."""
    enable_enrichment: Optional[bool] = None
    enable_ai: Optional[bool] = None
    ai_provider: Optional[str] = None
    api_keys: Optional[APIKeyConfig] = None


class SettingsResponse(BaseModel):
    """Settings response."""
    enrichment_enabled: bool
    ai_enabled: bool
    ai_provider: str
    api_keys_configured: Dict[str, bool]
    detection_rules_count: int


@router.get("", response_model=SettingsResponse)
async def get_current_settings(
    settings = Depends(get_settings),
):
    """
    Get current API settings.
    
    Returns:
        Current configuration (without sensitive values)
    """
    # Get detection rules count
    try:
        from app.services.detection import get_detection_engine
        engine = get_detection_engine()
        rules_count = len(engine.rules)
    except:
        rules_count = 0
    
    # Check which API keys are configured
    api_keys_configured = {
        "virustotal": bool(settings.virustotal_api_key if settings else False),
        "abuseipdb": bool(settings.abuseipdb_api_key if settings else False),
        "phishtank": bool(settings.phishtank_api_key if settings else False),
        "mxtoolbox": bool(getattr(settings, 'mxtoolbox_api_key', None) if settings else False),
        "ipqualityscore": bool(getattr(settings, 'ipqualityscore_api_key', None) if settings else False),
        "google_safebrowsing": bool(getattr(settings, 'google_safebrowsing_api_key', None) if settings else False),
        "urlscan": bool(getattr(settings, 'urlscan_api_key', None) if settings else False),
        "anthropic": bool(settings.anthropic_api_key if settings else False),
        "openai": bool(settings.openai_api_key if settings else False),
        "hybrid_analysis": bool(getattr(settings, 'hybrid_analysis_api_key', None) if settings else False),
    }
    
    return SettingsResponse(
        enrichment_enabled=settings.enrichment_enabled if settings else True,
        ai_enabled=settings.ai_enabled if settings else False,
        ai_provider=settings.ai_provider if settings else "anthropic",
        api_keys_configured=api_keys_configured,
        detection_rules_count=rules_count,
    )


@router.patch("")
async def update_settings(
    updates: SettingsUpdate,
    settings = Depends(get_mutable_settings),
):
    """
    Update API settings.
    
    Allows updating:
    - Feature toggles (enrichment, AI)
    - AI provider preference
    - API keys
    
    Returns:
        Updated settings
    """
    if not settings:
        raise HTTPException(status_code=500, detail="Settings not available")
    
    # Apply updates
    if updates.enable_enrichment is not None:
        settings.enrichment_enabled = updates.enable_enrichment
    
    if updates.enable_ai is not None:
        settings.ai_enabled = updates.enable_ai
    
    if updates.ai_provider is not None:
        if updates.ai_provider not in ["anthropic", "openai"]:
            raise HTTPException(status_code=400, detail="Invalid AI provider")
        settings.ai_provider = updates.ai_provider
    
    if updates.api_keys:
        if updates.api_keys.virustotal_api_key:
            settings.virustotal_api_key = updates.api_keys.virustotal_api_key
        if updates.api_keys.abuseipdb_api_key:
            settings.abuseipdb_api_key = updates.api_keys.abuseipdb_api_key
        if updates.api_keys.phishtank_api_key:
            settings.phishtank_api_key = updates.api_keys.phishtank_api_key
        if updates.api_keys.mxtoolbox_api_key:
            settings.mxtoolbox_api_key = updates.api_keys.mxtoolbox_api_key
        if updates.api_keys.ipqualityscore_api_key:
            settings.ipqualityscore_api_key = updates.api_keys.ipqualityscore_api_key
        if updates.api_keys.google_safebrowsing_api_key:
            settings.google_safebrowsing_api_key = updates.api_keys.google_safebrowsing_api_key
        if updates.api_keys.anthropic_api_key:
            settings.anthropic_api_key = updates.api_keys.anthropic_api_key
            # Reinitialize AI analyzer
            _reinit_ai(settings)
        if updates.api_keys.openai_api_key:
            settings.openai_api_key = updates.api_keys.openai_api_key
            _reinit_ai(settings)
        if updates.api_keys.hybrid_analysis_api_key:
            settings.hybrid_analysis_api_key = updates.api_keys.hybrid_analysis_api_key
            # Configure sandbox service with new key
            try:
                from app.services.hybrid_analysis import get_sandbox_service
                sandbox = get_sandbox_service()
                sandbox.configure(api_key=updates.api_keys.hybrid_analysis_api_key, enabled=True)
            except Exception as e:
                logger.warning(f"Failed to configure sandbox service: {e}")
    
    return {"message": "Settings updated", "success": True}


@router.get("/providers")
async def get_provider_status(
    settings = Depends(get_settings),
):
    """
    Get status of all providers (enrichment, AI).
    
    Returns:
        Provider configuration status
    """
    # Enrichment providers
    enrichment_status = {}
    try:
        from app.services.enrichment import get_enrichment_orchestrator
        orchestrator = get_enrichment_orchestrator()
        enrichment_status = orchestrator.get_provider_status()
    except Exception as e:
        enrichment_status = {"error": str(e)}
    
    # AI providers
    ai_status = {}
    try:
        from app.services.ai import get_ai_analyzer
        analyzer = get_ai_analyzer()
        if analyzer:
            for name in ["anthropic", "openai"]:
                provider = analyzer.get_provider(name)
                if provider:
                    ai_status[name] = {
                        "configured": provider.is_configured(),
                        "model": provider.model,
                    }
    except Exception as e:
        ai_status = {"error": str(e)}
    
    return {
        "enrichment": enrichment_status,
        "ai": ai_status,
    }


@router.post("/test-connection/{provider}")
async def test_provider_connection(
    provider: str,
    settings = Depends(get_settings),
):
    """
    Test connection to a specific provider.
    
    Returns:
        Connection test result
    """
    if provider in ["anthropic", "openai"]:
        try:
            from app.services.ai import get_ai_analyzer
            analyzer = get_ai_analyzer()
            if not analyzer:
                return {"provider": provider, "success": False, "error": "AI not configured"}
            
            prov = analyzer.get_provider(provider)
            if not prov:
                return {"provider": provider, "success": False, "error": "Provider not found"}
            
            success = await prov.test_connection()
            return {"provider": provider, "success": success}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    elif provider == "virustotal":
        try:
            api_key = settings.virustotal_api_key
            if not api_key:
                return {"provider": provider, "success": False, "error": "API key not configured"}
            
            # Test the API with a simple request
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                    headers={"x-apikey": api_key}
                )
                if response.status_code == 200:
                    return {"provider": provider, "success": True, "message": "API key valid"}
                elif response.status_code == 401:
                    return {"provider": provider, "success": False, "error": "Invalid API key"}
                else:
                    return {"provider": provider, "success": False, "error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    elif provider == "abuseipdb":
        try:
            api_key = settings.abuseipdb_api_key
            if not api_key:
                return {"provider": provider, "success": False, "error": "API key not configured"}
            
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": "8.8.8.8"},
                    headers={"Key": api_key, "Accept": "application/json"}
                )
                if response.status_code == 200:
                    return {"provider": provider, "success": True, "message": "API key valid"}
                elif response.status_code == 401:
                    return {"provider": provider, "success": False, "error": "Invalid API key"}
                else:
                    return {"provider": provider, "success": False, "error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    elif provider == "mxtoolbox":
        try:
            api_key = settings.mxtoolbox_api_key if hasattr(settings, 'mxtoolbox_api_key') else None
            if not api_key:
                return {"provider": provider, "success": False, "error": "API key not configured"}
            
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    "https://mxtoolbox.com/api/v1/lookup/dns/google.com",
                    headers={"Authorization": api_key}
                )
                if response.status_code == 200:
                    return {"provider": provider, "success": True, "message": "API key valid"}
                elif response.status_code == 401:
                    return {"provider": provider, "success": False, "error": "Invalid API key"}
                else:
                    return {"provider": provider, "success": False, "error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    elif provider == "urlhaus":
        # URLhaus doesn't require an API key
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get("https://urlhaus-api.abuse.ch/v1/")
                if response.status_code == 200:
                    return {"provider": provider, "success": True, "message": "URLhaus API accessible (no key required)"}
                else:
                    return {"provider": provider, "success": False, "error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    elif provider == "phishtank":
        # PhishTank has optional API key
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get("https://checkurl.phishtank.com/checkurl/")
                # PhishTank returns 200 for the base endpoint
                return {"provider": provider, "success": True, "message": "PhishTank API accessible"}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    elif provider == "hybrid_analysis":
        try:
            api_key = getattr(settings, 'hybrid_analysis_api_key', None)
            if not api_key:
                return {"provider": provider, "success": False, "error": "API key not configured"}
            
            import httpx
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                response = await client.get(
                    "https://hybrid-analysis.com/api/v2/key/current",
                    headers={
                        "api-key": api_key,
                        "User-Agent": "Falcon Sandbox"
                    }
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "provider": provider, 
                        "success": True, 
                        "message": f"API key valid. Limits: {data.get('api_key_data', {}).get('submission_limit', 'N/A')} submissions/month"
                    }
                elif response.status_code == 401 or response.status_code == 403:
                    return {"provider": provider, "success": False, "error": "Invalid or unauthorized API key"}
                else:
                    return {"provider": provider, "success": False, "error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"provider": provider, "success": False, "error": str(e)}
    
    else:
        # Return a helpful error for unknown providers
        known_providers = ["anthropic", "openai", "virustotal", "abuseipdb", "mxtoolbox", "urlhaus", "phishtank", "hybrid_analysis"]
        return {
            "provider": provider, 
            "success": False, 
            "error": f"Unknown provider: {provider}. Known providers: {', '.join(known_providers)}"
        }


def _reinit_ai(settings):
    """Reinitialize AI analyzer with new keys."""
    try:
        from app.services.ai import init_ai_analyzer
        init_ai_analyzer(
            anthropic_api_key=settings.anthropic_api_key,
            openai_api_key=settings.openai_api_key,
            preferred_provider=settings.ai_provider,
        )
    except Exception as e:
        logger.error(f"Failed to reinitialize AI: {e}")


# ============================================================
# Dynamic Detection Configuration
# ============================================================

from app.models.settings import DynamicDetectionConfig


class DynamicConfigUpdate(BaseModel):
    """Request model for updating dynamic detection config."""
    custom_suspicious_tlds: Optional[list] = None
    custom_spam_keywords: Optional[list] = None
    custom_romance_keywords: Optional[list] = None
    custom_freemail_domains: Optional[list] = None
    whitelisted_domains: Optional[list] = None
    whitelisted_senders: Optional[list] = None
    high_risk_countries: Optional[list] = None
    custom_financial_domains: Optional[list] = None
    risk_threshold_high: Optional[int] = None
    risk_threshold_critical: Optional[int] = None
    enable_geoip: Optional[bool] = None
    enable_whois: Optional[bool] = None
    enable_ai_description: Optional[bool] = None


@router.get("/detection-config")
async def get_detection_config():
    """
    Get current dynamic detection configuration.
    
    Returns all custom TLDs, keywords, whitelists, and thresholds.
    """
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    config = manager.get_config()
    
    # Also return the merged/effective values
    return {
        "config": config.model_dump(),
        "effective": {
            "all_suspicious_tlds": list(manager.get_suspicious_tlds()),
            "all_spam_keywords": list(manager.get_spam_keywords()),
            "all_freemail_domains": list(manager.get_freemail_domains()),
            "all_financial_domains": list(manager.get_financial_domains()),
        }
    }


@router.patch("/detection-config")
async def update_detection_config(updates: DynamicConfigUpdate):
    """
    Update dynamic detection configuration.
    
    Only provided fields are updated; others remain unchanged.
    """
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    
    # Build update dict from non-None values
    update_dict = {k: v for k, v in updates.model_dump().items() if v is not None}
    
    if not update_dict:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    new_config = manager.update_config(update_dict)
    
    logger.info(f"Detection config updated: {list(update_dict.keys())}")
    
    return {
        "success": True,
        "updated_fields": list(update_dict.keys()),
        "config": new_config.model_dump(),
    }


@router.post("/detection-config/add-tld")
async def add_suspicious_tld(tld: str):
    """Add a single suspicious TLD to the custom list."""
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    config = manager.get_config()
    
    # Normalize TLD
    if not tld.startswith('.'):
        tld = '.' + tld
    tld = tld.lower()
    
    if tld in config.custom_suspicious_tlds:
        return {"success": False, "message": f"TLD {tld} already in list"}
    
    config.custom_suspicious_tlds.append(tld)
    manager.save_config(config)
    
    return {"success": True, "message": f"Added TLD {tld}", "total": len(config.custom_suspicious_tlds)}


@router.post("/detection-config/add-keyword")
async def add_spam_keyword(keyword: str, category: str = "spam"):
    """Add a spam or romance keyword."""
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    config = manager.get_config()
    
    keyword = keyword.lower()
    
    if category == "romance":
        if keyword in config.custom_romance_keywords:
            return {"success": False, "message": f"Keyword '{keyword}' already in romance list"}
        config.custom_romance_keywords.append(keyword)
    else:
        if keyword in config.custom_spam_keywords:
            return {"success": False, "message": f"Keyword '{keyword}' already in spam list"}
        config.custom_spam_keywords.append(keyword)
    
    manager.save_config(config)
    return {"success": True, "message": f"Added keyword '{keyword}' to {category} list"}


@router.post("/detection-config/whitelist-domain")
async def whitelist_domain(domain: str):
    """Add a domain to the whitelist."""
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    config = manager.get_config()
    
    domain = domain.lower()
    
    if domain in config.whitelisted_domains:
        return {"success": False, "message": f"Domain {domain} already whitelisted"}
    
    config.whitelisted_domains.append(domain)
    manager.save_config(config)
    
    return {"success": True, "message": f"Whitelisted domain {domain}"}


@router.post("/detection-config/whitelist-sender")
async def whitelist_sender(email: str):
    """Add a sender email to the whitelist."""
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    config = manager.get_config()
    
    email = email.lower()
    
    if email in config.whitelisted_senders:
        return {"success": False, "message": f"Sender {email} already whitelisted"}
    
    config.whitelisted_senders.append(email)
    manager.save_config(config)
    
    return {"success": True, "message": f"Whitelisted sender {email}"}


@router.post("/detection-config/add-financial-domain")
async def add_financial_domain(domain: str):
    """Add a legitimate financial institution domain to whitelist BEC rules."""
    from app.services.detection.dynamic_config import get_config_manager
    
    manager = get_config_manager()
    config = manager.get_config()
    
    domain = domain.lower()
    
    if domain in config.custom_financial_domains:
        return {"success": False, "message": f"Domain {domain} already in financial whitelist"}
    
    config.custom_financial_domains.append(domain)
    manager.save_config(config)
    
    return {
        "success": True, 
        "message": f"Added {domain} to financial institution whitelist",
        "info": "Emails from this domain will not trigger BEC/wire transfer rules"
    }
