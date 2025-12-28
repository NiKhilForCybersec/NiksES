"""
NiksES Health API Routes

Health check and status endpoints.
"""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends

from app.api.dependencies import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check():
    """
    Basic health check endpoint.
    
    Returns:
        Health status
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "nikses-api",
        "version": "1.0.0",
    }


@router.get("/ready")
async def readiness_check(
    settings = Depends(get_settings),
):
    """
    Readiness check - verifies all dependencies.
    
    Returns:
        Readiness status with component checks
    """
    checks = {}
    all_ready = True
    
    # Check detection engine
    try:
        from app.services.detection import get_detection_engine
        engine = get_detection_engine()
        checks["detection_engine"] = {
            "status": "ready",
            "rules_loaded": len(engine.rules),
        }
    except Exception as e:
        checks["detection_engine"] = {"status": "error", "error": str(e)}
        all_ready = False
    
    # Check enrichment (optional)
    try:
        from app.services.enrichment import get_enrichment_orchestrator
        orchestrator = get_enrichment_orchestrator()
        status = orchestrator.get_provider_status()
        configured = sum(1 for v in status.values() if v.get('configured'))
        checks["enrichment"] = {
            "status": "ready",
            "providers_configured": configured,
        }
    except Exception as e:
        checks["enrichment"] = {"status": "warning", "error": str(e)}
    
    # Check AI (optional)
    try:
        from app.services.ai import get_ai_analyzer
        analyzer = get_ai_analyzer()
        if analyzer and analyzer.is_configured():
            checks["ai"] = {
                "status": "ready",
                "providers": analyzer.get_configured_providers(),
            }
        else:
            checks["ai"] = {"status": "not_configured"}
    except Exception as e:
        checks["ai"] = {"status": "warning", "error": str(e)}
    
    return {
        "status": "ready" if all_ready else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }


@router.get("/live")
async def liveness_check():
    """
    Liveness check - basic ping.
    
    Returns:
        Alive status
    """
    return {"status": "alive"}


@router.get("/version")
async def version_info():
    """
    Get version information.
    
    Returns:
        Version details
    """
    return {
        "service": "NiksES API",
        "version": "1.0.0",
        "api_version": "v1",
        "description": "AI-powered Email Security Analysis Platform",
    }


@router.get("/capabilities")
async def get_capabilities(
    settings = Depends(get_settings),
):
    """
    Get API capabilities and features.
    
    Returns:
        Available features and limits
    """
    capabilities = {
        "analysis": {
            "file_types": [".eml", ".msg"],
            "max_file_size_mb": 50,
        },
        "detection": {
            "enabled": True,
            "rule_count": 51,
            "categories": [
                "authentication",
                "phishing",
                "malware",
                "bec",
                "lookalike",
                "social_engineering",
            ],
        },
        "enrichment": {
            "enabled": True,
            "providers": [
                "geoip",
                "dns",
                "whois",
                "virustotal",
                "abuseipdb",
                "urlhaus",
                "phishtank",
            ],
        },
        "ai": {
            "enabled": settings.ai_enabled if settings else False,
            "providers": ["anthropic", "openai"],
        },
        "export": {
            "formats": ["json", "markdown", "csv", "stix", "pdf"],
        },
    }
    
    return capabilities


@router.get("/debug/keys")
async def debug_api_keys(
    settings = Depends(get_settings),
):
    """
    Debug endpoint to check which API keys are loaded.
    Shows first 4 chars of each key (for verification) or 'NOT SET'.
    
    Returns:
        Status of all API keys
    """
    import os
    
    def key_status(key_value):
        if key_value and len(key_value) > 4:
            return f"SET ({key_value[:4]}...)"
        elif key_value:
            return "SET (short)"
        return "NOT SET"
    
    # Check both settings object AND direct env vars
    return {
        "source": "settings_and_env",
        "settings_loaded": settings is not None,
        "keys_from_settings": {
            "openai": key_status(getattr(settings, 'openai_api_key', None) if settings else None),
            "anthropic": key_status(getattr(settings, 'anthropic_api_key', None) if settings else None),
            "virustotal": key_status(getattr(settings, 'virustotal_api_key', None) if settings else None),
            "ipqualityscore": key_status(getattr(settings, 'ipqualityscore_api_key', None) if settings else None),
            "abuseipdb": key_status(getattr(settings, 'abuseipdb_api_key', None) if settings else None),
        },
        "keys_from_env": {
            "OPENAI_API_KEY": key_status(os.getenv("OPENAI_API_KEY")),
            "ANTHROPIC_API_KEY": key_status(os.getenv("ANTHROPIC_API_KEY")),
            "VIRUSTOTAL_API_KEY": key_status(os.getenv("VIRUSTOTAL_API_KEY")),
            "IPQUALITYSCORE_API_KEY": key_status(os.getenv("IPQUALITYSCORE_API_KEY")),
            "ABUSEIPDB_API_KEY": key_status(os.getenv("ABUSEIPDB_API_KEY")),
            "AI_ENABLED": os.getenv("AI_ENABLED", "not set"),
            "AI_PROVIDER": os.getenv("AI_PROVIDER", "not set"),
        },
        "config": {
            "ai_enabled": settings.ai_enabled if settings else None,
            "ai_provider": settings.ai_provider if settings else None,
            "enrichment_enabled": settings.enrichment_enabled if settings else None,
        }
    }
