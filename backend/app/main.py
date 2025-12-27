"""
NiksES API Application

Main FastAPI application entry point.
"""

# Load environment variables FIRST before any other imports
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, use system env vars

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import get_api_router
from app.api.dependencies import init_settings, init_analysis_store, get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting NiksES API...")
    
    # Initialize settings from environment - ALL API keys
    settings = init_settings(
        # Threat Intelligence APIs
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        phishtank_api_key=os.getenv("PHISHTANK_API_KEY"),
        mxtoolbox_api_key=os.getenv("MXTOOLBOX_API_KEY"),
        ipqualityscore_api_key=os.getenv("IPQUALITYSCORE_API_KEY"),
        google_safebrowsing_api_key=os.getenv("GOOGLE_SAFEBROWSING_API_KEY"),
        # Sandbox APIs
        hybrid_analysis_api_key=os.getenv("HYBRID_ANALYSIS_API_KEY"),
        urlscan_api_key=os.getenv("URLSCAN_API_KEY"),
        # AI APIs
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        ai_enabled=os.getenv("AI_ENABLED", "true").lower() == "true",  # Default to true
        ai_provider=os.getenv("AI_PROVIDER", "openai"),  # Default to openai since user has it
    )
    
    # Log configured APIs
    logger.info("=== API Configuration ===")
    logger.info(f"  VirusTotal: {'✓' if settings.virustotal_api_key else '✗'}")
    logger.info(f"  AbuseIPDB: {'✓' if settings.abuseipdb_api_key else '✗'}")
    logger.info(f"  IPQualityScore: {'✓' if settings.ipqualityscore_api_key else '✗'}")
    logger.info(f"  Google Safe Browsing: {'✓' if settings.google_safebrowsing_api_key else '✗'}")
    logger.info(f"  MXToolbox: {'✓' if settings.mxtoolbox_api_key else '✗'}")
    logger.info(f"  Hybrid Analysis: {'✓' if settings.hybrid_analysis_api_key else '✗'}")
    logger.info(f"  URLScan: {'✓' if getattr(settings, 'urlscan_api_key', None) else '✗'}")
    logger.info(f"  OpenAI: {'✓' if settings.openai_api_key else '✗'}")
    logger.info(f"  Anthropic: {'✓' if settings.anthropic_api_key else '✗'}")
    logger.info(f"  AI Enabled: {settings.ai_enabled}, Provider: {settings.ai_provider}")
    
    # Initialize analysis store (SQLite for persistence)
    init_analysis_store("sqlite")
    
    # Initialize AI analyzer
    try:
        from app.services.ai import init_ai_analyzer, get_ai_analyzer
        init_ai_analyzer(
            anthropic_api_key=settings.anthropic_api_key,
            openai_api_key=settings.openai_api_key,
            preferred_provider=settings.ai_provider,
        )
        analyzer = get_ai_analyzer()
        if analyzer and analyzer.is_configured():
            configured_providers = analyzer.get_configured_providers()
            logger.info(f"AI analyzer initialized with providers: {configured_providers}")
        else:
            logger.warning("AI analyzer initialized but NO PROVIDERS CONFIGURED")
            logger.warning(f"  - AI_ENABLED: {settings.ai_enabled}")
            logger.warning(f"  - AI_PROVIDER: {settings.ai_provider}")
            logger.warning(f"  - OPENAI_API_KEY set: {bool(settings.openai_api_key)}")
            logger.warning(f"  - ANTHROPIC_API_KEY set: {bool(settings.anthropic_api_key)}")
    except Exception as e:
        logger.warning(f"AI analyzer not available: {e}")
    
    # Initialize enrichment orchestrator with ALL APIs
    try:
        from app.services.enrichment import get_enrichment_orchestrator
        from app.services.enrichment.mxtoolbox import configure_mxtoolbox
        
        orchestrator = get_enrichment_orchestrator()
        orchestrator.configure_api_keys(
            virustotal_api_key=settings.virustotal_api_key,
            abuseipdb_api_key=settings.abuseipdb_api_key,
            phishtank_api_key=settings.phishtank_api_key,
            mxtoolbox_api_key=settings.mxtoolbox_api_key,
            ipqualityscore_api_key=settings.ipqualityscore_api_key,
            google_safebrowsing_api_key=settings.google_safebrowsing_api_key,
        )
        
        # Configure MXToolbox if key is set
        mxtoolbox_key = os.getenv("MXTOOLBOX_API_KEY")
        if mxtoolbox_key:
            configure_mxtoolbox(mxtoolbox_key)
            logger.info("MXToolbox API configured")
        
        logger.info("Enrichment orchestrator initialized with all TI sources")
    except Exception as e:
        logger.warning(f"Enrichment orchestrator not available: {e}")
    
    # Initialize detection engine
    try:
        from app.services.detection import get_detection_engine
        engine = get_detection_engine()
        logger.info(f"Detection engine initialized with {len(engine.rules)} rules")
    except Exception as e:
        logger.warning(f"Detection engine not available: {e}")
    
    logger.info("NiksES API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down NiksES API...")
    
    # Cleanup AI sessions
    try:
        from app.services.ai import get_ai_analyzer
        analyzer = get_ai_analyzer()
        if analyzer:
            await analyzer.close()
    except:
        pass
    
    logger.info("NiksES API shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="NiksES API",
    description="AI-powered Email Security Analysis Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware - Configure allowed origins
def get_cors_origins():
    """Get CORS origins from environment or use defaults."""
    # Check for custom origins in environment
    custom_origins = os.getenv("CORS_ORIGINS", "")
    
    if custom_origins:
        # Split by comma and strip whitespace
        origins = [origin.strip() for origin in custom_origins.split(",") if origin.strip()]
    else:
        # Default: localhost only (development)
        origins = [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ]
    
    logger.info(f"CORS allowed origins: {origins}")
    return origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# Security middleware - Rate limiting and security headers
try:
    from app.utils.security import RateLimitMiddleware, SecurityHeadersMiddleware
    
    # Rate limiting: 120 requests per minute per IP (adjust as needed)
    rate_limit_rpm = int(os.getenv("RATE_LIMIT_RPM", "120"))
    app.add_middleware(RateLimitMiddleware, requests_per_minute=rate_limit_rpm)
    
    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    logger.info(f"Security middleware enabled (rate limit: {rate_limit_rpm} req/min)")
except ImportError as e:
    logger.warning(f"Security middleware not loaded: {e}")

# Include API routes
app.include_router(get_api_router())


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API info."""
    return {
        "name": "NiksES API",
        "description": "AI-powered Email Security Analysis Platform",
        "version": "1.0.0",
        "docs": "/docs",
    }


# Root-level health check (for Docker/K8s)
@app.get("/health")
async def health():
    """Basic health check."""
    return {
        "status": "healthy",
        "service": "nikses-api",
        "version": "1.0.0",
    }


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if os.getenv("DEBUG") else "An error occurred",
        },
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
