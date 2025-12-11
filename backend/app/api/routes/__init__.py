"""
NiksES API Routes

All API route modules.
"""

from fastapi import APIRouter

from .analyze import router as analyze_router
from .analyses import router as analyses_router
from .export import router as export_router
from .health import router as health_router
from .settings import router as settings_router
from .rules import router as rules_router
from .soc_tools import router as soc_tools_router

# Import sandbox router
try:
    from .sandbox import router as sandbox_router
    SANDBOX_AVAILABLE = True
except ImportError:
    sandbox_router = None
    SANDBOX_AVAILABLE = False


def get_api_router() -> APIRouter:
    """Create and return the main API router."""
    api_router = APIRouter(prefix="/api/v1")
    
    # Include all routers
    api_router.include_router(analyze_router)
    api_router.include_router(analyses_router)
    api_router.include_router(export_router)
    api_router.include_router(health_router)
    api_router.include_router(settings_router)
    api_router.include_router(rules_router)
    api_router.include_router(soc_tools_router)
    
    # Include sandbox router if available
    if SANDBOX_AVAILABLE and sandbox_router:
        api_router.include_router(sandbox_router)
    
    return api_router


__all__ = [
    'get_api_router',
    'analyze_router',
    'analyses_router',
    'export_router',
    'health_router',
    'settings_router',
    'rules_router',
    'soc_tools_router',
    'sandbox_router',
    'SANDBOX_AVAILABLE',
]
