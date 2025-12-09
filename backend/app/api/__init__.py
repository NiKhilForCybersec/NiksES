"""
NiksES API Module

FastAPI routes and dependencies.
"""

from .routes import get_api_router
from .dependencies import (
    Settings,
    get_settings,
    init_settings,
    AnalysisStore,
    get_analysis_store,
    init_analysis_store,
)

__all__ = [
    'get_api_router',
    'Settings',
    'get_settings',
    'init_settings',
    'AnalysisStore',
    'get_analysis_store',
    'init_analysis_store',
]
