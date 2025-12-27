"""
NiksES URL Sandbox Service

Dynamic URL analysis using sandbox environments.
"""

from .url_sandbox import (
    URLSandboxService,
    URLAnalysisResult,
    AnalysisStatus,
    SandboxProvider,
    get_url_sandbox_service,
)

__all__ = [
    'URLSandboxService',
    'URLAnalysisResult', 
    'AnalysisStatus',
    'SandboxProvider',
    'get_url_sandbox_service',
]
