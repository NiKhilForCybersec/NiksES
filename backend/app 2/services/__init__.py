"""
NiksES Services Package

Business logic modules for email analysis:
- parser: Email parsing and extraction
- enrichment: Threat intelligence enrichment
- detection: Rule-based detection engine
- ai: AI triage copilot
- export: Export functionality
"""

# Services are imported explicitly when needed to avoid circular imports
# Example: from app.services.parser import parse_email_auto
# Example: from app.services.enrichment import get_enrichment_orchestrator

__all__ = [
    'parser',
    'enrichment',
    'detection',
    'ai',
    'export',
]
