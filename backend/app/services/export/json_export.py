"""
NiksES JSON Export

Export analysis results to JSON format.
"""

import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime, date

from app.models.analysis import AnalysisResult, AnalysisSummary

logger = logging.getLogger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        if hasattr(obj, 'value'):  # Enum
            return obj.value
        if hasattr(obj, 'model_dump'):  # Pydantic model
            return obj.model_dump()
        return super().default(obj)


def export_to_json(
    analysis: AnalysisResult,
    pretty: bool = True,
    include_raw: bool = False,
) -> str:
    """
    Export analysis result to JSON string.
    
    Args:
        analysis: Complete analysis result
        pretty: Pretty print with indentation
        include_raw: Include raw email content
        
    Returns:
        JSON string
    """
    # Convert to dict
    data = analysis.model_dump()
    
    # Remove raw content if not requested
    if not include_raw and 'email' in data:
        if 'raw_content' in data['email']:
            del data['email']['raw_content']
        if 'body_html' in data['email']:
            # Truncate large HTML
            if data['email']['body_html'] and len(data['email']['body_html']) > 10000:
                data['email']['body_html'] = data['email']['body_html'][:10000] + '... [truncated]'
    
    indent = 2 if pretty else None
    return json.dumps(data, cls=DateTimeEncoder, indent=indent, ensure_ascii=False)


def export_summary_to_json(analyses: list[AnalysisSummary]) -> str:
    """
    Export list of analysis summaries to JSON.
    
    Args:
        analyses: List of analysis summaries
        
    Returns:
        JSON string
    """
    data = [a.model_dump() for a in analyses]
    return json.dumps(data, cls=DateTimeEncoder, indent=2, ensure_ascii=False)


def export_iocs_to_json(analysis: AnalysisResult) -> str:
    """
    Export only IOCs from analysis to JSON.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        JSON string with IOCs
    """
    iocs = analysis.iocs.model_dump()
    
    # Add metadata
    output = {
        'analysis_id': analysis.analysis_id,
        'analyzed_at': analysis.analyzed_at.isoformat(),
        'risk_score': analysis.detection.risk_score,
        'classification': analysis.detection.primary_classification.value,
        'iocs': iocs,
    }
    
    return json.dumps(output, indent=2, ensure_ascii=False)


def export_detection_to_json(analysis: AnalysisResult) -> str:
    """
    Export detection results to JSON.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        JSON string with detection results
    """
    detection = analysis.detection.model_dump()
    
    output = {
        'analysis_id': analysis.analysis_id,
        'analyzed_at': analysis.analyzed_at.isoformat(),
        'detection': detection,
    }
    
    return json.dumps(output, cls=DateTimeEncoder, indent=2, ensure_ascii=False)
