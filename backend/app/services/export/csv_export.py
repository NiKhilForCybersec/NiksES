"""
NiksES CSV Export

Export analysis data to CSV format.
"""

import csv
import io
import logging
from typing import List, Optional
from datetime import datetime

from app.models.analysis import AnalysisResult, AnalysisSummary

logger = logging.getLogger(__name__)


def export_summary_to_csv(analyses: List[AnalysisSummary]) -> str:
    """
    Export list of analysis summaries to CSV.
    
    Args:
        analyses: List of analysis summaries
        
    Returns:
        CSV string
    """
    output = io.StringIO()
    
    fieldnames = [
        'analysis_id',
        'analyzed_at',
        'subject',
        'sender_email',
        'sender_domain',
        'risk_score',
        'risk_level',
        'classification',
        'attachment_count',
        'url_count',
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for analysis in analyses:
        writer.writerow({
            'analysis_id': analysis.analysis_id,
            'analyzed_at': analysis.analyzed_at.isoformat(),
            'subject': analysis.subject or '',
            'sender_email': analysis.sender_email or '',
            'sender_domain': analysis.sender_domain or '',
            'risk_score': analysis.risk_score,
            'risk_level': analysis.risk_level,
            'classification': analysis.classification,
            'attachment_count': analysis.attachment_count,
            'url_count': analysis.url_count,
        })
    
    return output.getvalue()


def export_iocs_to_csv(analysis: AnalysisResult) -> str:
    """
    Export IOCs to CSV format.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        CSV string
    """
    output = io.StringIO()
    
    fieldnames = ['type', 'value', 'analysis_id', 'risk_score', 'classification']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    iocs = analysis.iocs
    base_row = {
        'analysis_id': analysis.analysis_id,
        'risk_score': analysis.detection.risk_score,
        'classification': analysis.detection.primary_classification.value,
    }
    
    for domain in iocs.domains:
        writer.writerow({**base_row, 'type': 'domain', 'value': domain})
    
    for url in iocs.urls:
        writer.writerow({**base_row, 'type': 'url', 'value': url})
    
    for ip in iocs.ips:
        writer.writerow({**base_row, 'type': 'ip', 'value': ip})
    
    for email in iocs.email_addresses:
        writer.writerow({**base_row, 'type': 'email', 'value': email})
    
    for hash_val in iocs.file_hashes_sha256:
        writer.writerow({**base_row, 'type': 'sha256', 'value': hash_val})
    
    for hash_val in iocs.file_hashes_md5:
        writer.writerow({**base_row, 'type': 'md5', 'value': hash_val})
    
    return output.getvalue()


def export_rules_to_csv(analysis: AnalysisResult) -> str:
    """
    Export triggered detection rules to CSV.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        CSV string
    """
    output = io.StringIO()
    
    fieldnames = [
        'rule_id',
        'rule_name',
        'category',
        'severity',
        'score_impact',
        'description',
        'mitre_technique',
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for rule in analysis.detection.rules_triggered:
        writer.writerow({
            'rule_id': rule.rule_id,
            'rule_name': rule.rule_name,
            'category': rule.category,
            'severity': rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity),
            'score_impact': rule.score_impact,
            'description': rule.description,
            'mitre_technique': rule.mitre_technique or '',
        })
    
    return output.getvalue()


def export_attachments_to_csv(analysis: AnalysisResult) -> str:
    """
    Export attachment information to CSV.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        CSV string
    """
    output = io.StringIO()
    
    fieldnames = [
        'filename',
        'content_type',
        'size_bytes',
        'extension',
        'md5',
        'sha256',
        'is_executable',
        'is_archive',
        'is_office_with_macros',
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for att in analysis.email.attachments:
        writer.writerow({
            'filename': att.filename,
            'content_type': att.content_type or '',
            'size_bytes': att.size_bytes,
            'extension': att.extension or '',
            'md5': att.md5 or '',
            'sha256': att.sha256 or '',
            'is_executable': att.is_executable,
            'is_archive': att.is_archive,
            'is_office_with_macros': att.is_office_with_macros,
        })
    
    return output.getvalue()


def export_urls_to_csv(analysis: AnalysisResult) -> str:
    """
    Export URL information to CSV.
    
    Args:
        analysis: Complete analysis result
        
    Returns:
        CSV string
    """
    output = io.StringIO()
    
    fieldnames = [
        'url',
        'domain',
        'scheme',
        'source',
        'is_shortened',
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for url in analysis.email.urls:
        writer.writerow({
            'url': url.url,
            'domain': url.domain or '',
            'scheme': url.scheme or '',
            'source': url.source or '',
            'is_shortened': url.is_shortened,
        })
    
    return output.getvalue()
