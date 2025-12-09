"""
NiksES AI Analysis Context Builder

Builds context for AI analysis from parsed email, enrichment, and detection data.
"""

import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import DetectionResults

logger = logging.getLogger(__name__)


@dataclass
class AnalysisContext:
    """
    Context for AI analysis.
    
    Aggregates all data needed for AI-powered email analysis.
    """
    email: ParsedEmail
    enrichment: Optional[EnrichmentResults] = None
    detection: Optional[DetectionResults] = None
    
    # Metadata
    analysis_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Computed fields
    _email_dict: Optional[Dict[str, Any]] = field(default=None, repr=False)
    _enrichment_dict: Optional[Dict[str, Any]] = field(default=None, repr=False)
    _detection_dict: Optional[Dict[str, Any]] = field(default=None, repr=False)
    
    def to_email_dict(self) -> Dict[str, Any]:
        """Convert email to dictionary for prompts."""
        if self._email_dict is not None:
            return self._email_dict
        
        email = self.email
        
        # Sender
        sender_dict = None
        if email.sender:
            sender_dict = {
                'email': email.sender.email,
                'display_name': email.sender.display_name,
                'domain': email.sender.domain,
            }
        
        # Recipients
        to_recipients = []
        for r in email.to_recipients:
            to_recipients.append({
                'email': r.email,
                'display_name': r.display_name,
                'domain': r.domain,
            })
        
        # Reply-to
        reply_to = []
        for r in (email.reply_to or []):
            reply_to.append({
                'email': r.email,
                'domain': r.domain,
            })
        
        # URLs
        urls = []
        for u in email.urls:
            urls.append({
                'url': u.url,
                'domain': u.domain,
                'is_shortened': u.is_shortened,
                'source': u.source,
            })
        
        # Attachments
        attachments = []
        for a in email.attachments:
            attachments.append({
                'filename': a.filename,
                'content_type': a.content_type,
                'size_bytes': a.size_bytes,
                'extension': a.extension,
                'is_executable': a.is_executable,
                'is_archive': a.is_archive,
                'is_office_with_macros': a.is_office_with_macros,
                'sha256': a.sha256,
            })
        
        # Authentication
        spf_result = None
        if email.spf_result:
            spf_result = {
                'result': email.spf_result.result,
                'domain': email.spf_result.domain,
            }
        elif email.header_analysis and email.header_analysis.spf_result:
            spf = email.header_analysis.spf_result
            spf_result = {
                'result': spf.result,
                'domain': spf.domain,
            }
        
        dkim_result = None
        if email.dkim_result:
            dkim_result = {
                'result': email.dkim_result.result,
                'domain': email.dkim_result.domain,
            }
        elif email.header_analysis and email.header_analysis.dkim_result:
            dkim = email.header_analysis.dkim_result
            dkim_result = {
                'result': dkim.result,
                'domain': dkim.domain,
            }
        
        dmarc_result = None
        if email.dmarc_result:
            dmarc_result = {
                'result': email.dmarc_result.result,
                'domain': email.dmarc_result.domain,
            }
        elif email.header_analysis and email.header_analysis.dmarc_result:
            dmarc = email.header_analysis.dmarc_result
            dmarc_result = {
                'result': dmarc.result,
                'domain': dmarc.domain,
            }
        
        self._email_dict = {
            'sender': sender_dict,
            'to_recipients': to_recipients,
            'reply_to': reply_to,
            'subject': email.subject,
            'date': str(email.date) if email.date else None,
            'body_text': email.body_text,
            'body_html': email.body_html,
            'urls': urls,
            'attachments': attachments,
            'qr_codes': [{'data': q.raw_data, 'type': q.data_type, 'url': q.extracted_url} for q in (email.qr_codes or [])],
            'spf_result': spf_result,
            'dkim_result': dkim_result,
            'dmarc_result': dmarc_result,
            'header_analysis': {
                'originating_ip': email.header_analysis.originating_ip if email.header_analysis else None,
                'anomalies': email.header_analysis.anomalies if email.header_analysis else [],
            } if email.header_analysis else None,
        }
        
        return self._email_dict
    
    def to_enrichment_dict(self) -> Dict[str, Any]:
        """Convert enrichment to dictionary for prompts."""
        if self._enrichment_dict is not None:
            return self._enrichment_dict
        
        if not self.enrichment:
            self._enrichment_dict = {}
            return self._enrichment_dict
        
        enr = self.enrichment
        
        # Sender domain
        sender_domain = None
        if enr.sender_domain:
            sd = enr.sender_domain
            sender_domain = {
                'domain': sd.domain,
                'registrar': sd.registrar,
                'age_days': sd.age_days,
                'is_newly_registered': sd.is_newly_registered,
                'has_mx_records': sd.has_mx_records,
                'has_spf_record': sd.has_spf_record,
                'has_dmarc_record': sd.has_dmarc_record,
                'virustotal_verdict': sd.virustotal_verdict.value if sd.virustotal_verdict else None,
                'is_known_phishing': sd.is_known_phishing,
            }
        
        # Originating IP
        orig_ip = None
        if enr.originating_ip:
            ip = enr.originating_ip
            orig_ip = {
                'ip': ip.ip_address,
                'country': ip.country,
                'city': ip.city,
                'asn': ip.asn,
                'isp': ip.isp,
                'abuseipdb_score': ip.abuseipdb_score,
                'abuseipdb_verdict': ip.abuseipdb_verdict.value if ip.abuseipdb_verdict else None,
                'is_vpn': ip.is_vpn,
                'is_proxy': ip.is_proxy,
                'is_tor': ip.is_tor,
                'is_datacenter': ip.is_datacenter,
            }
        
        # URLs
        urls = []
        for u in (enr.urls or []):
            urls.append({
                'url': u.url,
                'domain': u.domain,
                'final_verdict': u.final_verdict.value if u.final_verdict else None,
                'virustotal_positives': u.virustotal_positives,
                'urlhaus_status': u.urlhaus_status,
                'phishtank_verified': u.phishtank_verified,
            })
        
        # Attachments
        attachments = []
        for a in (enr.attachments or []):
            attachments.append({
                'filename': a.filename,
                'sha256': a.sha256,
                'final_verdict': a.final_verdict.value if a.final_verdict else None,
                'virustotal_positives': a.virustotal_positives,
                'virustotal_threat_names': a.virustotal_threat_names[:5] if a.virustotal_threat_names else [],
            })
        
        self._enrichment_dict = {
            'sender_domain': sender_domain,
            'originating_ip': orig_ip,
            'urls': urls,
            'attachments': attachments,
        }
        
        return self._enrichment_dict
    
    def to_detection_dict(self) -> Dict[str, Any]:
        """Convert detection results to dictionary for prompts."""
        if self._detection_dict is not None:
            return self._detection_dict
        
        if not self.detection:
            self._detection_dict = {}
            return self._detection_dict
        
        det = self.detection
        
        # Triggered rules
        triggered = []
        for rule in det.rules_triggered:
            triggered.append({
                'rule_id': rule.rule_id,
                'rule_name': rule.rule_name,
                'category': rule.category,
                'severity': rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity),
                'description': rule.description,
                'evidence': rule.evidence[:5],
                'mitre_technique': rule.mitre_technique,
            })
        
        self._detection_dict = {
            'risk_score': det.risk_score,
            'risk_level': det.risk_level.value if hasattr(det.risk_level, 'value') else str(det.risk_level),
            'confidence': det.confidence,
            'primary_classification': det.primary_classification.value if hasattr(det.primary_classification, 'value') else str(det.primary_classification),
            'secondary_classifications': [c.value if hasattr(c, 'value') else str(c) for c in det.secondary_classifications],
            'rules_triggered': triggered,
            'rules_triggered_count': len(det.rules_triggered),
            'urgency_score': det.urgency_score,
            'authority_score': det.authority_score,
            'fear_score': det.fear_score,
            'reward_score': det.reward_score,
            'impersonated_brand': det.impersonated_brand,
            'brand_confidence': det.brand_confidence,
        }
        
        return self._detection_dict
    
    def to_full_dict(self) -> Dict[str, Any]:
        """Get full context as dictionary."""
        return {
            'email': self.to_email_dict(),
            'enrichment': self.to_enrichment_dict(),
            'detection': self.to_detection_dict(),
            'analysis_id': self.analysis_id,
            'timestamp': str(self.timestamp),
        }
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for the analysis."""
        email = self.email
        
        return {
            'has_attachments': len(email.attachments) > 0,
            'attachment_count': len(email.attachments),
            'has_urls': len(email.urls) > 0,
            'url_count': len(email.urls),
            'has_qr_codes': len(email.qr_codes or []) > 0,
            'has_reply_to_mismatch': self._has_reply_to_mismatch(),
            'body_length': len(email.body_text or ''),
            'risk_score': self.detection.risk_score if self.detection else 0,
            'rules_triggered': len(self.detection.rules_triggered) if self.detection else 0,
        }
    
    def _has_reply_to_mismatch(self) -> bool:
        """Check if reply-to differs from sender."""
        if not self.email.sender or not self.email.reply_to:
            return False
        
        sender_domain = self.email.sender.domain
        for reply_to in self.email.reply_to:
            if reply_to.domain and reply_to.domain != sender_domain:
                return True
        
        return False


def build_context(
    email: ParsedEmail,
    enrichment: Optional[EnrichmentResults] = None,
    detection: Optional[DetectionResults] = None,
    analysis_id: Optional[str] = None,
) -> AnalysisContext:
    """
    Build analysis context from components.
    
    Args:
        email: Parsed email
        enrichment: Optional enrichment results
        detection: Optional detection results
        analysis_id: Optional analysis ID
        
    Returns:
        AnalysisContext instance
    """
    return AnalysisContext(
        email=email,
        enrichment=enrichment,
        detection=detection,
        analysis_id=analysis_id,
    )
