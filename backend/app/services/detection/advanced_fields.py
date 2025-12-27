"""
NiksES Advanced Field Evaluator

Provides advanced field extraction and evaluation for custom detection rules.
Supports authentication status, threat intel data, behavioral patterns, etc.
"""

import re
import logging
from typing import Any, Optional, List, Dict
from datetime import datetime, time

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults, ThreatIntelVerdict

logger = logging.getLogger(__name__)


class AdvancedFieldEvaluator:
    """
    Evaluates advanced fields from email and enrichment data.
    
    Supports:
    - Email metadata fields
    - Authentication results (SPF/DKIM/DMARC)
    - Threat intelligence data
    - URL/attachment analysis
    - Behavioral pattern detection
    """
    
    # Urgency keywords
    URGENCY_KEYWORDS = [
        'urgent', 'immediately', 'asap', 'right away', 'time sensitive',
        'act now', 'respond immediately', 'action required', 'urgent action',
        'within 24 hours', 'within 48 hours', 'expires today', 'last chance',
        'final notice', 'immediate attention', 'priority', 'critical',
    ]
    
    # Threat keywords
    THREAT_KEYWORDS = [
        'suspended', 'terminated', 'disabled', 'blocked', 'unauthorized',
        'illegal', 'violation', 'legal action', 'law enforcement', 'arrest',
        'court', 'lawsuit', 'penalty', 'fine', 'consequences', 'fraud alert',
        'security breach', 'compromised', 'hacked',
    ]
    
    # Financial request keywords
    FINANCIAL_KEYWORDS = [
        'wire transfer', 'bank transfer', 'gift card', 'itunes', 'amazon card',
        'google play', 'payment', 'invoice', 'remittance', 'ach', 'swift',
        'bitcoin', 'cryptocurrency', 'western union', 'moneygram', 'zelle',
        'venmo', 'paypal', 'cashapp', 'bank account', 'routing number',
    ]
    
    # Credential request keywords
    CREDENTIAL_KEYWORDS = [
        'password', 'login', 'sign in', 'signin', 'username', 'credential',
        'verify your account', 'confirm your identity', 'update your information',
        'reactivate', 'unlock', 'restore access', 'verify identity',
        'security verification', 'authentication required',
    ]
    
    # PII request keywords
    PII_KEYWORDS = [
        'social security', 'ssn', 'date of birth', 'dob', 'mother\'s maiden',
        'driver\'s license', 'passport', 'credit card', 'bank account',
        'tax id', 'ein', 'personal information', 'full address',
    ]
    
    # Brand names for impersonation detection
    BRAND_NAMES = [
        'microsoft', 'office 365', 'outlook', 'onedrive', 'sharepoint',
        'google', 'gmail', 'drive', 'paypal', 'amazon', 'apple', 'icloud',
        'netflix', 'facebook', 'instagram', 'linkedin', 'twitter',
        'bank of america', 'wells fargo', 'chase', 'citibank', 'usaa',
        'fedex', 'ups', 'dhl', 'usps', 'irs', 'social security',
        'docusign', 'dropbox', 'zoom', 'slack', 'salesforce',
    ]
    
    # Executive titles for BEC detection
    EXECUTIVE_TITLES = [
        'ceo', 'cfo', 'cto', 'coo', 'ciso', 'president', 'chairman',
        'director', 'vp', 'vice president', 'chief', 'executive',
        'managing director', 'partner', 'founder', 'owner',
    ]
    
    # URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 'v.gd', 'rb.gy',
        'cutt.ly', 'short.io', 'rebrand.ly',
    ]
    
    # Executable extensions
    EXECUTABLE_EXTENSIONS = [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse',
        '.wsf', '.wsh', '.msi', '.msp', '.scr', '.pif', '.com', '.hta',
        '.cpl', '.msc', '.jar',
    ]
    
    # Macro-enabled document extensions
    MACRO_EXTENSIONS = [
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm',
        '.xlam', '.ppam', '.sldm',
    ]
    
    # Archive extensions
    ARCHIVE_EXTENSIONS = [
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        '.iso', '.cab', '.arj', '.lzh',
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_field_value(
        self,
        field: str,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Any:
        """
        Get the value of an advanced field.
        
        Args:
            field: Field identifier
            email: Parsed email
            enrichment: Optional enrichment results
            
        Returns:
            Field value (type depends on field)
        """
        # Email metadata fields
        if field == 'subject':
            return email.subject or ''
        elif field == 'body':
            return email.body_text or ''
        elif field == 'body_html':
            return email.body_html or ''
        elif field == 'sender_email':
            return email.sender.email if email.sender else ''
        elif field == 'sender_domain':
            return email.sender.domain if email.sender else ''
        elif field == 'sender_display_name':
            return email.sender.display_name if email.sender else ''
        elif field == 'reply_to':
            return ','.join(r.email for r in (email.reply_to or []))
        elif field == 'return_path':
            return email.return_path or ''
        elif field == 'recipient_count':
            return len(email.to_recipients or []) + len(email.cc_recipients or [])
        
        # Authentication fields
        elif field == 'spf_result':
            spf = email.spf_result or (email.header_analysis.spf_result if email.header_analysis else None)
            return spf.result if spf else 'none'
        elif field == 'dkim_result':
            dkim = email.dkim_result or (email.header_analysis.dkim_result if email.header_analysis else None)
            return dkim.result if dkim else 'none'
        elif field == 'dmarc_result':
            dmarc = email.dmarc_result or (email.header_analysis.dmarc_result if email.header_analysis else None)
            return dmarc.result if dmarc else 'none'
        elif field == 'auth_all_pass':
            spf = self.get_field_value('spf_result', email, enrichment)
            dkim = self.get_field_value('dkim_result', email, enrichment)
            dmarc = self.get_field_value('dmarc_result', email, enrichment)
            return spf == 'pass' and dkim == 'pass' and dmarc == 'pass'
        elif field == 'auth_any_fail':
            spf = self.get_field_value('spf_result', email, enrichment)
            dkim = self.get_field_value('dkim_result', email, enrichment)
            dmarc = self.get_field_value('dmarc_result', email, enrichment)
            return 'fail' in [spf, dkim, dmarc]
        
        # Threat intel fields (require enrichment)
        elif field == 'sender_domain_vt_score':
            if enrichment and enrichment.sender_domain:
                stats = enrichment.sender_domain.virustotal_stats or {}
                return stats.get('malicious', 0)
            return 0
        elif field == 'sender_domain_age_days':
            if enrichment and enrichment.sender_domain and enrichment.sender_domain.domain_age_days:
                return enrichment.sender_domain.domain_age_days
            return 999  # Unknown = assume old
        elif field == 'sender_domain_is_new':
            age = self.get_field_value('sender_domain_age_days', email, enrichment)
            return age < 30
        elif field == 'originating_ip_abuse_score':
            if enrichment and enrichment.originating_ip:
                return enrichment.originating_ip.abuseipdb_score or 0
            return 0
        elif field == 'originating_ip_is_tor':
            if enrichment and enrichment.originating_ip:
                return enrichment.originating_ip.is_tor
            return False
        elif field == 'originating_ip_is_vpn':
            if enrichment and enrichment.originating_ip:
                return enrichment.originating_ip.is_vpn
            return False
        elif field == 'originating_ip_country':
            if enrichment and enrichment.originating_ip:
                return enrichment.originating_ip.country_code or ''
            return ''
        elif field == 'url_any_malicious':
            if enrichment and enrichment.urls:
                return any(u.final_verdict == ThreatIntelVerdict.MALICIOUS for u in enrichment.urls)
            return False
        elif field == 'attachment_any_malicious':
            if enrichment and enrichment.attachments:
                return any(a.final_verdict == ThreatIntelVerdict.MALICIOUS for a in enrichment.attachments)
            return False
        
        # URL/Link fields
        elif field == 'url_count':
            return len(email.urls or [])
        elif field == 'urls':
            return '\n'.join(u.url for u in (email.urls or []))
        elif field == 'url_domains':
            return '\n'.join(u.domain for u in (email.urls or []) if u.domain)
        elif field == 'has_shortened_url':
            for url in (email.urls or []):
                if any(short in url.url.lower() for short in self.URL_SHORTENERS):
                    return True
            return False
        elif field == 'has_ip_url':
            ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            for url in (email.urls or []):
                if re.search(ip_pattern, url.url):
                    return True
            return False
        elif field == 'has_data_uri':
            body = email.body_html or ''
            return 'data:' in body
        elif field == 'url_mismatch':
            # Check for display text != href
            body = email.body_html or ''
            # Simple check: look for href with different visible text
            pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
            matches = re.findall(pattern, body, re.IGNORECASE)
            for href, text in matches:
                # If text looks like a URL but differs from href
                if text.startswith('http') and href.lower() != text.lower():
                    return True
            return False
        elif field == 'has_credential_harvesting_url':
            patterns = ['login', 'signin', 'sign-in', 'password', 'credential', 'verify', 'authenticate']
            for url in (email.urls or []):
                if any(p in url.url.lower() for p in patterns):
                    return True
            return False
        
        # Attachment fields
        elif field == 'attachment_count':
            return len(email.attachments or [])
        elif field == 'attachment_names':
            return '\n'.join(a.filename for a in (email.attachments or []))
        elif field == 'attachment_extensions':
            return '\n'.join(a.extension or '' for a in (email.attachments or []))
        elif field == 'attachment_size_total':
            return sum(a.size or 0 for a in (email.attachments or [])) / 1024  # KB
        elif field == 'has_executable':
            for att in (email.attachments or []):
                ext = (att.extension or '').lower()
                if ext in self.EXECUTABLE_EXTENSIONS:
                    return True
            return False
        elif field == 'has_macro_document':
            for att in (email.attachments or []):
                ext = (att.extension or '').lower()
                if ext in self.MACRO_EXTENSIONS:
                    return True
            return False
        elif field == 'has_archive':
            for att in (email.attachments or []):
                ext = (att.extension or '').lower()
                if ext in self.ARCHIVE_EXTENSIONS:
                    return True
            return False
        elif field == 'has_double_extension':
            for att in (email.attachments or []):
                name = att.filename.lower()
                # Check for double extension like .pdf.exe
                if re.search(r'\.\w{2,4}\.\w{2,4}$', name):
                    return True
            return False
        elif field == 'has_password_protected':
            for att in (email.attachments or []):
                if att.is_encrypted:
                    return True
            return False
        
        # Header fields
        elif field == 'headers':
            return str(email.raw_headers) if email.raw_headers else ''
        elif field == 'x_mailer':
            headers = email.raw_headers or {}
            return headers.get('X-Mailer', headers.get('x-mailer', ''))
        elif field == 'received_hop_count':
            if email.header_analysis and email.header_analysis.received_chain:
                return len(email.header_analysis.received_chain)
            return 0
        elif field == 'received_delay_total':
            if email.header_analysis and email.header_analysis.received_chain:
                # Sum up all delays
                total = 0
                for hop in email.header_analysis.received_chain:
                    if hop.delay_seconds:
                        total += hop.delay_seconds
                return total
            return 0
        elif field == 'has_received_localhost':
            headers = str(email.raw_headers or '')
            return 'localhost' in headers.lower() or '127.0.0.1' in headers
        elif field == 'header_from_mismatch':
            # Check if header From differs from envelope From
            header_from = email.sender.email if email.sender else ''
            return_path = email.return_path or ''
            if header_from and return_path:
                return header_from.lower() != return_path.lower()
            return False
        
        # Behavioral fields
        elif field == 'urgency_score':
            return self._calculate_urgency_score(email)
        elif field == 'has_urgency_language':
            return self._has_keywords(email, self.URGENCY_KEYWORDS)
        elif field == 'has_threat_language':
            return self._has_keywords(email, self.THREAT_KEYWORDS)
        elif field == 'has_financial_request':
            return self._has_keywords(email, self.FINANCIAL_KEYWORDS)
        elif field == 'has_credential_request':
            return self._has_keywords(email, self.CREDENTIAL_KEYWORDS)
        elif field == 'has_pii_request':
            return self._has_keywords(email, self.PII_KEYWORDS)
        elif field == 'impersonates_brand':
            return self._has_keywords(email, self.BRAND_NAMES)
        elif field == 'impersonates_executive':
            # Check display name for executive titles
            display_name = (email.sender.display_name or '').lower() if email.sender else ''
            return any(title in display_name for title in self.EXECUTIVE_TITLES)
        elif field == 'sent_outside_business_hours':
            if email.date:
                hour = email.date.hour
                weekday = email.date.weekday()
                # Outside 8am-6pm or weekend
                return hour < 8 or hour >= 18 or weekday >= 5
            return False
        
        # Unknown field
        self.logger.warning(f"Unknown field: {field}")
        return None
    
    def _has_keywords(self, email: ParsedEmail, keywords: List[str]) -> bool:
        """Check if email contains any of the keywords."""
        text = f"{email.subject or ''} {email.body_text or ''}".lower()
        return any(kw in text for kw in keywords)
    
    def _calculate_urgency_score(self, email: ParsedEmail) -> int:
        """Calculate urgency score (0-100) based on keywords."""
        text = f"{email.subject or ''} {email.body_text or ''}".lower()
        score = 0
        
        for keyword in self.URGENCY_KEYWORDS:
            if keyword in text:
                score += 10
        
        # Cap at 100
        return min(score, 100)
    
    def evaluate_condition(
        self,
        field: str,
        operator: str,
        value: str,
        value2: Optional[str],
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> bool:
        """
        Evaluate a condition against email data.
        
        Args:
            field: Field identifier
            operator: Comparison operator
            value: Value to compare
            value2: Second value (for 'between' operator)
            email: Parsed email
            enrichment: Optional enrichment results
            
        Returns:
            True if condition matches
        """
        field_value = self.get_field_value(field, email, enrichment)
        
        if field_value is None:
            return False
        
        # Boolean operators
        if operator == 'is_true':
            return bool(field_value) == True
        elif operator == 'is_false':
            return bool(field_value) == False
        
        # String operators
        if isinstance(field_value, str):
            field_lower = field_value.lower()
            value_lower = value.lower()
            
            if operator == 'contains':
                return value_lower in field_lower
            elif operator == 'not_contains':
                return value_lower not in field_lower
            elif operator == 'equals':
                return field_lower == value_lower
            elif operator == 'not_equals':
                return field_lower != value_lower
            elif operator == 'starts_with':
                return field_lower.startswith(value_lower)
            elif operator == 'ends_with':
                return field_lower.endswith(value_lower)
            elif operator == 'regex':
                try:
                    return bool(re.search(value, field_value, re.IGNORECASE))
                except re.error:
                    return False
            elif operator == 'in_list':
                items = [i.strip().lower() for i in value.split(',')]
                return field_lower in items
            elif operator == 'similarity':
                # Simple Levenshtein-like check (could be enhanced)
                return self._fuzzy_match(field_lower, value_lower, threshold=0.8)
        
        # Number operators
        if isinstance(field_value, (int, float)):
            try:
                num_value = float(value)
                
                if operator == 'equals':
                    return field_value == num_value
                elif operator == 'not_equals':
                    return field_value != num_value
                elif operator == 'greater_than':
                    return field_value > num_value
                elif operator == 'less_than':
                    return field_value < num_value
                elif operator == 'greater_equal':
                    return field_value >= num_value
                elif operator == 'less_equal':
                    return field_value <= num_value
                elif operator == 'between':
                    num_value2 = float(value2) if value2 else num_value
                    return num_value <= field_value <= num_value2
            except (ValueError, TypeError):
                return False
        
        return False
    
    def _fuzzy_match(self, s1: str, s2: str, threshold: float = 0.8) -> bool:
        """Simple fuzzy string matching."""
        if not s1 or not s2:
            return False
        
        # Simple ratio based on common characters
        common = sum(1 for c in s1 if c in s2)
        ratio = (2.0 * common) / (len(s1) + len(s2))
        return ratio >= threshold


# Global instance
_field_evaluator: Optional[AdvancedFieldEvaluator] = None


def get_field_evaluator() -> AdvancedFieldEvaluator:
    """Get the field evaluator singleton."""
    global _field_evaluator
    if _field_evaluator is None:
        _field_evaluator = AdvancedFieldEvaluator()
    return _field_evaluator
