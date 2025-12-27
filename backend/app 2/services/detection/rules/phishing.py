"""
NiksES Phishing Detection Rules

Rules for detecting phishing indicators in emails.
"""

import re
from typing import Optional, List

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults, ThreatIntelVerdict
from app.models.detection import RiskLevel
from app.utils.constants import SHORTENER_DOMAINS, SUSPICIOUS_TLDS, FREEMAIL_DOMAINS

from .base import DetectionRule, RuleMatch, register_rule


# Phishing-related keywords
PHISHING_KEYWORDS = [
    'verify your account', 'confirm your identity', 'update your information',
    'click here immediately', 'your account has been compromised',
    'unusual activity', 'suspicious activity', 'unauthorized access',
    'reset your password', 'confirm your password', 'verify your password',
    'update payment', 'payment information', 'billing information',
    'action required', 'immediate action', 'urgent action',
    'account suspended', 'account will be closed', 'account terminated',
    'security alert', 'security warning', 'security notice',
    'verify within 24 hours', 'expires in 24 hours', 'limited time',
]

CREDENTIAL_KEYWORDS = [
    'enter your password', 'provide your credentials', 'login details',
    'sign in to verify', 'log in to confirm', 'enter your username',
    'social security', 'ssn', 'credit card number', 'bank account',
    'pin number', 'security code', 'cvv', 'routing number',
]


@register_rule
class MaliciousURLRule(DetectionRule):
    """Detect URLs flagged as malicious by threat intelligence."""
    
    rule_id = "PHISH-001"
    name = "Malicious URL Detected"
    description = "URL in email is flagged as malicious by threat intelligence sources"
    category = "phishing"
    severity = RiskLevel.CRITICAL
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.urls:
            return None
        
        malicious_urls = []
        for url_enrichment in enrichment.urls:
            if url_enrichment.final_verdict == ThreatIntelVerdict.MALICIOUS:
                malicious_urls.append({
                    'url': url_enrichment.url,
                    'domain': url_enrichment.domain,
                    'vt_positives': url_enrichment.virustotal_positives,
                    'urlhaus_status': url_enrichment.urlhaus_status,
                    'phishtank': url_enrichment.phishtank_verified,
                })
        
        if malicious_urls:
            evidence = [f"Found {len(malicious_urls)} malicious URL(s):"]
            for url in malicious_urls[:5]:  # Limit evidence to 5
                evidence.append(f"  - {url['url'][:100]}")
                if url.get('vt_positives'):
                    evidence.append(f"    VirusTotal: {url['vt_positives']} detections")
                if url.get('phishtank'):
                    evidence.append(f"    PhishTank: Verified phishing")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'malicious_url',
                    **url
                } for url in malicious_urls],
            )
        
        return None


@register_rule
class SuspiciousURLRule(DetectionRule):
    """Detect URLs flagged as suspicious by threat intelligence."""
    
    rule_id = "PHISH-002"
    name = "Suspicious URL Detected"
    description = "URL in email is flagged as suspicious by threat intelligence"
    category = "phishing"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.urls:
            return None
        
        suspicious_urls = []
        for url_enrichment in enrichment.urls:
            if url_enrichment.final_verdict == ThreatIntelVerdict.SUSPICIOUS:
                suspicious_urls.append({
                    'url': url_enrichment.url,
                    'domain': url_enrichment.domain,
                })
        
        if suspicious_urls:
            evidence = [f"Found {len(suspicious_urls)} suspicious URL(s):"]
            for url in suspicious_urls[:5]:
                evidence.append(f"  - {url['url'][:100]}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'suspicious_url',
                    **url
                } for url in suspicious_urls],
            )
        
        return None


@register_rule
class URLShortenerRule(DetectionRule):
    """Detect use of URL shortening services."""
    
    rule_id = "PHISH-003"
    name = "URL Shortener Used"
    description = "Email contains URLs from URL shortening services"
    category = "phishing"
    severity = RiskLevel.LOW
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        shortened_urls = []
        
        for url in email.urls:
            if url.is_shortened or (url.domain and url.domain.lower() in SHORTENER_DOMAINS):
                shortened_urls.append({
                    'url': url.url,
                    'domain': url.domain,
                    'source': url.source,
                })
        
        if shortened_urls:
            evidence = [
                f"Found {len(shortened_urls)} shortened URL(s)",
                "Shortened URLs can hide malicious destinations",
            ]
            for url in shortened_urls[:3]:
                evidence.append(f"  - {url['url']}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'shortened_url',
                    **url
                } for url in shortened_urls],
            )
        
        return None


@register_rule
class SuspiciousTLDRule(DetectionRule):
    """Detect URLs with suspicious top-level domains."""
    
    rule_id = "PHISH-004"
    name = "Suspicious TLD in URL"
    description = "URL uses a suspicious top-level domain often associated with abuse"
    category = "phishing"
    severity = RiskLevel.LOW
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        suspicious_urls = []
        
        for url in email.urls:
            if url.domain:
                for tld in SUSPICIOUS_TLDS:
                    if url.domain.lower().endswith(tld):
                        suspicious_urls.append({
                            'url': url.url,
                            'domain': url.domain,
                            'tld': tld,
                        })
                        break
        
        if suspicious_urls:
            evidence = [f"Found {len(suspicious_urls)} URL(s) with suspicious TLDs:"]
            for url in suspicious_urls[:3]:
                evidence.append(f"  - {url['domain']} ({url['tld']})")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'suspicious_tld',
                    **url
                } for url in suspicious_urls],
            )
        
        return None


@register_rule
class PhishingKeywordsRule(DetectionRule):
    """Detect common phishing language in email content."""
    
    rule_id = "PHISH-005"
    name = "Phishing Language Detected"
    description = "Email contains language commonly used in phishing attacks"
    category = "phishing"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found_keywords = []
        for keyword in PHISHING_KEYWORDS:
            if keyword.lower() in body_text:
                found_keywords.append(keyword)
        
        if len(found_keywords) >= 2:  # Require multiple keywords
            severity = RiskLevel.HIGH if len(found_keywords) >= 4 else RiskLevel.MEDIUM
            
            return self.create_match(
                evidence=[
                    f"Found {len(found_keywords)} phishing indicators:",
                ] + [f"  - '{kw}'" for kw in found_keywords[:5]],
                indicators=[{
                    'type': 'phishing_keyword',
                    'keyword': kw,
                } for kw in found_keywords],
                severity_override=severity,
            )
        
        return None


@register_rule
class CredentialHarvestingRule(DetectionRule):
    """Detect credential harvesting attempts."""
    
    rule_id = "PHISH-006"
    name = "Credential Harvesting Attempt"
    description = "Email appears to request sensitive credentials or personal information"
    category = "phishing"
    severity = RiskLevel.HIGH
    mitre_technique = "T1598.003"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found_keywords = []
        for keyword in CREDENTIAL_KEYWORDS:
            if keyword.lower() in body_text:
                found_keywords.append(keyword)
        
        # Check for forms in HTML
        has_form = False
        if email.body_html:
            html_lower = email.body_html.lower()
            has_form = '<form' in html_lower or '<input type="password"' in html_lower
        
        if len(found_keywords) >= 1 or (has_form and len(found_keywords) >= 1):
            severity = RiskLevel.CRITICAL if has_form else RiskLevel.HIGH
            
            evidence = [f"Credential harvesting indicators detected:"]
            evidence.extend([f"  - '{kw}'" for kw in found_keywords[:3]])
            if has_form:
                evidence.append("  - HTML form with input fields detected")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'credential_harvesting',
                    'keywords': found_keywords,
                    'has_form': has_form,
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class ExternalFormActionRule(DetectionRule):
    """Detect HTML forms with external action URLs."""
    
    rule_id = "PHISH-007"
    name = "External Form Action"
    description = "HTML form submits to an external or suspicious URL"
    category = "phishing"
    severity = RiskLevel.HIGH
    mitre_technique = "T1598.003"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.body_html:
            return None
        
        # Find form action URLs
        form_pattern = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.IGNORECASE)
        matches = form_pattern.findall(email.body_html)
        
        external_actions = []
        sender_domain = self.get_sender_domain(email)
        
        for action_url in matches:
            if action_url.startswith(('http://', 'https://')):
                # Extract domain from action URL
                try:
                    from urllib.parse import urlparse
                    action_domain = urlparse(action_url).netloc.lower()
                    
                    # Check if external
                    if sender_domain and action_domain != sender_domain:
                        external_actions.append({
                            'action_url': action_url,
                            'action_domain': action_domain,
                        })
                except Exception:
                    pass
        
        if external_actions:
            evidence = ["HTML form(s) submit to external URLs:"]
            for action in external_actions:
                evidence.append(f"  - {action['action_url'][:100]}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'external_form_action',
                    **action
                } for action in external_actions],
            )
        
        return None


@register_rule
class NewlyRegisteredDomainRule(DetectionRule):
    """Detect sender from newly registered domain."""
    
    rule_id = "PHISH-008"
    name = "Newly Registered Sender Domain"
    description = "Sender domain was registered recently (within 30 days)"
    category = "phishing"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1583.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.sender_domain:
            return None
        
        domain_info = enrichment.sender_domain
        
        if domain_info.is_newly_registered:
            return self.create_match(
                evidence=[
                    f"Sender domain: {domain_info.domain}",
                    f"Domain age: {domain_info.age_days} days",
                    f"Registrar: {domain_info.registrar or 'unknown'}",
                    "Newly registered domains are commonly used in phishing",
                ],
                indicators=[{
                    'type': 'newly_registered_domain',
                    'domain': domain_info.domain,
                    'age_days': domain_info.age_days,
                    'registrar': domain_info.registrar,
                }],
            )
        
        return None


@register_rule
class MaliciousSenderDomainRule(DetectionRule):
    """Detect sender from malicious domain."""
    
    rule_id = "PHISH-009"
    name = "Malicious Sender Domain"
    description = "Sender domain is flagged as malicious by threat intelligence"
    category = "phishing"
    severity = RiskLevel.CRITICAL
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.sender_domain:
            return None
        
        domain_info = enrichment.sender_domain
        
        if domain_info.virustotal_verdict == ThreatIntelVerdict.MALICIOUS:
            return self.create_match(
                evidence=[
                    f"Sender domain: {domain_info.domain}",
                    "Domain flagged as malicious by VirusTotal",
                ],
                indicators=[{
                    'type': 'malicious_sender_domain',
                    'domain': domain_info.domain,
                    'vt_stats': domain_info.virustotal_stats,
                }],
            )
        
        if domain_info.is_known_phishing:
            return self.create_match(
                evidence=[
                    f"Sender domain: {domain_info.domain}",
                    "Domain is known for phishing",
                ],
                indicators=[{
                    'type': 'known_phishing_domain',
                    'domain': domain_info.domain,
                }],
            )
        
        return None


@register_rule
class NoMXRecordRule(DetectionRule):
    """Detect sender domain with no MX records."""
    
    rule_id = "PHISH-010"
    name = "Sender Domain Has No MX Records"
    description = "Sender domain has no mail exchange (MX) records configured"
    category = "phishing"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1583.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not enrichment or not enrichment.sender_domain:
            return None
        
        domain_info = enrichment.sender_domain
        
        # Skip freemail domains - they definitely have MX
        sender_domain = self.get_sender_domain(email)
        if sender_domain and sender_domain in FREEMAIL_DOMAINS:
            return None
        
        if not domain_info.has_mx_records:
            return self.create_match(
                evidence=[
                    f"Sender domain: {domain_info.domain}",
                    "No MX records found",
                    "Legitimate sending domains should have MX records",
                ],
                indicators=[{
                    'type': 'no_mx_records',
                    'domain': domain_info.domain,
                }],
            )
        
        return None
