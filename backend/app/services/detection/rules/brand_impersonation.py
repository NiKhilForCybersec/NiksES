"""
NiksES Brand Impersonation Detection Rules

Detection rules for brand spoofing and domain impersonation.
"""

import re
import logging
from typing import Optional, List, Tuple

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import RiskLevel
from app.utils.constants import BRAND_TARGETS

from .base import DetectionRule, RuleMatch, register_rule

logger = logging.getLogger(__name__)


# =============================================================================
# BRAND IMPERSONATION RULES
# =============================================================================

@register_rule
class BrandKeywordMismatchRule(DetectionRule):
    """
    Detect emails that mention a brand but aren't sent from that brand's domain.
    
    Example: Email mentions "Microsoft", "Office 365", "OneDrive" but sender
    is from gmail.com or some random domain - clear impersonation attempt.
    """
    
    rule_id = "BRAND-001"
    name = "Brand Impersonation"
    description = "Email impersonates a known brand (mentions brand but sender domain doesn't match)"
    category = "brand_impersonation"
    severity = RiskLevel.HIGH
    mitre_technique = "T1656"  # Impersonation
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        # Get sender domain
        sender_domain = self.get_sender_domain(email)
        if not sender_domain:
            return None
        
        # Get combined text to search
        body_text = self.get_body_text(email)
        if not body_text:
            return None
        
        # Also check sender display name
        sender_name = ""
        if email.sender and email.sender.display_name:
            sender_name = email.sender.display_name.lower()
        
        # Check each brand
        impersonated_brands = []
        
        for brand_id, brand_info in BRAND_TARGETS.items():
            brand_name = brand_info["name"]
            keywords = brand_info["keywords"]
            legitimate_domains = brand_info["legitimate_domains"]
            
            # Is sender from legitimate domain for this brand?
            is_legitimate = any(
                sender_domain == legit or sender_domain.endswith(f".{legit}")
                for legit in legitimate_domains
            )
            
            if is_legitimate:
                continue  # Sender is legitimate, no impersonation
            
            # Check if email mentions this brand
            keyword_matches = []
            for keyword in keywords:
                if keyword.lower() in body_text or keyword.lower() in sender_name:
                    keyword_matches.append(keyword)
            
            # Also check display name for brand name
            if brand_name.lower() in sender_name:
                keyword_matches.append(brand_name)
            
            # If 2+ brand keywords found but sender isn't from brand domain
            if len(keyword_matches) >= 2:
                impersonated_brands.append({
                    'brand': brand_name,
                    'keywords_found': keyword_matches,
                    'sender_domain': sender_domain,
                    'legitimate_domains': legitimate_domains[:3],
                })
        
        if impersonated_brands:
            # Take the brand with most keyword matches
            top_brand = max(impersonated_brands, key=lambda x: len(x['keywords_found']))
            
            evidence = [
                f"Brand impersonation detected: {top_brand['brand']}",
                f"Sender domain: {top_brand['sender_domain']}",
                f"Legitimate {top_brand['brand']} domains: {', '.join(top_brand['legitimate_domains'])}",
                f"Brand keywords found: {', '.join(top_brand['keywords_found'][:5])}",
            ]
            
            # Critical if display name contains brand
            severity = RiskLevel.CRITICAL if top_brand['brand'].lower() in sender_name else RiskLevel.HIGH
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'brand_impersonation',
                    'brand': top_brand['brand'],
                    'sender_domain': top_brand['sender_domain'],
                    'keywords': top_brand['keywords_found'],
                }],
                severity_override=severity,
            )
        
        return None


@register_rule  
class DisplayNameSpoofRule(DetectionRule):
    """
    Detect display name spoofing where display name contains brand/company
    but email address is from a different domain.
    
    Example: "Microsoft Support <support@evil-domain.xyz>"
    """
    
    rule_id = "BRAND-002"
    name = "Display Name Spoofing"
    description = "Sender display name contains brand/organization but email domain doesn't match"
    category = "brand_impersonation"
    severity = RiskLevel.HIGH
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.sender:
            return None
        
        display_name = email.sender.display_name or ""
        sender_domain = email.sender.domain or ""
        
        if not display_name or not sender_domain:
            return None
        
        display_name_lower = display_name.lower()
        sender_domain_lower = sender_domain.lower()
        
        # Check for brand names in display name
        for brand_id, brand_info in BRAND_TARGETS.items():
            brand_name = brand_info["name"].lower()
            legitimate_domains = [d.lower() for d in brand_info["legitimate_domains"]]
            
            # Does display name contain brand?
            if brand_name in display_name_lower:
                # Is sender from legitimate domain?
                is_legitimate = any(
                    sender_domain_lower == legit or sender_domain_lower.endswith(f".{legit}")
                    for legit in legitimate_domains
                )
                
                if not is_legitimate:
                    return self.create_match(
                        evidence=[
                            f"Display name spoofing detected",
                            f"Display name: '{display_name}'",
                            f"Actual sender domain: {sender_domain}",
                            f"Expected domains for {brand_info['name']}: {', '.join(legitimate_domains[:3])}",
                        ],
                        indicators=[{
                            'type': 'display_name_spoof',
                            'display_name': display_name,
                            'claimed_brand': brand_info['name'],
                            'actual_domain': sender_domain,
                        }],
                        severity_override=RiskLevel.CRITICAL,
                    )
        
        return None


@register_rule
class SenderDomainMismatchRule(DetectionRule):
    """
    Detect mismatch between envelope From and header From domains,
    or between display name organization and sender domain.
    """
    
    rule_id = "BRAND-003"
    name = "Sender Domain Mismatch"
    description = "Email shows signs of sender spoofing or domain mismatch"
    category = "brand_impersonation"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        mismatches = []
        
        # Check From vs Envelope-From
        if email.sender and email.envelope_from:
            from_domain = email.sender.domain or ""
            envelope_domain = email.envelope_from.domain or ""
            
            if from_domain and envelope_domain and from_domain.lower() != envelope_domain.lower():
                mismatches.append({
                    'type': 'header_envelope_mismatch',
                    'from_domain': from_domain,
                    'envelope_domain': envelope_domain,
                })
        
        # Check From vs Reply-To
        if email.sender and email.reply_to:
            from_domain = email.sender.domain or ""
            for reply_addr in email.reply_to:
                reply_domain = reply_addr.domain or ""
                if reply_domain and from_domain.lower() != reply_domain.lower():
                    mismatches.append({
                        'type': 'from_replyto_mismatch',
                        'from_domain': from_domain,
                        'reply_to_domain': reply_domain,
                    })
                    break
        
        if mismatches:
            evidence = ["Sender domain mismatch detected:"]
            for m in mismatches:
                if m['type'] == 'header_envelope_mismatch':
                    evidence.append(f"  - From domain: {m['from_domain']}")
                    evidence.append(f"  - Envelope domain: {m['envelope_domain']}")
                elif m['type'] == 'from_replyto_mismatch':
                    evidence.append(f"  - From domain: {m['from_domain']}")
                    evidence.append(f"  - Reply-To domain: {m['reply_to_domain']}")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'sender_mismatch',
                    'mismatches': mismatches,
                }],
            )
        
        return None


@register_rule
class FakeSecurityAlertRule(DetectionRule):
    """
    Detect fake security alerts that impersonate tech companies.
    
    Common patterns:
    - "Your account has been compromised"
    - "Unusual sign-in activity"  
    - "Verify your identity"
    Combined with non-legitimate sender domains.
    """
    
    rule_id = "BRAND-004"
    name = "Fake Security Alert"
    description = "Email appears to be a fake security alert impersonating a service provider"
    category = "brand_impersonation"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    # Security alert phrases commonly used in phishing
    SECURITY_ALERT_PHRASES = [
        "unusual sign-in",
        "unusual activity",
        "suspicious activity",
        "security alert",
        "security notice",
        "your account has been",
        "account compromised",
        "unauthorized access",
        "verify your identity",
        "verify your account",
        "confirm your identity",
        "action required",
        "immediate action",
        "account suspended",
        "account limited",
        "account restricted",
        "limited state",
        "verify your information",
        "update your information",
        "confirm your information",
        "restore full access",
    ]
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        # Find security alert phrases
        found_phrases = []
        for phrase in self.SECURITY_ALERT_PHRASES:
            if phrase in body_text:
                found_phrases.append(phrase)
        
        if len(found_phrases) < 2:
            return None  # Not enough security alert language
        
        # Check if it mentions a brand
        mentioned_brand = None
        for brand_id, brand_info in BRAND_TARGETS.items():
            for keyword in brand_info["keywords"]:
                if keyword.lower() in body_text:
                    mentioned_brand = brand_info
                    break
            if mentioned_brand:
                break
        
        if not mentioned_brand:
            return None  # No brand mentioned
        
        # Is sender from legitimate domain?
        is_legitimate = False
        if sender_domain:
            legitimate_domains = [d.lower() for d in mentioned_brand["legitimate_domains"]]
            is_legitimate = any(
                sender_domain == legit or sender_domain.endswith(f".{legit}")
                for legit in legitimate_domains
            )
        
        if is_legitimate:
            return None  # Actually from the brand
        
        # This looks like a fake security alert
        evidence = [
            f"Fake security alert detected",
            f"Claims to be from: {mentioned_brand['name']}",
            f"Actual sender domain: {sender_domain or 'unknown'}",
            f"Security phrases found: {', '.join(found_phrases[:4])}",
        ]
        
        return self.create_match(
            evidence=evidence,
            indicators=[{
                'type': 'fake_security_alert',
                'claimed_brand': mentioned_brand['name'],
                'sender_domain': sender_domain,
                'alert_phrases': found_phrases,
            }],
            severity_override=RiskLevel.CRITICAL,
        )


@register_rule
class LookalikeURLRule(DetectionRule):
    """
    Detect URLs that appear to impersonate legitimate services
    using lookalike domains.
    
    Example: account-microsoft-verify-login.xyz instead of microsoft.com
    """
    
    rule_id = "BRAND-005"
    name = "Lookalike URL Detected"
    description = "Email contains URLs with domains designed to look like legitimate services"
    category = "brand_impersonation"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.002"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.urls:
            return None
        
        lookalike_urls = []
        
        for url_info in email.urls:
            url_domain = url_info.domain.lower() if url_info.domain else ""
            
            if not url_domain:
                continue
            
            # Check if domain contains brand keywords but isn't the real brand
            for brand_id, brand_info in BRAND_TARGETS.items():
                brand_name = brand_info["name"].lower()
                legitimate_domains = [d.lower() for d in brand_info["legitimate_domains"]]
                
                # Is this a legitimate domain for the brand?
                is_legitimate = any(
                    url_domain == legit or url_domain.endswith(f".{legit}")
                    for legit in legitimate_domains
                )
                
                if is_legitimate:
                    continue
                
                # Does domain contain brand name or keywords?
                brand_in_domain = brand_name in url_domain
                keyword_in_domain = any(
                    kw.lower() in url_domain 
                    for kw in brand_info["keywords"][:3]
                )
                
                if brand_in_domain or keyword_in_domain:
                    lookalike_urls.append({
                        'url': url_info.url,
                        'domain': url_domain,
                        'impersonating': brand_info['name'],
                    })
                    break
        
        if lookalike_urls:
            evidence = ["Lookalike URLs detected:"]
            for lookalike in lookalike_urls[:3]:
                evidence.append(f"  - {lookalike['domain']} (impersonating {lookalike['impersonating']})")
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'lookalike_url',
                    'urls': lookalike_urls,
                }],
                severity_override=RiskLevel.CRITICAL if len(lookalike_urls) >= 2 else RiskLevel.HIGH,
            )
        
        return None


@register_rule
class UrgencyWithDeadlineRule(DetectionRule):
    """
    Detect specific time-based urgency (24 hours, 48 hours, etc.)
    combined with threats - a classic phishing pattern.
    """
    
    rule_id = "BRAND-006"
    name = "Time-Limited Threat"
    description = "Email threatens consequences within a specific deadline"
    category = "social_engineering"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    # Time-based urgency patterns
    TIME_PATTERNS = [
        r'\b\d+\s*hours?\b',
        r'\b24\s*hours?\b',
        r'\b48\s*hours?\b',
        r'\b72\s*hours?\b',
        r'\bwithin\s+\d+\s*(?:hour|day|minute)',
        r'\bexpire[sd]?\s+(?:in|within)',
    ]
    
    # Threat/consequence words
    THREAT_WORDS = [
        "permanently",
        "suspended",
        "restricted",
        "terminated",
        "closed",
        "deleted",
        "locked",
        "disabled",
        "blocked",
        "lose access",
        "lost forever",
    ]
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        # Find time-based urgency
        found_time_refs = []
        for pattern in self.TIME_PATTERNS:
            matches = re.findall(pattern, body_text, re.IGNORECASE)
            found_time_refs.extend(matches)
        
        # Find threat words
        found_threats = []
        for threat in self.THREAT_WORDS:
            if threat in body_text:
                found_threats.append(threat)
        
        # Both time pressure AND threats = high confidence phishing
        if found_time_refs and found_threats:
            evidence = [
                "Time-limited threat detected (classic phishing pattern)",
                f"Deadline mentioned: {', '.join(found_time_refs[:2])}",
                f"Consequences threatened: {', '.join(found_threats[:3])}",
            ]
            
            return self.create_match(
                evidence=evidence,
                indicators=[{
                    'type': 'urgency_threat',
                    'time_references': found_time_refs,
                    'threats': found_threats,
                }],
                severity_override=RiskLevel.HIGH,
            )
        
        return None
