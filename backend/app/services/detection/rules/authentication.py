"""
NiksES Authentication Detection Rules

Rules for detecting email authentication failures and anomalies.
"""

from typing import Optional, List

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import RiskLevel

from .base import DetectionRule, RuleMatch, register_rule


@register_rule
class SPFFailRule(DetectionRule):
    """Detect SPF authentication failures."""
    
    rule_id = "AUTH-001"
    name = "SPF Failure"
    description = "Email failed SPF (Sender Policy Framework) authentication"
    category = "authentication"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        # Check header_analysis first, then legacy fields
        spf_result = None
        if email.header_analysis and email.header_analysis.spf_result:
            spf_result = email.header_analysis.spf_result
        elif email.spf_result:
            spf_result = email.spf_result
        
        if not spf_result:
            return None
        
        result_lower = spf_result.result.lower()
        
        if result_lower in ['fail', 'hardfail']:
            return self.create_match(
                evidence=[
                    f"SPF result: {spf_result.result}",
                    f"Domain: {spf_result.domain or 'unknown'}",
                ],
                indicators=[{
                    'type': 'spf_failure',
                    'domain': spf_result.domain,
                    'result': spf_result.result,
                }],
                severity_override=RiskLevel.HIGH,
            )
        elif result_lower == 'softfail':
            return self.create_match(
                evidence=[
                    f"SPF result: {spf_result.result}",
                    f"Domain: {spf_result.domain or 'unknown'}",
                ],
                indicators=[{
                    'type': 'spf_softfail',
                    'domain': spf_result.domain,
                    'result': spf_result.result,
                }],
            )
        
        return None


@register_rule
class DKIMFailRule(DetectionRule):
    """Detect DKIM authentication failures."""
    
    rule_id = "AUTH-002"
    name = "DKIM Failure"
    description = "Email failed DKIM (DomainKeys Identified Mail) authentication"
    category = "authentication"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        dkim_result = None
        if email.header_analysis and email.header_analysis.dkim_result:
            dkim_result = email.header_analysis.dkim_result
        elif email.dkim_result:
            dkim_result = email.dkim_result
        
        if not dkim_result:
            return None
        
        result_lower = dkim_result.result.lower()
        
        if result_lower in ['fail', 'hardfail', 'permerror']:
            return self.create_match(
                evidence=[
                    f"DKIM result: {dkim_result.result}",
                    f"Domain: {dkim_result.domain or 'unknown'}",
                    f"Selector: {dkim_result.selector or 'unknown'}",
                ],
                indicators=[{
                    'type': 'dkim_failure',
                    'domain': dkim_result.domain,
                    'selector': dkim_result.selector,
                    'result': dkim_result.result,
                }],
                severity_override=RiskLevel.HIGH,
            )
        
        return None


@register_rule
class DMARCFailRule(DetectionRule):
    """Detect DMARC authentication failures."""
    
    rule_id = "AUTH-003"
    name = "DMARC Failure"
    description = "Email failed DMARC (Domain-based Message Authentication) check"
    category = "authentication"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        dmarc_result = None
        if email.header_analysis and email.header_analysis.dmarc_result:
            dmarc_result = email.header_analysis.dmarc_result
        elif email.dmarc_result:
            dmarc_result = email.dmarc_result
        
        if not dmarc_result:
            return None
        
        result_lower = dmarc_result.result.lower()
        
        if result_lower in ['fail', 'reject', 'quarantine']:
            return self.create_match(
                evidence=[
                    f"DMARC result: {dmarc_result.result}",
                    f"Domain: {dmarc_result.domain or 'unknown'}",
                ],
                indicators=[{
                    'type': 'dmarc_failure',
                    'domain': dmarc_result.domain,
                    'result': dmarc_result.result,
                }],
            )
        
        return None


@register_rule
class NoAuthenticationRule(DetectionRule):
    """Detect emails with no authentication (no SPF, DKIM, or DMARC)."""
    
    rule_id = "AUTH-004"
    name = "No Email Authentication"
    description = "Email has no SPF, DKIM, or DMARC authentication records"
    category = "authentication"
    severity = RiskLevel.LOW
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        # Get all auth results
        auth_results = []
        if email.header_analysis and email.header_analysis.auth_results:
            auth_results = email.header_analysis.auth_results
        elif email.auth_results:
            auth_results = email.auth_results
        
        # Check for any authentication
        has_spf = email.spf_result is not None or (email.header_analysis and email.header_analysis.spf_result)
        has_dkim = email.dkim_result is not None or (email.header_analysis and email.header_analysis.dkim_result)
        has_dmarc = email.dmarc_result is not None or (email.header_analysis and email.header_analysis.dmarc_result)
        
        # Also check auth_results list
        for result in auth_results:
            mech = result.mechanism.lower()
            if 'spf' in mech:
                has_spf = True
            if 'dkim' in mech:
                has_dkim = True
            if 'dmarc' in mech:
                has_dmarc = True
        
        if not has_spf and not has_dkim and not has_dmarc:
            sender_domain = self.get_sender_domain(email)
            return self.create_match(
                evidence=[
                    "No SPF authentication found",
                    "No DKIM authentication found",
                    "No DMARC authentication found",
                    f"Sender domain: {sender_domain or 'unknown'}",
                ],
                indicators=[{
                    'type': 'no_authentication',
                    'sender_domain': sender_domain,
                }],
            )
        
        return None


@register_rule
class EnvelopeFromMismatchRule(DetectionRule):
    """Detect mismatch between envelope-from (Return-Path) and header From."""
    
    rule_id = "AUTH-005"
    name = "Envelope-From Mismatch"
    description = "Return-Path/envelope-from domain differs from header From domain"
    category = "authentication"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.sender or not email.envelope_from:
            return None
        
        sender_domain = email.sender.domain.lower() if email.sender.domain else None
        envelope_domain = email.envelope_from.domain.lower() if email.envelope_from.domain else None
        
        if not sender_domain or not envelope_domain:
            return None
        
        # Check if domains match (allowing subdomains of same parent)
        if sender_domain != envelope_domain:
            # Check if one is subdomain of other
            if not (sender_domain.endswith('.' + envelope_domain) or 
                    envelope_domain.endswith('.' + sender_domain)):
                return self.create_match(
                    evidence=[
                        f"From header domain: {sender_domain}",
                        f"Return-Path/Envelope-From domain: {envelope_domain}",
                        "Domain mismatch may indicate spoofing",
                    ],
                    indicators=[{
                        'type': 'envelope_mismatch',
                        'from_domain': sender_domain,
                        'envelope_domain': envelope_domain,
                    }],
                )
        
        return None


@register_rule
class ReplyToMismatchRule(DetectionRule):
    """Detect mismatch between Reply-To and From addresses."""
    
    rule_id = "AUTH-006"
    name = "Reply-To Mismatch"
    description = "Reply-To domain differs from From domain"
    category = "authentication"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.sender or not email.reply_to or len(email.reply_to) == 0:
            return None
        
        sender_domain = email.sender.domain.lower() if email.sender.domain else None
        reply_to_domain = email.reply_to[0].domain.lower() if email.reply_to[0].domain else None
        
        if not sender_domain or not reply_to_domain:
            return None
        
        if sender_domain != reply_to_domain:
            return self.create_match(
                evidence=[
                    f"From domain: {sender_domain}",
                    f"Reply-To domain: {reply_to_domain}",
                    "Replies will go to different domain than sender",
                ],
                indicators=[{
                    'type': 'reply_to_mismatch',
                    'from_domain': sender_domain,
                    'reply_to_domain': reply_to_domain,
                    'reply_to_email': email.reply_to[0].email,
                }],
            )
        
        return None


@register_rule
class MultipleAuthFailuresRule(DetectionRule):
    """Detect multiple authentication failures."""
    
    rule_id = "AUTH-007"
    name = "Multiple Authentication Failures"
    description = "Email failed multiple authentication checks (SPF, DKIM, and/or DMARC)"
    category = "authentication"
    severity = RiskLevel.HIGH
    mitre_technique = "T1566.001"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        failures = []
        
        # Check SPF
        spf_result = email.header_analysis.spf_result if email.header_analysis else email.spf_result
        if spf_result and spf_result.result.lower() in ['fail', 'hardfail', 'softfail']:
            failures.append(f"SPF: {spf_result.result}")
        
        # Check DKIM
        dkim_result = email.header_analysis.dkim_result if email.header_analysis else email.dkim_result
        if dkim_result and dkim_result.result.lower() in ['fail', 'hardfail', 'permerror']:
            failures.append(f"DKIM: {dkim_result.result}")
        
        # Check DMARC
        dmarc_result = email.header_analysis.dmarc_result if email.header_analysis else email.dmarc_result
        if dmarc_result and dmarc_result.result.lower() in ['fail', 'reject', 'quarantine']:
            failures.append(f"DMARC: {dmarc_result.result}")
        
        if len(failures) >= 2:
            return self.create_match(
                evidence=failures + ["Multiple authentication mechanisms failed"],
                indicators=[{
                    'type': 'multiple_auth_failures',
                    'failure_count': len(failures),
                    'failures': failures,
                }],
                severity_override=RiskLevel.CRITICAL if len(failures) >= 3 else RiskLevel.HIGH,
            )
        
        return None
