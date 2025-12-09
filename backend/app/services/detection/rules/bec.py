"""
NiksES Business Email Compromise (BEC) Detection Rules

Rules for detecting BEC attacks including executive impersonation,
wire transfer fraud, and invoice manipulation.
"""

import re
from typing import Optional, List

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import RiskLevel
from app.utils.constants import FREEMAIL_DOMAINS, BEC_KEYWORDS, AUTHORITY_KEYWORDS

from .base import DetectionRule, RuleMatch, register_rule


# Executive titles for impersonation detection
EXECUTIVE_TITLES = [
    'ceo', 'cfo', 'cto', 'coo', 'cio', 'ciso',
    'chief executive', 'chief financial', 'chief technology',
    'chief operating', 'chief information', 'chief security',
    'president', 'vice president', 'vp', 'evp', 'svp',
    'managing director', 'executive director', 'director',
    'chairman', 'board member', 'partner', 'founder',
    'owner', 'principal', 'general manager', 'gm',
]

# Wire transfer / payment keywords
WIRE_TRANSFER_KEYWORDS = [
    'wire transfer', 'bank transfer', 'payment', 'invoice',
    'routing number', 'account number', 'swift code', 'iban',
    'ach transfer', 'bank details', 'payment details',
    'transfer funds', 'send money', 'remittance',
    'vendor payment', 'supplier payment', 'urgent payment',
    'update banking', 'new bank account', 'change bank',
]

# Gift card keywords
GIFT_CARD_KEYWORDS = [
    'gift card', 'gift cards', 'itunes card', 'google play card',
    'amazon card', 'steam card', 'ebay card', 'visa gift',
    'prepaid card', 'scratch off', 'activation code',
    'send the codes', 'email the codes', 'purchase gift',
]

# Confidentiality requests
CONFIDENTIALITY_KEYWORDS = [
    'keep this confidential', 'between us', 'don\'t tell anyone',
    'keep quiet', 'secret', 'discreet', 'private matter',
    'confidential transaction', 'off the books', 'sensitive matter',
]


@register_rule
class ExecutiveImpersonationRule(DetectionRule):
    """Detect executive title in display name with non-corporate email."""
    
    rule_id = "BEC-001"
    name = "Executive Impersonation"
    description = "Sender claims executive title but uses freemail or suspicious domain"
    category = "bec"
    severity = RiskLevel.HIGH
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        if not email.sender:
            return None
        
        display_name = (email.sender.display_name or '').lower()
        sender_domain = self.get_sender_domain(email)
        
        if not display_name or not sender_domain:
            return None
        
        # Check for executive title
        found_title = None
        for title in EXECUTIVE_TITLES:
            if title in display_name:
                found_title = title
                break
        
        if found_title and sender_domain in FREEMAIL_DOMAINS:
            return self.create_match(
                evidence=[
                    f"Display name: {email.sender.display_name}",
                    f"Executive title detected: {found_title}",
                    f"Sender using freemail: {sender_domain}",
                    "Legitimate executives typically use corporate email",
                ],
                indicators=[{
                    'type': 'executive_impersonation',
                    'display_name': email.sender.display_name,
                    'title_found': found_title,
                    'email_domain': sender_domain,
                }],
                severity_override=RiskLevel.CRITICAL,
            )
        
        return None


@register_rule
class WireTransferRequestRule(DetectionRule):
    """Detect wire transfer or payment requests."""
    
    rule_id = "BEC-002"
    name = "Wire Transfer Request"
    description = "Email requests wire transfer, payment, or banking changes"
    category = "bec"
    severity = RiskLevel.HIGH
    mitre_technique = "T1657"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        # Import whitelist
        from app.utils.constants import LEGITIMATE_FINANCIAL_DOMAINS
        
        # Skip if sender is from a legitimate financial institution
        sender_domain = email.sender.domain.lower() if email.sender and email.sender.domain else ''
        if any(legit in sender_domain for legit in LEGITIMATE_FINANCIAL_DOMAINS):
            # Legitimate bank sending payment info is expected behavior
            return None
        
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found_keywords = []
        for keyword in WIRE_TRANSFER_KEYWORDS:
            if keyword in body_text:
                found_keywords.append(keyword)
        
        if len(found_keywords) >= 2:
            severity = RiskLevel.CRITICAL if len(found_keywords) >= 4 else RiskLevel.HIGH
            
            return self.create_match(
                evidence=[
                    f"Found {len(found_keywords)} wire transfer/payment indicators:",
                ] + [f"  - '{kw}'" for kw in found_keywords[:5]],
                indicators=[{
                    'type': 'wire_transfer_request',
                    'keywords': found_keywords,
                }],
                severity_override=severity,
            )
        
        return None


@register_rule
class GiftCardScamRule(DetectionRule):
    """Detect gift card scam requests."""
    
    rule_id = "BEC-003"
    name = "Gift Card Request"
    description = "Email requests purchase of gift cards"
    category = "bec"
    severity = RiskLevel.HIGH
    mitre_technique = "T1657"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found_keywords = []
        for keyword in GIFT_CARD_KEYWORDS:
            if keyword in body_text:
                found_keywords.append(keyword)
        
        if found_keywords:
            return self.create_match(
                evidence=[
                    "Gift card request detected",
                    f"Keywords found: {', '.join(found_keywords[:3])}",
                    "Gift card requests are a common BEC tactic",
                ],
                indicators=[{
                    'type': 'gift_card_scam',
                    'keywords': found_keywords,
                }],
            )
        
        return None


@register_rule
class ConfidentialityRequestRule(DetectionRule):
    """Detect suspicious confidentiality requests."""
    
    rule_id = "BEC-004"
    name = "Confidentiality Request"
    description = "Email requests secrecy or confidential handling"
    category = "bec"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        found_keywords = []
        for keyword in CONFIDENTIALITY_KEYWORDS:
            if keyword in body_text:
                found_keywords.append(keyword)
        
        if found_keywords:
            return self.create_match(
                evidence=[
                    "Confidentiality request detected",
                    f"Phrases found: {', '.join(found_keywords[:3])}",
                    "Secrecy requests are used to bypass verification",
                ],
                indicators=[{
                    'type': 'confidentiality_request',
                    'keywords': found_keywords,
                }],
            )
        
        return None


@register_rule
class FreemailToBusinessRule(DetectionRule):
    """Detect freemail sender to business recipient."""
    
    rule_id = "BEC-005"
    name = "Freemail to Business"
    description = "Email from freemail account to what appears to be business recipient"
    category = "bec"
    severity = RiskLevel.LOW
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        sender_domain = self.get_sender_domain(email)
        
        if not sender_domain or sender_domain not in FREEMAIL_DOMAINS:
            return None
        
        # Check if any recipient is non-freemail
        business_recipients = []
        for recipient in email.to_recipients + email.cc_recipients:
            if recipient.domain and recipient.domain.lower() not in FREEMAIL_DOMAINS:
                business_recipients.append(recipient.email)
        
        if business_recipients:
            return self.create_match(
                evidence=[
                    f"Sender using freemail: {sender_domain}",
                    f"Business recipient(s): {', '.join(business_recipients[:3])}",
                    "Business-related requests from freemail can indicate BEC",
                ],
                indicators=[{
                    'type': 'freemail_to_business',
                    'sender_domain': sender_domain,
                    'business_recipients': business_recipients,
                }],
            )
        
        return None


@register_rule
class InvoiceModificationRule(DetectionRule):
    """Detect invoice/payment modification language."""
    
    rule_id = "BEC-006"
    name = "Invoice Modification Request"
    description = "Email requests changes to invoices or payment details"
    category = "bec"
    severity = RiskLevel.HIGH
    mitre_technique = "T1657"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        # Look for invoice + change patterns
        modification_patterns = [
            r'updat(e|ed|ing)\s+(the\s+)?invoice',
            r'chang(e|ed|ing)\s+(the\s+)?bank',
            r'new\s+bank\s+account',
            r'revised\s+invoice',
            r'correct(ed)?\s+invoice',
            r'updated?\s+payment\s+details',
            r'new\s+payment\s+instructions',
        ]
        
        found_patterns = []
        for pattern in modification_patterns:
            if re.search(pattern, body_text):
                found_patterns.append(pattern)
        
        if found_patterns:
            return self.create_match(
                evidence=[
                    "Invoice/payment modification language detected",
                    f"Pattern matches: {len(found_patterns)}",
                    "Attackers modify invoices to redirect payments",
                ],
                indicators=[{
                    'type': 'invoice_modification',
                    'patterns_matched': len(found_patterns),
                }],
            )
        
        return None


@register_rule
class UrgentPaymentRule(DetectionRule):
    """Detect urgent payment requests combining urgency with financial action."""
    
    rule_id = "BEC-007"
    name = "Urgent Payment Request"
    description = "Email combines urgency with payment/wire transfer request"
    category = "bec"
    severity = RiskLevel.HIGH
    mitre_technique = "T1657"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        # Import whitelist
        from app.utils.constants import LEGITIMATE_FINANCIAL_DOMAINS
        
        # Skip if sender is from a legitimate financial institution
        sender_domain = email.sender.domain.lower() if email.sender and email.sender.domain else ''
        if any(legit in sender_domain for legit in LEGITIMATE_FINANCIAL_DOMAINS):
            # Legitimate bank may send urgent payment info legitimately
            return None
        
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        # Check for urgency
        urgency_keywords = [
            'urgent', 'immediately', 'asap', 'right away', 'as soon as possible',
            'today', 'by end of day', 'time sensitive', 'critical',
        ]
        
        has_urgency = any(kw in body_text for kw in urgency_keywords)
        
        # Check for payment
        has_payment = any(kw in body_text for kw in WIRE_TRANSFER_KEYWORDS[:10])
        
        if has_urgency and has_payment:
            return self.create_match(
                evidence=[
                    "Urgent payment request detected",
                    "Combines urgency language with payment/transfer request",
                    "This is a common BEC attack pattern",
                ],
                indicators=[{
                    'type': 'urgent_payment',
                    'has_urgency': True,
                    'has_payment': True,
                }],
            )
        
        return None


@register_rule
class VendorImpersonationRule(DetectionRule):
    """Detect potential vendor impersonation."""
    
    rule_id = "BEC-008"
    name = "Vendor Impersonation"
    description = "Email appears to impersonate a vendor with payment focus"
    category = "bec"
    severity = RiskLevel.MEDIUM
    mitre_technique = "T1656"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        # Vendor impersonation patterns
        vendor_keywords = [
            'as your vendor', 'valued vendor', 'vendor update',
            'supplier notification', 'as your supplier',
            'our banking information has changed',
            'update your records', 'accounts payable',
            'remit payment to', 'send payment to new',
        ]
        
        found = []
        for kw in vendor_keywords:
            if kw in body_text:
                found.append(kw)
        
        if len(found) >= 2:
            return self.create_match(
                evidence=[
                    "Potential vendor impersonation detected",
                    f"Keywords: {', '.join(found[:3])}",
                    "Verify banking changes through known contact methods",
                ],
                indicators=[{
                    'type': 'vendor_impersonation',
                    'keywords': found,
                }],
            )
        
        return None


@register_rule
class PayrollDiversionRule(DetectionRule):
    """Detect payroll diversion attempts."""
    
    rule_id = "BEC-009"
    name = "Payroll Diversion Attempt"
    description = "Email requests changes to direct deposit or payroll information"
    category = "bec"
    severity = RiskLevel.HIGH
    mitre_technique = "T1657"
    
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        body_text = self.get_body_text(email)
        
        if not body_text:
            return None
        
        payroll_patterns = [
            'direct deposit', 'payroll', 'my bank account',
            'update my banking', 'change my payment',
            'new bank for salary', 'paycheck', 'salary deposit',
            'dd form', 'w4', 'w-4',
        ]
        
        found = []
        for pattern in payroll_patterns:
            if pattern in body_text:
                found.append(pattern)
        
        if len(found) >= 2:
            return self.create_match(
                evidence=[
                    "Payroll/direct deposit change request detected",
                    f"Keywords: {', '.join(found[:3])}",
                    "Payroll changes should be verified in person",
                ],
                indicators=[{
                    'type': 'payroll_diversion',
                    'keywords': found,
                }],
            )
        
        return None
