"""
NiksES Content Deconstruction Analyzer

Deep semantic analysis of email content using LLM.
Extracts structured fields about intent, requested actions, 
target data, and attack patterns.

Uses DYNAMIC authentication-based brand validation:
- No hardcoded brand lists needed
- Uses SPF/DKIM/DMARC as source of truth
- Automatically works for any brand
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from app.models.email import ParsedEmail

logger = logging.getLogger(__name__)


class AttackIntent(str, Enum):
    """Classification of attack intent."""
    CREDENTIAL_HARVEST = "credential_harvest"
    PAYMENT_FRAUD = "payment_fraud"
    MALWARE_DELIVERY = "malware_delivery"
    DATA_THEFT = "data_theft"
    ACCOUNT_TAKEOVER = "account_takeover"
    BUSINESS_EMAIL_COMPROMISE = "bec"
    INVOICE_FRAUD = "invoice_fraud"
    GIFT_CARD_SCAM = "gift_card_scam"
    CALLBACK_PHISHING = "callback_phishing"
    RECONNAISSANCE = "reconnaissance"
    SPAM = "spam"
    MARKETING = "marketing"
    LEGITIMATE = "legitimate"
    UNKNOWN = "unknown"


class RequestedAction(str, Enum):
    """What the attacker wants the victim to do."""
    CLICK_LINK = "click_link"
    OPEN_ATTACHMENT = "open_attachment"
    REPLY_WITH_INFO = "reply_with_info"
    CALL_NUMBER = "call_number"
    SEND_PAYMENT = "send_payment"
    PURCHASE_GIFT_CARDS = "purchase_gift_cards"
    CHANGE_PAYMENT_DETAILS = "change_payment_details"
    DOWNLOAD_FILE = "download_file"
    ENABLE_MACROS = "enable_macros"
    SCAN_QR_CODE = "scan_qr_code"
    FORWARD_EMAIL = "forward_email"
    NONE = "none"


class TargetData(str, Enum):
    """What data the attacker is trying to obtain."""
    PASSWORD = "password"
    MFA_CODE = "mfa_code"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    PERSONAL_INFO = "personal_info"
    CORPORATE_DATA = "corporate_data"
    LOGIN_CREDENTIALS = "login_credentials"
    FINANCIAL_INFO = "financial_info"
    NONE = "none"


class BusinessProcess(str, Enum):
    """Business process being abused."""
    PAYROLL = "payroll"
    INVOICE_PAYMENT = "invoice_payment"
    WIRE_TRANSFER = "wire_transfer"
    TAX_FILING = "tax_filing"
    PROCUREMENT = "procurement"
    HR_ONBOARDING = "hr_onboarding"
    IT_SUPPORT = "it_support"
    ACCOUNT_VERIFICATION = "account_verification"
    PASSWORD_RESET = "password_reset"
    SECURITY_ALERT = "security_alert"
    SHIPPING = "shipping"
    NONE = "none"


@dataclass
class ContentAnalysisResult:
    """Result of content deconstruction analysis."""
    
    # Primary classification
    intent: AttackIntent = AttackIntent.UNKNOWN
    confidence: float = 0.0
    
    # What the email asks victim to do
    requested_actions: List[RequestedAction] = field(default_factory=list)
    
    # What data is being targeted
    target_data: List[TargetData] = field(default_factory=list)
    
    # Business context
    business_process_abused: BusinessProcess = BusinessProcess.NONE
    
    # Brand/entity being spoofed
    spoofed_brand: Optional[str] = None
    spoofed_entity_type: Optional[str] = None  # bank, tech_company, government, etc.
    
    # Impact assessment
    potential_impact: List[str] = field(default_factory=list)  # account_takeover, financial_loss, data_leak
    
    # Extracted entities
    mentioned_amounts: List[str] = field(default_factory=list)  # "$500", "€1000"
    mentioned_deadlines: List[str] = field(default_factory=list)
    mentioned_organizations: List[str] = field(default_factory=list)
    
    # Analysis metadata
    analysis_method: str = "heuristic"  # heuristic, llm, hybrid
    llm_raw_response: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent.value,
            "confidence": self.confidence,
            "requested_actions": [a.value for a in self.requested_actions],
            "target_data": [d.value for d in self.target_data],
            "business_process_abused": self.business_process_abused.value,
            "spoofed_brand": self.spoofed_brand,
            "spoofed_entity_type": self.spoofed_entity_type,
            "potential_impact": self.potential_impact,
            "mentioned_amounts": self.mentioned_amounts,
            "mentioned_deadlines": self.mentioned_deadlines,
            "mentioned_organizations": self.mentioned_organizations,
            "analysis_method": self.analysis_method,
        }


# Heuristic patterns for content analysis
CREDENTIAL_PATTERNS = [
    r'\b(password|passcode|pin)\b',
    r'\b(login|log.?in|sign.?in)\b.*\b(credentials?|details?|information)\b',
    r'\benter your (password|credentials)\b',
    r'\bverify your (identity|account|login)\b',
    r'\b(username|user.?id)\s*(and|&|,)\s*(password)\b',
]

PAYMENT_PATTERNS = [
    r'\b(wire transfer|bank transfer|payment)\b',
    r'\b(routing number|account number|swift|iban)\b',
    r'\b(invoice|billing|payment)\s*(attached|enclosed|due)\b',
    r'\bupdate.*(payment|banking)\s*(details?|information)\b',
    r'\b(pay|send|transfer)\s*\$?\d+',
]

GIFT_CARD_PATTERNS = [
    r'\b(gift\s*card|itunes|amazon|google\s*play)\b',
    r'\bbuy\s*(some|a few)?\s*(gift\s*cards?|cards?)\b',
    r'\b(redemption|scratch)\s*code\b',
]

CALLBACK_PATTERNS = [
    r'\bcall\s*(me|us|this number|now|immediately)\b',
    r'\b(phone|contact)\s*(me|us)\s*(at|on|urgently)\b',
    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone number
]

AMOUNT_PATTERNS = [
    r'\$[\d,]+(?:\.\d{2})?',
    r'€[\d,]+(?:\.\d{2})?',
    r'£[\d,]+(?:\.\d{2})?',
    r'\b\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:dollars?|usd|eur|gbp)\b',
]


class ContentAnalyzer:
    """
    Deconstructs email content to extract structured attack information.
    
    Uses hybrid approach:
    1. Fast heuristic extraction (always runs)
    2. LLM deep analysis (for complex cases)
    """
    
    def __init__(self, openai_client=None):
        self.openai_client = openai_client
        self.logger = logging.getLogger(__name__)
    
    async def analyze(
        self,
        email: ParsedEmail,
        use_llm: bool = True,
    ) -> ContentAnalysisResult:
        """
        Analyze email content for attack semantics.
        
        Args:
            email: Parsed email to analyze
            use_llm: Whether to use LLM for deep analysis
            
        Returns:
            ContentAnalysisResult with structured fields
        """
        result = ContentAnalysisResult()
        
        body_text = self._get_body_text(email)
        subject = email.subject or ""
        
        # Step 1: Heuristic analysis
        result = self._run_heuristics(result, body_text, subject, email)
        
        # Step 2: LLM analysis if available and useful
        if use_llm and self.openai_client:
            # Run LLM if heuristics found something suspicious
            if result.intent != AttackIntent.LEGITIMATE or result.requested_actions:
                try:
                    llm_result = await self._run_llm_analysis(body_text, subject)
                    result = self._merge_llm_results(result, llm_result)
                    result.analysis_method = "hybrid"
                except Exception as e:
                    self.logger.warning(f"LLM content analysis failed: {e}")
        
        # Step 3: Dynamic validation - use EMAIL AUTHENTICATION as source of truth
        # If SPF+DKIM+DMARC pass AND sender domain relates to brand, it's legitimate!
        if result.spoofed_brand and email.sender:
            if self._is_legitimate_brand_sender_dynamic(email, result.spoofed_brand):
                self.logger.info(f"Cleared false positive: {result.spoofed_brand} - sender authenticated and domain matches brand")
                result.spoofed_brand = None
                result.spoofed_entity_type = None
                # Also update intent if it was flagged as suspicious just because of brand
                if result.intent in [AttackIntent.CREDENTIAL_HARVEST, AttackIntent.UNKNOWN]:
                    result.intent = AttackIntent.LEGITIMATE
                    result.confidence = 0.8
        
        # Step 4: Infer potential impact
        result.potential_impact = self._infer_impact(result)
        
        return result
    
    def _is_legitimate_brand_sender_dynamic(self, email: ParsedEmail, detected_brand: str) -> bool:
        """
        DYNAMIC brand validation using email authentication.
        No hardcoded brand list needed!
        
        Logic:
        1. Check if sender domain is a subdomain of known legitimate domains (highest trust)
        2. Check if email passes authentication (SPF, DKIM, DMARC)
        3. Check if sender domain relates to the detected brand name
        4. If #1 OR (#2 AND #3) pass → sender IS the brand, not spoofing
        
        Args:
            email: ParsedEmail with auth results
            detected_brand: Brand name detected in content (e.g., "Axis Bank")
            
        Returns:
            True if sender is legitimately the brand
        """
        if not detected_brand or not email.sender or not email.sender.domain:
            return False
        
        sender_domain = email.sender.domain.lower()
        brand_lower = detected_brand.lower()
        
        # Step 0: Check if sender is a subdomain of known legitimate domains
        # This is the highest trust signal - no auth needed for apple.com subdomains
        from app.utils.constants import BRAND_TARGETS
        for brand_id, brand_info in BRAND_TARGETS.items():
            # Check if this brand matches the detected brand
            if brand_info["name"].lower() in brand_lower or brand_lower in brand_info["name"].lower():
                legitimate_domains = [d.lower() for d in brand_info.get("legitimate_domains", [])]
                # Check if sender is exactly a legitimate domain or subdomain of one
                if sender_domain in legitimate_domains:
                    self.logger.info(f"Exact legitimate domain match: {sender_domain}")
                    return True
                for legit in legitimate_domains:
                    if sender_domain.endswith(f".{legit}"):
                        self.logger.info(f"Legitimate subdomain match: {sender_domain} is subdomain of {legit}")
                        return True
        
        # Step 1: Check email authentication
        # DMARC=pass is the strongest signal - it means SPF or DKIM aligned with From domain
        auth_passed = self._check_authentication_passed(email)
        
        if not auth_passed:
            self.logger.debug(f"Auth failed for {email.sender.domain} - cannot trust sender")
            return False
        
        # Step 2: Check if sender domain relates to detected brand
        sender_domain = email.sender.domain.lower()
        brand_lower = detected_brand.lower()
        
        # Extract meaningful words from brand name
        # Remove common suffixes like "bank", "inc", "corp", "ltd", "limited", "company"
        stop_words = {'bank', 'inc', 'corp', 'ltd', 'limited', 'company', 'co', 'the', 'of', 'and'}
        brand_words = [
            word for word in re.split(r'[\s\-_]+', brand_lower) 
            if word and len(word) >= 3 and word not in stop_words
        ]
        
        if not brand_words:
            # Fallback: use whole brand name without spaces
            brand_words = [brand_lower.replace(' ', '')]
        
        # Check if any brand word appears in sender domain
        # e.g., "axis" in "axisbank.com" → True
        # e.g., "microsoft" in "microsoft.com" → True
        for word in brand_words:
            if word in sender_domain:
                self.logger.info(f"Dynamic match: '{word}' found in '{sender_domain}' with valid auth")
                return True
        
        # Also check reverse: domain name in brand
        # e.g., domain "paypal.com" → "paypal" in "PayPal Security"
        domain_base = sender_domain.split('.')[0]  # "axisbank" from "axisbank.com"
        if len(domain_base) >= 4 and domain_base in brand_lower.replace(' ', ''):
            self.logger.info(f"Dynamic match: domain base '{domain_base}' found in brand '{brand_lower}'")
            return True
        
        return False
    
    def _check_authentication_passed(self, email: ParsedEmail) -> bool:
        """
        Check if email passes authentication.
        
        Priority: DMARC > (SPF + DKIM) > SPF alone
        
        Returns:
            True if email is authenticated
        """
        # Check DMARC first - strongest signal
        if email.dmarc_result:
            dmarc_status = email.dmarc_result.result.lower() if email.dmarc_result.result else ""
            if dmarc_status == "pass":
                return True
        
        # Check via header_analysis if available
        if email.header_analysis:
            if email.header_analysis.dmarc_result:
                dmarc_status = email.header_analysis.dmarc_result.result.lower() if email.header_analysis.dmarc_result.result else ""
                if dmarc_status == "pass":
                    return True
        
        # Fallback: Check SPF and DKIM individually
        spf_pass = False
        dkim_pass = False
        
        if email.spf_result:
            spf_status = email.spf_result.result.lower() if email.spf_result.result else ""
            spf_pass = spf_status == "pass"
        
        if email.dkim_result:
            dkim_status = email.dkim_result.result.lower() if email.dkim_result.result else ""
            dkim_pass = dkim_status == "pass"
        
        # Check header_analysis fallback
        if email.header_analysis:
            if email.header_analysis.spf_result and not spf_pass:
                spf_status = email.header_analysis.spf_result.result.lower() if email.header_analysis.spf_result.result else ""
                spf_pass = spf_status == "pass"
            
            if email.header_analysis.dkim_result and not dkim_pass:
                dkim_status = email.header_analysis.dkim_result.result.lower() if email.header_analysis.dkim_result.result else ""
                dkim_pass = dkim_status == "pass"
        
        # Need at least SPF or DKIM to pass
        # Ideally both, but SPF+pass with no DKIM is still okay for many legitimate senders
        if spf_pass and dkim_pass:
            return True
        
        # SPF pass alone is weaker but acceptable if DKIM is not present (not failed)
        if spf_pass and not email.dkim_result:
            return True
        
        # DKIM pass alone is acceptable
        if dkim_pass:
            return True
        
        return False
    
    def _get_body_text(self, email: ParsedEmail) -> str:
        """Extract body text from email."""
        parts = []
        if email.body_text:
            parts.append(email.body_text)
        if email.body_html:
            text = re.sub(r'<[^>]+>', ' ', email.body_html)
            text = re.sub(r'\s+', ' ', text)
            parts.append(text)
        return ' '.join(parts)
    
    def _run_heuristics(
        self,
        result: ContentAnalysisResult,
        body_text: str,
        subject: str,
        email: ParsedEmail,
    ) -> ContentAnalysisResult:
        """Run heuristic pattern matching."""
        combined = f"{subject} {body_text}".lower()
        
        # Detect requested actions
        
        # Check for link clicks
        if email.urls and len(email.urls) > 0:
            # Check if there's call-to-action near URLs
            if re.search(r'(click|visit|go to|follow|open)\s*(the|this)?\s*(link|url|button)', combined):
                result.requested_actions.append(RequestedAction.CLICK_LINK)
        
        # Check for attachment opens
        if email.attachments and len(email.attachments) > 0:
            if re.search(r'(open|view|see|check|review)\s*(the)?\s*(attached|attachment|document|file)', combined):
                result.requested_actions.append(RequestedAction.OPEN_ATTACHMENT)
        
        # Check for callback phishing
        for pattern in CALLBACK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                result.requested_actions.append(RequestedAction.CALL_NUMBER)
                break
        
        # Check for payment requests
        for pattern in PAYMENT_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                result.requested_actions.append(RequestedAction.SEND_PAYMENT)
                break
        
        # Check for gift card requests
        for pattern in GIFT_CARD_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                result.requested_actions.append(RequestedAction.PURCHASE_GIFT_CARDS)
                break
        
        # Detect target data
        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                result.target_data.append(TargetData.LOGIN_CREDENTIALS)
                if 'password' in combined:
                    result.target_data.append(TargetData.PASSWORD)
                break
        
        if re.search(r'\b(mfa|2fa|verification code|one.?time|otp)\b', combined, re.IGNORECASE):
            result.target_data.append(TargetData.MFA_CODE)
        
        if re.search(r'\b(credit card|card number|cvv|expir)\b', combined, re.IGNORECASE):
            result.target_data.append(TargetData.CREDIT_CARD)
        
        if re.search(r'\b(bank|routing|account number|iban|swift)\b', combined, re.IGNORECASE):
            result.target_data.append(TargetData.BANK_ACCOUNT)
        
        if re.search(r'\b(ssn|social security|tax.?id)\b', combined, re.IGNORECASE):
            result.target_data.append(TargetData.SSN)
        
        # Detect business process
        if re.search(r'\b(invoice|billing|payment due)\b', combined):
            result.business_process_abused = BusinessProcess.INVOICE_PAYMENT
        elif re.search(r'\b(wire transfer|bank transfer)\b', combined):
            result.business_process_abused = BusinessProcess.WIRE_TRANSFER
        elif re.search(r'\b(payroll|salary|direct deposit)\b', combined):
            result.business_process_abused = BusinessProcess.PAYROLL
        elif re.search(r'\b(security alert|suspicious|unusual|sign.?in)\b', combined):
            result.business_process_abused = BusinessProcess.SECURITY_ALERT
        elif re.search(r'\b(password reset|forgot password|reset your)\b', combined):
            result.business_process_abused = BusinessProcess.PASSWORD_RESET
        elif re.search(r'\b(verify|confirm|update).*(account|identity)\b', combined):
            result.business_process_abused = BusinessProcess.ACCOUNT_VERIFICATION
        
        # Extract mentioned amounts
        for pattern in AMOUNT_PATTERNS:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            result.mentioned_amounts.extend(matches[:5])
        
        # Determine intent from patterns
        result = self._determine_intent_from_heuristics(result)
        
        # Deduplicate
        result.requested_actions = list(set(result.requested_actions))
        result.target_data = list(set(result.target_data))
        
        return result
    
    def _determine_intent_from_heuristics(self, result: ContentAnalysisResult) -> ContentAnalysisResult:
        """Determine attack intent from detected patterns."""
        
        # Gift card scam
        if RequestedAction.PURCHASE_GIFT_CARDS in result.requested_actions:
            result.intent = AttackIntent.GIFT_CARD_SCAM
            result.confidence = 0.85
            return result
        
        # Callback phishing
        if RequestedAction.CALL_NUMBER in result.requested_actions:
            result.intent = AttackIntent.CALLBACK_PHISHING
            result.confidence = 0.75
            return result
        
        # Credential harvesting
        if TargetData.PASSWORD in result.target_data or TargetData.LOGIN_CREDENTIALS in result.target_data:
            result.intent = AttackIntent.CREDENTIAL_HARVEST
            result.confidence = 0.80
            return result
        
        # Payment fraud / BEC
        if RequestedAction.SEND_PAYMENT in result.requested_actions:
            if TargetData.BANK_ACCOUNT in result.target_data:
                result.intent = AttackIntent.INVOICE_FRAUD
            else:
                result.intent = AttackIntent.PAYMENT_FRAUD
            result.confidence = 0.75
            return result
        
        # Malware delivery
        if RequestedAction.OPEN_ATTACHMENT in result.requested_actions:
            result.intent = AttackIntent.MALWARE_DELIVERY
            result.confidence = 0.65
            return result
        
        # Generic phishing
        if RequestedAction.CLICK_LINK in result.requested_actions:
            result.intent = AttackIntent.CREDENTIAL_HARVEST
            result.confidence = 0.60
            return result
        
        result.confidence = 0.50
        return result
    
    async def _run_llm_analysis(self, body_text: str, subject: str) -> Dict[str, Any]:
        """Run LLM-based deep content analysis."""
        
        prompt = f"""Analyze this email and extract structured attack information. Return JSON only.

Subject: {subject[:200]}

Body: {body_text[:2500]}

Return this exact JSON structure:
{{
  "intent": "credential_harvest|payment_fraud|malware_delivery|data_theft|account_takeover|bec|invoice_fraud|gift_card_scam|callback_phishing|reconnaissance|spam|marketing|legitimate|unknown",
  "confidence": 0.0-1.0,
  "requested_actions": ["click_link", "open_attachment", "reply_with_info", "call_number", "send_payment", "purchase_gift_cards", "change_payment_details", "download_file", "scan_qr_code", "none"],
  "target_data": ["password", "mfa_code", "ssn", "credit_card", "bank_account", "personal_info", "corporate_data", "login_credentials", "financial_info", "none"],
  "business_process": "payroll|invoice_payment|wire_transfer|tax_filing|procurement|hr_onboarding|it_support|account_verification|password_reset|security_alert|shipping|none",
  "spoofed_brand": "brand name or null",
  "spoofed_entity_type": "bank|tech_company|government|shipping|ecommerce|social_media|null",
  "organizations_mentioned": ["list of organization names"],
  "deadlines_mentioned": ["list of time references"]
}}"""

        response = await self.openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security analyst. Extract attack semantics from emails. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=600,
        )
        
        content = response.choices[0].message.content.strip()
        if content.startswith("```"):
            content = re.sub(r'^```(?:json)?\n?', '', content)
            content = re.sub(r'\n?```$', '', content)
        
        return json.loads(content)
    
    def _merge_llm_results(
        self,
        heuristic_result: ContentAnalysisResult,
        llm_result: Dict[str, Any],
    ) -> ContentAnalysisResult:
        """Merge LLM results with heuristic results."""
        
        result = heuristic_result
        result.llm_raw_response = llm_result
        
        # Update intent if LLM is more confident
        try:
            llm_intent = AttackIntent(llm_result.get("intent", "unknown"))
            llm_confidence = llm_result.get("confidence", 0.5)
            
            if llm_confidence > result.confidence:
                result.intent = llm_intent
                result.confidence = llm_confidence
        except ValueError:
            pass
        
        # Add LLM-detected actions (union with heuristics)
        for action_str in llm_result.get("requested_actions", []):
            try:
                action = RequestedAction(action_str)
                if action not in result.requested_actions and action != RequestedAction.NONE:
                    result.requested_actions.append(action)
            except ValueError:
                pass
        
        # Add LLM-detected target data
        for data_str in llm_result.get("target_data", []):
            try:
                data = TargetData(data_str)
                if data not in result.target_data and data != TargetData.NONE:
                    result.target_data.append(data)
            except ValueError:
                pass
        
        # Update business process if heuristics didn't find one
        if result.business_process_abused == BusinessProcess.NONE:
            try:
                result.business_process_abused = BusinessProcess(llm_result.get("business_process", "none"))
            except ValueError:
                pass
        
        # Add LLM-detected brand spoofing
        if not result.spoofed_brand and llm_result.get("spoofed_brand"):
            result.spoofed_brand = llm_result["spoofed_brand"]
            result.spoofed_entity_type = llm_result.get("spoofed_entity_type")
        
        # Add mentioned organizations
        result.mentioned_organizations.extend(llm_result.get("organizations_mentioned", []))
        result.mentioned_deadlines.extend(llm_result.get("deadlines_mentioned", []))
        
        return result
    
    def _infer_impact(self, result: ContentAnalysisResult) -> List[str]:
        """Infer potential impact from analysis."""
        impacts = []
        
        intent_impacts = {
            AttackIntent.CREDENTIAL_HARVEST: ["account_takeover", "data_breach"],
            AttackIntent.PAYMENT_FRAUD: ["financial_loss"],
            AttackIntent.MALWARE_DELIVERY: ["system_compromise", "data_breach", "ransomware"],
            AttackIntent.ACCOUNT_TAKEOVER: ["account_takeover", "data_breach"],
            AttackIntent.INVOICE_FRAUD: ["financial_loss"],
            AttackIntent.GIFT_CARD_SCAM: ["financial_loss"],
            AttackIntent.CALLBACK_PHISHING: ["financial_loss", "data_theft"],
            AttackIntent.DATA_THEFT: ["data_breach", "compliance_violation"],
            AttackIntent.BUSINESS_EMAIL_COMPROMISE: ["financial_loss", "reputation_damage"],
        }
        
        if result.intent in intent_impacts:
            impacts.extend(intent_impacts[result.intent])
        
        # Additional impacts based on target data
        if TargetData.CREDIT_CARD in result.target_data:
            impacts.append("financial_loss")
        if TargetData.SSN in result.target_data:
            impacts.append("identity_theft")
        if TargetData.CORPORATE_DATA in result.target_data:
            impacts.append("competitive_loss")
        
        return list(set(impacts))


# Singleton
_content_analyzer: Optional[ContentAnalyzer] = None


def get_content_analyzer(openai_client=None) -> ContentAnalyzer:
    """Get or create content analyzer singleton."""
    global _content_analyzer
    if _content_analyzer is None:
        _content_analyzer = ContentAnalyzer(openai_client)
    elif openai_client and _content_analyzer.openai_client is None:
        _content_analyzer.openai_client = openai_client
    return _content_analyzer
