"""
NiksES Dynamic Evidence System

Core evidence models for the Dynamic Intelligent Detection Architecture (DIDA).
All scoring is derived from evidence quality, not hardcoded values.

Key Principles:
- Every detection signal becomes an Evidence object with quality metrics
- Evidence quality determines score contribution (not fixed severity levels)
- External validation (TI) significantly boosts evidence weight
- Correlation between evidence pieces boosts confidence
"""

import math
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# =============================================================================
# EVIDENCE CATEGORIES & TYPES
# =============================================================================

class EvidenceCategory(str, Enum):
    """High-level evidence categories."""
    TECHNICAL = "technical"
    SOCIAL_ENGINEERING = "social_engineering"
    BRAND_IMPERSONATION = "brand_impersonation"
    CONTENT = "content"
    THREAT_INTEL = "threat_intel"
    BEHAVIORAL = "behavioral"
    INFRASTRUCTURE = "infrastructure"


class EvidenceType(str, Enum):
    """Specific evidence types for detection."""
    # Technical
    SPF_FAIL = "spf_fail"
    DKIM_FAIL = "dkim_fail"
    DMARC_FAIL = "dmarc_fail"
    AUTH_FAILURE = "auth_failure"
    HEADER_ANOMALY = "header_anomaly"
    REPLY_TO_MISMATCH = "reply_to_mismatch"
    ENVELOPE_MISMATCH = "envelope_mismatch"
    
    # Social Engineering
    URGENCY_LANGUAGE = "urgency_language"
    FEAR_LANGUAGE = "fear_language"
    AUTHORITY_CLAIM = "authority_claim"
    REWARD_PROMISE = "reward_promise"
    SECRECY_REQUEST = "secrecy_request"
    TIME_PRESSURE = "time_pressure"
    EMOTIONAL_MANIPULATION = "emotional_manipulation"
    
    # Brand Impersonation
    LOOKALIKE_DOMAIN = "lookalike_domain"
    BRAND_KEYWORD_MISMATCH = "brand_keyword_mismatch"
    DISPLAY_NAME_SPOOF = "display_name_spoof"
    LOGO_PRESENT = "logo_present"
    BRAND_IN_URL = "brand_in_url"
    HOMOGLYPH_DETECTED = "homoglyph_detected"
    
    # Content
    CREDENTIAL_FORM = "credential_form"
    CREDENTIAL_REQUEST = "credential_request"
    PAYMENT_REQUEST = "payment_request"
    WIRE_TRANSFER_REQUEST = "wire_transfer_request"
    GIFT_CARD_REQUEST = "gift_card_request"
    SENSITIVE_DATA_REQUEST = "sensitive_data_request"
    EXTERNAL_LINK = "external_link"
    SHORTENED_URL = "shortened_url"
    SUSPICIOUS_ATTACHMENT = "suspicious_attachment"
    MACRO_ENABLED = "macro_enabled"
    EXECUTABLE_ATTACHMENT = "executable_attachment"
    PASSWORD_IN_BODY = "password_in_body"
    QR_CODE_PRESENT = "qr_code_present"
    
    # Threat Intel
    URL_FLAGGED_MALICIOUS = "url_flagged_malicious"
    URL_FLAGGED_PHISHING = "url_flagged_phishing"
    DOMAIN_FLAGGED = "domain_flagged"
    IP_FLAGGED = "ip_flagged"
    HASH_FLAGGED = "hash_flagged"
    SENDER_BLACKLISTED = "sender_blacklisted"
    
    # Infrastructure
    NEWLY_REGISTERED_DOMAIN = "newly_registered_domain"
    FREE_EMAIL_PROVIDER = "free_email_provider"
    DISPOSABLE_EMAIL = "disposable_email"
    BULLETPROOF_HOSTING = "bulletproof_hosting"
    VPN_PROXY_ORIGIN = "vpn_proxy_origin"
    HIGH_RISK_TLD = "high_risk_tld"
    HIGH_RISK_COUNTRY = "high_risk_country"
    
    # Behavioral
    EXECUTIVE_IMPERSONATION = "executive_impersonation"
    VENDOR_IMPERSONATION = "vendor_impersonation"
    THREAD_HIJACKING = "thread_hijacking"
    UNUSUAL_SEND_TIME = "unusual_send_time"
    FIRST_TIME_SENDER = "first_time_sender"
    
    # Generic
    PATTERN_MATCH = "pattern_match"
    AI_DETECTION = "ai_detection"
    CUSTOM_RULE = "custom_rule"


class EvidenceSource(str, Enum):
    """Sources that can produce evidence."""
    SPF_CHECK = "spf_check"
    DKIM_CHECK = "dkim_check"
    DMARC_CHECK = "dmarc_check"
    HEADER_ANALYSIS = "header_analysis"
    PATTERN_ENGINE = "pattern_engine"
    LOOKALIKE_DETECTOR = "lookalike_detector"
    SE_ANALYZER = "se_analyzer"
    CONTENT_ANALYZER = "content_analyzer"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    PHISHTANK = "phishtank"
    URLHAUS = "urlhaus"
    MXTOOLBOX = "mxtoolbox"
    WHOIS = "whois"
    AI_ANALYSIS = "ai_analysis"
    STATIC_ANALYSIS = "static_analysis"
    CUSTOM_RULE = "custom_rule"


# =============================================================================
# EVIDENCE DATA CLASSES
# =============================================================================

@dataclass
class Evidence:
    """
    Single piece of evidence with quality metrics.
    
    All scoring is derived from evidence quality, not fixed values.
    """
    
    # Identification
    evidence_id: str = ""
    evidence_type: EvidenceType = EvidenceType.PATTERN_MATCH
    category: EvidenceCategory = EvidenceCategory.TECHNICAL
    source: EvidenceSource = EvidenceSource.PATTERN_ENGINE
    
    # What was found
    description: str = ""
    raw_value: Any = None
    matched_text: Optional[str] = None
    
    # Quality metrics (all 0.0 - 1.0, calculated dynamically)
    source_reliability: float = 0.5
    specificity: float = 0.5
    external_validation: float = 0.0
    recency: float = 1.0
    
    # Context
    mitre_technique: Optional[str] = None
    related_iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamps
    detected_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Generate evidence ID if not provided."""
        if not self.evidence_id:
            hash_input = f"{self.evidence_type.value}:{self.source.value}:{self.raw_value}"
            self.evidence_id = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
    
    @property
    def quality_score(self) -> float:
        """
        Calculate overall evidence quality (0-1).
        
        This replaces hardcoded severity scores.
        Higher quality = more weight in final score.
        """
        # Weighted combination of quality factors
        quality = (
            self.source_reliability * 0.30 +    # How reliable is the source?
            self.specificity * 0.30 +            # How specific is this evidence?
            self.external_validation * 0.25 +    # Confirmed by external sources?
            self.recency * 0.15                  # How recent is this intel?
        )
        return min(1.0, max(0.0, quality))
    
    @property
    def is_high_quality(self) -> bool:
        """Check if this is high-quality evidence."""
        return self.quality_score >= 0.7
    
    @property
    def is_externally_validated(self) -> bool:
        """Check if this evidence has external validation."""
        return self.external_validation >= 0.5
    
    def boost_with_ti(self, ti_confidence: float):
        """Boost evidence quality when TI confirms it."""
        self.external_validation = max(self.external_validation, ti_confidence)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "category": self.category.value,
            "source": self.source.value,
            "description": self.description,
            "raw_value": str(self.raw_value) if self.raw_value else None,
            "matched_text": self.matched_text,
            "quality_score": round(self.quality_score, 3),
            "source_reliability": round(self.source_reliability, 3),
            "specificity": round(self.specificity, 3),
            "external_validation": round(self.external_validation, 3),
            "mitre_technique": self.mitre_technique,
            "related_iocs": self.related_iocs,
        }


@dataclass
class AttackChain:
    """
    Detected attack pattern/chain from correlated evidence.
    
    Attack chains represent coordinated attack patterns
    that are more significant than individual indicators.
    """
    
    name: str
    confidence: float = 0.0
    required_evidence: List[Evidence] = field(default_factory=list)
    supporting_evidence: List[Evidence] = field(default_factory=list)
    ti_confirmation: bool = False
    mitre_tactics: List[str] = field(default_factory=list)
    description: str = ""
    
    @property
    def total_evidence_count(self) -> int:
        return len(self.required_evidence) + len(self.supporting_evidence)
    
    @property
    def avg_evidence_quality(self) -> float:
        """Average quality of evidence in this chain."""
        all_evidence = self.required_evidence + self.supporting_evidence
        if not all_evidence:
            return 0.0
        return sum(e.quality_score for e in all_evidence) / len(all_evidence)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "confidence": round(self.confidence, 3),
            "evidence_count": self.total_evidence_count,
            "avg_quality": round(self.avg_evidence_quality, 3),
            "ti_confirmed": self.ti_confirmation,
            "mitre_tactics": self.mitre_tactics,
            "description": self.description,
        }


# =============================================================================
# SOURCE RELIABILITY CALCULATOR
# =============================================================================

class SourceReliabilityCalculator:
    """
    Calculate source reliability dynamically.
    
    Reliability is based on:
    - Source type (TI sources generally more reliable)
    - API health status
    - Consensus with other sources
    - Historical accuracy (future enhancement)
    """
    
    # Base reliability by source type (starting points, not fixed scores)
    BASE_RELIABILITY = {
        EvidenceSource.VIRUSTOTAL: 0.90,      # Aggregates 70+ engines
        EvidenceSource.PHISHTANK: 0.85,       # Verified phishing database
        EvidenceSource.URLHAUS: 0.85,         # Malware URL database
        EvidenceSource.ABUSEIPDB: 0.80,       # Community abuse reports
        EvidenceSource.MXTOOLBOX: 0.75,       # Blacklist aggregator
        EvidenceSource.WHOIS: 0.70,           # Domain registration data
        EvidenceSource.AI_ANALYSIS: 0.70,     # Context-aware but can hallucinate
        EvidenceSource.HEADER_ANALYSIS: 0.65, # Technical but has exceptions
        EvidenceSource.STATIC_ANALYSIS: 0.75, # File analysis
        EvidenceSource.SE_ANALYZER: 0.60,     # Pattern-based SE detection
        EvidenceSource.CONTENT_ANALYZER: 0.60,# Content pattern matching
        EvidenceSource.LOOKALIKE_DETECTOR: 0.70,  # Domain similarity
        EvidenceSource.PATTERN_ENGINE: 0.55,  # Rule-based patterns
        EvidenceSource.SPF_CHECK: 0.80,       # Authentication check
        EvidenceSource.DKIM_CHECK: 0.80,      # Authentication check
        EvidenceSource.DMARC_CHECK: 0.80,     # Authentication check
        EvidenceSource.CUSTOM_RULE: 0.50,     # User-defined rules
    }
    
    def calculate(
        self,
        source: EvidenceSource,
        api_status: Optional[Dict[str, str]] = None,
        consensus_sources: Optional[Set[str]] = None,
    ) -> float:
        """
        Calculate source reliability dynamically.
        
        Args:
            source: The evidence source
            api_status: Current API health status
            consensus_sources: Other sources that agree with this one
            
        Returns:
            Reliability score 0-1
        """
        # Start with base reliability
        reliability = self.BASE_RELIABILITY.get(source, 0.5)
        
        # Adjust based on API health
        if api_status:
            source_name = source.value.lower()
            for api_name, status in api_status.items():
                if source_name in api_name.lower():
                    status_lower = status.lower()
                    if "error" in status_lower or "failed" in status_lower:
                        reliability *= 0.5  # Significant reduction
                    elif "limited" in status_lower or "rate" in status_lower:
                        reliability *= 0.8  # Slight reduction
                    elif "success" in status_lower or "ok" in status_lower:
                        reliability *= 1.05  # Small boost
        
        # Boost if other sources agree (consensus)
        if consensus_sources:
            consensus_count = len(consensus_sources)
            if consensus_count >= 3:
                reliability *= 1.15  # Strong consensus
            elif consensus_count >= 2:
                reliability *= 1.10  # Moderate consensus
            elif consensus_count >= 1:
                reliability *= 1.05  # Some consensus
        
        return min(1.0, max(0.0, reliability))


# =============================================================================
# EVIDENCE SPECIFICITY CALCULATOR
# =============================================================================

class SpecificityCalculator:
    """
    Calculate how specific/targeted evidence is.
    
    More specific evidence = higher quality.
    Generic patterns have lower specificity.
    """
    
    # Specificity by evidence type
    TYPE_SPECIFICITY = {
        # High specificity - very targeted indicators
        EvidenceType.HASH_FLAGGED: 0.95,           # Exact file hash
        EvidenceType.URL_FLAGGED_MALICIOUS: 0.90,  # Specific URL
        EvidenceType.URL_FLAGGED_PHISHING: 0.90,
        EvidenceType.HOMOGLYPH_DETECTED: 0.85,     # Specific evasion technique
        EvidenceType.CREDENTIAL_FORM: 0.85,        # Definite credential harvesting
        EvidenceType.MACRO_ENABLED: 0.80,          # Specific risk indicator
        EvidenceType.EXECUTABLE_ATTACHMENT: 0.80,
        
        # Medium-high specificity
        EvidenceType.LOOKALIKE_DOMAIN: 0.75,
        EvidenceType.DISPLAY_NAME_SPOOF: 0.75,
        EvidenceType.WIRE_TRANSFER_REQUEST: 0.75,
        EvidenceType.IP_FLAGGED: 0.70,
        EvidenceType.DOMAIN_FLAGGED: 0.70,
        EvidenceType.SPF_FAIL: 0.70,
        EvidenceType.DKIM_FAIL: 0.70,
        EvidenceType.DMARC_FAIL: 0.70,
        EvidenceType.REPLY_TO_MISMATCH: 0.70,
        
        # Medium specificity
        EvidenceType.BRAND_KEYWORD_MISMATCH: 0.65,
        EvidenceType.CREDENTIAL_REQUEST: 0.65,
        EvidenceType.PAYMENT_REQUEST: 0.65,
        EvidenceType.EXECUTIVE_IMPERSONATION: 0.65,
        EvidenceType.NEWLY_REGISTERED_DOMAIN: 0.60,
        EvidenceType.PASSWORD_IN_BODY: 0.60,
        EvidenceType.SHORTENED_URL: 0.55,
        EvidenceType.SECRECY_REQUEST: 0.55,
        
        # Lower specificity - common patterns
        EvidenceType.URGENCY_LANGUAGE: 0.50,
        EvidenceType.FEAR_LANGUAGE: 0.50,
        EvidenceType.AUTHORITY_CLAIM: 0.50,
        EvidenceType.TIME_PRESSURE: 0.50,
        EvidenceType.EXTERNAL_LINK: 0.45,
        EvidenceType.FREE_EMAIL_PROVIDER: 0.40,
        EvidenceType.HEADER_ANOMALY: 0.45,
        
        # Generic
        EvidenceType.PATTERN_MATCH: 0.50,
        EvidenceType.AI_DETECTION: 0.60,
        EvidenceType.CUSTOM_RULE: 0.50,
    }
    
    def calculate(
        self,
        evidence_type: EvidenceType,
        matched_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> float:
        """
        Calculate specificity for evidence.
        
        Args:
            evidence_type: Type of evidence
            matched_text: Text that was matched (longer = more specific)
            context: Additional context that may affect specificity
            
        Returns:
            Specificity score 0-1
        """
        # Base specificity from type
        specificity = self.TYPE_SPECIFICITY.get(evidence_type, 0.5)
        
        # Adjust based on matched text length (longer matches = more specific)
        if matched_text:
            text_len = len(matched_text)
            if text_len > 100:
                specificity *= 1.1
            elif text_len > 50:
                specificity *= 1.05
            elif text_len < 10:
                specificity *= 0.9
        
        # Adjust based on context
        if context:
            # Multiple matches increase specificity
            match_count = context.get("match_count", 1)
            if match_count >= 3:
                specificity *= 1.1
            
            # Exact match vs fuzzy match
            if context.get("exact_match"):
                specificity *= 1.1
            elif context.get("fuzzy_match"):
                specificity *= 0.9
        
        return min(1.0, max(0.0, specificity))


# =============================================================================
# EVIDENCE COLLECTOR
# =============================================================================

class EvidenceCollector:
    """
    Collects and normalizes evidence from all detection sources.
    
    Transforms raw detection outputs into standardized Evidence objects
    with calculated quality metrics.
    """
    
    def __init__(self):
        self.reliability_calc = SourceReliabilityCalculator()
        self.specificity_calc = SpecificityCalculator()
        self.evidence_list: List[Evidence] = []
        self.api_status: Dict[str, str] = {}
    
    def set_api_status(self, status: Dict[str, str]):
        """Set current API health status for reliability calculations."""
        self.api_status = status
    
    def clear(self):
        """Clear collected evidence."""
        self.evidence_list = []
    
    def add_evidence(
        self,
        evidence_type: EvidenceType,
        category: EvidenceCategory,
        source: EvidenceSource,
        description: str,
        raw_value: Any = None,
        matched_text: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        related_iocs: Optional[List[str]] = None,
        external_validation: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Evidence:
        """
        Add evidence with automatically calculated quality metrics.
        """
        # Calculate source reliability
        consensus = self._find_consensus_sources(evidence_type)
        reliability = self.reliability_calc.calculate(
            source=source,
            api_status=self.api_status,
            consensus_sources=consensus,
        )
        
        # Calculate specificity
        specificity = self.specificity_calc.calculate(
            evidence_type=evidence_type,
            matched_text=matched_text,
            context=metadata,
        )
        
        evidence = Evidence(
            evidence_type=evidence_type,
            category=category,
            source=source,
            description=description,
            raw_value=raw_value,
            matched_text=matched_text,
            source_reliability=reliability,
            specificity=specificity,
            external_validation=external_validation,
            mitre_technique=mitre_technique,
            related_iocs=related_iocs or [],
            metadata=metadata or {},
        )
        
        self.evidence_list.append(evidence)
        return evidence
    
    def _find_consensus_sources(self, evidence_type: EvidenceType) -> Set[str]:
        """Find other sources that have provided similar evidence."""
        consensus = set()
        
        # Group related evidence types
        related_types = self._get_related_types(evidence_type)
        
        for existing in self.evidence_list:
            if existing.evidence_type in related_types:
                consensus.add(existing.source.value)
        
        return consensus
    
    def _get_related_types(self, evidence_type: EvidenceType) -> Set[EvidenceType]:
        """Get evidence types that are related/corroborating."""
        relations = {
            # TI confirmations
            EvidenceType.URL_FLAGGED_MALICIOUS: {
                EvidenceType.URL_FLAGGED_PHISHING,
                EvidenceType.DOMAIN_FLAGGED,
                EvidenceType.EXTERNAL_LINK,
            },
            EvidenceType.URL_FLAGGED_PHISHING: {
                EvidenceType.URL_FLAGGED_MALICIOUS,
                EvidenceType.CREDENTIAL_FORM,
                EvidenceType.BRAND_IN_URL,
            },
            # Auth failures
            EvidenceType.SPF_FAIL: {
                EvidenceType.DKIM_FAIL,
                EvidenceType.DMARC_FAIL,
                EvidenceType.AUTH_FAILURE,
            },
            # Brand impersonation
            EvidenceType.LOOKALIKE_DOMAIN: {
                EvidenceType.BRAND_KEYWORD_MISMATCH,
                EvidenceType.DISPLAY_NAME_SPOOF,
                EvidenceType.HOMOGLYPH_DETECTED,
            },
            # Social engineering
            EvidenceType.URGENCY_LANGUAGE: {
                EvidenceType.FEAR_LANGUAGE,
                EvidenceType.TIME_PRESSURE,
                EvidenceType.EMOTIONAL_MANIPULATION,
            },
        }
        
        return relations.get(evidence_type, {evidence_type})
    
    def add_from_detection_rules(self, rules_triggered: List[Dict[str, Any]]):
        """Convert detection rule matches to evidence."""
        for rule in rules_triggered:
            rule_id = rule.get("rule_id", "")
            category = self._map_rule_category(rule.get("category", ""))
            evidence_type = self._map_rule_to_evidence_type(rule_id, rule.get("category", ""))
            
            self.add_evidence(
                evidence_type=evidence_type,
                category=category,
                source=EvidenceSource.PATTERN_ENGINE,
                description=rule.get("description", rule.get("rule_name", "")),
                raw_value=rule.get("evidence", []),
                matched_text=rule.get("evidence", [""])[0] if rule.get("evidence") else None,
                mitre_technique=rule.get("mitre_technique"),
                metadata={"rule_id": rule_id, "severity": rule.get("severity")},
            )
    
    def add_from_ti_results(self, ti_results: Dict[str, Any]):
        """Convert threat intelligence results to evidence."""
        sources = ti_results.get("sources", {})
        
        for source_name, source_data in sources.items():
            verdict = source_data.get("verdict", "clean")
            score = source_data.get("score", 0)
            
            if verdict in ["malicious", "suspicious"] or score > 0:
                # Map source to evidence source
                evidence_source = self._map_ti_source(source_name)
                
                # Determine evidence type based on what was checked
                evidence_type = self._determine_ti_evidence_type(source_name, source_data)
                
                # Calculate external validation from TI score
                max_score = self._get_ti_max_score(source_name)
                external_validation = score / max_score if max_score > 0 else 0.5
                
                self.add_evidence(
                    evidence_type=evidence_type,
                    category=EvidenceCategory.THREAT_INTEL,
                    source=evidence_source,
                    description=f"{source_name}: {verdict} (score: {score})",
                    raw_value={"verdict": verdict, "score": score},
                    external_validation=external_validation,
                    metadata=source_data,
                )
    
    def add_from_se_analysis(self, se_analysis: Dict[str, Any]):
        """Convert social engineering analysis to evidence."""
        techniques = se_analysis.get("techniques", [])
        technique_scores = se_analysis.get("technique_scores", {})
        
        for technique in techniques:
            score = technique_scores.get(technique, 50)
            evidence_type = self._map_se_technique(technique)
            
            self.add_evidence(
                evidence_type=evidence_type,
                category=EvidenceCategory.SOCIAL_ENGINEERING,
                source=EvidenceSource.SE_ANALYZER,
                description=f"SE technique: {technique}",
                raw_value=technique,
                metadata={"score": score},
            )
        
        # Add key indicators
        for indicator in se_analysis.get("key_indicators", []):
            self.add_evidence(
                evidence_type=EvidenceType.EMOTIONAL_MANIPULATION,
                category=EvidenceCategory.SOCIAL_ENGINEERING,
                source=EvidenceSource.SE_ANALYZER,
                description=indicator,
                matched_text=indicator,
            )
    
    def add_from_lookalike_analysis(self, lookalike_results: Dict[str, Any]):
        """Convert lookalike domain analysis to evidence."""
        
        # Check for direct matches
        if lookalike_results.get("is_lookalike"):
            for match in lookalike_results.get("matches", []):
                domain = match.get("domain", "")
                target = match.get("target_brand", match.get("brand", ""))
                confidence = match.get("confidence", 0.5)
                methods = match.get("detection_methods", [])
                
                # Determine specific evidence type
                if "homoglyph" in str(methods).lower():
                    evidence_type = EvidenceType.HOMOGLYPH_DETECTED
                else:
                    evidence_type = EvidenceType.LOOKALIKE_DOMAIN
                
                self.add_evidence(
                    evidence_type=evidence_type,
                    category=EvidenceCategory.BRAND_IMPERSONATION,
                    source=EvidenceSource.LOOKALIKE_DETECTOR,
                    description=f"Lookalike domain '{domain}' impersonating {target}",
                    raw_value=domain,
                    matched_text=domain,
                    external_validation=confidence,
                    metadata=match,
                )
        
        # Also check for high brand impersonation score without is_lookalike
        # This handles cases where the analysis detects brand abuse in URLs
        brand_score = lookalike_results.get("score", 0)
        if brand_score >= 70:
            brand_name = lookalike_results.get("brand", lookalike_results.get("impersonating", ""))
            domain = lookalike_results.get("real_domain", lookalike_results.get("domain", ""))
            
            # Add brand impersonation evidence if we have a brand
            if brand_name and not lookalike_results.get("is_lookalike"):
                self.add_evidence(
                    evidence_type=EvidenceType.BRAND_IN_URL,
                    category=EvidenceCategory.BRAND_IMPERSONATION,
                    source=EvidenceSource.LOOKALIKE_DETECTOR,
                    description=f"Brand impersonation detected: {brand_name} (score: {brand_score})",
                    raw_value=brand_name,
                    matched_text=domain,
                    external_validation=brand_score / 100,
                    metadata=lookalike_results,
                )
            
            # If very high score, also add as lookalike domain
            if brand_score >= 85:
                self.add_evidence(
                    evidence_type=EvidenceType.LOOKALIKE_DOMAIN,
                    category=EvidenceCategory.BRAND_IMPERSONATION,
                    source=EvidenceSource.LOOKALIKE_DETECTOR,
                    description=f"High-confidence brand impersonation: {brand_name}",
                    raw_value=domain,
                    external_validation=brand_score / 100,
                    metadata=lookalike_results,
                )
    
    def add_from_content_analysis(self, content_analysis: Dict[str, Any]):
        """Convert content analysis to evidence."""
        intent = content_analysis.get("intent", "unknown")
        
        # Map intent to evidence type
        intent_mapping = {
            "credential_harvest": EvidenceType.CREDENTIAL_REQUEST,
            "credential_theft": EvidenceType.CREDENTIAL_REQUEST,  # Same as harvest
            "payment_fraud": EvidenceType.PAYMENT_REQUEST,
            "wire_fraud": EvidenceType.WIRE_TRANSFER_REQUEST,
            "malware_delivery": EvidenceType.SUSPICIOUS_ATTACHMENT,
            "account_takeover": EvidenceType.CREDENTIAL_REQUEST,
            "data_theft": EvidenceType.SENSITIVE_DATA_REQUEST,
            "phishing": EvidenceType.CREDENTIAL_REQUEST,
        }
        
        if intent in intent_mapping:
            self.add_evidence(
                evidence_type=intent_mapping[intent],
                category=EvidenceCategory.CONTENT,
                source=EvidenceSource.CONTENT_ANALYZER,
                description=f"Content intent: {intent}",
                raw_value=intent,
                metadata=content_analysis,
            )
        
        # Add requested actions
        for action in content_analysis.get("requested_actions", []):
            self.add_evidence(
                evidence_type=EvidenceType.SENSITIVE_DATA_REQUEST,
                category=EvidenceCategory.CONTENT,
                source=EvidenceSource.CONTENT_ANALYZER,
                description=f"Action requested: {action}",
                matched_text=action,
            )
    
    def add_from_header_analysis(self, header_analysis: Dict[str, Any]):
        """Convert header analysis to evidence."""
        auth_failures = []
        
        # Authentication results
        for auth_type in ["spf_result", "dkim_result", "dmarc_result"]:
            result = header_analysis.get(auth_type)
            if result and result.lower() not in ["pass", "none", ""]:
                evidence_type = {
                    "spf_result": EvidenceType.SPF_FAIL,
                    "dkim_result": EvidenceType.DKIM_FAIL,
                    "dmarc_result": EvidenceType.DMARC_FAIL,
                }.get(auth_type, EvidenceType.AUTH_FAILURE)
                
                self.add_evidence(
                    evidence_type=evidence_type,
                    category=EvidenceCategory.TECHNICAL,
                    source=getattr(EvidenceSource, auth_type.upper().replace("_RESULT", "_CHECK"), EvidenceSource.HEADER_ANALYSIS),
                    description=f"{auth_type.replace('_result', '').upper()} failed: {result}",
                    raw_value=result,
                )
                auth_failures.append(auth_type.replace('_result', '').upper())
        
        # Add general AUTH_FAILURE if any auth failed (for easier detection)
        if auth_failures:
            self.add_evidence(
                evidence_type=EvidenceType.AUTH_FAILURE,
                category=EvidenceCategory.TECHNICAL,
                source=EvidenceSource.HEADER_ANALYSIS,
                description=f"Email authentication failed: {', '.join(auth_failures)}",
                raw_value=auth_failures,
                metadata={"failed_checks": auth_failures},
            )
        
        # Check for free email provider in sender
        sender_domain = header_analysis.get("sender_domain", "").lower()
        free_email_providers = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
            "aol.com", "mail.com", "protonmail.com", "proton.me", "ymail.com",
            "icloud.com", "me.com", "gmx.com", "zoho.com", "yandex.com",
            "mail.ru", "inbox.com", "fastmail.com"
        }
        if sender_domain in free_email_providers:
            self.add_evidence(
                evidence_type=EvidenceType.FREE_EMAIL_PROVIDER,
                category=EvidenceCategory.BEHAVIORAL,
                source=EvidenceSource.HEADER_ANALYSIS,
                description=f"Sender using free email provider: {sender_domain}",
                raw_value=sender_domain,
            )
        
        # Check for display name / email mismatch (potential spoofing)
        display_name = header_analysis.get("display_name", "").lower()
        sender_email = header_analysis.get("sender_email", "").lower()
        if display_name and sender_email:
            # Check if display name looks like an email but doesn't match sender
            if "@" in display_name and display_name != sender_email:
                self.add_evidence(
                    evidence_type=EvidenceType.DISPLAY_NAME_SPOOF,
                    category=EvidenceCategory.SOCIAL_ENGINEERING,
                    source=EvidenceSource.HEADER_ANALYSIS,
                    description=f"Display name contains different email: {display_name}",
                    raw_value=display_name,
                    matched_text=display_name,
                )
            
            # Check if display name contains executive titles
            executive_keywords = ["ceo", "cfo", "cto", "coo", "president", "director", 
                                 "executive", "chief", "vp ", "vice president", "manager"]
            if any(kw in display_name for kw in executive_keywords):
                self.add_evidence(
                    evidence_type=EvidenceType.EXECUTIVE_IMPERSONATION,
                    category=EvidenceCategory.BEHAVIORAL,
                    source=EvidenceSource.HEADER_ANALYSIS,
                    description=f"Display name contains executive title: {display_name}",
                    raw_value=display_name,
                    matched_text=display_name,
                )
        
        # Check reply-to mismatch
        reply_to = header_analysis.get("reply_to", "").lower()
        if reply_to and sender_email and reply_to != sender_email:
            # Different reply-to is suspicious
            reply_to_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
            sender_domain_from_email = sender_email.split("@")[-1] if "@" in sender_email else ""
            
            if reply_to_domain != sender_domain_from_email:
                self.add_evidence(
                    evidence_type=EvidenceType.REPLY_TO_MISMATCH,
                    category=EvidenceCategory.BEHAVIORAL,
                    source=EvidenceSource.HEADER_ANALYSIS,
                    description=f"Reply-to domain differs from sender: {reply_to} vs {sender_email}",
                    raw_value=reply_to,
                )
        
        # Header anomalies
        for anomaly in header_analysis.get("anomalies", []):
            self.add_evidence(
                evidence_type=EvidenceType.HEADER_ANOMALY,
                category=EvidenceCategory.TECHNICAL,
                source=EvidenceSource.HEADER_ANALYSIS,
                description=anomaly,
                matched_text=anomaly,
            )
    
    def get_all_evidence(self) -> List[Evidence]:
        """Get all collected evidence."""
        return self.evidence_list
    
    def get_evidence_by_category(self, category: EvidenceCategory) -> List[Evidence]:
        """Get evidence filtered by category."""
        return [e for e in self.evidence_list if e.category == category]
    
    def get_high_quality_evidence(self, threshold: float = 0.7) -> List[Evidence]:
        """Get only high-quality evidence."""
        return [e for e in self.evidence_list if e.quality_score >= threshold]
    
    def get_externally_validated_evidence(self) -> List[Evidence]:
        """Get evidence with external validation."""
        return [e for e in self.evidence_list if e.is_externally_validated]
    
    # Helper mapping methods
    def _map_rule_category(self, category: str) -> EvidenceCategory:
        mapping = {
            "authentication": EvidenceCategory.TECHNICAL,
            "ip_reputation": EvidenceCategory.THREAT_INTEL,
            "phishing": EvidenceCategory.CONTENT,
            "social_engineering": EvidenceCategory.SOCIAL_ENGINEERING,
            "bec": EvidenceCategory.BEHAVIORAL,
            "malware": EvidenceCategory.CONTENT,
            "brand_impersonation": EvidenceCategory.BRAND_IMPERSONATION,
            "lookalike": EvidenceCategory.BRAND_IMPERSONATION,
        }
        return mapping.get(category.lower(), EvidenceCategory.TECHNICAL)
    
    def _map_rule_to_evidence_type(self, rule_id: str, category: str) -> EvidenceType:
        """Map rule ID to evidence type."""
        # Extract rule prefix
        prefix = rule_id.split("-")[0] if "-" in rule_id else rule_id[:4]
        
        prefix_mapping = {
            "AUTH": EvidenceType.AUTH_FAILURE,
            "PHISH": EvidenceType.CREDENTIAL_REQUEST,
            "BEC": EvidenceType.WIRE_TRANSFER_REQUEST,
            "MAL": EvidenceType.SUSPICIOUS_ATTACHMENT,
            "BRAND": EvidenceType.BRAND_KEYWORD_MISMATCH,
            "LOOK": EvidenceType.LOOKALIKE_DOMAIN,
            "SE": EvidenceType.URGENCY_LANGUAGE,
            "IP": EvidenceType.IP_FLAGGED,
        }
        
        return prefix_mapping.get(prefix, EvidenceType.PATTERN_MATCH)
    
    def _map_ti_source(self, source_name: str) -> EvidenceSource:
        mapping = {
            "virustotal": EvidenceSource.VIRUSTOTAL,
            "abuseipdb": EvidenceSource.ABUSEIPDB,
            "phishtank": EvidenceSource.PHISHTANK,
            "urlhaus": EvidenceSource.URLHAUS,
            "mxtoolbox": EvidenceSource.MXTOOLBOX,
        }
        return mapping.get(source_name.lower(), EvidenceSource.PATTERN_ENGINE)
    
    def _determine_ti_evidence_type(self, source_name: str, source_data: Dict) -> EvidenceType:
        """Determine evidence type from TI source."""
        source_lower = source_name.lower()
        
        if "phish" in source_lower:
            return EvidenceType.URL_FLAGGED_PHISHING
        elif "url" in source_lower or "urlhaus" in source_lower:
            return EvidenceType.URL_FLAGGED_MALICIOUS
        elif "abuse" in source_lower:
            return EvidenceType.IP_FLAGGED
        elif "blacklist" in str(source_data).lower():
            return EvidenceType.SENDER_BLACKLISTED
        else:
            return EvidenceType.DOMAIN_FLAGGED
    
    def _get_ti_max_score(self, source_name: str) -> int:
        """Get maximum score for TI source normalization."""
        max_scores = {
            "virustotal": 90,
            "abuseipdb": 100,
            "phishtank": 1,
            "urlhaus": 1,
            "mxtoolbox": 10,
        }
        return max_scores.get(source_name.lower(), 100)
    
    def _map_se_technique(self, technique: str) -> EvidenceType:
        """Map SE technique to evidence type."""
        mapping = {
            "urgency": EvidenceType.URGENCY_LANGUAGE,
            "fear": EvidenceType.FEAR_LANGUAGE,
            "authority": EvidenceType.AUTHORITY_CLAIM,
            "reward": EvidenceType.REWARD_PROMISE,
            "scarcity": EvidenceType.TIME_PRESSURE,
            "social_proof": EvidenceType.AUTHORITY_CLAIM,
            "secrecy": EvidenceType.SECRECY_REQUEST,
        }
        
        technique_lower = technique.lower()
        for key, value in mapping.items():
            if key in technique_lower:
                return value
        
        return EvidenceType.EMOTIONAL_MANIPULATION
