"""
NiksES Email Dynamic Scoring Integration

Integrates the Dynamic Intelligent Detection Architecture (DIDA)
with the existing email analysis pipeline.

This module provides a bridge between:
- Legacy detection engine results
- New evidence-based dynamic scoring
- Existing API response models
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from app.models.detection import RiskLevel, EmailClassification

from .evidence import (
    Evidence,
    EvidenceCategory,
    EvidenceType,
    EvidenceSource,
    EvidenceCollector,
)
from .dynamic_scorer import (
    DynamicScoreCalculator,
    ThreatIntelScorer,
    FinalScore,
    calculate_dynamic_score,
)

logger = logging.getLogger(__name__)


@dataclass
class EmailDynamicResult:
    """Result from dynamic email scoring."""
    score: int
    level: str
    confidence: float
    classification: str
    verdict: str
    explanation: List[str]
    attack_chains: List[Dict[str, Any]]
    mitre_techniques: List[Dict[str, str]]
    recommended_action: str
    breakdown: Dict[str, Any]
    top_evidence: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "confidence": self.confidence,
            "classification": self.classification,
            "verdict": self.verdict,
            "explanation": self.explanation,
            "attack_chains": self.attack_chains,
            "mitre_techniques": self.mitre_techniques,
            "recommended_action": self.recommended_action,
            "breakdown": self.breakdown,
            "top_evidence": self.top_evidence,
        }


def calculate_email_dynamic_score(
    detection_results: Optional[Dict[str, Any]] = None,
    se_analysis: Optional[Dict[str, Any]] = None,
    content_analysis: Optional[Dict[str, Any]] = None,
    lookalike_results: Optional[Dict[str, Any]] = None,
    ti_results: Optional[Dict[str, Any]] = None,
    header_analysis: Optional[Dict[str, Any]] = None,
    ai_analysis: Optional[Dict[str, Any]] = None,
) -> EmailDynamicResult:
    """
    Calculate dynamic score for email using DIDA.
    
    This is the main entry point for email dynamic scoring.
    Converts all inputs to evidence and calculates unified score.
    
    Args:
        detection_results: Results from detection engine rules
        se_analysis: Social engineering analysis
        content_analysis: Content deconstruction analysis
        lookalike_results: Lookalike domain detection
        ti_results: Threat intelligence enrichment
        header_analysis: Email header analysis
        ai_analysis: AI analysis results
        
    Returns:
        EmailDynamicResult with comprehensive scoring
    """
    try:
        # Use the main dynamic score calculator
        result = calculate_dynamic_score(
            detection_results=detection_results,
            se_analysis=se_analysis,
            content_analysis=content_analysis,
            lookalike_results=lookalike_results,
            ti_results=ti_results,
            header_analysis=header_analysis,
            ai_analysis=ai_analysis,
        )
        
        # Convert to email-specific result
        return EmailDynamicResult(
            score=result.value,
            level=result.level,
            confidence=result.confidence,
            classification=result.classification,
            verdict=result.verdict,
            explanation=result.explanation,
            attack_chains=[c.to_dict() for c in result.attack_chains],
            mitre_techniques=result.mitre_techniques,
            recommended_action=result.recommended_action,
            breakdown=result.breakdown.to_dict(),
            top_evidence=[e.to_dict() for e in result.top_evidence],
        )
        
    except Exception as e:
        logger.error(f"Email dynamic scoring failed: {e}")
        # Return safe default
        return EmailDynamicResult(
            score=0,
            level="informational",
            confidence=0.0,
            classification="unknown",
            verdict="⚠️ Scoring error - manual review required",
            explanation=[f"Error during analysis: {str(e)}"],
            attack_chains=[],
            mitre_techniques=[],
            recommended_action="MANUAL REVIEW required due to analysis error",
            breakdown={},
            top_evidence=[],
        )


def map_dynamic_to_risk_level(level: str) -> RiskLevel:
    """Map dynamic level string to RiskLevel enum."""
    mapping = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "informational": RiskLevel.INFORMATIONAL,
    }
    return mapping.get(level.lower(), RiskLevel.INFORMATIONAL)


def map_dynamic_to_classification(classification: str, level: str) -> EmailClassification:
    """Map dynamic classification to EmailClassification enum."""
    # Direct mappings
    mapping = {
        "phishing": EmailClassification.PHISHING,
        "credential_phishing": EmailClassification.PHISHING,
        "bec": EmailClassification.BEC,
        "bec_wire_fraud": EmailClassification.BEC,
        "malware_delivery": EmailClassification.MALWARE,
        "malware": EmailClassification.MALWARE,
        "brand_impersonation": EmailClassification.BRAND_IMPERSONATION,
        "spam": EmailClassification.SPAM,
        "suspicious": EmailClassification.SUSPICIOUS,
        "callback_phishing": EmailClassification.PHISHING,
        "account_takeover": EmailClassification.PHISHING,
        "smishing": EmailClassification.PHISHING,
    }
    
    result = mapping.get(classification.lower())
    if result:
        return result
    
    # Fallback based on level
    if level in ["critical", "high"]:
        return EmailClassification.SUSPICIOUS
    elif level == "medium":
        return EmailClassification.SUSPICIOUS
    else:
        return EmailClassification.BENIGN


class DynamicMultiDimensionalScorer:
    """
    Drop-in replacement for MultiDimensionalScorer using DIDA.
    
    Provides same interface but uses evidence-based dynamic scoring.
    """
    
    def __init__(self):
        self.calculator = DynamicScoreCalculator()
        self.ti_scorer = ThreatIntelScorer()
        self.logger = logging.getLogger(__name__)
    
    def calculate_unified_score(
        self,
        detection_results: Optional[Dict[str, Any]] = None,
        se_analysis: Optional[Dict[str, Any]] = None,
        content_analysis: Optional[Dict[str, Any]] = None,
        lookalike_results: Optional[Dict[str, Any]] = None,
        ti_results: Optional[Dict[str, Any]] = None,
        header_analysis: Optional[Dict[str, Any]] = None,
        sender_domain: Optional[str] = None,
        ai_analysis: Optional[Dict[str, Any]] = None,
    ) -> "UnifiedRiskScore":
        """
        Calculate unified score using dynamic system.
        
        Returns object compatible with legacy UnifiedRiskScore.
        """
        # Calculate dynamic score
        result = calculate_email_dynamic_score(
            detection_results=detection_results,
            se_analysis=se_analysis,
            content_analysis=content_analysis,
            lookalike_results=lookalike_results,
            ti_results=ti_results,
            header_analysis=header_analysis,
            ai_analysis=ai_analysis,
        )
        
        # Create legacy-compatible response
        from .multi_scorer import UnifiedRiskScore, DimensionScore, RiskDimension, RecommendedAction
        
        unified = UnifiedRiskScore()
        unified.overall_score = result.score
        unified.overall_level = result.level
        unified.confidence = result.confidence
        unified.classification = self._map_classification(result.classification)
        unified.explanation = result.explanation
        unified.rules_triggered = len(detection_results.get("rules_triggered", [])) if detection_results else 0
        
        # Map dimensions from breakdown
        if result.breakdown:
            dimensions_data = result.breakdown.get("dimensions", {})
            for dim_name, dim_data in dimensions_data.items():
                try:
                    dim_enum = RiskDimension(dim_name)
                    unified.dimensions[dim_name] = DimensionScore(
                        dimension=dim_enum,
                        score=int(dim_data.get("score", 0)),
                        level=self._score_to_level(dim_data.get("score", 0)),
                        weight=dim_data.get("weight", 0.2),
                        indicators=dim_data.get("indicators", []),
                    )
                except ValueError:
                    pass  # Unknown dimension, skip
        
        # Map recommended actions
        unified.recommended_actions = [
            RecommendedAction(
                action=result.recommended_action,
                priority=1 if result.level in ["critical", "high"] else 2,
                category="block" if result.level == "critical" else "investigate",
                description=result.recommended_action,
                automated=result.level == "critical",
            )
        ]
        
        # Add MITRE techniques
        unified.mitre_techniques = result.mitre_techniques
        
        # Add attack chains to indicators
        for chain in result.attack_chains:
            chain_name = chain.get("name", "unknown")
            chain_conf = chain.get("confidence", 0)
            unified.key_indicators.append(f"Attack Chain: {chain_name} ({int(chain_conf*100)}% confidence)")
        
        # Add top evidence as indicators
        for evidence in result.top_evidence[:5]:
            unified.key_indicators.append(evidence.get("description", ""))
        
        return unified
    
    def _score_to_level(self, score: float) -> str:
        """Convert score to level string."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        elif score >= 10:
            return "low"
        return "informational"
    
    def _map_classification(self, classification: str) -> EmailClassification:
        """Map classification string to enum."""
        return map_dynamic_to_classification(classification, "medium")


# =============================================================================
# ENHANCED EVIDENCE COLLECTION FOR EMAIL
# =============================================================================

class EmailEvidenceCollector(EvidenceCollector):
    """
    Extended evidence collector with email-specific evidence extraction.
    """
    
    def add_from_email_headers(self, headers: Dict[str, Any]):
        """Extract evidence from email headers."""
        # Authentication results
        auth_checks = [
            ("spf_result", EvidenceType.SPF_FAIL, EvidenceSource.SPF_CHECK),
            ("dkim_result", EvidenceType.DKIM_FAIL, EvidenceSource.DKIM_CHECK),
            ("dmarc_result", EvidenceType.DMARC_FAIL, EvidenceSource.DMARC_CHECK),
        ]
        
        for field, evidence_type, source in auth_checks:
            result = headers.get(field, "").lower()
            if result and result not in ["pass", "none", ""]:
                self.add_evidence(
                    evidence_type=evidence_type,
                    category=EvidenceCategory.TECHNICAL,
                    source=source,
                    description=f"{field.replace('_result', '').upper()} check failed: {result}",
                    raw_value=result,
                    mitre_technique="T1566.002",
                )
        
        # Reply-to mismatch
        from_addr = headers.get("from", "")
        reply_to = headers.get("reply_to", "")
        if from_addr and reply_to and from_addr.lower() != reply_to.lower():
            from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
            reply_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
            if from_domain.lower() != reply_domain.lower():
                self.add_evidence(
                    evidence_type=EvidenceType.REPLY_TO_MISMATCH,
                    category=EvidenceCategory.TECHNICAL,
                    source=EvidenceSource.HEADER_ANALYSIS,
                    description=f"Reply-to domain mismatch: {from_domain} vs {reply_domain}",
                    raw_value={"from": from_domain, "reply_to": reply_domain},
                    mitre_technique="T1566.001",
                )
        
        # Header anomalies
        for anomaly in headers.get("anomalies", []):
            self.add_evidence(
                evidence_type=EvidenceType.HEADER_ANOMALY,
                category=EvidenceCategory.TECHNICAL,
                source=EvidenceSource.HEADER_ANALYSIS,
                description=str(anomaly),
                raw_value=anomaly,
            )
    
    def add_from_attachments(self, attachments: List[Dict[str, Any]]):
        """Extract evidence from attachments."""
        dangerous_extensions = {
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
            ".jar", ".msi", ".ps1", ".hta", ".wsf", ".wsh", ".lnk",
        }
        
        macro_extensions = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
        
        for attachment in attachments:
            filename = attachment.get("filename", "").lower()
            
            # Check for dangerous extensions
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    self.add_evidence(
                        evidence_type=EvidenceType.EXECUTABLE_ATTACHMENT,
                        category=EvidenceCategory.CONTENT,
                        source=EvidenceSource.STATIC_ANALYSIS,
                        description=f"Dangerous attachment type: {ext}",
                        raw_value=filename,
                        mitre_technique="T1204.002",
                    )
                    break
            
            # Check for macro-enabled
            for ext in macro_extensions:
                if filename.endswith(ext):
                    self.add_evidence(
                        evidence_type=EvidenceType.MACRO_ENABLED,
                        category=EvidenceCategory.CONTENT,
                        source=EvidenceSource.STATIC_ANALYSIS,
                        description=f"Macro-enabled document: {filename}",
                        raw_value=filename,
                        mitre_technique="T1059.005",
                    )
                    break
            
            # Check for password protected
            if attachment.get("is_encrypted") or "password" in str(attachment.get("metadata", {})).lower():
                self.add_evidence(
                    evidence_type=EvidenceType.PASSWORD_IN_BODY,
                    category=EvidenceCategory.CONTENT,
                    source=EvidenceSource.STATIC_ANALYSIS,
                    description="Password-protected attachment (evasion technique)",
                    raw_value=filename,
                    mitre_technique="T1027",
                )
    
    def add_from_urls(self, urls: List[str], body: str = ""):
        """Extract evidence from URLs in email body."""
        import re
        from urllib.parse import urlparse
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # IP address in URL
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    self.add_evidence(
                        evidence_type=EvidenceType.EXTERNAL_LINK,
                        category=EvidenceCategory.INFRASTRUCTURE,
                        source=EvidenceSource.CONTENT_ANALYZER,
                        description=f"URL uses IP address instead of domain: {domain}",
                        raw_value=url,
                        mitre_technique="T1566.002",
                    )
                
                # Shortened URL
                shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
                base_domain = ".".join(domain.split(".")[-2:])
                if base_domain in shorteners:
                    self.add_evidence(
                        evidence_type=EvidenceType.SHORTENED_URL,
                        category=EvidenceCategory.CONTENT,
                        source=EvidenceSource.CONTENT_ANALYZER,
                        description=f"URL shortened to hide destination: {base_domain}",
                        raw_value=url,
                    )
                
                # Credential harvesting indicators in URL
                cred_params = ["login", "signin", "password", "credential", "verify", "secure", "account"]
                path_lower = parsed.path.lower() + parsed.query.lower()
                for param in cred_params:
                    if param in path_lower:
                        self.add_evidence(
                            evidence_type=EvidenceType.CREDENTIAL_FORM,
                            category=EvidenceCategory.CONTENT,
                            source=EvidenceSource.CONTENT_ANALYZER,
                            description=f"URL contains credential-related path: {param}",
                            raw_value=url,
                            mitre_technique="T1566.002",
                        )
                        break
                
            except Exception as e:
                logger.debug(f"Error parsing URL {url}: {e}")
    
    def add_from_body_content(self, body: str, subject: str = ""):
        """Extract evidence from email body content."""
        import re
        
        body_lower = body.lower()
        subject_lower = subject.lower()
        combined = f"{subject_lower} {body_lower}"
        
        # Credential/sensitive data requests
        cred_patterns = [
            (r"(?:verify|confirm|update).*(?:password|credential|login)", "Credential verification request"),
            (r"(?:enter|provide|submit).*(?:ssn|social\s*security|tax\s*id)", "SSN/Tax ID request"),
            (r"(?:click|visit).*(?:verify|confirm).*(?:account|identity)", "Account verification via link"),
            (r"(?:bank|credit\s*card).*(?:detail|information|number)", "Financial information request"),
        ]
        
        for pattern, desc in cred_patterns:
            if re.search(pattern, combined):
                self.add_evidence(
                    evidence_type=EvidenceType.CREDENTIAL_REQUEST,
                    category=EvidenceCategory.CONTENT,
                    source=EvidenceSource.CONTENT_ANALYZER,
                    description=desc,
                    matched_text=re.search(pattern, combined).group(0) if re.search(pattern, combined) else None,
                    mitre_technique="T1598.003",
                )
        
        # Wire transfer / payment requests
        payment_patterns = [
            (r"(?:wire|transfer|send).*(?:\$|usd|dollar|payment)", "Wire transfer request"),
            (r"(?:urgent|immediate).*(?:payment|transfer|wire)", "Urgent payment request"),
            (r"(?:gift\s*card|itunes|google\s*play|steam)", "Gift card request"),
            (r"(?:bitcoin|btc|crypto|wallet).*(?:address|send|transfer)", "Cryptocurrency payment request"),
        ]
        
        for pattern, desc in payment_patterns:
            if re.search(pattern, combined):
                self.add_evidence(
                    evidence_type=EvidenceType.WIRE_TRANSFER_REQUEST if "wire" in desc.lower() else EvidenceType.PAYMENT_REQUEST,
                    category=EvidenceCategory.CONTENT,
                    source=EvidenceSource.CONTENT_ANALYZER,
                    description=desc,
                    matched_text=re.search(pattern, combined).group(0) if re.search(pattern, combined) else None,
                    mitre_technique="T1657",
                )


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_dynamic_email_scorer() -> DynamicMultiDimensionalScorer:
    """Get instance of dynamic email scorer."""
    return DynamicMultiDimensionalScorer()


def analyze_email_with_dida(
    email_data: Dict[str, Any],
    detection_results: Dict[str, Any],
    enrichment_results: Dict[str, Any],
    ai_analysis: Optional[Dict[str, Any]] = None,
) -> EmailDynamicResult:
    """
    Analyze email using full DIDA pipeline.
    
    Args:
        email_data: Parsed email data (headers, body, attachments)
        detection_results: Results from detection engine
        enrichment_results: Results from TI enrichment
        ai_analysis: Optional AI analysis results
        
    Returns:
        Complete dynamic analysis result
    """
    # Build components for scoring
    header_analysis = {
        "spf_result": email_data.get("spf_result"),
        "dkim_result": email_data.get("dkim_result"),
        "dmarc_result": email_data.get("dmarc_result"),
        "from": email_data.get("from"),
        "reply_to": email_data.get("reply_to"),
        "anomalies": email_data.get("header_anomalies", []),
    }
    
    se_analysis = detection_results.get("se_analysis")
    content_analysis = detection_results.get("content_analysis")
    lookalike_results = detection_results.get("lookalike_results")
    
    ti_results = enrichment_results
    
    return calculate_email_dynamic_score(
        detection_results=detection_results,
        se_analysis=se_analysis,
        content_analysis=content_analysis,
        lookalike_results=lookalike_results,
        ti_results=ti_results,
        header_analysis=header_analysis,
        ai_analysis=ai_analysis,
    )
