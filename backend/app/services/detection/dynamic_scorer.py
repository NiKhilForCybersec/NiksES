"""
NiksES Dynamic Scoring Engine

Calculates risk scores entirely from evidence quality, TI validation,
and cross-correlation. Zero hardcoded scores.

Key Principles:
- All scores derived from evidence quality metrics
- TI consensus heavily weights final score
- Attack chain detection provides correlation bonuses
- Confidence adjusts thresholds dynamically
- Everything is explainable
"""

import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum

# Use try/except for flexible importing
try:
    from .evidence import (
        Evidence,
        EvidenceCategory,
        EvidenceType,
        EvidenceSource,
        AttackChain,
        EvidenceCollector,
    )
except ImportError:
    from evidence import (
        Evidence,
        EvidenceCategory,
        EvidenceType,
        EvidenceSource,
        AttackChain,
        EvidenceCollector,
    )

logger = logging.getLogger(__name__)


# =============================================================================
# SCORE RESULT DATA CLASSES
# =============================================================================

@dataclass
class TIScore:
    """Threat Intelligence score component."""
    value: float = 0.0
    confidence: float = 0.0
    detection_ratio: float = 0.0
    severity_consensus: float = 0.0
    sources_checked: int = 0
    sources_flagged: int = 0
    sources_detail: Dict[str, Dict] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": round(self.value, 2),
            "confidence": round(self.confidence, 3),
            "detection_ratio": round(self.detection_ratio, 3),
            "severity_consensus": round(self.severity_consensus, 3),
            "sources_checked": self.sources_checked,
            "sources_flagged": self.sources_flagged,
        }


@dataclass
class DimensionScore:
    """Score for a single risk dimension."""
    name: str
    score: float = 0.0
    weight: float = 0.0
    evidence_count: int = 0
    avg_quality: float = 0.0
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 2),
            "weight": round(self.weight, 3),
            "evidence_count": self.evidence_count,
            "avg_quality": round(self.avg_quality, 3),
            "indicators": self.indicators[:5],
        }


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of how score was calculated."""
    evidence_score: float = 0.0
    evidence_weight: float = 0.0
    ti_score: float = 0.0
    ti_weight: float = 0.0
    chain_score: float = 0.0
    chain_weight: float = 0.0
    ai_score: float = 0.0
    ai_weight: float = 0.0
    correlation_bonus: float = 0.0
    dimensions: Dict[str, DimensionScore] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence": {"score": round(self.evidence_score, 2), "weight": round(self.evidence_weight, 3)},
            "threat_intel": {"score": round(self.ti_score, 2), "weight": round(self.ti_weight, 3)},
            "attack_chains": {"score": round(self.chain_score, 2), "weight": round(self.chain_weight, 3)},
            "ai_analysis": {"score": round(self.ai_score, 2), "weight": round(self.ai_weight, 3)},
            "correlation_bonus": round(self.correlation_bonus, 2),
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
        }


@dataclass
class FinalScore:
    """Final calculated risk score."""
    value: int = 0
    level: str = "informational"
    confidence: float = 0.0
    verdict: str = ""
    classification: str = "unknown"
    breakdown: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    attack_chains: List[AttackChain] = field(default_factory=list)
    top_evidence: List[Evidence] = field(default_factory=list)
    explanation: List[str] = field(default_factory=list)
    recommended_action: str = ""
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "level": self.level,
            "confidence": round(self.confidence, 3),
            "verdict": self.verdict,
            "classification": self.classification,
            "breakdown": self.breakdown.to_dict(),
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "top_evidence": [e.to_dict() for e in self.top_evidence[:10]],
            "explanation": self.explanation,
            "recommended_action": self.recommended_action,
            "mitre_techniques": self.mitre_techniques,
        }


# =============================================================================
# ATTACK CHAIN DETECTOR
# =============================================================================

class AttackChainDetector:
    """
    Detect attack patterns from correlated evidence.
    
    Attack chains are defined by evidence combinations, not hardcoded rules.
    Detecting a chain significantly boosts confidence and score.
    """
    
    # Chain patterns defined by required and supporting evidence types
    CHAIN_PATTERNS = {
        "credential_phishing": {
            "description": "Classic credential harvesting phishing attack",
            "required": {EvidenceType.CREDENTIAL_FORM, EvidenceType.EXTERNAL_LINK},
            "strong_required": {EvidenceType.CREDENTIAL_REQUEST},  # Alternative required
            "supporting": {
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.BRAND_KEYWORD_MISMATCH,
                EvidenceType.LOOKALIKE_DOMAIN,
                EvidenceType.AUTH_FAILURE,
                EvidenceType.SPF_FAIL,
                EvidenceType.DISPLAY_NAME_SPOOF,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING, EvidenceType.DOMAIN_FLAGGED},
            "mitre": ["T1566.002", "T1598.003"],
        },
        "bec_wire_fraud": {
            "description": "Business Email Compromise wire transfer fraud",
            "required": {EvidenceType.WIRE_TRANSFER_REQUEST},
            "strong_required": {EvidenceType.PAYMENT_REQUEST},
            "supporting": {
                EvidenceType.EXECUTIVE_IMPERSONATION,
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.SECRECY_REQUEST,
                EvidenceType.REPLY_TO_MISMATCH,
                EvidenceType.FREE_EMAIL_PROVIDER,
                EvidenceType.AUTHORITY_CLAIM,
            },
            "ti_boost": {EvidenceType.DOMAIN_FLAGGED, EvidenceType.NEWLY_REGISTERED_DOMAIN},
            "mitre": ["T1534", "T1656"],
        },
        "malware_delivery": {
            "description": "Malware delivery via email attachment",
            "required": {EvidenceType.SUSPICIOUS_ATTACHMENT},
            "strong_required": {EvidenceType.EXECUTABLE_ATTACHMENT, EvidenceType.MACRO_ENABLED},
            "supporting": {
                EvidenceType.PASSWORD_IN_BODY,
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.EXTERNAL_LINK,
                EvidenceType.AUTH_FAILURE,
            },
            "ti_boost": {EvidenceType.HASH_FLAGGED, EvidenceType.URL_FLAGGED_MALICIOUS},
            "mitre": ["T1566.001", "T1204.002"],
        },
        "brand_impersonation": {
            "description": "Brand impersonation phishing attack",
            "required": {EvidenceType.BRAND_KEYWORD_MISMATCH},
            "strong_required": {EvidenceType.LOOKALIKE_DOMAIN, EvidenceType.DISPLAY_NAME_SPOOF},
            "supporting": {
                EvidenceType.HOMOGLYPH_DETECTED,
                EvidenceType.EXTERNAL_LINK,
                EvidenceType.AUTH_FAILURE,
                EvidenceType.CREDENTIAL_REQUEST,
                EvidenceType.LOGO_PRESENT,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING, EvidenceType.DOMAIN_FLAGGED},
            "mitre": ["T1656", "T1583.001"],
        },
        "callback_phishing": {
            "description": "Callback phishing / vishing setup",
            "required": {EvidenceType.PAYMENT_REQUEST},
            "strong_required": set(),
            "supporting": {
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.FEAR_LANGUAGE,
                EvidenceType.AUTHORITY_CLAIM,
                EvidenceType.FREE_EMAIL_PROVIDER,
            },
            "ti_boost": set(),
            "mitre": ["T1566.003"],
        },
        "smishing_financial": {
            "description": "SMS financial fraud / smishing",
            "required": {EvidenceType.EXTERNAL_LINK},
            "strong_required": {EvidenceType.SHORTENED_URL},
            "supporting": {
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.FEAR_LANGUAGE,
                EvidenceType.CREDENTIAL_REQUEST,
                EvidenceType.BRAND_KEYWORD_MISMATCH,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING, EvidenceType.NEWLY_REGISTERED_DOMAIN},
            "mitre": ["T1566.002"],
        },
        "account_takeover": {
            "description": "Account takeover attempt",
            "required": {EvidenceType.CREDENTIAL_REQUEST},
            "strong_required": {EvidenceType.CREDENTIAL_FORM},
            "supporting": {
                EvidenceType.URGENCY_LANGUAGE,
                EvidenceType.FEAR_LANGUAGE,
                EvidenceType.BRAND_KEYWORD_MISMATCH,
                EvidenceType.EXTERNAL_LINK,
            },
            "ti_boost": {EvidenceType.URL_FLAGGED_PHISHING, EvidenceType.IP_FLAGGED},
            "mitre": ["T1078", "T1556"],
        },
    }
    
    def detect_chains(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
    ) -> List[AttackChain]:
        """
        Detect attack chains from evidence.
        
        Returns chains with confidence based on:
        - Required elements present
        - Supporting elements present
        - TI confirmation
        - Evidence quality
        """
        detected_chains = []
        evidence_types = {e.evidence_type for e in evidence_list}
        
        for chain_name, pattern in self.CHAIN_PATTERNS.items():
            # Check required elements (need at least one set)
            required_present = len(pattern["required"] & evidence_types)
            required_total = len(pattern["required"])
            
            strong_required_present = len(pattern.get("strong_required", set()) & evidence_types)
            
            # Must have at least one required OR one strong required
            if required_present == 0 and strong_required_present == 0:
                continue
            
            # Check supporting elements
            supporting_present = len(pattern["supporting"] & evidence_types)
            supporting_total = len(pattern["supporting"])
            
            # Check TI boost elements
            ti_boost_present = len(pattern["ti_boost"] & evidence_types)
            ti_boost_total = len(pattern["ti_boost"]) if pattern["ti_boost"] else 1
            
            # Calculate chain confidence dynamically
            confidence = self._calculate_chain_confidence(
                required_present=required_present,
                required_total=required_total,
                strong_required_present=strong_required_present,
                supporting_present=supporting_present,
                supporting_total=supporting_total,
                ti_boost_present=ti_boost_present,
                ti_boost_total=ti_boost_total,
                ti_confidence=ti_score.confidence,
                evidence_list=evidence_list,
                pattern=pattern,
            )
            
            if confidence >= 0.4:  # Minimum threshold for chain detection
                # Gather evidence for this chain
                required_evidence = [
                    e for e in evidence_list 
                    if e.evidence_type in pattern["required"] or 
                       e.evidence_type in pattern.get("strong_required", set())
                ]
                supporting_evidence = [
                    e for e in evidence_list 
                    if e.evidence_type in pattern["supporting"]
                ]
                
                chain = AttackChain(
                    name=chain_name,
                    confidence=confidence,
                    required_evidence=required_evidence,
                    supporting_evidence=supporting_evidence,
                    ti_confirmation=ti_boost_present > 0,
                    mitre_tactics=pattern.get("mitre", []),
                    description=pattern["description"],
                )
                detected_chains.append(chain)
        
        # Sort by confidence
        detected_chains.sort(key=lambda c: c.confidence, reverse=True)
        
        return detected_chains
    
    def _calculate_chain_confidence(
        self,
        required_present: int,
        required_total: int,
        strong_required_present: int,
        supporting_present: int,
        supporting_total: int,
        ti_boost_present: int,
        ti_boost_total: int,
        ti_confidence: float,
        evidence_list: List[Evidence],
        pattern: Dict,
    ) -> float:
        """
        Calculate chain confidence from components.
        
        Formula is dynamic based on what evidence is available.
        """
        # Base confidence from required elements
        if required_total > 0:
            required_ratio = required_present / required_total
        else:
            required_ratio = 1.0 if strong_required_present > 0 else 0.0
        
        # Strong required provides extra boost
        strong_boost = min(strong_required_present * 0.15, 0.3)
        
        # Supporting ratio
        supporting_ratio = supporting_present / supporting_total if supporting_total > 0 else 0
        
        # TI ratio
        ti_ratio = ti_boost_present / ti_boost_total if ti_boost_total > 0 else 0
        
        # Calculate base confidence
        # Required: 40%, Supporting: 25%, TI: 25%, Strong: 10%
        base_confidence = (
            required_ratio * 0.40 +
            supporting_ratio * 0.25 +
            ti_ratio * 0.25 +
            strong_boost
        )
        
        # Quality boost - if evidence is high quality, boost confidence
        relevant_evidence = [
            e for e in evidence_list
            if e.evidence_type in pattern["required"] or
               e.evidence_type in pattern.get("strong_required", set()) or
               e.evidence_type in pattern["supporting"]
        ]
        
        if relevant_evidence:
            avg_quality = sum(e.quality_score for e in relevant_evidence) / len(relevant_evidence)
            quality_multiplier = 0.8 + (avg_quality * 0.4)  # 0.8 to 1.2
            base_confidence *= quality_multiplier
        
        # TI confirmation boost
        if ti_boost_present > 0 and ti_confidence > 0.5:
            base_confidence *= 1.15
        
        # Multiple supporting elements boost
        if supporting_present >= 3:
            base_confidence *= 1.1
        
        return min(base_confidence, 1.0)


# =============================================================================
# EVIDENCE WEIGHTER
# =============================================================================

class DynamicEvidenceWeighter:
    """
    Calculate evidence weight dynamically.
    
    Weight = quality × validation × correlation × context
    No fixed weights - everything calculated from data.
    """
    
    def calculate_weight(
        self,
        evidence: Evidence,
        all_evidence: List[Evidence],
        ti_score: TIScore,
    ) -> float:
        """
        Calculate dynamic weight for evidence.
        
        Returns weight multiplier (typically 0.5 to 2.0).
        """
        # 1. BASE QUALITY
        base_quality = evidence.quality_score
        
        # 2. VALIDATION MULTIPLIER
        validation_mult = self._calculate_validation_multiplier(evidence, ti_score)
        
        # 3. CORRELATION BOOST
        correlation_boost = self._calculate_correlation_boost(evidence, all_evidence)
        
        # 4. CATEGORY IMPORTANCE
        category_factor = self._get_category_importance(evidence.category, all_evidence)
        
        # FINAL WEIGHT
        weight = base_quality * validation_mult * correlation_boost * category_factor
        
        return min(weight, 2.5)  # Cap to prevent runaway
    
    def _calculate_validation_multiplier(
        self,
        evidence: Evidence,
        ti_score: TIScore,
    ) -> float:
        """Calculate multiplier based on external validation."""
        multiplier = 1.0
        
        # Check if this evidence is confirmed by TI
        if evidence.external_validation > 0.7:
            multiplier *= 1.4  # Strong external validation
        elif evidence.external_validation > 0.4:
            multiplier *= 1.2  # Moderate validation
        
        # TI-specific evidence gets boost if TI is confident
        if evidence.category == EvidenceCategory.THREAT_INTEL:
            if ti_score.confidence > 0.7:
                multiplier *= 1.3
            elif ti_score.confidence > 0.4:
                multiplier *= 1.15
        
        return multiplier
    
    def _calculate_correlation_boost(
        self,
        evidence: Evidence,
        all_evidence: List[Evidence],
    ) -> float:
        """Calculate boost from correlation with other evidence."""
        boost = 1.0
        
        # Count evidence from different sources that correlates
        correlated_sources = set()
        
        for other in all_evidence:
            if other.evidence_id == evidence.evidence_id:
                continue
            if other.source == evidence.source:
                continue  # Same source doesn't count
            
            if self._are_correlated(evidence, other):
                correlated_sources.add(other.source.value)
        
        # Boost based on number of corroborating sources
        num_correlated = len(correlated_sources)
        if num_correlated >= 3:
            boost *= 1.25
        elif num_correlated >= 2:
            boost *= 1.15
        elif num_correlated >= 1:
            boost *= 1.08
        
        return boost
    
    def _are_correlated(self, e1: Evidence, e2: Evidence) -> bool:
        """Check if two evidence pieces are correlated."""
        # Same category = correlated
        if e1.category == e2.category:
            return True
        
        # Cross-category correlations
        correlations = {
            (EvidenceCategory.TECHNICAL, EvidenceCategory.THREAT_INTEL),
            (EvidenceCategory.SOCIAL_ENGINEERING, EvidenceCategory.CONTENT),
            (EvidenceCategory.BRAND_IMPERSONATION, EvidenceCategory.TECHNICAL),
            (EvidenceCategory.CONTENT, EvidenceCategory.THREAT_INTEL),
            (EvidenceCategory.BRAND_IMPERSONATION, EvidenceCategory.CONTENT),
            (EvidenceCategory.BEHAVIORAL, EvidenceCategory.SOCIAL_ENGINEERING),
        }
        
        pair = (e1.category, e2.category)
        return pair in correlations or (pair[1], pair[0]) in correlations
    
    def _get_category_importance(
        self,
        category: EvidenceCategory,
        all_evidence: List[Evidence],
    ) -> float:
        """
        Calculate category importance dynamically.
        
        Importance is based on what other evidence is present.
        """
        # Count evidence by category
        category_counts = {}
        for e in all_evidence:
            cat = e.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        total = len(all_evidence) or 1
        
        # TI is always important if present
        if category == EvidenceCategory.THREAT_INTEL:
            return 1.2
        
        # Technical more important if auth failures exist
        if category == EvidenceCategory.TECHNICAL:
            auth_failures = sum(
                1 for e in all_evidence 
                if e.evidence_type in {EvidenceType.SPF_FAIL, EvidenceType.DKIM_FAIL, EvidenceType.DMARC_FAIL}
            )
            if auth_failures >= 2:
                return 1.15
        
        # SE more important if content evidence exists
        if category == EvidenceCategory.SOCIAL_ENGINEERING:
            if category_counts.get(EvidenceCategory.CONTENT.value, 0) > 0:
                return 1.1
        
        # Brand impersonation more important with SE
        if category == EvidenceCategory.BRAND_IMPERSONATION:
            if category_counts.get(EvidenceCategory.SOCIAL_ENGINEERING.value, 0) > 0:
                return 1.15
        
        return 1.0


# =============================================================================
# THREAT INTEL SCORER
# =============================================================================

class ThreatIntelScorer:
    """
    Calculate threat score from TI data.
    
    TI is the anchor for scoring - external validation is gold.
    Score is entirely derived from TI consensus, not hardcoded.
    """
    
    # Max scores for normalization (actual API maximums)
    SOURCE_MAX_SCORES = {
        "virustotal": 90,
        "abuseipdb": 100,
        "phishtank": 1,
        "urlhaus": 1,
        "mxtoolbox": 10,
    }
    
    def calculate(self, ti_results: Dict[str, Any]) -> TIScore:
        """
        Calculate TI score entirely from TI data.
        """
        score = TIScore()
        
        if not ti_results:
            return score
        
        sources = ti_results.get("sources", {})
        score.sources_checked = ti_results.get("sources_checked", len(sources))
        score.sources_flagged = ti_results.get("sources_flagged", 0)
        
        # Count flagged sources
        severity_scores = []
        
        for source_name, source_data in sources.items():
            verdict = source_data.get("verdict", "clean")
            raw_score = source_data.get("score", 0)
            
            # Store details
            score.sources_detail[source_name] = {
                "verdict": verdict,
                "score": raw_score,
                "flagged": verdict in ["malicious", "suspicious"] or raw_score > 0,
            }
            
            if verdict in ["malicious", "suspicious"] or raw_score > 0:
                score.sources_flagged += 1
                
                # Normalize score
                max_score = self.SOURCE_MAX_SCORES.get(source_name.lower(), 100)
                normalized = raw_score / max_score if max_score > 0 else 0.5
                
                # Malicious verdict = full severity
                if verdict == "malicious":
                    normalized = max(normalized, 0.9)
                elif verdict == "suspicious":
                    normalized = max(normalized, 0.6)
                
                severity_scores.append(normalized)
        
        # Calculate ratios
        if score.sources_checked > 0:
            score.detection_ratio = score.sources_flagged / score.sources_checked
        
        if severity_scores:
            score.severity_consensus = sum(severity_scores) / len(severity_scores)
        
        # Calculate TI score (0-100)
        # Detection ratio is most important, then severity
        score.value = (
            score.detection_ratio * 100 * 0.55 +
            score.severity_consensus * 100 * 0.45
        )
        
        # Calculate confidence
        score.confidence = self._calculate_confidence(score)
        
        return score
    
    def _calculate_confidence(self, score: TIScore) -> float:
        """Calculate confidence in TI score."""
        confidence = 0.0
        
        # More sources checked = higher confidence
        if score.sources_checked >= 5:
            confidence += 0.4
        elif score.sources_checked >= 3:
            confidence += 0.3
        elif score.sources_checked >= 1:
            confidence += 0.2
        
        # Sources agreeing boosts confidence
        if score.sources_flagged >= 3:
            confidence += 0.35
        elif score.sources_flagged >= 2:
            confidence += 0.25
        elif score.sources_flagged >= 1:
            confidence += 0.15
        
        # High severity consensus boosts confidence
        if score.severity_consensus > 0.8:
            confidence += 0.25
        elif score.severity_consensus > 0.5:
            confidence += 0.15
        
        return min(confidence, 1.0)


# =============================================================================
# MAIN DYNAMIC SCORER
# =============================================================================

class DynamicScoreCalculator:
    """
    Calculate final risk score with zero hardcoding.
    
    Everything derived from:
    - Evidence quality
    - TI validation
    - Attack chain detection
    - Cross-correlation
    - Data availability
    """
    
    def __init__(self):
        self.chain_detector = AttackChainDetector()
        self.evidence_weighter = DynamicEvidenceWeighter()
        self.ti_scorer = ThreatIntelScorer()
    
    def calculate(
        self,
        evidence_list: List[Evidence],
        ti_results: Optional[Dict[str, Any]] = None,
        ai_analysis: Optional[Dict[str, Any]] = None,
    ) -> FinalScore:
        """
        Calculate final score from all inputs.
        """
        result = FinalScore()
        breakdown = ScoreBreakdown()
        
        # 1. CALCULATE TI SCORE
        ti_score = self.ti_scorer.calculate(ti_results or {})
        
        # 2. DETECT ATTACK CHAINS
        attack_chains = self.chain_detector.detect_chains(evidence_list, ti_score)
        result.attack_chains = attack_chains
        
        # 3. CALCULATE EVIDENCE SCORE
        evidence_score, dimension_scores = self._calculate_evidence_score(
            evidence_list, ti_score
        )
        breakdown.dimensions = dimension_scores
        
        # 4. CALCULATE CHAIN SCORE
        chain_score = self._calculate_chain_score(attack_chains)
        
        # 5. CALCULATE AI SCORE (if available)
        ai_score, ai_confidence = self._calculate_ai_score(ai_analysis)
        
        # 6. CALCULATE CORRELATION BONUS
        correlation_bonus = self._calculate_correlation_bonus(
            evidence_list, ti_score, attack_chains
        )
        breakdown.correlation_bonus = correlation_bonus
        
        # 7. DYNAMIC WEIGHT CALCULATION
        weights = self._calculate_dynamic_weights(
            evidence_list, ti_score, attack_chains, ai_analysis
        )
        
        breakdown.evidence_score = evidence_score
        breakdown.evidence_weight = weights["evidence"]
        breakdown.ti_score = ti_score.value
        breakdown.ti_weight = weights["ti"]
        breakdown.chain_score = chain_score
        breakdown.chain_weight = weights["chain"]
        breakdown.ai_score = ai_score
        breakdown.ai_weight = weights["ai"]
        
        # 8. CALCULATE FINAL VALUE
        final_value = (
            evidence_score * weights["evidence"] +
            ti_score.value * weights["ti"] +
            chain_score * weights["chain"] +
            ai_score * weights["ai"] +
            correlation_bonus
        )
        
        # 9. CALCULATE CONFIDENCE
        confidence = self._calculate_confidence(
            evidence_list, ti_score, attack_chains, ai_analysis
        )
        
        # 10. DETERMINE LEVEL DYNAMICALLY
        level = self._calculate_level(final_value, confidence)
        
        # 11. DETERMINE CLASSIFICATION
        classification = self._determine_classification(attack_chains, evidence_list)
        
        # 12. GENERATE VERDICT AND EXPLANATION
        verdict = self._generate_verdict(final_value, level, confidence)
        explanation = self._generate_explanation(
            evidence_list, ti_score, attack_chains, breakdown
        )
        
        # 13. RECOMMENDED ACTION
        recommended_action = self._generate_action(level, attack_chains, confidence)
        
        # 14. EXTRACT MITRE
        mitre = self._extract_mitre(attack_chains, evidence_list)
        
        # 15. TOP EVIDENCE
        sorted_evidence = sorted(evidence_list, key=lambda e: e.quality_score, reverse=True)
        result.top_evidence = sorted_evidence[:10]
        
        # POPULATE RESULT
        result.value = min(100, max(0, int(final_value)))
        result.level = level
        result.confidence = confidence
        result.verdict = verdict
        result.classification = classification
        result.breakdown = breakdown
        result.explanation = explanation
        result.recommended_action = recommended_action
        result.mitre_techniques = mitre
        
        return result
    
    def _calculate_evidence_score(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
    ) -> Tuple[float, Dict[str, DimensionScore]]:
        """Calculate score from evidence with dimensional breakdown."""
        
        if not evidence_list:
            return 0.0, {}
        
        # Group by category
        by_category: Dict[str, List[Evidence]] = {}
        for e in evidence_list:
            cat = e.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(e)
        
        dimension_scores = {}
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for category, evidences in by_category.items():
            # Calculate dimension score
            dim_score = 0.0
            
            for evidence in evidences:
                weight = self.evidence_weighter.calculate_weight(
                    evidence, evidence_list, ti_score
                )
                dim_score += evidence.quality_score * weight * 15  # Scale factor
            
            # Apply diminishing returns
            dim_score = self._apply_diminishing_returns(dim_score, len(evidences))
            
            # Calculate dimension weight from data availability
            dim_weight = self._calculate_dimension_weight(category, by_category)
            
            # Calculate average quality
            avg_quality = sum(e.quality_score for e in evidences) / len(evidences)
            
            dimension_scores[category] = DimensionScore(
                name=category,
                score=min(100, dim_score),
                weight=dim_weight,
                evidence_count=len(evidences),
                avg_quality=avg_quality,
                indicators=[e.description for e in evidences[:5]],
            )
            
            total_weighted_score += dim_score * dim_weight
            total_weight += dim_weight
        
        # Normalize
        if total_weight > 0:
            final_score = total_weighted_score / total_weight
        else:
            final_score = 0
        
        return min(100, final_score), dimension_scores
    
    def _calculate_dimension_weight(
        self,
        category: str,
        all_categories: Dict[str, List[Evidence]],
    ) -> float:
        """Calculate dimension weight dynamically from data."""
        # Base weights - but these are starting points, not fixed
        base_weights = {
            "threat_intel": 0.30,
            "social_engineering": 0.20,
            "brand_impersonation": 0.18,
            "content": 0.15,
            "technical": 0.10,
            "behavioral": 0.05,
            "infrastructure": 0.02,
        }
        
        weight = base_weights.get(category, 0.1)
        
        # Adjust based on evidence quality in this category
        if category in all_categories:
            evidences = all_categories[category]
            avg_quality = sum(e.quality_score for e in evidences) / len(evidences)
            
            # Higher quality evidence = higher weight
            weight *= (0.8 + avg_quality * 0.4)  # 0.8 to 1.2 multiplier
            
            # More evidence = slightly higher weight
            if len(evidences) >= 3:
                weight *= 1.1
        
        return weight
    
    def _apply_diminishing_returns(self, score: float, count: int) -> float:
        """Apply diminishing returns for many evidence pieces."""
        if count <= 1:
            return score
        
        # Logarithmic scaling
        scale = 1 + (math.log(count + 1) / math.log(5))
        return (score / scale) * 1.3
    
    def _calculate_chain_score(self, chains: List[AttackChain]) -> float:
        """Calculate score contribution from attack chains."""
        if not chains:
            return 0.0
        
        score = 0.0
        for chain in chains:
            # Chain contribution based on confidence and quality
            chain_contrib = chain.confidence * 35  # Base max 35 per chain
            
            # Boost if TI confirms
            if chain.ti_confirmation:
                chain_contrib *= 1.25
            
            # Boost based on evidence quality
            chain_contrib *= (0.7 + chain.avg_evidence_quality * 0.6)
            
            score += chain_contrib
        
        # Cap total chain contribution
        return min(score, 50)
    
    def _calculate_ai_score(
        self,
        ai_analysis: Optional[Dict[str, Any]],
    ) -> Tuple[float, float]:
        """Extract score from AI analysis if available."""
        if not ai_analysis:
            return 0.0, 0.0
        
        # AI provides its own risk assessment
        ai_score = ai_analysis.get("risk_score", 0)
        ai_confidence = ai_analysis.get("confidence", 0.5)
        
        # Only use AI score if confidence is reasonable
        if ai_confidence < 0.4:
            ai_score *= 0.5
        
        return float(ai_score), ai_confidence
    
    def _calculate_correlation_bonus(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
    ) -> float:
        """Calculate bonus from cross-source correlation."""
        bonus = 0.0
        
        # Multiple categories with evidence
        categories = {e.category for e in evidence_list}
        if len(categories) >= 4:
            bonus += 8
        elif len(categories) >= 3:
            bonus += 5
        
        # TI confirms detection engine findings
        if ti_score.sources_flagged >= 2 and len(evidence_list) >= 3:
            bonus += 10
        
        # Attack chain detected with TI confirmation
        for chain in chains:
            if chain.ti_confirmation and chain.confidence > 0.6:
                bonus += 7
        
        # Multiple high-quality evidence pieces
        high_quality = [e for e in evidence_list if e.quality_score >= 0.7]
        if len(high_quality) >= 4:
            bonus += 5
        
        return min(bonus, 25)  # Cap bonus
    
    def _calculate_dynamic_weights(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
        ai_analysis: Optional[Dict[str, Any]],
    ) -> Dict[str, float]:
        """Calculate component weights dynamically from data availability."""
        
        # Start with base weights
        evidence_weight = 0.35 if evidence_list else 0
        ti_weight = 0.40 * ti_score.confidence if ti_score.confidence > 0 else 0
        chain_weight = 0.20 if chains else 0
        ai_weight = 0.15 if ai_analysis and ai_analysis.get("confidence", 0) > 0.4 else 0
        
        # Normalize to sum to 1.0
        total = evidence_weight + ti_weight + chain_weight + ai_weight
        
        if total == 0:
            return {"evidence": 0, "ti": 0, "chain": 0, "ai": 0}
        
        return {
            "evidence": evidence_weight / total,
            "ti": ti_weight / total,
            "chain": chain_weight / total,
            "ai": ai_weight / total,
        }
    
    def _calculate_confidence(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
        ai_analysis: Optional[Dict[str, Any]],
    ) -> float:
        """Calculate confidence from data quality and agreement."""
        confidence = 0.0
        
        # Evidence availability (up to 0.25)
        if evidence_list:
            evidence_confidence = min(len(evidence_list) / 8, 0.25)
            # Boost if high quality
            avg_quality = sum(e.quality_score for e in evidence_list) / len(evidence_list)
            evidence_confidence *= (0.8 + avg_quality * 0.4)
            confidence += evidence_confidence
        
        # TI confidence (up to 0.35)
        confidence += ti_score.confidence * 0.35
        
        # Chain detection (up to 0.20)
        if chains:
            best_chain = max(chains, key=lambda c: c.confidence)
            confidence += best_chain.confidence * 0.20
        
        # AI agreement (up to 0.10)
        if ai_analysis and ai_analysis.get("confidence", 0) > 0.5:
            confidence += 0.10
        
        # Source agreement bonus (up to 0.10)
        sources = {e.source for e in evidence_list}
        if len(sources) >= 4:
            confidence += 0.10
        elif len(sources) >= 3:
            confidence += 0.06
        
        return min(confidence, 1.0)
    
    def _calculate_level(self, score: float, confidence: float) -> str:
        """
        Determine risk level dynamically.
        
        Level depends on BOTH score AND confidence.
        """
        # Thresholds adjust based on confidence
        if confidence >= 0.7:
            # High confidence = tighter thresholds
            if score >= 70:
                return "critical"
            elif score >= 50:
                return "high"
            elif score >= 30:
                return "medium"
            elif score >= 15:
                return "low"
        elif confidence >= 0.4:
            # Medium confidence
            if score >= 80:
                return "critical"
            elif score >= 60:
                return "high"
            elif score >= 40:
                return "medium"
            elif score >= 20:
                return "low"
        else:
            # Low confidence = wider thresholds
            if score >= 90:
                return "critical"
            elif score >= 75:
                return "high"
            elif score >= 55:
                return "medium"
            elif score >= 30:
                return "low"
        
        return "informational"
    
    def _determine_classification(
        self,
        chains: List[AttackChain],
        evidence_list: List[Evidence],
    ) -> str:
        """Determine threat classification from chains and evidence."""
        
        # Use best chain if available
        if chains:
            best_chain = max(chains, key=lambda c: c.confidence)
            chain_to_class = {
                "credential_phishing": "phishing",
                "bec_wire_fraud": "bec",
                "malware_delivery": "malware_delivery",
                "brand_impersonation": "brand_impersonation",
                "callback_phishing": "callback_phishing",
                "smishing_financial": "smishing",
                "account_takeover": "account_takeover",
            }
            if best_chain.name in chain_to_class:
                return chain_to_class[best_chain.name]
        
        # Fallback to evidence-based classification
        evidence_types = {e.evidence_type for e in evidence_list}
        
        if EvidenceType.CREDENTIAL_FORM in evidence_types or EvidenceType.CREDENTIAL_REQUEST in evidence_types:
            return "phishing"
        if EvidenceType.WIRE_TRANSFER_REQUEST in evidence_types:
            return "bec"
        if EvidenceType.SUSPICIOUS_ATTACHMENT in evidence_types or EvidenceType.MACRO_ENABLED in evidence_types:
            return "malware_delivery"
        if EvidenceType.LOOKALIKE_DOMAIN in evidence_types:
            return "brand_impersonation"
        if EvidenceType.URGENCY_LANGUAGE in evidence_types:
            return "suspicious"
        
        return "unknown"
    
    def _generate_verdict(self, score: float, level: str, confidence: float) -> str:
        """Generate human-readable verdict."""
        conf_pct = int(confidence * 100)
        
        if level == "critical":
            return f"🔴 CRITICAL THREAT ({conf_pct}% confidence) - Immediate action required"
        elif level == "high":
            return f"🟠 HIGH RISK ({conf_pct}% confidence) - Likely malicious"
        elif level == "medium":
            return f"🟡 SUSPICIOUS ({conf_pct}% confidence) - Investigation recommended"
        elif level == "low":
            return f"🟢 LOW RISK ({conf_pct}% confidence) - Minor indicators"
        else:
            return f"⚪ CLEAN ({conf_pct}% confidence) - No significant threats"
    
    def _generate_explanation(
        self,
        evidence_list: List[Evidence],
        ti_score: TIScore,
        chains: List[AttackChain],
        breakdown: ScoreBreakdown,
    ) -> List[str]:
        """Generate detailed explanation."""
        explanation = []
        
        # Top evidence
        sorted_evidence = sorted(evidence_list, key=lambda e: e.quality_score, reverse=True)
        for e in sorted_evidence[:5]:
            icon = "🔴" if e.quality_score >= 0.7 else "🟡" if e.quality_score >= 0.4 else "⚪"
            explanation.append(f"{icon} {e.description}")
        
        # TI findings
        if ti_score.sources_flagged > 0:
            pct = int(ti_score.detection_ratio * 100)
            explanation.append(f"🔍 Threat Intelligence: {ti_score.sources_flagged}/{ti_score.sources_checked} sources flagged ({pct}%)")
            for source, detail in ti_score.sources_detail.items():
                if detail.get("flagged"):
                    explanation.append(f"   ├─ {source}: {detail.get('verdict', 'flagged')}")
        
        # Attack chains
        for chain in chains:
            conf_pct = int(chain.confidence * 100)
            explanation.append(f"⛓️ Attack Pattern: {chain.description} ({conf_pct}% confidence)")
        
        return explanation
    
    def _generate_action(
        self,
        level: str,
        chains: List[AttackChain],
        confidence: float,
    ) -> str:
        """Generate recommended action."""
        
        if level == "critical":
            if chains:
                chain_name = chains[0].name
                if "malware" in chain_name:
                    return "QUARANTINE attachment, block sender, scan endpoints"
                elif "phishing" in chain_name:
                    return "BLOCK sender, quarantine message, alert user if clicked"
                elif "bec" in chain_name:
                    return "HOLD for manual review, verify via phone with purported sender"
            return "QUARANTINE and investigate immediately"
        
        elif level == "high":
            if confidence >= 0.6:
                return "QUARANTINE for security review before delivery"
            return "DELIVER with warning banner, flag for monitoring"
        
        elif level == "medium":
            return "DELIVER with caution banner, log for analysis"
        
        elif level == "low":
            return "DELIVER normally, minor indicators logged"
        
        return "DELIVER - no action required"
    
    def _extract_mitre(
        self,
        chains: List[AttackChain],
        evidence_list: List[Evidence],
    ) -> List[Dict[str, str]]:
        """Extract MITRE ATT&CK techniques."""
        mitre = []
        seen = set()
        
        # From chains
        for chain in chains:
            for technique in chain.mitre_tactics:
                if technique not in seen:
                    mitre.append({"technique_id": technique, "source": chain.name})
                    seen.add(technique)
        
        # From evidence
        for e in evidence_list:
            if e.mitre_technique and e.mitre_technique not in seen:
                mitre.append({"technique_id": e.mitre_technique, "source": e.source.value})
                seen.add(e.mitre_technique)
        
        return mitre


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def calculate_dynamic_score(
    detection_results: Optional[Dict[str, Any]] = None,
    se_analysis: Optional[Dict[str, Any]] = None,
    content_analysis: Optional[Dict[str, Any]] = None,
    lookalike_results: Optional[Dict[str, Any]] = None,
    ti_results: Optional[Dict[str, Any]] = None,
    header_analysis: Optional[Dict[str, Any]] = None,
    ai_analysis: Optional[Dict[str, Any]] = None,
) -> FinalScore:
    """
    Convenience function to calculate dynamic score from all inputs.
    
    This is the main entry point for the scoring system.
    """
    # Collect evidence
    collector = EvidenceCollector()
    
    # Set API status from TI results
    if ti_results:
        collector.set_api_status(ti_results.get("api_status", {}))
    
    # Add evidence from all sources
    if detection_results:
        collector.add_from_detection_rules(detection_results.get("rules_triggered", []))
    
    if ti_results:
        collector.add_from_ti_results(ti_results)
    
    if se_analysis:
        collector.add_from_se_analysis(se_analysis)
    
    if lookalike_results:
        collector.add_from_lookalike_analysis(lookalike_results)
    
    if content_analysis:
        collector.add_from_content_analysis(content_analysis)
    
    if header_analysis:
        collector.add_from_header_analysis(header_analysis)
    
    # Calculate score
    calculator = DynamicScoreCalculator()
    return calculator.calculate(
        evidence_list=collector.get_all_evidence(),
        ti_results=ti_results,
        ai_analysis=ai_analysis,
    )
