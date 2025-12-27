"""
NiksES Dynamic Scoring Configuration

ALL scoring thresholds and weights are centralized here.
No hardcoded values anywhere else in the codebase.

This can be loaded from:
1. Environment variables
2. Database/settings API
3. Config file

Usage:
    from app.config.scoring import get_scoring_config
    config = get_scoring_config()
    
    if score >= config.thresholds.critical:
        level = "critical"
"""

import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# RISK LEVEL THRESHOLDS
# =============================================================================

@dataclass
class RiskThresholds:
    """Thresholds for risk level classification."""
    
    # Score thresholds (0-100)
    critical: int = 75      # >= this = CRITICAL
    high: int = 50          # >= this = HIGH
    medium: int = 25        # >= this = MEDIUM
    low: int = 10           # >= this = LOW
    # Below low = CLEAN
    
    # Confidence-adjusted thresholds
    # When confidence is high, we can be more aggressive
    high_confidence_critical: int = 50
    high_confidence_high: int = 30
    high_confidence_medium: int = 18
    high_confidence_low: int = 8
    
    # When confidence is medium
    medium_confidence_critical: int = 60
    medium_confidence_high: int = 40
    medium_confidence_medium: int = 22
    medium_confidence_low: int = 10
    
    # When confidence is low, we need higher scores
    low_confidence_critical: int = 75
    low_confidence_high: int = 50
    low_confidence_medium: int = 28
    low_confidence_low: int = 12
    
    def get_threshold(self, level: str, confidence: float = 0.5) -> int:
        """Get dynamic threshold based on confidence."""
        if confidence >= 0.7:
            prefix = "high_confidence_"
        elif confidence >= 0.4:
            prefix = "medium_confidence_"
        else:
            prefix = "low_confidence_"
        
        return getattr(self, f"{prefix}{level}", getattr(self, level))


# =============================================================================
# THREAT INTELLIGENCE WEIGHTS
# =============================================================================

@dataclass
class TIWeights:
    """Weights for threat intelligence sources in fusion."""
    
    # URL/Domain scanning
    virustotal: float = 0.25
    google_safebrowsing: float = 0.20
    ipqualityscore: float = 0.20
    urlhaus: float = 0.15
    phishtank: float = 0.10
    
    # IP reputation
    abuseipdb: float = 0.15
    
    # Domain info
    whois: float = 0.05
    
    # Sandbox
    hybrid_analysis: float = 0.20
    urlscan: float = 0.15
    
    def get_weight(self, source: str) -> float:
        """Get weight for a TI source."""
        return getattr(self, source.lower().replace("-", "_"), 0.1)


@dataclass
class TIThresholds:
    """Thresholds for TI source verdicts."""
    
    # VirusTotal
    vt_malicious_engines: int = 3      # >= this = MALICIOUS
    vt_suspicious_engines: int = 1     # >= this = SUSPICIOUS
    
    # IPQualityScore  
    ipqs_malicious: int = 85           # >= this = MALICIOUS
    ipqs_suspicious: int = 75          # >= this = SUSPICIOUS
    ipqs_risky: int = 50               # >= this = RISKY
    
    # AbuseIPDB
    abuseipdb_malicious: int = 75      # >= this = MALICIOUS
    abuseipdb_suspicious: int = 25     # >= this = SUSPICIOUS
    
    # Consensus thresholds
    sources_for_high_confidence: int = 3   # Need >= this many sources
    sources_flagged_for_malicious: int = 2  # >= this many flagged = MALICIOUS
    sources_flagged_for_consensus: int = 3  # >= this = HIGH confidence


# =============================================================================
# SOCIAL ENGINEERING SCORING
# =============================================================================

@dataclass
class SEWeights:
    """Weights for SE technique scoring."""
    
    urgency: float = 0.20
    fear: float = 0.25
    authority: float = 0.20
    reward: float = 0.10
    scarcity: float = 0.10
    trust: float = 0.10
    social_proof: float = 0.05
    
    def get_weight(self, technique: str) -> float:
        return getattr(self, technique.lower(), 0.1)


@dataclass
class SEThresholds:
    """Thresholds for SE analysis."""
    
    # Overall SE score levels
    critical: int = 75
    high: int = 50
    medium: int = 25
    low: int = 10
    
    # Individual technique thresholds
    technique_significant: int = 30   # >= this = technique is being used
    technique_strong: int = 50        # >= this = strong usage
    
    # Multiple tactics bonus
    multiple_tactics_threshold: int = 2   # >= this many = bonus
    multiple_tactics_bonus: int = 10
    strong_multiple_tactics_threshold: int = 3
    strong_multiple_tactics_bonus: int = 15
    
    # Keyword scoring
    keyword_match_score: int = 20     # Base score per keyword match
    deadline_bonus: int = 30          # Bonus for deadline detection
    threat_bonus: int = 30            # Bonus for threat detection


# =============================================================================
# DETECTION RULE SCORING
# =============================================================================

@dataclass
class DetectionWeights:
    """Weights for detection rule categories."""
    
    # Category weights
    authentication: float = 0.20      # SPF, DKIM, DMARC failures
    reputation: float = 0.25          # TI-based detection
    content: float = 0.20             # Pattern matching
    social_engineering: float = 0.15  # SE tactics
    lookalike: float = 0.10           # Domain spoofing
    header_anomaly: float = 0.10      # Suspicious headers
    
    # Severity multipliers
    critical_multiplier: float = 1.0
    high_multiplier: float = 0.75
    medium_multiplier: float = 0.5
    low_multiplier: float = 0.25
    info_multiplier: float = 0.1
    
    def get_severity_multiplier(self, severity: str) -> float:
        return getattr(self, f"{severity.lower()}_multiplier", 0.5)


@dataclass
class DetectionThresholds:
    """Thresholds for detection rule scoring."""
    
    # Minimum confidence for rule to contribute
    min_rule_confidence: float = 0.3
    
    # Quality score thresholds
    high_quality_evidence: float = 0.7
    medium_quality_evidence: float = 0.4
    
    # Score normalization
    max_raw_score: int = 150          # Cap raw scores before normalization
    
    # Chain detection
    min_chain_confidence: float = 0.4


# =============================================================================
# AI ANALYSIS CONFIGURATION
# =============================================================================

@dataclass
class AIConfig:
    """Configuration for AI analysis."""
    
    # LLM blending
    llm_blend_weight: float = 0.4     # How much LLM contributes vs heuristics
    min_llm_confidence: float = 0.3   # Min confidence to use LLM results
    
    # Scoring
    ti_confirmation_bonus: int = 10    # Bonus when TI confirms AI assessment
    multi_source_bonus: int = 5        # Bonus for each additional confirming source
    
    # Thresholds for AI recommendations
    block_threshold: int = 80
    quarantine_threshold: int = 60
    review_threshold: int = 40
    
    # Model selection
    default_model: str = "gpt-4o-mini"
    fallback_model: str = "gpt-3.5-turbo"


# =============================================================================
# ENRICHMENT CONFIGURATION
# =============================================================================

@dataclass
class EnrichmentConfig:
    """Configuration for enrichment services."""
    
    # Timeouts (seconds)
    default_timeout: int = 15
    sandbox_timeout: int = 120
    
    # Rate limiting
    max_urls_to_check: int = 10
    max_ips_to_check: int = 5
    max_hashes_to_check: int = 5
    
    # Retry configuration
    max_retries: int = 3
    retry_delay: float = 1.0


# =============================================================================
# MASTER CONFIGURATION
# =============================================================================

@dataclass
class ScoringConfig:
    """Master scoring configuration."""
    
    thresholds: RiskThresholds = field(default_factory=RiskThresholds)
    ti_weights: TIWeights = field(default_factory=TIWeights)
    ti_thresholds: TIThresholds = field(default_factory=TIThresholds)
    se_weights: SEWeights = field(default_factory=SEWeights)
    se_thresholds: SEThresholds = field(default_factory=SEThresholds)
    detection_weights: DetectionWeights = field(default_factory=DetectionWeights)
    detection_thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)
    ai_config: AIConfig = field(default_factory=AIConfig)
    enrichment_config: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "thresholds": self.thresholds.__dict__,
            "ti_weights": self.ti_weights.__dict__,
            "ti_thresholds": self.ti_thresholds.__dict__,
            "se_weights": self.se_weights.__dict__,
            "se_thresholds": self.se_thresholds.__dict__,
            "detection_weights": self.detection_weights.__dict__,
            "detection_thresholds": self.detection_thresholds.__dict__,
            "ai_config": self.ai_config.__dict__,
            "enrichment_config": self.enrichment_config.__dict__,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScoringConfig":
        """Create config from dictionary."""
        config = cls()
        
        if "thresholds" in data:
            for k, v in data["thresholds"].items():
                if hasattr(config.thresholds, k):
                    setattr(config.thresholds, k, v)
        
        if "ti_weights" in data:
            for k, v in data["ti_weights"].items():
                if hasattr(config.ti_weights, k):
                    setattr(config.ti_weights, k, v)
        
        # ... similar for other sections
        
        return config
    
    @classmethod
    def from_env(cls) -> "ScoringConfig":
        """Create config from environment variables."""
        config = cls()
        
        # Risk thresholds
        if os.getenv("RISK_THRESHOLD_CRITICAL"):
            config.thresholds.critical = int(os.getenv("RISK_THRESHOLD_CRITICAL"))
        if os.getenv("RISK_THRESHOLD_HIGH"):
            config.thresholds.high = int(os.getenv("RISK_THRESHOLD_HIGH"))
        if os.getenv("RISK_THRESHOLD_MEDIUM"):
            config.thresholds.medium = int(os.getenv("RISK_THRESHOLD_MEDIUM"))
        if os.getenv("RISK_THRESHOLD_LOW"):
            config.thresholds.low = int(os.getenv("RISK_THRESHOLD_LOW"))
        
        # TI weights
        if os.getenv("TI_WEIGHT_VIRUSTOTAL"):
            config.ti_weights.virustotal = float(os.getenv("TI_WEIGHT_VIRUSTOTAL"))
        if os.getenv("TI_WEIGHT_GSB"):
            config.ti_weights.google_safebrowsing = float(os.getenv("TI_WEIGHT_GSB"))
        if os.getenv("TI_WEIGHT_IPQS"):
            config.ti_weights.ipqualityscore = float(os.getenv("TI_WEIGHT_IPQS"))
        
        # AI config
        if os.getenv("AI_BLOCK_THRESHOLD"):
            config.ai_config.block_threshold = int(os.getenv("AI_BLOCK_THRESHOLD"))
        if os.getenv("AI_QUARANTINE_THRESHOLD"):
            config.ai_config.quarantine_threshold = int(os.getenv("AI_QUARANTINE_THRESHOLD"))
        
        return config


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_scoring_config: Optional[ScoringConfig] = None


def get_scoring_config() -> ScoringConfig:
    """Get the global scoring configuration."""
    global _scoring_config
    if _scoring_config is None:
        _scoring_config = ScoringConfig.from_env()
        logger.info("Scoring configuration loaded")
    return _scoring_config


def update_scoring_config(updates: Dict[str, Any]) -> ScoringConfig:
    """Update scoring configuration dynamically."""
    global _scoring_config
    config = get_scoring_config()
    
    # Update thresholds
    if "thresholds" in updates:
        for k, v in updates["thresholds"].items():
            if hasattr(config.thresholds, k):
                setattr(config.thresholds, k, v)
                logger.info(f"Updated threshold {k} = {v}")
    
    # Update TI weights
    if "ti_weights" in updates:
        for k, v in updates["ti_weights"].items():
            if hasattr(config.ti_weights, k):
                setattr(config.ti_weights, k, v)
                logger.info(f"Updated TI weight {k} = {v}")
    
    # Update SE weights
    if "se_weights" in updates:
        for k, v in updates["se_weights"].items():
            if hasattr(config.se_weights, k):
                setattr(config.se_weights, k, v)
                logger.info(f"Updated SE weight {k} = {v}")
    
    return config


def reset_scoring_config():
    """Reset scoring config to defaults."""
    global _scoring_config
    _scoring_config = None
    logger.info("Scoring configuration reset to defaults")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def calculate_risk_level(score: int, confidence: float = 0.5) -> str:
    """Calculate risk level from score with confidence adjustment."""
    config = get_scoring_config()
    thresholds = config.thresholds
    
    critical = thresholds.get_threshold("critical", confidence)
    high = thresholds.get_threshold("high", confidence)
    medium = thresholds.get_threshold("medium", confidence)
    low = thresholds.get_threshold("low", confidence)
    
    if score >= critical:
        return "critical"
    elif score >= high:
        return "high"
    elif score >= medium:
        return "medium"
    elif score >= low:
        return "low"
    else:
        return "clean"


def calculate_ti_verdict(source: str, score: int) -> str:
    """Calculate TI verdict based on source-specific thresholds."""
    config = get_scoring_config()
    ti = config.ti_thresholds
    
    if source.lower() == "ipqualityscore":
        if score >= ti.ipqs_malicious:
            return "malicious"
        elif score >= ti.ipqs_suspicious:
            return "suspicious"
        elif score >= ti.ipqs_risky:
            return "risky"
        return "clean"
    
    elif source.lower() == "abuseipdb":
        if score >= ti.abuseipdb_malicious:
            return "malicious"
        elif score >= ti.abuseipdb_suspicious:
            return "suspicious"
        return "clean"
    
    elif source.lower() == "virustotal":
        if score >= ti.vt_malicious_engines:
            return "malicious"
        elif score >= ti.vt_suspicious_engines:
            return "suspicious"
        return "clean"
    
    # Generic
    if score >= 75:
        return "malicious"
    elif score >= 40:
        return "suspicious"
    elif score > 0:
        return "risky"
    return "clean"


def calculate_se_level(score: int) -> str:
    """Calculate SE level from score."""
    config = get_scoring_config()
    se = config.se_thresholds
    
    if score >= se.critical:
        return "critical"
    elif score >= se.high:
        return "high"
    elif score >= se.medium:
        return "medium"
    elif score >= se.low:
        return "low"
    return "none"


def get_ai_recommendation(score: int) -> str:
    """Get AI recommendation based on score."""
    config = get_scoring_config()
    ai = config.ai_config
    
    if score >= ai.block_threshold:
        return "block"
    elif score >= ai.quarantine_threshold:
        return "quarantine"
    elif score >= ai.review_threshold:
        return "review"
    return "allow"
