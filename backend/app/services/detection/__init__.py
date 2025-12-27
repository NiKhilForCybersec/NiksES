"""
NiksES Detection Module

Rule-based threat detection engine for email analysis.

Includes the Dynamic Intelligent Detection Architecture (DIDA):
- Evidence-based scoring (no hardcoded values)
- TI-anchored validation
- Attack chain detection
- Confidence-adjusted thresholds
"""

from .engine import (
    DetectionEngine,
    get_detection_engine,
    analyze_email,
)

from .scorer import RiskScorer

from .rules import (
    DetectionRule,
    RuleMatch,
    rule_registry,
    get_all_rules,
    get_rules_by_category,
    SEVERITY_SCORES,
)

__all__ = [
    # Engine
    'DetectionEngine',
    'get_detection_engine',
    'analyze_email',
    
    # Scorer
    'RiskScorer',
    
    # Rules
    'DetectionRule',
    'RuleMatch',
    'rule_registry',
    'get_all_rules',
    'get_rules_by_category',
    'SEVERITY_SCORES',
]

# Custom rules
from .custom_rules import (
    get_custom_rule_engine,
    CustomRule,
    CustomRuleEngine,
    MatchType,
    FieldTarget,
)

__all__.extend([
    'get_custom_rule_engine',
    'CustomRule', 
    'CustomRuleEngine',
    'MatchType',
    'FieldTarget',
])

# Dynamic Intelligent Detection Architecture (DIDA)
from .evidence import (
    Evidence,
    EvidenceCategory,
    EvidenceType,
    EvidenceSource,
    AttackChain,
    EvidenceCollector,
    SourceReliabilityCalculator,
    SpecificityCalculator,
)

from .dynamic_scorer import (
    DynamicScoreCalculator,
    DynamicEvidenceWeighter,
    AttackChainDetector,
    ThreatIntelScorer,
    TIScore,
    FinalScore,
    ScoreBreakdown,
    DimensionScore,
    calculate_dynamic_score,
)

from .sms_dynamic_scorer import (
    SMSDynamicScorer,
    SMSEvidenceCollector,
    SMSAttackChainDetector,
    calculate_sms_dynamic_score,
)

__all__.extend([
    # Evidence System
    'Evidence',
    'EvidenceCategory',
    'EvidenceType',
    'EvidenceSource',
    'AttackChain',
    'EvidenceCollector',
    'SourceReliabilityCalculator',
    'SpecificityCalculator',
    
    # Dynamic Scoring
    'DynamicScoreCalculator',
    'DynamicEvidenceWeighter',
    'AttackChainDetector',
    'ThreatIntelScorer',
    'TIScore',
    'FinalScore',
    'ScoreBreakdown',
    'DimensionScore',
    'calculate_dynamic_score',
    
    # SMS/URL Dynamic Scoring
    'SMSDynamicScorer',
    'SMSEvidenceCollector',
    'SMSAttackChainDetector',
    'calculate_sms_dynamic_score',
])
