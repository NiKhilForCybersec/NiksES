"""
NiksES Detection Module

Rule-based threat detection engine for email analysis.
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
