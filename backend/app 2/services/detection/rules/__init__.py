"""
NiksES Detection Rules

All detection rules are automatically registered via the @register_rule decorator.
"""

from .base import (
    DetectionRule,
    RuleMatch,
    RuleRegistry,
    rule_registry,
    register_rule,
    SEVERITY_SCORES,
)

# Import all rule modules to trigger registration
from . import authentication
from . import phishing
from . import malware
from . import bec
from . import lookalike
from . import social_engineering
from . import ip_reputation  # IP reputation/threat intelligence rules
from . import brand_impersonation  # Brand spoofing and impersonation rules

# Get all registered rules
def get_all_rules():
    """Get all registered detection rules."""
    return rule_registry.get_all_rules()

def get_rules_by_category(category: str):
    """Get rules by category."""
    return rule_registry.get_rules_by_category(category)

__all__ = [
    'DetectionRule',
    'RuleMatch',
    'RuleRegistry',
    'rule_registry',
    'register_rule',
    'SEVERITY_SCORES',
    'get_all_rules',
    'get_rules_by_category',
]
