"""
NiksES Detection Rule Base Class

Abstract base class for all detection rules.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import RiskLevel

logger = logging.getLogger(__name__)


# Score weights by severity
# These scores should reflect the actual risk - authentication failures are serious!
SEVERITY_SCORES = {
    RiskLevel.INFORMATIONAL: 5,
    RiskLevel.LOW: 10,
    RiskLevel.MEDIUM: 20,
    RiskLevel.HIGH: 35,      # SPF/DKIM failures, malicious URLs
    RiskLevel.CRITICAL: 50,   # Multiple auth failures, known malware
}


@dataclass
class RuleMatch:
    """Result of a detection rule evaluation."""
    rule_id: str
    rule_name: str
    category: str
    severity: RiskLevel
    description: str
    evidence: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    
    @property
    def score_contribution(self) -> int:
        """Get score contribution based on severity."""
        return SEVERITY_SCORES.get(self.severity, 0)


class DetectionRule(ABC):
    """
    Abstract base class for all detection rules.
    
    Each rule must define:
    - rule_id: Unique identifier (e.g., "AUTH-001")
    - name: Human-readable name
    - description: What this rule detects
    - category: Rule category (authentication, phishing, malware, bec, etc.)
    - severity: Default severity level
    - mitre_technique: Optional MITRE ATT&CK ID
    
    Each rule must implement:
    - evaluate(): Check if rule matches and return RuleMatch or None
    """
    
    rule_id: str = "BASE-000"
    name: str = "Base Rule"
    description: str = "Base detection rule"
    category: str = "general"
    severity: RiskLevel = RiskLevel.INFORMATIONAL
    mitre_technique: Optional[str] = None
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def evaluate(
        self,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> Optional[RuleMatch]:
        """
        Evaluate rule against email.
        
        Args:
            email: Parsed email data
            enrichment: Optional enrichment results
            
        Returns:
            RuleMatch if rule triggered, None otherwise
        """
        pass
    
    def create_match(
        self,
        evidence: List[str],
        indicators: Optional[List[Dict[str, Any]]] = None,
        severity_override: Optional[RiskLevel] = None,
        description_override: Optional[str] = None,
    ) -> RuleMatch:
        """
        Create a RuleMatch for this rule.
        
        Args:
            evidence: List of evidence strings
            indicators: Optional list of indicator dictionaries
            severity_override: Override default severity
            description_override: Override default description
            
        Returns:
            RuleMatch instance
        """
        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
            severity=severity_override or self.severity,
            description=description_override or self.description,
            evidence=evidence,
            indicators=indicators or [],
            mitre_technique=self.mitre_technique,
        )
    
    def get_body_text(self, email: ParsedEmail) -> str:
        """Get combined body text for analysis."""
        parts = []
        if email.subject:
            parts.append(email.subject)
        if email.body_text:
            parts.append(email.body_text)
        if email.body_html:
            # Strip HTML for text analysis
            import re
            text = re.sub(r'<[^>]+>', ' ', email.body_html)
            text = re.sub(r'\s+', ' ', text)
            parts.append(text)
        return ' '.join(parts).lower()
    
    def get_sender_domain(self, email: ParsedEmail) -> Optional[str]:
        """Get sender domain from email."""
        if email.sender and email.sender.domain:
            return email.sender.domain.lower()
        return None
    
    def get_reply_to_domain(self, email: ParsedEmail) -> Optional[str]:
        """Get reply-to domain from email."""
        if email.reply_to and len(email.reply_to) > 0:
            return email.reply_to[0].domain.lower()
        return None


class RuleRegistry:
    """Registry of all detection rules."""
    
    _instance = None
    _rules: List[DetectionRule] = []
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._rules = []
        return cls._instance
    
    def register(self, rule: DetectionRule) -> None:
        """Register a detection rule."""
        self._rules.append(rule)
    
    def get_all_rules(self) -> List[DetectionRule]:
        """Get all registered rules."""
        return self._rules
    
    def get_rules_by_category(self, category: str) -> List[DetectionRule]:
        """Get rules by category."""
        return [r for r in self._rules if r.category == category]
    
    def clear(self) -> None:
        """Clear all registered rules."""
        self._rules = []


# Global registry
rule_registry = RuleRegistry()


def register_rule(rule_class: type) -> type:
    """Decorator to register a rule class."""
    rule_registry.register(rule_class())
    return rule_class
