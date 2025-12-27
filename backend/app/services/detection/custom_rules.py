"""
NiksES Custom Detection Rules

Allows users to create and manage custom detection rules.
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

from app.models.detection import RiskLevel, DetectionRule
from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults

logger = logging.getLogger(__name__)

# Alias for compatibility
Severity = RiskLevel


class MatchType(str, Enum):
    """Types of matching for custom rules."""
    CONTAINS = "contains"
    REGEX = "regex"
    EQUALS = "equals"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    NOT_CONTAINS = "not_contains"


class FieldTarget(str, Enum):
    """Email fields that can be targeted by rules."""
    SUBJECT = "subject"
    BODY = "body"
    SENDER_EMAIL = "sender_email"
    SENDER_DOMAIN = "sender_domain"
    REPLY_TO = "reply_to"
    URLS = "urls"
    ATTACHMENT_NAMES = "attachment_names"
    ATTACHMENT_EXTENSIONS = "attachment_extensions"
    HEADERS = "headers"


@dataclass
class RuleCondition:
    """A single condition within a custom rule."""
    field: FieldTarget
    match_type: MatchType
    value: str
    case_sensitive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field.value,
            "match_type": self.match_type.value,
            "value": self.value,
            "case_sensitive": self.case_sensitive,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleCondition":
        return cls(
            field=FieldTarget(data["field"]),
            match_type=MatchType(data["match_type"]),
            value=data["value"],
            case_sensitive=data.get("case_sensitive", False),
        )


@dataclass
class CustomRule:
    """User-defined detection rule."""
    rule_id: str
    name: str
    description: str
    category: str
    severity: RiskLevel
    conditions: List[RuleCondition]
    logic: str = "AND"
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    author: str = "user"
    tags: List[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "conditions": [c.to_dict() for c in self.conditions],
            "logic": self.logic,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "author": self.author,
            "tags": self.tags,
            "mitre_technique": self.mitre_technique,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CustomRule":
        return cls(
            rule_id=data["rule_id"],
            name=data["name"],
            description=data["description"],
            category=data["category"],
            severity=RiskLevel(data["severity"]),
            conditions=[RuleCondition.from_dict(c) for c in data["conditions"]],
            logic=data.get("logic", "AND"),
            enabled=data.get("enabled", True),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data.get("created_at"), str) else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if isinstance(data.get("updated_at"), str) else datetime.utcnow(),
            author=data.get("author", "user"),
            tags=data.get("tags", []),
            mitre_technique=data.get("mitre_technique"),
        )


class CustomRuleEngine:
    """Engine for evaluating custom detection rules."""
    
    def __init__(self):
        self._rules: Dict[str, CustomRule] = {}
        self._rule_counter = 0
    
    def add_rule(self, rule: CustomRule) -> str:
        """Add a custom rule."""
        self._rules[rule.rule_id] = rule
        logger.info(f"Added custom rule: {rule.rule_id} - {rule.name}")
        return rule.rule_id
    
    def create_rule(
        self,
        name: str,
        description: str,
        category: str,
        severity: RiskLevel,
        conditions: List[Dict[str, Any]],
        logic: str = "AND",
        tags: List[str] = None,
        mitre_technique: str = None,
    ) -> CustomRule:
        """Create and add a new custom rule."""
        self._rule_counter += 1
        rule_id = f"CUSTOM-{self._rule_counter:03d}"
        
        rule = CustomRule(
            rule_id=rule_id,
            name=name,
            description=description,
            category=category,
            severity=severity,
            conditions=[RuleCondition.from_dict(c) for c in conditions],
            logic=logic,
            tags=tags or [],
            mitre_technique=mitre_technique,
        )
        
        self.add_rule(rule)
        return rule
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[CustomRule]:
        """Update an existing rule."""
        if rule_id not in self._rules:
            return None
        
        rule = self._rules[rule_id]
        
        if "name" in updates:
            rule.name = updates["name"]
        if "description" in updates:
            rule.description = updates["description"]
        if "category" in updates:
            rule.category = updates["category"]
        if "severity" in updates:
            rule.severity = RiskLevel(updates["severity"])
        if "conditions" in updates:
            rule.conditions = [RuleCondition.from_dict(c) for c in updates["conditions"]]
        if "logic" in updates:
            rule.logic = updates["logic"]
        if "enabled" in updates:
            rule.enabled = updates["enabled"]
        if "tags" in updates:
            rule.tags = updates["tags"]
        if "mitre_technique" in updates:
            rule.mitre_technique = updates["mitre_technique"]
        
        rule.updated_at = datetime.utcnow()
        return rule
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a custom rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Deleted custom rule: {rule_id}")
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[CustomRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)
    
    def list_rules(self, enabled_only: bool = False) -> List[CustomRule]:
        """List all custom rules."""
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules
    
    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = enabled
            self._rules[rule_id].updated_at = datetime.utcnow()
            return True
        return False
    
    def _get_field_value(self, email: ParsedEmail, field: FieldTarget) -> List[str]:
        """Extract field value(s) from email."""
        if field == FieldTarget.SUBJECT:
            return [email.subject or ""]
        elif field == FieldTarget.BODY:
            return [email.body_text or ""]
        elif field == FieldTarget.SENDER_EMAIL:
            return [email.sender.email if email.sender else ""]
        elif field == FieldTarget.SENDER_DOMAIN:
            return [email.sender.domain if email.sender else ""]
        elif field == FieldTarget.REPLY_TO:
            return [r.email for r in (email.reply_to or [])]
        elif field == FieldTarget.URLS:
            return [u.url for u in (email.urls or [])]
        elif field == FieldTarget.ATTACHMENT_NAMES:
            return [a.filename for a in (email.attachments or [])]
        elif field == FieldTarget.ATTACHMENT_EXTENSIONS:
            return [a.extension or "" for a in (email.attachments or [])]
        elif field == FieldTarget.HEADERS:
            return [str(email.raw_headers) if email.raw_headers else ""]
        return []
    
    def _check_condition(self, value: str, condition: RuleCondition) -> bool:
        """Check if a value matches a condition."""
        test_value = value if condition.case_sensitive else value.lower()
        match_value = condition.value if condition.case_sensitive else condition.value.lower()
        
        if condition.match_type == MatchType.CONTAINS:
            return match_value in test_value
        elif condition.match_type == MatchType.NOT_CONTAINS:
            return match_value not in test_value
        elif condition.match_type == MatchType.EQUALS:
            return test_value == match_value
        elif condition.match_type == MatchType.STARTS_WITH:
            return test_value.startswith(match_value)
        elif condition.match_type == MatchType.ENDS_WITH:
            return test_value.endswith(match_value)
        elif condition.match_type == MatchType.REGEX:
            try:
                flags = 0 if condition.case_sensitive else re.IGNORECASE
                return bool(re.search(condition.value, value, flags))
            except re.error:
                logger.warning(f"Invalid regex pattern: {condition.value}")
                return False
        return False
    
    def _evaluate_condition(self, email: ParsedEmail, condition: RuleCondition) -> tuple:
        """Evaluate a single condition against an email."""
        field_values = self._get_field_value(email, condition.field)
        evidence = []
        
        for value in field_values:
            if self._check_condition(value, condition):
                evidence.append(f"{condition.field.value}: matched '{condition.value}'")
                return True, evidence
        
        return False, evidence
    
    def _get_severity_score(self, severity: RiskLevel) -> int:
        """Get score impact for severity."""
        scores = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5,
            RiskLevel.INFORMATIONAL: 2,
        }
        return scores.get(severity, 5)
    
    def evaluate_rule(self, rule: CustomRule, email: ParsedEmail) -> Optional[DetectionRule]:
        """Evaluate a single rule against an email."""
        if not rule.enabled:
            return None
        
        all_evidence = []
        results = []
        
        for condition in rule.conditions:
            matched, evidence = self._evaluate_condition(email, condition)
            results.append(matched)
            all_evidence.extend(evidence)
        
        # Apply logic
        if rule.logic == "AND":
            triggered = all(results) if results else False
        else:  # OR
            triggered = any(results)
        
        if triggered:
            return DetectionRule(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                category=rule.category,
                severity=rule.severity,
                description=rule.description,
                evidence=all_evidence,
                score_impact=self._get_severity_score(rule.severity),
                triggered=True,
                mitre_technique=rule.mitre_technique,
            )
        
        return None
    
    async def analyze(self, email: ParsedEmail, enrichment: Optional[EnrichmentResults] = None) -> List[DetectionRule]:
        """Run all enabled custom rules against an email."""
        matches = []
        
        for rule in self._rules.values():
            if rule.enabled:
                match = self.evaluate_rule(rule, email)
                if match:
                    matches.append(match)
        
        return matches
    
    def export_rules(self) -> str:
        """Export all rules to JSON."""
        return json.dumps([r.to_dict() for r in self._rules.values()], indent=2)
    
    def import_rules(self, json_data: str) -> int:
        """Import rules from JSON. Returns count of imported rules."""
        data = json.loads(json_data)
        count = 0
        
        for rule_data in data:
            rule = CustomRule.from_dict(rule_data)
            self._rules[rule.rule_id] = rule
            count += 1
            
            # Update counter
            if rule.rule_id.startswith("CUSTOM-"):
                try:
                    num = int(rule.rule_id.split("-")[1])
                    self._rule_counter = max(self._rule_counter, num)
                except:
                    pass
        
        return count


# Global instance
_custom_rule_engine: Optional[CustomRuleEngine] = None


def get_custom_rule_engine() -> CustomRuleEngine:
    """Get or create the custom rule engine."""
    global _custom_rule_engine
    if _custom_rule_engine is None:
        _custom_rule_engine = CustomRuleEngine()
        _add_example_rules(_custom_rule_engine)
    return _custom_rule_engine


def _add_example_rules(engine: CustomRuleEngine):
    """Add some example custom rules."""
    # Example: Detect internal keyword
    engine.create_rule(
        name="Confidential Keyword Detection",
        description="Detects emails containing confidential markers",
        category="data_protection",
        severity=RiskLevel.MEDIUM,
        conditions=[
            {"field": "subject", "match_type": "contains", "value": "CONFIDENTIAL"},
            {"field": "body", "match_type": "contains", "value": "do not forward"},
        ],
        logic="OR",
        tags=["dlp", "confidential"],
    )
    
    # Example: Suspicious sender pattern
    engine.create_rule(
        name="Numeric Sender Domain",
        description="Sender domain contains excessive numbers (suspicious)",
        category="phishing",
        severity=RiskLevel.LOW,
        conditions=[
            {"field": "sender_domain", "match_type": "regex", "value": r"\d{4,}"},
        ],
        tags=["suspicious-sender"],
    )
