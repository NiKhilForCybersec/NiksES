"""
NiksES Detection Engine

Main detection engine that orchestrates all detection rules.
"""

import logging
import asyncio
from typing import List, Optional, Dict, Any

from app.models.email import ParsedEmail
from app.models.enrichment import EnrichmentResults
from app.models.detection import (
    DetectionResults,
    DetectionRule as DetectionRuleModel,
    RiskLevel,
    EmailClassification,
)
from app.services.detection.rules import rule_registry, RuleMatch
from app.services.detection.scorer import RiskScorer

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Main detection engine.
    
    Runs all detection rules against parsed email and enrichment data,
    aggregates results, and calculates risk scores.
    """
    
    def __init__(self):
        """Initialize detection engine with all rules."""
        self.scorer = RiskScorer()
        self._rules = None  # Lazy load
    
    @property
    def rules(self):
        """Get all registered rules (lazy loaded)."""
        if self._rules is None:
            self._rules = rule_registry.get_all_rules()
        return self._rules
    
    def reload_rules(self):
        """Reload rules from registry."""
        self._rules = rule_registry.get_all_rules()
    
    async def analyze(
        self,
        parsed_email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> DetectionResults:
        """
        Run all detection rules and return results.
        
        Args:
            parsed_email: Parsed email data
            enrichment: Optional enrichment results
            
        Returns:
            DetectionResults with all triggered rules and scores
        """
        logger.info(f"Starting detection analysis with {len(self.rules)} rules")
        
        # Run all rules concurrently
        tasks = []
        for rule in self.rules:
            tasks.append(self._run_rule(rule, parsed_email, enrichment))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Separate triggered and passed rules
        triggered_matches: List[RuleMatch] = []
        passed_rules: List[DetectionRuleModel] = []
        
        for rule, result in zip(self.rules, results):
            if isinstance(result, Exception):
                logger.warning(f"Rule {rule.rule_id} failed: {result}")
                continue
            
            if result is not None:
                triggered_matches.append(result)
            else:
                passed_rules.append(self._rule_to_model(rule, triggered=False))
        
        # Calculate scores
        score = self.scorer.calculate_score(triggered_matches)
        risk_level = self.scorer.get_risk_level(score)
        confidence = self.scorer.calculate_confidence(triggered_matches, score)
        
        # Classify email
        primary_class, secondary_classes = self.scorer.classify_email(triggered_matches)
        
        # Get SE scores
        se_scores = self.scorer.calculate_se_scores(triggered_matches)
        
        # Detect brand impersonation
        brand, brand_confidence = self.scorer.detect_impersonated_brand(triggered_matches)
        
        # Generate summary
        summary = self.scorer.generate_summary(triggered_matches, score, primary_class)
        
        # Convert matches to models
        triggered_models = [
            self._match_to_model(match)
            for match in triggered_matches
        ]
        
        logger.info(f"Detection complete: score={score}, rules_triggered={len(triggered_matches)}")
        
        return DetectionResults(
            rules_triggered=triggered_models,
            rules_passed=passed_rules,
            risk_score=score,
            risk_level=risk_level,
            confidence=confidence,
            primary_classification=primary_class,
            secondary_classifications=secondary_classes,
            urgency_score=se_scores['urgency'],
            authority_score=se_scores['authority'],
            fear_score=se_scores['fear'],
            reward_score=se_scores['reward'],
            impersonated_brand=brand,
            brand_confidence=brand_confidence,
        )
    
    async def _run_rule(
        self,
        rule,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults]
    ) -> Optional[RuleMatch]:
        """
        Run a single detection rule.
        
        Args:
            rule: Detection rule instance
            email: Parsed email
            enrichment: Optional enrichment data
            
        Returns:
            RuleMatch if triggered, None otherwise
        """
        try:
            return await rule.evaluate(email, enrichment)
        except Exception as e:
            logger.error(f"Error in rule {rule.rule_id}: {e}")
            raise
    
    def _match_to_model(self, match: RuleMatch) -> DetectionRuleModel:
        """Convert RuleMatch to DetectionRule model."""
        return DetectionRuleModel(
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            category=match.category,
            description=match.description,
            severity=match.severity,
            score_impact=match.score_contribution,
            triggered=True,
            evidence=match.evidence,
            mitre_technique=match.mitre_technique,
        )
    
    def _rule_to_model(self, rule, triggered: bool = False) -> DetectionRuleModel:
        """Convert detection rule to DetectionRule model."""
        return DetectionRuleModel(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            category=rule.category,
            description=rule.description,
            severity=rule.severity,
            score_impact=0,
            triggered=triggered,
            evidence=[],
            mitre_technique=rule.mitre_technique,
        )
    
    async def run_category(
        self,
        category: str,
        email: ParsedEmail,
        enrichment: Optional[EnrichmentResults] = None
    ) -> List[RuleMatch]:
        """
        Run only rules from a specific category.
        
        Args:
            category: Category name
            email: Parsed email
            enrichment: Optional enrichment data
            
        Returns:
            List of triggered RuleMatch objects
        """
        category_rules = rule_registry.get_rules_by_category(category)
        
        tasks = []
        for rule in category_rules:
            tasks.append(self._run_rule(rule, email, enrichment))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        matches = []
        for result in results:
            if isinstance(result, RuleMatch):
                matches.append(result)
        
        return matches
    
    def get_rule_summary(self) -> Dict[str, Any]:
        """
        Get summary of all registered rules.
        
        Returns:
            Dictionary with rule counts by category
        """
        summary = {
            'total_rules': len(self.rules),
            'by_category': {},
            'by_severity': {},
        }
        
        for rule in self.rules:
            # By category
            cat = rule.category
            if cat not in summary['by_category']:
                summary['by_category'][cat] = 0
            summary['by_category'][cat] += 1
            
            # By severity
            sev = rule.severity.value
            if sev not in summary['by_severity']:
                summary['by_severity'][sev] = 0
            summary['by_severity'][sev] += 1
        
        return summary


# Singleton instance
_detection_engine: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    """Get the detection engine singleton."""
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine


async def analyze_email(
    email: ParsedEmail,
    enrichment: Optional[EnrichmentResults] = None
) -> DetectionResults:
    """
    Convenience function to analyze an email.
    
    Args:
        email: Parsed email
        enrichment: Optional enrichment data
        
    Returns:
        DetectionResults
    """
    engine = get_detection_engine()
    return await engine.analyze(email, enrichment)
