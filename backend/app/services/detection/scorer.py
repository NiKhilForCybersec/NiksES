"""
NiksES Risk Scorer

Aggregates detection results and calculates overall risk score.
"""

import logging
from typing import List, Dict, Any, Tuple
from collections import Counter

from app.models.detection import RiskLevel, EmailClassification
from app.services.detection.rules.base import RuleMatch, SEVERITY_SCORES
from app.utils.constants import RISK_THRESHOLDS

logger = logging.getLogger(__name__)


# Category to classification mapping
CATEGORY_CLASSIFICATION = {
    'phishing': EmailClassification.PHISHING,
    'malware': EmailClassification.MALWARE_DELIVERY,
    'bec': EmailClassification.BEC,
    'lookalike': EmailClassification.BRAND_IMPERSONATION,
    'social_engineering': EmailClassification.PHISHING,
    'authentication': EmailClassification.UNKNOWN,
    'ip_reputation': EmailClassification.PHISHING,  # IP-based threats often indicate phishing/malware
}

# Classification severity ranking
CLASSIFICATION_PRIORITY = {
    EmailClassification.RANSOMWARE: 100,
    EmailClassification.MALWARE_DELIVERY: 90,
    EmailClassification.CREDENTIAL_HARVESTING: 85,
    EmailClassification.BEC: 80,
    EmailClassification.INVOICE_FRAUD: 75,
    EmailClassification.SPEAR_PHISHING: 70,
    EmailClassification.PHISHING: 65,
    EmailClassification.QR_PHISHING: 60,
    EmailClassification.BRAND_IMPERSONATION: 55,
    EmailClassification.GIFT_CARD_SCAM: 50,
    EmailClassification.CALLBACK_PHISHING: 45,
    EmailClassification.ACCOUNT_TAKEOVER: 40,
    EmailClassification.SPAM: 20,
    EmailClassification.MARKETING: 10,
    EmailClassification.BENIGN: 0,
    EmailClassification.UNKNOWN: 0,
}


class RiskScorer:
    """
    Calculate risk scores and classifications from detection results.
    """
    
    def __init__(self):
        self.max_score = 100
    
    def calculate_score(self, matches: List[RuleMatch]) -> int:
        """
        Calculate total risk score from rule matches.
        
        Args:
            matches: List of triggered rule matches
            
        Returns:
            Risk score 0-100
        """
        if not matches:
            return 0
        
        total_score = 0
        
        for match in matches:
            total_score += match.score_contribution
        
        # Cap at 100
        return min(total_score, self.max_score)
    
    def get_risk_level(self, score: int) -> RiskLevel:
        """
        Get risk level from numeric score.
        
        Args:
            score: Risk score 0-100
            
        Returns:
            RiskLevel enum value
        """
        for level_name, (min_score, max_score) in RISK_THRESHOLDS.items():
            if min_score <= score <= max_score:
                return RiskLevel(level_name)
        
        return RiskLevel.INFORMATIONAL
    
    def get_verdict(self, score: int) -> str:
        """
        Get verdict string from score.
        
        Args:
            score: Risk score 0-100
            
        Returns:
            Verdict: 'clean', 'suspicious', or 'malicious'
        """
        if score >= 60:
            return 'malicious'
        elif score >= 20:
            return 'suspicious'
        else:
            return 'clean'
    
    def calculate_confidence(self, matches: List[RuleMatch], score: int) -> float:
        """
        Calculate detection confidence based on rule diversity.
        
        Args:
            matches: List of triggered rule matches
            score: Calculated risk score
            
        Returns:
            Confidence 0.0-1.0
        """
        if not matches:
            return 1.0  # High confidence in clean
        
        # Count unique categories
        categories = set(m.category for m in matches)
        
        # More categories = higher confidence
        category_factor = min(len(categories) / 3, 1.0)
        
        # More high-severity matches = higher confidence
        severity_counts = Counter(m.severity for m in matches)
        high_severity = severity_counts.get(RiskLevel.CRITICAL, 0) + severity_counts.get(RiskLevel.HIGH, 0)
        severity_factor = min(high_severity / 2, 1.0)
        
        # Score factor (higher score = higher confidence in detection)
        score_factor = min(score / 60, 1.0)
        
        # Weighted average
        confidence = (category_factor * 0.3 + severity_factor * 0.4 + score_factor * 0.3)
        
        return round(confidence, 2)
    
    def classify_email(self, matches: List[RuleMatch]) -> Tuple[EmailClassification, List[EmailClassification]]:
        """
        Determine email classification based on triggered rules.
        
        Args:
            matches: List of triggered rule matches
            
        Returns:
            Tuple of (primary_classification, secondary_classifications)
        """
        if not matches:
            return EmailClassification.BENIGN, []
        
        # Collect all possible classifications
        classifications = []
        
        for match in matches:
            # Map category to classification
            if match.category in CATEGORY_CLASSIFICATION:
                classifications.append(CATEGORY_CLASSIFICATION[match.category])
            
            # Special cases based on indicators
            for indicator in match.indicators:
                ind_type = indicator.get('type', '')
                
                if 'credential' in ind_type:
                    classifications.append(EmailClassification.CREDENTIAL_HARVESTING)
                elif 'gift_card' in ind_type:
                    classifications.append(EmailClassification.GIFT_CARD_SCAM)
                elif 'callback' in ind_type:
                    classifications.append(EmailClassification.CALLBACK_PHISHING)
                elif 'invoice' in ind_type:
                    classifications.append(EmailClassification.INVOICE_FRAUD)
                elif 'qr_code' in ind_type or 'qr' in ind_type:
                    classifications.append(EmailClassification.QR_PHISHING)
        
        if not classifications:
            return EmailClassification.UNKNOWN, []
        
        # Count occurrences
        classification_counts = Counter(classifications)
        
        # Sort by priority (highest first)
        sorted_classifications = sorted(
            classification_counts.keys(),
            key=lambda c: CLASSIFICATION_PRIORITY.get(c, 0),
            reverse=True
        )
        
        primary = sorted_classifications[0]
        secondary = sorted_classifications[1:4]  # Top 3 secondary
        
        return primary, secondary
    
    def get_category_breakdown(self, matches: List[RuleMatch]) -> Dict[str, int]:
        """
        Get score breakdown by category.
        
        Args:
            matches: List of triggered rule matches
            
        Returns:
            Dictionary of category -> score contribution
        """
        breakdown = {}
        
        for match in matches:
            category = match.category
            if category not in breakdown:
                breakdown[category] = 0
            breakdown[category] += match.score_contribution
        
        return breakdown
    
    def calculate_se_scores(self, matches: List[RuleMatch]) -> Dict[str, int]:
        """
        Calculate social engineering tactic scores.
        
        Args:
            matches: List of triggered rule matches
            
        Returns:
            Dictionary with urgency, authority, fear, reward scores (0-10 each)
        """
        scores = {
            'urgency': 0,
            'authority': 0,
            'fear': 0,
            'reward': 0,
        }
        
        for match in matches:
            if match.category != 'social_engineering':
                continue
            
            for indicator in match.indicators:
                tactics = indicator.get('tactics', [])
                keywords = indicator.get('keywords', [])
                ind_type = indicator.get('type', '')
                
                if 'urgency' in ind_type or 'urgency' in tactics:
                    scores['urgency'] = min(scores['urgency'] + 3, 10)
                if 'authority' in ind_type or 'authority' in tactics:
                    scores['authority'] = min(scores['authority'] + 3, 10)
                if 'fear' in ind_type or 'fear' in tactics:
                    scores['fear'] = min(scores['fear'] + 3, 10)
                if 'reward' in ind_type or 'reward' in tactics:
                    scores['reward'] = min(scores['reward'] + 3, 10)
        
        return scores
    
    def detect_impersonated_brand(self, matches: List[RuleMatch]) -> Tuple[str, float]:
        """
        Detect if a specific brand is being impersonated.
        
        Args:
            matches: List of triggered rule matches
            
        Returns:
            Tuple of (brand_name or None, confidence)
        """
        brands_found = []
        
        for match in matches:
            if match.category == 'lookalike':
                for indicator in match.indicators:
                    brand = indicator.get('brand')
                    if brand:
                        brands_found.append(brand)
        
        if not brands_found:
            return None, 0.0
        
        # Most common brand
        brand_counts = Counter(brands_found)
        top_brand, count = brand_counts.most_common(1)[0]
        
        confidence = min(count / 3, 1.0)
        
        return top_brand, round(confidence, 2)
    
    def generate_summary(self, matches: List[RuleMatch], score: int, classification: EmailClassification) -> str:
        """
        Generate human-readable summary of detection results.
        
        Args:
            matches: List of triggered rule matches
            score: Risk score
            classification: Primary classification
            
        Returns:
            Summary string
        """
        if not matches:
            return "No threats detected. Email appears safe."
        
        risk_level = self.get_risk_level(score)
        verdict = self.get_verdict(score)
        
        # Group by category
        categories = set(m.category for m in matches)
        
        summary_parts = [
            f"Risk Level: {risk_level.value.title()}",
            f"Classification: {classification.value.replace('_', ' ').title()}",
            f"Rules Triggered: {len(matches)}",
        ]
        
        if categories:
            summary_parts.append(f"Categories: {', '.join(sorted(categories))}")
        
        return " | ".join(summary_parts)
