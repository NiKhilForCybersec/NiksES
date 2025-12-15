"""
NiksES Multi-Dimensional Risk Scoring System

Provides unified risk assessment across multiple dimensions:
- Technical Risk (headers, auth, infrastructure)
- Social Engineering Risk (manipulation tactics)
- Brand/Impersonation Risk (spoofing, lookalikes)
- Content Risk (credentials, payments, attachments)
- Threat Intelligence Risk (external reputation)

Output:
- Overall risk score (0-100)
- Per-dimension scores
- Confidence level
- Key indicators for explanation
- Recommended actions
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from app.models.detection import RiskLevel, EmailClassification

logger = logging.getLogger(__name__)


class RiskDimension(str, Enum):
    """Risk assessment dimensions."""
    TECHNICAL = "technical"
    SOCIAL_ENGINEERING = "social_engineering"
    BRAND_IMPERSONATION = "brand_impersonation"
    CONTENT = "content"
    THREAT_INTEL = "threat_intel"
    BEHAVIORAL = "behavioral"


@dataclass
class DimensionScore:
    """Score for a single risk dimension."""
    dimension: RiskDimension
    score: int = 0  # 0-100
    level: str = "low"  # low, medium, high, critical
    weight: float = 1.0  # Weight in final calculation
    indicators: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension.value,
            "score": self.score,
            "level": self.level,
            "weight": self.weight,
            "indicators": self.indicators,
            "details": self.details,
        }


@dataclass
class RecommendedAction:
    """Recommended response action."""
    action: str
    priority: int  # 1 (highest) to 5 (lowest)
    category: str  # block, investigate, educate, monitor
    description: str
    automated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "priority": self.priority,
            "category": self.category,
            "description": self.description,
            "automated": self.automated,
        }


@dataclass
class UnifiedRiskScore:
    """Complete unified risk assessment."""
    
    # Overall assessment
    overall_score: int = 0  # 0-100
    overall_level: str = "low"  # low, medium, high, critical
    confidence: float = 0.0  # 0-1, based on data availability
    
    # Classification
    primary_classification: EmailClassification = EmailClassification.UNKNOWN
    secondary_classifications: List[EmailClassification] = field(default_factory=list)
    
    # Dimensional scores
    dimensions: Dict[str, DimensionScore] = field(default_factory=dict)
    
    # Top indicators (for quick view)
    top_indicators: List[str] = field(default_factory=list)
    
    # Explanation
    summary: str = ""
    detailed_explanation: str = ""
    
    # Recommended actions
    recommended_actions: List[RecommendedAction] = field(default_factory=list)
    
    # MITRE ATT&CK mapping
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    
    # Metadata
    rules_triggered: int = 0
    data_sources_available: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "overall_level": self.overall_level,
            "confidence": self.confidence,
            "primary_classification": self.primary_classification.value,
            "secondary_classifications": [c.value for c in self.secondary_classifications],
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
            "top_indicators": self.top_indicators,
            "summary": self.summary,
            "detailed_explanation": self.detailed_explanation,
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "mitre_techniques": self.mitre_techniques,
            "rules_triggered": self.rules_triggered,
            "data_sources_available": self.data_sources_available,
        }


# Dimension weights for overall score
DIMENSION_WEIGHTS = {
    RiskDimension.SOCIAL_ENGINEERING: 0.30,
    RiskDimension.BRAND_IMPERSONATION: 0.25,
    RiskDimension.CONTENT: 0.20,
    RiskDimension.THREAT_INTEL: 0.15,
    RiskDimension.TECHNICAL: 0.10,
}

# MITRE ATT&CK technique details
MITRE_TECHNIQUES = {
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1566.003": {"name": "Spearphishing via Service", "tactic": "Initial Access"},
    "T1598.003": {"name": "Spearphishing Link (Recon)", "tactic": "Reconnaissance"},
    "T1656": {"name": "Impersonation", "tactic": "Defense Evasion"},
    "T1204.001": {"name": "Malicious Link", "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1090.002": {"name": "External Proxy", "tactic": "Command and Control"},
    "T1090.003": {"name": "Multi-hop Proxy", "tactic": "Command and Control"},
    "T1583.003": {"name": "Virtual Private Server", "tactic": "Resource Development"},
    "T1534": {"name": "Internal Spearphishing", "tactic": "Lateral Movement"},
}


class MultiDimensionalScorer:
    """
    Calculates multi-dimensional risk scores.
    
    Combines inputs from:
    - Detection rules
    - Social engineering analyzer
    - Content analyzer
    - Lookalike detector
    - Threat intel fusion
    - Header analysis
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_unified_score(
        self,
        detection_results: Optional[Dict[str, Any]] = None,
        se_analysis: Optional[Dict[str, Any]] = None,
        content_analysis: Optional[Dict[str, Any]] = None,
        lookalike_results: Optional[Dict[str, Any]] = None,
        ti_results: Optional[Dict[str, Any]] = None,
        header_analysis: Optional[Dict[str, Any]] = None,
        sender_domain: Optional[str] = None,  # Added to check sender legitimacy
    ) -> UnifiedRiskScore:
        """
        Calculate unified multi-dimensional risk score.
        
        Args:
            detection_results: Results from detection engine
            se_analysis: Social engineering analysis results
            content_analysis: Content deconstruction results
            lookalike_results: Lookalike domain detection results
            ti_results: Threat intelligence fusion results
            header_analysis: Email header analysis results
            sender_domain: Sender's domain for legitimacy checks
            
        Returns:
            UnifiedRiskScore with complete assessment
        """
        result = UnifiedRiskScore()
        
        # Calculate each dimension
        if detection_results:
            result.dimensions[RiskDimension.TECHNICAL.value] = self._score_technical(
                detection_results, header_analysis
            )
            result.rules_triggered = len(detection_results.get("rules_triggered", []))
        
        if se_analysis:
            result.dimensions[RiskDimension.SOCIAL_ENGINEERING.value] = self._score_social_engineering(
                se_analysis
            )
        
        if lookalike_results or detection_results:
            result.dimensions[RiskDimension.BRAND_IMPERSONATION.value] = self._score_brand(
                lookalike_results, detection_results, sender_domain
            )
        
        if content_analysis or detection_results:
            result.dimensions[RiskDimension.CONTENT.value] = self._score_content(
                content_analysis, detection_results
            )
        
        if ti_results:
            result.dimensions[RiskDimension.THREAT_INTEL.value] = self._score_threat_intel(
                ti_results
            )
        
        # Calculate overall score
        result = self._calculate_overall(result)
        
        # Determine classification
        result = self._determine_classification(result, content_analysis, se_analysis)
        
        # Generate explanation
        result = self._generate_explanation(result)
        
        # Generate recommended actions
        result = self._generate_actions(result)
        
        # Extract MITRE techniques
        result = self._extract_mitre(result, detection_results)
        
        # Extract top indicators
        result = self._extract_top_indicators(result)
        
        return result
    
    def _score_technical(
        self,
        detection_results: Dict[str, Any],
        header_analysis: Optional[Dict[str, Any]],
    ) -> DimensionScore:
        """Score technical risk dimension."""
        dim = DimensionScore(dimension=RiskDimension.TECHNICAL)
        score = 0
        
        rules = detection_results.get("rules_triggered", [])
        
        # Check authentication results
        auth_passed = 0
        auth_total = 0
        
        for rule in rules:
            category = rule.get("category", "")
            severity = rule.get("severity", "informational")
            
            if category == "authentication":
                auth_total += 1
                if "pass" in rule.get("rule_name", "").lower():
                    auth_passed += 1
                elif severity in ["high", "critical"]:
                    score += 20
                    dim.indicators.append(rule.get("rule_name"))
            
            elif category == "ip_reputation":
                if severity == "critical":
                    score += 15
                elif severity == "high":
                    score += 10
                dim.indicators.append(rule.get("rule_name"))
        
        # Auth results reduce score
        if auth_total > 0:
            auth_ratio = auth_passed / auth_total
            score = max(0, score - int(auth_ratio * 20))
            dim.details["auth_pass_rate"] = auth_ratio
        
        # Header anomalies
        if header_analysis:
            anomalies = header_analysis.get("anomalies", [])
            score += len(anomalies) * 5
            dim.indicators.extend(anomalies[:3])
        
        dim.score = min(100, score)
        dim.level = self._score_to_level(dim.score)
        dim.weight = DIMENSION_WEIGHTS[RiskDimension.TECHNICAL]
        
        return dim
    
    def _score_social_engineering(
        self,
        se_analysis: Dict[str, Any],
    ) -> DimensionScore:
        """Score social engineering risk dimension."""
        dim = DimensionScore(dimension=RiskDimension.SOCIAL_ENGINEERING)
        
        # Use SE analyzer score directly
        dim.score = se_analysis.get("se_score", 0)
        dim.level = se_analysis.get("se_level", "low")
        dim.weight = DIMENSION_WEIGHTS[RiskDimension.SOCIAL_ENGINEERING]
        
        # Extract indicators
        techniques = se_analysis.get("techniques", [])
        for tech in techniques[:4]:
            dim.indicators.append(f"{tech.replace('_', ' ').title()} tactics detected")
        
        # Add key indicators from SE analysis
        key_indicators = se_analysis.get("key_indicators", [])
        dim.indicators.extend(key_indicators[:3])
        
        dim.details = {
            "urgency": se_analysis.get("heuristic_breakdown", {}).get("urgency", 0),
            "fear": se_analysis.get("heuristic_breakdown", {}).get("fear", 0),
            "authority": se_analysis.get("heuristic_breakdown", {}).get("authority", 0),
            "reward": se_analysis.get("heuristic_breakdown", {}).get("reward", 0),
        }
        
        return dim
    
    def _score_brand(
        self,
        lookalike_results: Optional[Dict[str, Any]],
        detection_results: Optional[Dict[str, Any]],
        sender_domain: Optional[str] = None,
    ) -> DimensionScore:
        """Score brand impersonation risk dimension."""
        dim = DimensionScore(dimension=RiskDimension.BRAND_IMPERSONATION)
        score = 0
        
        # CRITICAL FIX: Check if sender IS a legitimate brand domain
        # If sender is from apple.com/id.apple.com, don't flag for Apple impersonation
        sender_is_legitimate_brand = False
        sender_brand = None
        
        if sender_domain:
            sender_domain_lower = sender_domain.lower()
            from app.utils.constants import BRAND_TARGETS
            
            for brand_id, brand_info in BRAND_TARGETS.items():
                legitimate_domains = [d.lower() for d in brand_info.get("legitimate_domains", [])]
                # Check exact match or subdomain
                for legit in legitimate_domains:
                    if sender_domain_lower == legit or sender_domain_lower.endswith(f".{legit}"):
                        sender_is_legitimate_brand = True
                        sender_brand = brand_id
                        self.logger.info(f"Sender {sender_domain} is legitimate {brand_info['name']} domain")
                        break
                if sender_is_legitimate_brand:
                    break
        
        # Lookalike detection results
        if lookalike_results and lookalike_results.get("has_lookalikes"):
            target = lookalike_results.get("primary_target")
            confidence = lookalike_results.get("highest_confidence", 0)
            
            # If sender IS the brand being "impersonated", this is a FALSE POSITIVE
            # Example: Email from id.apple.com with URLs flagged as "Apple lookalike"
            if sender_is_legitimate_brand and target and target.lower() == sender_brand:
                self.logger.info(f"Suppressing brand impersonation - sender IS legitimate {sender_brand}")
                dim.indicators.append(f"Sender verified as legitimate {sender_brand.title()}")
                # Don't add lookalike score - sender is legitimate
            else:
                score += int(confidence * 80)
                if target:
                    dim.indicators.append(f"Lookalike domain targeting {target}")
        
        # Brand impersonation rules from detection engine
        if detection_results:
            for rule in detection_results.get("rules_triggered", []):
                if rule.get("category") == "brand_impersonation":
                    # Skip brand rules if sender is the legitimate brand
                    rule_indicators = rule.get("indicators", [])
                    rule_brand = None
                    for ind in rule_indicators:
                        if isinstance(ind, dict):
                            rule_brand = ind.get("brand", "").lower()
                            break
                    
                    if sender_is_legitimate_brand and rule_brand == sender_brand:
                        self.logger.info(f"Suppressing brand rule - sender IS legitimate {sender_brand}")
                        continue
                    
                    severity = rule.get("severity", "low")
                    if severity == "critical":
                        score += 30
                    elif severity == "high":
                        score += 20
                    elif severity == "medium":
                        score += 10
                    
                    dim.indicators.append(rule.get("rule_name"))
        
        dim.score = min(100, score)
        dim.level = self._score_to_level(dim.score)
        dim.weight = DIMENSION_WEIGHTS[RiskDimension.BRAND_IMPERSONATION]
        
        # If sender is legitimate brand and score is still > 0, add clarification
        if sender_is_legitimate_brand and dim.score == 0:
            dim.details["sender_verified"] = True
            dim.details["verified_brand"] = sender_brand
        
        return dim
    
    def _score_content(
        self,
        content_analysis: Optional[Dict[str, Any]],
        detection_results: Optional[Dict[str, Any]],
    ) -> DimensionScore:
        """Score content risk dimension."""
        dim = DimensionScore(dimension=RiskDimension.CONTENT)
        score = 0
        
        # Content analysis results
        if content_analysis:
            intent = content_analysis.get("intent", "unknown")
            confidence = content_analysis.get("confidence", 0.5)
            
            # If intent is legitimate, don't add content-based penalties
            if intent == "legitimate":
                dim.score = 0
                dim.level = "low"
                dim.weight = DIMENSION_WEIGHTS[RiskDimension.CONTENT]
                dim.indicators.append("Content appears legitimate")
                dim.details["intent"] = intent
                dim.details["confidence"] = confidence
                return dim
            
            intent_scores = {
                "credential_harvest": 80,
                "payment_fraud": 75,
                "malware_delivery": 85,
                "account_takeover": 70,
                "gift_card_scam": 65,
                "callback_phishing": 60,
                "invoice_fraud": 70,
            }
            
            if intent in intent_scores:
                score = int(intent_scores[intent] * confidence)
                dim.indicators.append(f"Attack intent: {intent.replace('_', ' ').title()}")
            
            # Only add target data penalties for suspicious intents
            if intent not in ["legitimate", "marketing", "spam", "unknown"]:
                target_data = content_analysis.get("target_data", [])
                for target in target_data[:3]:
                    dim.indicators.append(f"Targets: {target.replace('_', ' ')}")
                    score += 10
                
                # Requested actions
                actions = content_analysis.get("requested_actions", [])
                risky_actions = ["send_payment", "purchase_gift_cards", "change_payment_details", "enable_macros"]
                for action in actions[:2]:
                    dim.indicators.append(f"Requests: {action.replace('_', ' ')}")
                    if action in risky_actions:
                        score += 15
        
        # Detection rules
        if detection_results:
            for rule in detection_results.get("rules_triggered", []):
                category = rule.get("category")
                if category in ["phishing", "credential_harvesting", "malware"]:
                    severity = rule.get("severity", "low")
                    if severity == "critical":
                        score += 20
                    elif severity == "high":
                        score += 15
                    elif severity == "medium":
                        score += 10
        
        dim.score = min(100, score)
        dim.level = self._score_to_level(dim.score)
        dim.weight = DIMENSION_WEIGHTS[RiskDimension.CONTENT]
        
        return dim
    
    def _score_threat_intel(
        self,
        ti_results: Dict[str, Any],
    ) -> DimensionScore:
        """Score threat intelligence risk dimension."""
        dim = DimensionScore(dimension=RiskDimension.THREAT_INTEL)
        
        # Use fused TI score directly
        dim.score = ti_results.get("fused_score", 0)
        dim.level = self._score_to_level(dim.score)
        dim.weight = DIMENSION_WEIGHTS[RiskDimension.THREAT_INTEL]
        
        # Extract findings
        findings = ti_results.get("findings", [])
        dim.indicators.extend(findings[:3])
        
        # Note API status
        api_status = ti_results.get("api_status", {})
        unavailable = [k for k, v in api_status.items() if "Error" in v or "limited" in v]
        if unavailable:
            dim.details["unavailable_sources"] = unavailable
        
        dim.details["sources_available"] = ti_results.get("sources_available", 0)
        dim.details["sources_flagged"] = ti_results.get("sources_flagged", 0)
        
        return dim
    
    def _calculate_overall(self, result: UnifiedRiskScore) -> UnifiedRiskScore:
        """Calculate overall score from dimensions."""
        
        if not result.dimensions:
            result.overall_score = 0
            result.overall_level = "unknown"
            result.confidence = 0.0
            return result
        
        weighted_sum = 0.0
        weight_sum = 0.0
        
        for dim_name, dim_score in result.dimensions.items():
            weighted_sum += dim_score.score * dim_score.weight
            weight_sum += dim_score.weight
        
        if weight_sum > 0:
            result.overall_score = int(weighted_sum / weight_sum)
        
        # Boost if multiple high-risk dimensions
        high_dims = sum(1 for d in result.dimensions.values() if d.score >= 60)
        if high_dims >= 3:
            result.overall_score = min(100, result.overall_score + 10)
        elif high_dims >= 2:
            result.overall_score = min(100, result.overall_score + 5)
        
        result.overall_level = self._score_to_level(result.overall_score)
        
        # Confidence based on data availability
        result.data_sources_available = len(result.dimensions)
        result.confidence = min(1.0, result.data_sources_available / 5)
        
        return result
    
    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to level string."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"
    
    def _determine_classification(
        self,
        result: UnifiedRiskScore,
        content_analysis: Optional[Dict[str, Any]],
        se_analysis: Optional[Dict[str, Any]],
    ) -> UnifiedRiskScore:
        """Determine email classification."""
        
        # Use content analysis intent if available
        if content_analysis:
            intent = content_analysis.get("intent", "")
            intent_to_class = {
                "credential_harvest": EmailClassification.CREDENTIAL_HARVESTING,
                "payment_fraud": EmailClassification.INVOICE_FRAUD,
                "malware_delivery": EmailClassification.MALWARE_DELIVERY,
                "gift_card_scam": EmailClassification.GIFT_CARD_SCAM,
                "callback_phishing": EmailClassification.CALLBACK_PHISHING,
                "bec": EmailClassification.BEC,
                "invoice_fraud": EmailClassification.INVOICE_FRAUD,
                "account_takeover": EmailClassification.ACCOUNT_TAKEOVER,
                "legitimate": EmailClassification.BENIGN,
            }
            
            if intent in intent_to_class:
                result.primary_classification = intent_to_class[intent]
        
        # Fallback to score-based classification
        if result.primary_classification == EmailClassification.UNKNOWN:
            brand_dim = result.dimensions.get(RiskDimension.BRAND_IMPERSONATION.value)
            if brand_dim and brand_dim.score >= 60:
                result.primary_classification = EmailClassification.BRAND_IMPERSONATION
            elif result.overall_score >= 60:
                result.primary_classification = EmailClassification.PHISHING
            elif result.overall_score >= 30:
                result.primary_classification = EmailClassification.SPAM
            else:
                result.primary_classification = EmailClassification.BENIGN
        
        return result
    
    def _generate_explanation(self, result: UnifiedRiskScore) -> UnifiedRiskScore:
        """Generate human-readable explanation."""
        
        level_desc = {
            "critical": "This email poses a critical threat",
            "high": "This email shows strong signs of malicious intent",
            "medium": "This email contains suspicious elements",
            "low": "This email appears relatively safe",
        }
        
        result.summary = f"{level_desc.get(result.overall_level, 'Email analyzed')}. "
        
        # Add top concerns
        concerns = []
        for dim in sorted(result.dimensions.values(), key=lambda d: d.score, reverse=True):
            if dim.score >= 40:
                concerns.append(f"{dim.dimension.value.replace('_', ' ')} ({dim.score}/100)")
        
        if concerns:
            result.summary += f"Primary concerns: {', '.join(concerns[:3])}."
        
        # Detailed explanation
        details = []
        for dim in result.dimensions.values():
            if dim.indicators:
                details.append(f"**{dim.dimension.value.replace('_', ' ').title()}** (Score: {dim.score})")
                for ind in dim.indicators[:3]:
                    details.append(f"  • {ind}")
        
        result.detailed_explanation = "\n".join(details)
        
        return result
    
    def _generate_actions(self, result: UnifiedRiskScore) -> UnifiedRiskScore:
        """Generate recommended response actions."""
        
        actions = []
        
        if result.overall_level == "critical":
            actions.extend([
                RecommendedAction(
                    action="Block sender domain",
                    priority=1,
                    category="block",
                    description="Add sender domain to blocklist immediately",
                    automated=True,
                ),
                RecommendedAction(
                    action="Quarantine email",
                    priority=1,
                    category="block",
                    description="Move email to quarantine",
                    automated=True,
                ),
                RecommendedAction(
                    action="Alert security team",
                    priority=1,
                    category="investigate",
                    description="Escalate to security team for investigation",
                    automated=False,
                ),
            ])
        elif result.overall_level == "high":
            actions.extend([
                RecommendedAction(
                    action="Quarantine email",
                    priority=2,
                    category="block",
                    description="Move email to quarantine pending review",
                    automated=True,
                ),
                RecommendedAction(
                    action="Check for similar emails",
                    priority=2,
                    category="investigate",
                    description="Search for similar emails from this sender/domain",
                    automated=False,
                ),
            ])
        elif result.overall_level == "medium":
            actions.extend([
                RecommendedAction(
                    action="Add warning banner",
                    priority=3,
                    category="educate",
                    description="Add external sender warning to email",
                    automated=True,
                ),
                RecommendedAction(
                    action="Monitor sender",
                    priority=3,
                    category="monitor",
                    description="Add sender to watchlist for future emails",
                    automated=False,
                ),
            ])
        else:
            actions.append(
                RecommendedAction(
                    action="Deliver normally",
                    priority=5,
                    category="monitor",
                    description="No immediate action required",
                    automated=True,
                )
            )
        
        result.recommended_actions = actions
        return result
    
    def _extract_mitre(
        self,
        result: UnifiedRiskScore,
        detection_results: Optional[Dict[str, Any]],
    ) -> UnifiedRiskScore:
        """Extract MITRE ATT&CK techniques."""
        
        techniques_seen = set()
        
        if detection_results:
            for rule in detection_results.get("rules_triggered", []):
                mitre = rule.get("mitre_technique")
                if mitre and mitre not in techniques_seen:
                    techniques_seen.add(mitre)
                    
                    tech_info = MITRE_TECHNIQUES.get(mitre, {
                        "name": "Unknown",
                        "tactic": "Unknown"
                    })
                    
                    result.mitre_techniques.append({
                        "technique_id": mitre,
                        "name": tech_info["name"],
                        "tactic": tech_info["tactic"],
                    })
        
        return result
    
    def _extract_top_indicators(self, result: UnifiedRiskScore) -> UnifiedRiskScore:
        """Extract top indicators for quick view."""
        
        all_indicators = []
        
        for dim in sorted(result.dimensions.values(), key=lambda d: d.score, reverse=True):
            for ind in dim.indicators:
                all_indicators.append(ind)
        
        result.top_indicators = all_indicators[:5]
        return result


# Singleton
_scorer: Optional[MultiDimensionalScorer] = None


def get_multi_dimensional_scorer() -> MultiDimensionalScorer:
    """Get or create scorer singleton."""
    global _scorer
    if _scorer is None:
        _scorer = MultiDimensionalScorer()
    return _scorer
