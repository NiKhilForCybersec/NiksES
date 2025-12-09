"""
NiksES Social Engineering Analyzer

Combines LLM analysis with heuristic rules to create a comprehensive
social engineering profile for each email.

Features:
- OpenAI-powered intent classification
- Heuristic keyword matching for urgency, fear, authority, reward
- Combined scoring (0-100)
- Detailed breakdown for analysts
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from app.models.email import ParsedEmail
from app.utils.constants import (
    URGENCY_KEYWORDS, FEAR_KEYWORDS, AUTHORITY_KEYWORDS, BEC_KEYWORDS
)

logger = logging.getLogger(__name__)


class SEIntent(str, Enum):
    """Social engineering intent classification."""
    CREDENTIAL_HARVESTING = "credential_harvesting"
    PAYMENT_FRAUD = "payment_fraud"
    MALWARE_DELIVERY = "malware_delivery"
    INFORMATION_GATHERING = "information_gathering"
    ACCOUNT_TAKEOVER = "account_takeover"
    GIFT_CARD_SCAM = "gift_card_scam"
    CALLBACK_PHISHING = "callback_phishing"
    ROMANCE_SCAM = "romance_scam"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class PersuasionTechnique(str, Enum):
    """Social engineering persuasion techniques."""
    URGENCY = "urgency"
    FEAR = "fear"
    AUTHORITY = "authority"
    REWARD = "reward"
    SCARCITY = "scarcity"
    SOCIAL_PROOF = "social_proof"
    RECIPROCITY = "reciprocity"
    CURIOSITY = "curiosity"
    TRUST = "trust"


@dataclass
class HeuristicMatch:
    """A matched heuristic indicator."""
    category: str
    keyword: str
    context: str  # Surrounding text
    weight: float = 1.0


@dataclass
class SEHeuristicResults:
    """Results from heuristic analysis."""
    urgency_matches: List[HeuristicMatch] = field(default_factory=list)
    fear_matches: List[HeuristicMatch] = field(default_factory=list)
    authority_matches: List[HeuristicMatch] = field(default_factory=list)
    reward_matches: List[HeuristicMatch] = field(default_factory=list)
    scarcity_matches: List[HeuristicMatch] = field(default_factory=list)
    
    # Scores (0-100)
    urgency_score: int = 0
    fear_score: int = 0
    authority_score: int = 0
    reward_score: int = 0
    scarcity_score: int = 0
    
    # Additional indicators
    has_deadline: bool = False
    deadline_text: Optional[str] = None
    has_threat: bool = False
    threat_text: Optional[str] = None
    caps_ratio: float = 0.0
    exclamation_count: int = 0
    question_count: int = 0


@dataclass
class SEAnalysisResult:
    """Complete social engineering analysis result."""
    # Overall score
    se_score: int = 0  # 0-100
    se_level: str = "low"  # low, medium, high, critical
    confidence: float = 0.0
    
    # Intent
    primary_intent: SEIntent = SEIntent.UNKNOWN
    secondary_intents: List[SEIntent] = field(default_factory=list)
    
    # Techniques detected
    techniques: List[PersuasionTechnique] = field(default_factory=list)
    technique_scores: Dict[str, int] = field(default_factory=dict)
    
    # Detailed breakdown
    heuristic_results: Optional[SEHeuristicResults] = None
    llm_analysis: Optional[Dict[str, Any]] = None
    
    # For analysts
    explanation: str = ""
    key_indicators: List[str] = field(default_factory=list)
    
    # Source tracking
    used_llm: bool = False
    llm_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "se_score": self.se_score,
            "se_level": self.se_level,
            "confidence": self.confidence,
            "primary_intent": self.primary_intent.value,
            "secondary_intents": [i.value for i in self.secondary_intents],
            "techniques": [t.value for t in self.techniques],
            "technique_scores": self.technique_scores,
            "explanation": self.explanation,
            "key_indicators": self.key_indicators,
            "used_llm": self.used_llm,
            "llm_error": self.llm_error,
            "heuristic_breakdown": {
                "urgency": self.heuristic_results.urgency_score if self.heuristic_results else 0,
                "fear": self.heuristic_results.fear_score if self.heuristic_results else 0,
                "authority": self.heuristic_results.authority_score if self.heuristic_results else 0,
                "reward": self.heuristic_results.reward_score if self.heuristic_results else 0,
                "scarcity": self.heuristic_results.scarcity_score if self.heuristic_results else 0,
            } if self.heuristic_results else {},
        }


# Extended keyword lists for better detection
REWARD_KEYWORDS = [
    "you have won", "you've won", "congratulations", "winner",
    "prize", "lottery", "reward", "bonus", "free money", "cash prize",
    "million dollars", "inheritance", "beneficiary", "unclaimed funds",
    "claim your", "gift for you", "special offer", "exclusive deal",
    "refund", "reimbursement", "compensation", "payment waiting",
    "bitcoin", "crypto", "investment opportunity",
]

SCARCITY_KEYWORDS = [
    "limited time", "offer expires", "act now", "don't miss",
    "last chance", "final notice", "expires today", "only today",
    "hours left", "ending soon", "while supplies last",
    "exclusive access", "limited availability", "running out",
    "one-time offer", "today only", "deadline",
]

# Time-based patterns
TIME_DEADLINE_PATTERNS = [
    r'\b(\d+)\s*(hours?|days?|minutes?)\b',
    r'\bwithin\s+(\d+)\s*(hours?|days?)\b',
    r'\bby\s+(today|tomorrow|end of day|end of business)\b',
    r'\b(24|48|72)\s*hours?\b',
    r'\bexpires?\s+(today|tomorrow|soon)\b',
]

# Threat patterns
THREAT_PATTERNS = [
    r'\b(will be|may be|could be)\s+(suspended|terminated|deleted|closed|restricted|blocked)\b',
    r'\bpermanently\s+(suspended|deleted|restricted|closed)\b',
    r'\b(lose|lost)\s+(access|data|account)\b',
    r'\blegal\s+(action|consequences)\b',
    r'\breport.*(police|authorities|fbi)\b',
]


class SocialEngineeringAnalyzer:
    """
    Analyzes emails for social engineering tactics.
    
    Uses a two-tier approach:
    1. Heuristic analysis (always runs, free)
    2. LLM analysis (runs for high-risk or on-demand)
    """
    
    def __init__(self, openai_client=None):
        """
        Initialize analyzer.
        
        Args:
            openai_client: Optional OpenAI client for LLM analysis
        """
        self.openai_client = openai_client
        self.logger = logging.getLogger(__name__)
    
    async def analyze(
        self,
        email: ParsedEmail,
        use_llm: bool = True,
        force_llm: bool = False,
    ) -> SEAnalysisResult:
        """
        Perform social engineering analysis on email.
        
        Args:
            email: Parsed email to analyze
            use_llm: Whether to use LLM analysis
            force_llm: Force LLM even for low-risk emails
            
        Returns:
            SEAnalysisResult with complete analysis
        """
        result = SEAnalysisResult()
        
        # Get email text content
        body_text = self._get_body_text(email)
        subject = email.subject or ""
        
        # Step 1: Always run heuristic analysis (free)
        heuristic_results = self._run_heuristics(body_text, subject)
        result.heuristic_results = heuristic_results
        
        # Calculate initial score from heuristics
        heuristic_score = self._calculate_heuristic_score(heuristic_results)
        
        # Step 2: Optionally run LLM analysis
        llm_analysis = None
        if use_llm and self.openai_client:
            # Run LLM if score is high enough or forced
            if force_llm or heuristic_score > 40:
                try:
                    llm_analysis = await self._run_llm_analysis(body_text, subject)
                    result.used_llm = True
                    result.llm_analysis = llm_analysis
                except Exception as e:
                    self.logger.warning(f"LLM analysis failed: {e}")
                    result.llm_error = str(e)
        
        # Step 3: Fuse results
        result = self._fuse_results(result, heuristic_results, llm_analysis, heuristic_score)
        
        # Step 4: Generate explanation
        result.explanation = self._generate_explanation(result)
        result.key_indicators = self._extract_key_indicators(result)
        
        return result
    
    def _get_body_text(self, email: ParsedEmail) -> str:
        """Extract combined body text from email."""
        parts = []
        if email.subject:
            parts.append(email.subject)
        if email.body_text:
            parts.append(email.body_text)
        if email.body_html:
            # Strip HTML tags
            text = re.sub(r'<[^>]+>', ' ', email.body_html)
            text = re.sub(r'\s+', ' ', text)
            parts.append(text)
        return ' '.join(parts).lower()
    
    def _run_heuristics(self, body_text: str, subject: str) -> SEHeuristicResults:
        """Run heuristic keyword matching."""
        results = SEHeuristicResults()
        combined_text = f"{subject} {body_text}".lower()
        
        # Match urgency keywords
        for keyword in URGENCY_KEYWORDS:
            if keyword.lower() in combined_text:
                results.urgency_matches.append(HeuristicMatch(
                    category="urgency",
                    keyword=keyword,
                    context=self._get_context(combined_text, keyword),
                ))
        
        # Match fear keywords
        for keyword in FEAR_KEYWORDS:
            if keyword.lower() in combined_text:
                results.fear_matches.append(HeuristicMatch(
                    category="fear",
                    keyword=keyword,
                    context=self._get_context(combined_text, keyword),
                ))
        
        # Match authority keywords
        for keyword in AUTHORITY_KEYWORDS:
            if keyword.lower() in combined_text:
                results.authority_matches.append(HeuristicMatch(
                    category="authority",
                    keyword=keyword,
                    context=self._get_context(combined_text, keyword),
                ))
        
        # Match reward keywords
        for keyword in REWARD_KEYWORDS:
            if keyword.lower() in combined_text:
                results.reward_matches.append(HeuristicMatch(
                    category="reward",
                    keyword=keyword,
                    context=self._get_context(combined_text, keyword),
                ))
        
        # Match scarcity keywords
        for keyword in SCARCITY_KEYWORDS:
            if keyword.lower() in combined_text:
                results.scarcity_matches.append(HeuristicMatch(
                    category="scarcity",
                    keyword=keyword,
                    context=self._get_context(combined_text, keyword),
                ))
        
        # Check for deadlines
        for pattern in TIME_DEADLINE_PATTERNS:
            match = re.search(pattern, combined_text, re.IGNORECASE)
            if match:
                results.has_deadline = True
                results.deadline_text = match.group(0)
                break
        
        # Check for threats
        for pattern in THREAT_PATTERNS:
            match = re.search(pattern, combined_text, re.IGNORECASE)
            if match:
                results.has_threat = True
                results.threat_text = match.group(0)
                break
        
        # Text style analysis
        original_text = f"{subject} {body_text}"
        if len(original_text) > 0:
            caps_chars = sum(1 for c in original_text if c.isupper())
            results.caps_ratio = caps_chars / len(original_text)
        results.exclamation_count = original_text.count('!')
        results.question_count = original_text.count('?')
        
        # Calculate scores (0-100) based on matches
        results.urgency_score = min(100, len(results.urgency_matches) * 20 + (30 if results.has_deadline else 0))
        results.fear_score = min(100, len(results.fear_matches) * 25 + (30 if results.has_threat else 0))
        results.authority_score = min(100, len(results.authority_matches) * 30)
        results.reward_score = min(100, len(results.reward_matches) * 25)
        results.scarcity_score = min(100, len(results.scarcity_matches) * 20)
        
        return results
    
    def _get_context(self, text: str, keyword: str, window: int = 50) -> str:
        """Get context around a keyword match."""
        idx = text.find(keyword.lower())
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(text), idx + len(keyword) + window)
        return text[start:end]
    
    def _calculate_heuristic_score(self, results: SEHeuristicResults) -> int:
        """Calculate overall SE score from heuristics."""
        # Weighted combination
        score = (
            results.urgency_score * 0.25 +
            results.fear_score * 0.30 +
            results.authority_score * 0.20 +
            results.reward_score * 0.15 +
            results.scarcity_score * 0.10
        )
        
        # Bonus for combined tactics
        tactics_count = sum([
            1 if results.urgency_score > 30 else 0,
            1 if results.fear_score > 30 else 0,
            1 if results.authority_score > 30 else 0,
            1 if results.reward_score > 30 else 0,
            1 if results.scarcity_score > 30 else 0,
        ])
        
        if tactics_count >= 3:
            score += 15
        elif tactics_count >= 2:
            score += 10
        
        # Bonus for deadline + threat combo
        if results.has_deadline and results.has_threat:
            score += 10
        
        # Cap at 100
        return min(100, int(score))
    
    async def _run_llm_analysis(self, body_text: str, subject: str) -> Dict[str, Any]:
        """Run LLM-based analysis."""
        if not self.openai_client:
            return {}
        
        prompt = f"""Analyze this email for social engineering tactics. Return JSON only.

Subject: {subject[:200]}

Body (truncated): {body_text[:2000]}

Return this exact JSON structure:
{{
  "intent": "credential_harvesting|payment_fraud|malware_delivery|information_gathering|account_takeover|gift_card_scam|callback_phishing|benign|unknown",
  "primary_persuasion": ["urgency", "fear", "authority", "reward", "scarcity"],
  "urgency_level": "none|low|medium|high",
  "fear_level": "none|low|medium|high",
  "authority_level": "none|low|medium|high",
  "reward_level": "none|low|medium|high",
  "confidence": 0.0-1.0,
  "targeted_role": "generic_user|executive|finance|hr|it|unknown",
  "spoofed_brand": "brand name or null",
  "language_formality": "formal|informal|mixed",
  "manipulation_summary": "Brief explanation of tactics used"
}}"""

        try:
            response = await self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a security analyst specializing in social engineering detection. Return only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500,
            )
            
            content = response.choices[0].message.content
            # Parse JSON from response
            import json
            # Clean up response if needed
            content = content.strip()
            if content.startswith("```"):
                content = re.sub(r'^```(?:json)?\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
            
            return json.loads(content)
            
        except Exception as e:
            self.logger.error(f"LLM analysis error: {e}")
            raise
    
    def _fuse_results(
        self,
        result: SEAnalysisResult,
        heuristics: SEHeuristicResults,
        llm_analysis: Optional[Dict[str, Any]],
        heuristic_score: int,
    ) -> SEAnalysisResult:
        """Fuse heuristic and LLM results into final analysis."""
        
        # Base score from heuristics
        final_score = heuristic_score
        
        # If we have LLM results, blend them
        if llm_analysis:
            llm_confidence = llm_analysis.get("confidence", 0.5)
            
            # Convert LLM levels to scores
            level_to_score = {"none": 0, "low": 25, "medium": 50, "high": 75}
            llm_urgency = level_to_score.get(llm_analysis.get("urgency_level", "none"), 0)
            llm_fear = level_to_score.get(llm_analysis.get("fear_level", "none"), 0)
            llm_authority = level_to_score.get(llm_analysis.get("authority_level", "none"), 0)
            llm_reward = level_to_score.get(llm_analysis.get("reward_level", "none"), 0)
            
            # Blend scores (weight LLM by its confidence)
            blend_weight = llm_confidence * 0.4  # LLM contributes up to 40%
            
            result.technique_scores = {
                "urgency": int(heuristics.urgency_score * (1 - blend_weight) + llm_urgency * blend_weight),
                "fear": int(heuristics.fear_score * (1 - blend_weight) + llm_fear * blend_weight),
                "authority": int(heuristics.authority_score * (1 - blend_weight) + llm_authority * blend_weight),
                "reward": int(heuristics.reward_score * (1 - blend_weight) + llm_reward * blend_weight),
                "scarcity": heuristics.scarcity_score,
            }
            
            # Recalculate final score
            final_score = int(
                result.technique_scores["urgency"] * 0.25 +
                result.technique_scores["fear"] * 0.30 +
                result.technique_scores["authority"] * 0.20 +
                result.technique_scores["reward"] * 0.15 +
                result.technique_scores["scarcity"] * 0.10
            )
            
            # Set intent from LLM
            intent_str = llm_analysis.get("intent", "unknown")
            try:
                result.primary_intent = SEIntent(intent_str)
            except ValueError:
                result.primary_intent = SEIntent.UNKNOWN
            
            result.confidence = llm_confidence
            
        else:
            # Heuristics only
            result.technique_scores = {
                "urgency": heuristics.urgency_score,
                "fear": heuristics.fear_score,
                "authority": heuristics.authority_score,
                "reward": heuristics.reward_score,
                "scarcity": heuristics.scarcity_score,
            }
            
            # Infer intent from heuristics
            if heuristics.fear_score > 50 and heuristics.urgency_score > 50:
                result.primary_intent = SEIntent.CREDENTIAL_HARVESTING
            elif heuristics.reward_score > 50:
                result.primary_intent = SEIntent.GIFT_CARD_SCAM
            elif heuristics.authority_score > 50:
                result.primary_intent = SEIntent.PAYMENT_FRAUD
            else:
                result.primary_intent = SEIntent.UNKNOWN
            
            result.confidence = 0.6  # Lower confidence without LLM
        
        # Set final score and level
        result.se_score = min(100, final_score)
        
        if result.se_score >= 75:
            result.se_level = "critical"
        elif result.se_score >= 50:
            result.se_level = "high"
        elif result.se_score >= 25:
            result.se_level = "medium"
        else:
            result.se_level = "low"
        
        # Determine which techniques are present
        if result.technique_scores.get("urgency", 0) > 30:
            result.techniques.append(PersuasionTechnique.URGENCY)
        if result.technique_scores.get("fear", 0) > 30:
            result.techniques.append(PersuasionTechnique.FEAR)
        if result.technique_scores.get("authority", 0) > 30:
            result.techniques.append(PersuasionTechnique.AUTHORITY)
        if result.technique_scores.get("reward", 0) > 30:
            result.techniques.append(PersuasionTechnique.REWARD)
        if result.technique_scores.get("scarcity", 0) > 30:
            result.techniques.append(PersuasionTechnique.SCARCITY)
        
        return result
    
    def _generate_explanation(self, result: SEAnalysisResult) -> str:
        """Generate human-readable explanation."""
        if result.se_score < 25:
            return "Low social engineering indicators. Email appears to use normal communication patterns."
        
        parts = []
        
        # Intent
        if result.primary_intent != SEIntent.UNKNOWN:
            intent_descriptions = {
                SEIntent.CREDENTIAL_HARVESTING: "attempting to steal login credentials",
                SEIntent.PAYMENT_FRAUD: "attempting to redirect payments or steal financial information",
                SEIntent.MALWARE_DELIVERY: "attempting to deliver malware",
                SEIntent.ACCOUNT_TAKEOVER: "attempting to gain account access",
                SEIntent.GIFT_CARD_SCAM: "attempting a gift card scam",
                SEIntent.CALLBACK_PHISHING: "attempting to get the victim to call a fraudulent number",
            }
            desc = intent_descriptions.get(result.primary_intent, "potentially malicious")
            parts.append(f"This email appears to be {desc}.")
        
        # Techniques
        if result.techniques:
            technique_names = [t.value.replace("_", " ").title() for t in result.techniques]
            parts.append(f"It employs {', '.join(technique_names)} tactics.")
        
        # Specific indicators
        if result.heuristic_results:
            h = result.heuristic_results
            if h.has_deadline:
                parts.append(f"Creates time pressure with deadline: '{h.deadline_text}'.")
            if h.has_threat:
                parts.append(f"Uses threatening language: '{h.threat_text}'.")
        
        return " ".join(parts)
    
    def _extract_key_indicators(self, result: SEAnalysisResult) -> List[str]:
        """Extract top indicators for display."""
        indicators = []
        
        if result.heuristic_results:
            h = result.heuristic_results
            
            # Add top urgency matches
            for match in h.urgency_matches[:2]:
                indicators.append(f"Urgency: '{match.keyword}'")
            
            # Add top fear matches
            for match in h.fear_matches[:2]:
                indicators.append(f"Fear: '{match.keyword}'")
            
            # Add deadline
            if h.has_deadline:
                indicators.append(f"Deadline: {h.deadline_text}")
            
            # Add threat
            if h.has_threat:
                indicators.append(f"Threat: {h.threat_text}")
        
        return indicators[:5]  # Top 5


# Singleton instance
_se_analyzer: Optional[SocialEngineeringAnalyzer] = None


def get_se_analyzer(openai_client=None) -> SocialEngineeringAnalyzer:
    """Get or create SE analyzer singleton."""
    global _se_analyzer
    if _se_analyzer is None:
        _se_analyzer = SocialEngineeringAnalyzer(openai_client)
    elif openai_client and _se_analyzer.openai_client is None:
        _se_analyzer.openai_client = openai_client
    return _se_analyzer
