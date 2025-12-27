"""
NiksES Two-Pass AI Threat Analyzer

A comprehensive AI analysis system that:
1. First Pass: Analyzes email content for intent and social engineering tactics
2. Second Pass: Synthesizes all data (SE, TI, detection) for final assessment

This provides much more accurate threat assessment by giving AI full context.
"""

import logging
import json
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

# Import centralized scoring configuration
try:
    from app.config.scoring import get_scoring_config, calculate_risk_level, get_ai_recommendation
    USE_CENTRALIZED_CONFIG = True
except ImportError:
    USE_CENTRALIZED_CONFIG = False

logger = logging.getLogger(__name__)


class ThreatIntent(str, Enum):
    """Attack intent categories."""
    CREDENTIAL_THEFT = "credential_theft"
    MALWARE_DELIVERY = "malware_delivery"
    FINANCIAL_FRAUD = "financial_fraud"
    BEC = "business_email_compromise"
    ACCOUNT_TAKEOVER = "account_takeover"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    CALLBACK_PHISHING = "callback_phishing"
    ROMANCE_SCAM = "romance_scam"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    SPAM = "spam"
    LEGITIMATE = "legitimate"
    UNKNOWN = "unknown"


@dataclass
class SEScores:
    """Social Engineering technique scores."""
    urgency: int = 0
    fear: int = 0
    authority: int = 0
    reward: int = 0
    scarcity: int = 0
    trust: int = 0
    social_proof: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        return {
            "urgency": self.urgency,
            "fear": self.fear,
            "authority": self.authority,
            "reward": self.reward,
            "scarcity": self.scarcity,
            "trust": self.trust,
            "social_proof": self.social_proof,
        }
    
    @property
    def overall_score(self) -> int:
        """Weighted overall SE score."""
        return int(
            self.urgency * 0.20 +
            self.fear * 0.25 +
            self.authority * 0.20 +
            self.reward * 0.10 +
            self.scarcity * 0.10 +
            self.trust * 0.10 +
            self.social_proof * 0.05
        )


@dataclass
class FirstPassResult:
    """Result from first AI pass (content analysis)."""
    intent: ThreatIntent = ThreatIntent.UNKNOWN
    intent_confidence: float = 0.0
    se_scores: SEScores = field(default_factory=SEScores)
    spoofed_brand: Optional[str] = None
    requested_actions: List[str] = field(default_factory=list)
    red_flags: List[str] = field(default_factory=list)
    target_role: str = "generic"
    language_analysis: str = ""
    raw_response: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent.value,
            "intent_confidence": self.intent_confidence,
            "se_scores": self.se_scores.to_dict(),
            "se_overall": self.se_scores.overall_score,
            "spoofed_brand": self.spoofed_brand,
            "requested_actions": self.requested_actions,
            "red_flags": self.red_flags,
            "target_role": self.target_role,
            "language_analysis": self.language_analysis,
        }


@dataclass
class FinalAssessment:
    """Final AI assessment with all context."""
    threat_score: int = 0
    threat_level: str = "unknown"
    confidence: float = 0.0
    
    # Classification
    primary_threat: str = ""
    attack_chain: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    
    # AI reasoning
    summary: str = ""
    key_findings: List[str] = field(default_factory=list)
    ti_correlation: str = ""
    
    # Recommendations
    recommended_action: str = "review"
    action_priority: str = "medium"
    response_steps: List[str] = field(default_factory=list)
    
    # For SOC
    ioc_summary: Dict[str, Any] = field(default_factory=dict)
    escalation_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "primary_threat": self.primary_threat,
            "attack_chain": self.attack_chain,
            "mitre_tactics": self.mitre_tactics,
            "summary": self.summary,
            "key_findings": self.key_findings,
            "ti_correlation": self.ti_correlation,
            "recommended_action": self.recommended_action,
            "action_priority": self.action_priority,
            "response_steps": self.response_steps,
            "ioc_summary": self.ioc_summary,
            "escalation_reason": self.escalation_reason,
        }


@dataclass
class TwoPassAnalysisResult:
    """Complete result from two-pass AI analysis."""
    first_pass: FirstPassResult = field(default_factory=FirstPassResult)
    final_assessment: FinalAssessment = field(default_factory=FinalAssessment)
    
    # Combined scores
    ai_threat_score: int = 0
    ai_se_score: int = 0
    ai_confidence: float = 0.0
    
    # Metadata
    model_used: str = ""
    first_pass_tokens: int = 0
    second_pass_tokens: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "first_pass": self.first_pass.to_dict(),
            "final_assessment": self.final_assessment.to_dict(),
            "ai_threat_score": self.ai_threat_score,
            "ai_se_score": self.ai_se_score,
            "ai_confidence": self.ai_confidence,
            "model_used": self.model_used,
        }


class TwoPassThreatAnalyzer:
    """
    Two-pass AI threat analyzer.
    
    Pass 1: Content analysis
    - Intent detection
    - Social engineering scoring
    - Brand spoofing detection
    - Action extraction
    
    Pass 2: Full synthesis
    - Correlate with TI results
    - Incorporate detection rules
    - Final threat assessment
    - Generate recommendations
    """
    
    def __init__(self, openai_client=None, model: str = "gpt-4o-mini"):
        self.openai_client = openai_client
        self.model = model
        self.logger = logging.getLogger(__name__)
    
    async def analyze(
        self,
        email_content: Dict[str, Any],
        ti_results: Optional[Dict[str, Any]] = None,
        detection_results: Optional[Dict[str, Any]] = None,
        sender_info: Optional[Dict[str, Any]] = None,
    ) -> TwoPassAnalysisResult:
        """
        Perform two-pass AI analysis.
        
        Args:
            email_content: Email text, subject, sender
            ti_results: Threat intelligence results (VT, GSB, IPQS, etc.)
            detection_results: Rule-based detection results
            sender_info: Sender authentication info
            
        Returns:
            TwoPassAnalysisResult with complete AI analysis
        """
        result = TwoPassAnalysisResult()
        result.model_used = self.model
        
        if not self.openai_client:
            self.logger.warning("No OpenAI client configured")
            return result
        
        try:
            # === PASS 1: Content Analysis ===
            self.logger.info("Starting AI Pass 1: Content Analysis")
            result.first_pass = await self._first_pass(email_content, sender_info)
            
            # === PASS 2: Full Synthesis ===
            self.logger.info("Starting AI Pass 2: Full Synthesis")
            result.final_assessment = await self._second_pass(
                email_content,
                result.first_pass,
                ti_results,
                detection_results,
                sender_info,
            )
            
            # Set combined scores
            result.ai_se_score = result.first_pass.se_scores.overall_score
            result.ai_threat_score = result.final_assessment.threat_score
            result.ai_confidence = result.final_assessment.confidence
            
            self.logger.info(f"Two-pass analysis complete: threat={result.ai_threat_score}, se={result.ai_se_score}")
            
        except Exception as e:
            self.logger.error(f"Two-pass analysis failed: {e}", exc_info=True)
        
        return result
    
    async def _first_pass(
        self,
        email_content: Dict[str, Any],
        sender_info: Optional[Dict[str, Any]] = None,
    ) -> FirstPassResult:
        """
        First pass: Analyze email content for intent and SE tactics.
        """
        result = FirstPassResult()
        
        subject = email_content.get("subject", "")
        body = email_content.get("body", "")[:3000]  # Limit body size
        sender = email_content.get("sender", "")
        
        prompt = f"""Analyze this email for social engineering tactics and malicious intent.

SENDER: {sender}
SUBJECT: {subject}

BODY:
{body}

SENDER AUTHENTICATION:
{json.dumps(sender_info, indent=2) if sender_info else "Not available"}

Respond with JSON only:
{{
    "intent": "credential_theft|malware_delivery|financial_fraud|business_email_compromise|account_takeover|data_exfiltration|reconnaissance|callback_phishing|romance_scam|tech_support_scam|spam|legitimate|unknown",
    "intent_confidence": 0.0-1.0,
    "se_scores": {{
        "urgency": 0-100,
        "fear": 0-100,
        "authority": 0-100,
        "reward": 0-100,
        "scarcity": 0-100,
        "trust": 0-100,
        "social_proof": 0-100
    }},
    "spoofed_brand": "brand name or null",
    "requested_actions": ["list of actions email asks user to take"],
    "red_flags": ["specific suspicious elements found"],
    "target_role": "generic|executive|finance|hr|it|customer",
    "language_analysis": "brief analysis of language patterns and manipulation tactics"
}}

Score each SE technique 0-100 based on how strongly it's used:
- urgency: Time pressure, deadlines, "act now"
- fear: Threats, consequences, account suspension
- authority: Impersonation, official language, credentials
- reward: Prizes, refunds, benefits promised
- scarcity: Limited time, exclusive offers
- trust: Familiarity, rapport building, shared connections
- social_proof: "Others have done this", testimonials"""

        try:
            response = await self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert email security analyst specializing in phishing and social engineering detection. Analyze emails objectively and return only valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=800,
            )
            
            content = response.choices[0].message.content.strip()
            
            # Clean JSON
            if content.startswith("```"):
                content = re.sub(r'^```(?:json)?\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
            
            data = json.loads(content)
            result.raw_response = data
            
            # Parse intent
            intent_str = data.get("intent", "unknown")
            try:
                result.intent = ThreatIntent(intent_str)
            except ValueError:
                result.intent = ThreatIntent.UNKNOWN
            
            result.intent_confidence = float(data.get("intent_confidence", 0.5))
            
            # Parse SE scores
            se_data = data.get("se_scores", {})
            result.se_scores = SEScores(
                urgency=int(se_data.get("urgency", 0)),
                fear=int(se_data.get("fear", 0)),
                authority=int(se_data.get("authority", 0)),
                reward=int(se_data.get("reward", 0)),
                scarcity=int(se_data.get("scarcity", 0)),
                trust=int(se_data.get("trust", 0)),
                social_proof=int(se_data.get("social_proof", 0)),
            )
            
            result.spoofed_brand = data.get("spoofed_brand")
            result.requested_actions = data.get("requested_actions", [])
            result.red_flags = data.get("red_flags", [])
            result.target_role = data.get("target_role", "generic")
            result.language_analysis = data.get("language_analysis", "")
            
            self.logger.info(f"Pass 1 complete: intent={result.intent.value}, se_score={result.se_scores.overall_score}")
            
        except Exception as e:
            self.logger.error(f"First pass failed: {e}")
        
        return result
    
    async def _second_pass(
        self,
        email_content: Dict[str, Any],
        first_pass: FirstPassResult,
        ti_results: Optional[Dict[str, Any]],
        detection_results: Optional[Dict[str, Any]],
        sender_info: Optional[Dict[str, Any]],
    ) -> FinalAssessment:
        """
        Second pass: Synthesize all data for final assessment.
        """
        result = FinalAssessment()
        
        # Build context from first pass
        first_pass_summary = f"""
FIRST PASS ANALYSIS:
- Detected Intent: {first_pass.intent.value} (confidence: {first_pass.intent_confidence:.0%})
- Social Engineering Score: {first_pass.se_scores.overall_score}/100
  - Urgency: {first_pass.se_scores.urgency}/100
  - Fear: {first_pass.se_scores.fear}/100
  - Authority: {first_pass.se_scores.authority}/100
  - Reward: {first_pass.se_scores.reward}/100
  - Scarcity: {first_pass.se_scores.scarcity}/100
- Spoofed Brand: {first_pass.spoofed_brand or 'None detected'}
- Red Flags: {', '.join(first_pass.red_flags) if first_pass.red_flags else 'None'}
- Requested Actions: {', '.join(first_pass.requested_actions) if first_pass.requested_actions else 'None'}
"""
        
        # Build TI summary
        ti_summary = self._build_ti_summary(ti_results)
        
        # Build detection summary
        detection_summary = self._build_detection_summary(detection_results)
        
        subject = email_content.get("subject", "")
        sender = email_content.get("sender", "")
        
        prompt = f"""You are a senior SOC analyst performing final threat assessment.

EMAIL:
- Sender: {sender}
- Subject: {subject}

{first_pass_summary}

THREAT INTELLIGENCE RESULTS:
{ti_summary}

DETECTION RULE RESULTS:
{detection_summary}

SENDER AUTHENTICATION:
{json.dumps(sender_info, indent=2) if sender_info else "Not available"}

Based on ALL available data, provide final threat assessment as JSON:
{{
    "threat_score": 0-100,
    "threat_level": "clean|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "primary_threat": "main threat type or 'none'",
    "attack_chain": ["step1", "step2"],
    "mitre_tactics": ["TA0001", "TA0043"],
    "summary": "2-3 sentence executive summary",
    "key_findings": ["finding1", "finding2", "finding3"],
    "ti_correlation": "how TI data supports or contradicts the threat assessment",
    "recommended_action": "allow|quarantine|block|escalate",
    "action_priority": "low|medium|high|critical",
    "response_steps": ["step1", "step2"],
    "escalation_reason": "reason if escalation needed or null"
}}

SCORING GUIDELINES:
- 0-20: Clean/Legitimate
- 21-40: Low risk (spam, marketing)
- 41-60: Medium risk (suspicious, needs review)
- 61-80: High risk (likely malicious)
- 81-100: Critical (confirmed threat)

Consider:
1. Does TI data confirm or contradict the content analysis?
2. Are there mismatches between claimed sender and actual infrastructure?
3. What's the realistic impact if this is malicious?
4. Weight confirmed malicious indicators heavily."""

        try:
            response = await self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior SOC analyst. Synthesize all available threat data into actionable intelligence. Return only valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000,
            )
            
            content = response.choices[0].message.content.strip()
            
            # Clean JSON
            if content.startswith("```"):
                content = re.sub(r'^```(?:json)?\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
            
            data = json.loads(content)
            
            result.threat_score = int(data.get("threat_score", 0))
            result.threat_level = data.get("threat_level", "unknown")
            result.confidence = float(data.get("confidence", 0.5))
            result.primary_threat = data.get("primary_threat", "")
            result.attack_chain = data.get("attack_chain", [])
            result.mitre_tactics = data.get("mitre_tactics", [])
            result.summary = data.get("summary", "")
            result.key_findings = data.get("key_findings", [])
            result.ti_correlation = data.get("ti_correlation", "")
            result.recommended_action = data.get("recommended_action", "review")
            result.action_priority = data.get("action_priority", "medium")
            result.response_steps = data.get("response_steps", [])
            result.escalation_reason = data.get("escalation_reason")
            
            self.logger.info(f"Pass 2 complete: score={result.threat_score}, level={result.threat_level}, action={result.recommended_action}")
            
        except Exception as e:
            self.logger.error(f"Second pass failed: {e}")
            # Fall back to first pass data
            result.threat_score = first_pass.se_scores.overall_score
            result.summary = f"AI synthesis failed. First pass detected {first_pass.intent.value} intent."
        
        return result
    
    def _build_ti_summary(self, ti_results: Optional[Dict[str, Any]]) -> str:
        """Build human-readable TI summary."""
        if not ti_results:
            return "No threat intelligence data available."
        
        lines = []
        
        # URL/Domain results
        url_results = ti_results.get("url_results", [])
        for url_result in url_results:
            url = url_result.get("url", "unknown")
            
            # Check each source
            vt = url_result.get("virustotal", {})
            if vt.get("malicious", 0) > 0:
                lines.append(f"⚠️ {url}: VirusTotal {vt.get('malicious')}/{vt.get('total', 0)} engines flagged")
            
            gsb = url_result.get("google_safebrowsing", {})
            if gsb.get("is_malicious"):
                lines.append(f"🚨 {url}: Google Safe Browsing flagged as {gsb.get('threat_type', 'malicious')}")
            
            ipqs = url_result.get("ipqualityscore", {})
            if ipqs.get("risk_score", 0) >= 75:
                lines.append(f"⚠️ {url}: IPQualityScore risk={ipqs.get('risk_score')}/100")
                if ipqs.get("is_phishing"):
                    lines.append(f"  - Flagged as phishing")
                if ipqs.get("is_malware"):
                    lines.append(f"  - Flagged as malware")
            
            urlhaus = url_result.get("urlhaus", {})
            if urlhaus.get("threat"):
                lines.append(f"🚨 {url}: URLhaus threat={urlhaus.get('threat')}")
        
        # IP results
        ip_results = ti_results.get("ip_results", [])
        for ip_result in ip_results:
            ip = ip_result.get("ip", "unknown")
            
            abuseipdb = ip_result.get("abuseipdb", {})
            if abuseipdb.get("abuse_score", 0) >= 25:
                lines.append(f"⚠️ {ip}: AbuseIPDB confidence={abuseipdb.get('abuse_score')}%")
        
        # Fused verdict
        fused = ti_results.get("fused", {})
        if fused:
            lines.append(f"\nFused TI Score: {fused.get('score', 0)}/100")
            lines.append(f"TI Verdict: {fused.get('verdict', 'unknown')}")
            lines.append(f"Sources checked: {fused.get('sources_available', 0)}/{fused.get('sources_checked', 0)}")
        
        return "\n".join(lines) if lines else "All TI sources returned clean or unavailable."
    
    def _build_detection_summary(self, detection_results: Optional[Dict[str, Any]]) -> str:
        """Build human-readable detection summary."""
        if not detection_results:
            return "No detection rule results available."
        
        lines = []
        
        score = detection_results.get("score", 0)
        rules_triggered = detection_results.get("rules_triggered", [])
        
        lines.append(f"Detection Score: {score}/100")
        lines.append(f"Rules Triggered: {len(rules_triggered)}")
        
        # Group by severity
        critical = [r for r in rules_triggered if r.get("severity") == "critical"]
        high = [r for r in rules_triggered if r.get("severity") == "high"]
        medium = [r for r in rules_triggered if r.get("severity") == "medium"]
        
        if critical:
            lines.append("\n🚨 CRITICAL:")
            for r in critical[:3]:
                lines.append(f"  - {r.get('name', 'Unknown')}: {r.get('description', '')}")
        
        if high:
            lines.append("\n⚠️ HIGH:")
            for r in high[:3]:
                lines.append(f"  - {r.get('name', 'Unknown')}: {r.get('description', '')}")
        
        if medium:
            lines.append(f"\n📋 MEDIUM: {len(medium)} rules triggered")
        
        return "\n".join(lines)


# Singleton
_analyzer: Optional[TwoPassThreatAnalyzer] = None


def get_threat_analyzer(openai_client=None) -> TwoPassThreatAnalyzer:
    """Get or create threat analyzer."""
    global _analyzer
    if _analyzer is None or openai_client:
        _analyzer = TwoPassThreatAnalyzer(openai_client)
    return _analyzer
