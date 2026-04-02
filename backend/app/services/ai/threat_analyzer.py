"""
NiksES Two-Pass AI Threat Analyzer

A comprehensive AI analysis system that:
1. First Pass: Analyzes email content for intent and social engineering tactics
2. Second Pass: Synthesizes all data (SE, TI, detection) for final assessment

This provides much more accurate threat assessment by giving AI full context.
"""

import asyncio
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

    Supports Anthropic Claude (primary) and OpenAI (fallback).
    """

    def __init__(self, openai_client=None, anthropic_client=None, model: str = None):
        self.openai_client = openai_client
        self.anthropic_client = anthropic_client
        # Auto-select model based on available client
        if model:
            self.model = model
        elif anthropic_client:
            self.model = "claude-sonnet-4-6"
        elif openai_client:
            self.model = "gpt-4o-mini"
        else:
            self.model = "unknown"
        self.provider = "anthropic" if anthropic_client else ("openai" if openai_client else "none")
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
        
        if not self.anthropic_client and not self.openai_client:
            self.logger.warning("No AI client configured (need Anthropic or OpenAI)")
            return result
        
        try:
            # === PASS 1: Content Analysis (30s timeout) ===
            self.logger.info("Starting AI Pass 1: Content Analysis")
            try:
                result.first_pass = await asyncio.wait_for(
                    self._first_pass(email_content, sender_info),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                self.logger.warning("AI Pass 1 timed out after 30s — continuing with defaults")

            # === PASS 2: Full Synthesis (45s timeout) ===
            self.logger.info("Starting AI Pass 2: Full Synthesis")
            try:
                result.final_assessment = await asyncio.wait_for(
                    self._second_pass(
                        email_content,
                        result.first_pass,
                        ti_results,
                        detection_results,
                        sender_info,
                    ),
                    timeout=45.0,
                )
            except asyncio.TimeoutError:
                self.logger.warning("AI Pass 2 timed out after 45s — using Pass 1 results only")
                result.final_assessment.threat_score = result.first_pass.se_scores.overall_score
                result.final_assessment.summary = f"Pass 2 timed out. Pass 1 detected {result.first_pass.intent.value} intent."
            
            # Set combined scores
            result.ai_se_score = result.first_pass.se_scores.overall_score
            result.ai_threat_score = result.final_assessment.threat_score
            result.ai_confidence = result.final_assessment.confidence
            
            self.logger.info(f"Two-pass analysis complete: threat={result.ai_threat_score}, se={result.ai_se_score}")
            
        except Exception as e:
            self.logger.error(f"Two-pass analysis failed: {e}", exc_info=True)
        
        return result
    
    async def _call_ai(self, system_prompt: str, user_prompt: str, max_tokens: int = 800) -> str:
        """
        Unified AI call supporting Anthropic (primary) and OpenAI (fallback).
        Returns the raw text content from the AI response.
        """
        if self.anthropic_client:
            response = await self.anthropic_client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.1,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            # Anthropic returns content as list of blocks
            text_blocks = [b.text for b in response.content if b.type == "text"]
            if not text_blocks:
                raise ValueError("Anthropic returned no text content")
            return text_blocks[0].strip()
        elif self.openai_client:
            response = await self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=max_tokens,
            )
            content = response.choices[0].message.content
            if not content:
                raise ValueError("OpenAI returned no content")
            return content.strip()
        else:
            raise RuntimeError("No AI client available")

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
        body = email_content.get("body", "")[:8000]  # Limit body size (8K chars for better context)
        sender = email_content.get("sender", "")

        system_prompt = """You are an elite email security analyst with expertise in:
• Phishing campaign identification (credential harvesting, malware delivery, BEC)
• Social engineering tactics detection (urgency, fear, authority, reward)
• Brand impersonation analysis (Microsoft 365, Google, banks, shipping)
• Attack chain reconstruction (initial access → execution → impact)

CRITICAL AUTHENTICATION RULE:
Email authentication (SPF, DKIM, DMARC) is the GROUND TRUTH for sender identity.
- If SPF=pass AND DKIM=pass AND DMARC=pass → the sender IS who they claim to be
- If sender domain is a known brand (google.com, paypal.com, microsoft.com, apple.com,
  amazon.com, etc.) AND authentication passes → classify as "legitimate"
- Do NOT flag legitimate brand emails as phishing just because they mention
  security alerts, password resets, or payment notifications — these are normal
- Only flag as impersonation if authentication FAILS or sender domain is NOT the real brand

ANALYSIS APPROACH:
1. FIRST check sender authentication — if all pass + known brand domain → likely legitimate
2. If auth fails or unknown domain → analyze for attacker intent
3. Score social engineering techniques (0-100 each) — score 0 for legitimate brand emails
4. Flag red flags only if they contradict authentication evidence

🚫 ANTI-HALLUCINATION RULES:
- NEVER say TI sources returned "clean" or "no malicious indicators" unless the data explicitly says so
- If TI data is missing, empty, or shows "UNKNOWN" → say "No TI data available" NOT "TI returned clean"
- "Not found in database" means NO DATA, not SAFE
- "UNKNOWN" verdict means INCONCLUSIVE, not CLEAN
- Only state facts from the actual data provided. Never infer or assume results that aren't there.

You are objective and evidence-based. Return only valid JSON."""

        user_prompt = f"""Analyze this email for social engineering tactics and malicious intent.

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
            content = await self._call_ai(system_prompt, user_prompt, max_tokens=800)

            # Clean JSON - strip code blocks and find JSON object
            content = re.sub(r'^```(?:json)?\s*', '', content)
            content = re.sub(r'\s*```\s*$', '', content)
            # Find the JSON object even if surrounded by text
            json_match = re.search(r'\{[\s\S]*\}', content)
            if not json_match:
                raise ValueError(f"No JSON object found in AI response: {content[:200]}")
            data = json.loads(json_match.group())
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
        
        prompt = f"""🔍 FINAL THREAT ASSESSMENT REQUEST

═══════════════════════════════════════════════════════════════
📧 EMAIL UNDER INVESTIGATION
═══════════════════════════════════════════════════════════════
- Sender: {sender}
- Subject: {subject}

═══════════════════════════════════════════════════════════════
🧠 AI CONTENT ANALYSIS (First Pass)
═══════════════════════════════════════════════════════════════
{first_pass_summary}

═══════════════════════════════════════════════════════════════
🛡️ THREAT INTELLIGENCE FINDINGS
═══════════════════════════════════════════════════════════════
{ti_summary}

═══════════════════════════════════════════════════════════════
🔎 DETECTION ENGINE RESULTS
═══════════════════════════════════════════════════════════════
{detection_summary}

═══════════════════════════════════════════════════════════════
✉️ SENDER AUTHENTICATION (SPF/DKIM/DMARC)
═══════════════════════════════════════════════════════════════
{json.dumps(sender_info, indent=2) if sender_info else "Not available"}

═══════════════════════════════════════════════════════════════
📋 REQUIRED OUTPUT (JSON)
═══════════════════════════════════════════════════════════════
{{
    "threat_score": 0-100,
    "threat_level": "clean|low|medium|high|critical",
    "confidence": 0.0-1.0,
    "primary_threat": "main threat type or 'none'",
    "attack_chain": ["step1", "step2"],
    "mitre_tactics": ["TA0001", "TA0043"],
    "summary": "2-3 sentence executive summary for management",
    "key_findings": [
        "Finding 1 - cite specific evidence",
        "Finding 2 - reference TI if applicable",
        "Finding 3 - note authentication issues"
    ],
    "ti_correlation": "How TI data supports/contradicts the assessment",
    "recommended_action": "allow|quarantine|block|escalate",
    "action_priority": "low|medium|high|critical",
    "response_steps": [
        "🚫 IMMEDIATE: First action to take",
        "🔍 INVESTIGATE: What to check in logs",
        "📢 NOTIFY: Who needs to know",
        "🛡️ PREVENT: Block future similar attacks"
    ],
    "iocs_to_block": ["malicious-domain.com", "1.2.3.4"],
    "escalation_reason": "reason if escalation needed or null"
}}

SCORING GUIDELINES:
- 0-20: Clean/Legitimate
- 21-40: Low risk (spam, marketing)
- 41-60: Medium risk (suspicious, needs review)
- 61-80: High risk (likely malicious)
- 81-100: Critical (confirmed threat, TI positive)

⚠️ CRITICAL RULES:
1. If TI flagged ANY URL/domain as malicious → minimum 70 score
2. Authentication failures (SPF fail, no DKIM) → add 15-20 points
3. Brand impersonation detected → add 20-30 points
4. Response steps must be SPECIFIC and ACTIONABLE"""

        system_prompt = """You are a Senior SOC Analyst Team Lead with 10+ years in incident response.

YOUR ROLE: Make the final threat determination by synthesizing ALL evidence:
• First-pass content analysis (intent, social engineering)
• Threat intelligence (VirusTotal, IPQualityScore, PhishTank, URLhaus)
• Detection rules triggered
• Sender authentication (SPF, DKIM, DMARC)

⚠️ AUTHENTICATION IS GROUND TRUTH:
If SPF=pass, DKIM=pass, DMARC=pass AND sender domain is a known legitimate brand
(google.com, paypal.com, microsoft.com, apple.com, amazon.com, etc.):
→ The email IS from that brand. Score 0-15 (CLEAN/LOW).
→ Do NOT classify as phishing or impersonation.
→ Security alerts, password resets, and payment notifications from real brands are LEGITIMATE.
→ Only override this if TI flagged URLs/domains as malicious (compromised brand account).

DECISION FRAMEWORK:
🔴 CRITICAL (81-100): Confirmed malicious - TI positive, auth fails, known bad actors
🟠 HIGH (61-80): Likely malicious - Strong indicators, auth fails or suspicious domain
🟡 MEDIUM (41-60): Suspicious - Mixed signals, needs investigation
🟢 LOW (21-40): Low risk - Spam/marketing or minor concerns
✅ CLEAN (0-15): Legitimate - Auth passes, known brand, no TI hits

YOUR RECOMMENDATIONS MUST BE ACTIONABLE:
❌ BAD: "Be careful"
✅ GOOD: "Block sender domain at email gateway"
✅ GOOD: "Check SIEM for other recipients of this campaign"
✅ GOOD: "Submit hash to VirusTotal, add to EDR blocklist"
✅ GOOD: "No action needed - legitimate email from verified sender"

🚫 ANTI-HALLUCINATION RULES — STRICTLY FOLLOW:
- NEVER claim TI sources returned "clean" unless the TI data explicitly shows "clean" or "benign"
- If TI data says "UNKNOWN", "not found", or is empty → say "No TI data available for this indicator"
- "Not found in threat database" = NO DATA, NOT "confirmed safe"
- "UNKNOWN" verdict = INCONCLUSIVE, NOT "clean"
- If sandbox analysis shows "UNKNOWN" with score 0 → say "Sandbox returned no verdict" NOT "Sandbox confirmed safe"
- Only reference data that is ACTUALLY present in the evidence below. Never fabricate or assume results.
- If you cannot determine something from the data, say "Insufficient data" — never guess.

You think like an incident responder. Return only valid JSON."""

        try:
            content = await self._call_ai(system_prompt, prompt, max_tokens=1000)

            # Clean JSON - strip code blocks and find JSON object
            content = re.sub(r'^```(?:json)?\s*', '', content)
            content = re.sub(r'\s*```\s*$', '', content)
            json_match = re.search(r'\{[\s\S]*\}', content)
            if not json_match:
                raise ValueError(f"No JSON object found in AI response: {content[:200]}")
            data = json.loads(json_match.group())
            
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


def get_threat_analyzer(openai_client=None, anthropic_client=None) -> TwoPassThreatAnalyzer:
    """Get or create threat analyzer."""
    global _analyzer
    if _analyzer is None or openai_client or anthropic_client:
        _analyzer = TwoPassThreatAnalyzer(openai_client=openai_client, anthropic_client=anthropic_client)
    return _analyzer
