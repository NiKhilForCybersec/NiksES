"""
NiksES Text/SMS/URL Analysis Route

Endpoint for analyzing SMS, WhatsApp, Telegram messages and standalone URLs
for smishing, phishing, and scam detection with AI analysis and URL enrichment.
"""

import re
import logging
import hashlib
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.api.dependencies import get_analysis_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analysis"])


class TextSource(str, Enum):
    """Source of the text message."""
    SMS = "sms"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    URL = "url"
    OTHER = "other"


class ScamCategory(str, Enum):
    """Categories of detected scams."""
    LEGITIMATE = "legitimate"
    SMISHING_FINANCIAL = "smishing_financial"
    SMISHING_DELIVERY = "smishing_delivery"
    SMISHING_PRIZE = "smishing_prize"
    SMISHING_GOVERNMENT = "smishing_government"
    SMISHING_TECH_SUPPORT = "smishing_tech_support"
    PHISHING_URL = "phishing_url"
    MALICIOUS_URL = "malicious_url"
    SUSPICIOUS = "suspicious"


class TextAnalysisRequest(BaseModel):
    """Request model for text analysis."""
    text: str = Field(..., min_length=1, max_length=5000, description="Message text or URLs to analyze")
    sender: Optional[str] = Field(None, description="Sender phone number or ID")
    source: TextSource = Field(TextSource.SMS, description="Source platform")
    enable_url_enrichment: bool = Field(True, description="Enable URL threat intel enrichment")
    enable_ai_analysis: bool = Field(True, description="Enable AI-powered analysis")
    enable_url_sandbox: bool = Field(False, description="Enable URL dynamic sandbox analysis")


class ScamPattern(BaseModel):
    """A detected scam pattern."""
    pattern_id: str
    name: str
    description: str
    severity: str  # low, medium, high, critical
    matched_text: Optional[str] = None
    mitre_technique: Optional[str] = None


class URLEnrichmentResult(BaseModel):
    """Enrichment results for a URL."""
    url: str
    domain: str
    is_malicious: bool = False
    threat_score: int = 0
    sources: List[str] = []
    categories: List[str] = []
    first_seen: Optional[str] = None
    ssl_valid: Optional[bool] = None
    redirect_chain: List[str] = []
    final_url: Optional[str] = None
    screenshot_url: Optional[str] = None
    # Detailed source scores
    ipqs_score: Optional[int] = None
    ipqs_phishing: Optional[bool] = None
    ipqs_malware: Optional[bool] = None
    vt_malicious: Optional[int] = None
    gsb_malicious: Optional[bool] = None


class URLSandboxResult(BaseModel):
    """Dynamic URL sandbox analysis result."""
    url: str
    provider: str
    status: str
    is_malicious: bool = False
    threat_score: int = 0
    threat_level: str = "unknown"
    categories: List[str] = []
    indicators: List[str] = []
    contacted_ips: List[str] = []
    contacted_domains: List[str] = []
    redirects: List[str] = []
    final_url: Optional[str] = None
    page_title: Optional[str] = None
    screenshot_url: Optional[str] = None
    report_url: Optional[str] = None
    analysis_time_ms: int = 0


class AIAnalysisResult(BaseModel):
    """AI analysis results with full threat intelligence context."""
    enabled: bool = False
    provider: Optional[str] = None
    summary: str = ""
    threat_assessment: str = ""
    key_findings: List[str] = []
    recommendations: List[str] = []
    social_engineering_tactics: List[str] = []
    confidence: float = 0.0
    intent: Optional[str] = None  # What the attacker is trying to achieve


def _ensure_list(value: Any) -> List[str]:
    """
    Safely convert a value to a list of strings.
    Handles cases where AI returns a string instead of a list.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        # If it's a string, check if it contains list-like content
        value = value.strip()
        if not value or value.lower() in ('none', 'n/a', 'none detected', 'null'):
            return []
        # If it looks like a single item, wrap it in a list
        if ',' in value:
            return [item.strip() for item in value.split(',') if item.strip()]
        if '\n' in value:
            return [item.strip() for item in value.split('\n') if item.strip()]
        # Single string item
        return [value] if value else []
    return []


class TextAnalysisResponse(BaseModel):
    """Response model for text/SMS/URL analysis."""
    analysis_id: str
    analyzed_at: str
    analysis_type: str  # "sms", "url", "message"
    source: TextSource
    
    # Original content
    original_text: str
    message_length: int
    
    # Risk assessment
    overall_score: int = Field(..., ge=0, le=100)
    overall_level: str
    classification: ScamCategory
    is_threat: bool
    confidence: float = Field(..., ge=0, le=1)
    
    # Extracted IOCs
    urls_found: List[str]
    domains_found: List[str]
    ips_found: List[str]
    phone_numbers_found: List[str]
    
    # URL Enrichment
    url_enrichment: List[URLEnrichmentResult] = []
    
    # URL Sandbox (Dynamic Analysis)
    url_sandbox: List[URLSandboxResult] = []
    
    # Pattern matches
    patterns_matched: List[ScamPattern]
    threat_indicators: List[str]
    
    # AI Analysis
    ai_analysis: AIAnalysisResult
    
    # Recommendations
    recommendations: List[str]
    
    # MITRE ATT&CK
    mitre_techniques: List[Dict[str, str]] = []


# ============================================================================
# SCAM DETECTION PATTERNS
# ============================================================================

SMS_SCAM_PATTERNS = {
    "package_scam": {
        "patterns": [
            r"package.*(?:held|pending|deliver|customs)",
            r"(?:usps|ups|fedex|dhl).*(?:deliver|package|parcel)",
            r"your.*(?:package|parcel|shipment).*(?:track|confirm|reschedule)",
            r"delivery.*(?:failed|attempt|pending)",
            r"customs.*(?:fee|charge|payment)",
        ],
        "name": "Package/Delivery Scam",
        "description": "Fake delivery notification attempting to steal info or money",
        "severity": "high",
        "category": ScamCategory.SMISHING_DELIVERY,
        "mitre": "T1566.002",
    },
    "bank_phishing": {
        "patterns": [
            r"(?:bank|account).*(?:suspend|lock|limit|unusual|verify)",
            r"(?:verify|confirm).*(?:account|identity|transaction)",
            r"(?:chase|wells\s*fargo|bank\s*of\s*america|citi|capital\s*one).*(?:alert|security|verify)",
            r"unauthorized.*(?:transaction|access|login)",
            r"your.*(?:card|account).*(?:block|suspend|lock)",
        ],
        "name": "Banking Phishing",
        "description": "Fake bank alert attempting to steal credentials",
        "severity": "critical",
        "category": ScamCategory.SMISHING_FINANCIAL,
        "mitre": "T1566.001",
    },
    "prize_scam": {
        "patterns": [
            r"(?:won|winner|selected|chosen).*(?:\$|dollar|prize|gift|reward)",
            r"(?:claim|collect).*(?:prize|reward|winnings)",
            r"congratulations.*(?:won|winner|selected)",
            r"(?:free|gift).*(?:iphone|samsung|card|cash)",
            r"(?:lottery|sweepstakes).*(?:winner|won|claim)",
        ],
        "name": "Prize/Lottery Scam",
        "description": "Fake prize notification to collect personal info",
        "severity": "high",
        "category": ScamCategory.SMISHING_PRIZE,
        "mitre": "T1566.002",
    },
    "irs_scam": {
        "patterns": [
            r"(?:irs|internal\s*revenue).*(?:refund|owe|audit|action)",
            r"(?:social\s*security|ssa).*(?:suspend|expire|block)",
            r"(?:tax|stimulus).*(?:refund|payment|claim)",
            r"(?:government|federal).*(?:benefit|payment|assistance)",
            r"(?:dmv|license).*(?:suspend|expire|renew)",
        ],
        "name": "Government Impersonation",
        "description": "Fake government agency message",
        "severity": "critical",
        "category": ScamCategory.SMISHING_GOVERNMENT,
        "mitre": "T1583.001",
    },
    "tech_support_scam": {
        "patterns": [
            r"(?:apple|microsoft|google).*(?:security|virus|hacked|compromised)",
            r"(?:icloud|gmail|outlook).*(?:full|storage|expire)",
            r"(?:virus|malware).*detected",
            r"(?:call|contact).*(?:support|tech|help).*(?:immediately|urgent)",
            r"your.*(?:computer|phone|device).*(?:infected|compromised|hacked)",
        ],
        "name": "Tech Support Scam",
        "description": "Fake tech support attempting remote access or payment",
        "severity": "high",
        "category": ScamCategory.SMISHING_TECH_SUPPORT,
        "mitre": "T1566.003",
    },
    "urgency_indicators": {
        "patterns": [
            r"(?:act|respond|reply).*(?:now|immediately|today|urgent)",
            r"(?:expire|expires|expiring).*(?:today|soon|hours|24\s*h)",
            r"(?:last|final).*(?:chance|notice|warning)",
            r"(?:avoid|prevent).*(?:suspend|cancel|close|charges)",
            r"(?:limited|only).*(?:time|hours|today)",
        ],
        "name": "Urgency Tactics",
        "description": "Uses urgency to pressure quick action",
        "severity": "medium",
        "category": ScamCategory.SUSPICIOUS,
        "mitre": "T1204.001",
    },
}

URL_THREAT_PATTERNS = {
    "url_shortener": {
        "patterns": [
            r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl", r"ow\.ly",
            r"is\.gd", r"buff\.ly", r"adf\.ly", r"tiny\.cc", r"cutt\.ly",
        ],
        "name": "URL Shortener",
        "description": "Shortened URL hides the actual destination",
        "severity": "medium",
        "mitre": "T1608.005",
    },
    "suspicious_tld": {
        "patterns": [
            r"\.tk\b", r"\.ml\b", r"\.ga\b", r"\.cf\b", r"\.gq\b",
            r"\.xyz\b", r"\.top\b", r"\.work\b", r"\.click\b", r"\.link\b",
            r"\.online\b", r"\.site\b", r"\.live\b", r"\.info\b",
        ],
        "name": "Suspicious TLD",
        "description": "Domain uses a TLD commonly associated with malicious sites",
        "severity": "high",
        "mitre": "T1583.001",
    },
    "ip_in_url": {
        "patterns": [
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        ],
        "name": "IP Address URL",
        "description": "URL contains raw IP address instead of domain name",
        "severity": "high",
        "mitre": "T1583.003",
    },
    "brand_impersonation": {
        "patterns": [
            r"paypa[l1]", r"amaz[o0]n", r"faceb[o0]{2}k", r"g[o0]{2}gle",
            r"micr[o0]s[o0]ft", r"app[l1]e", r"netf[l1]ix", r"bank.*login",
            r"secure.*verify", r"account.*update", r"signin.*confirm",
        ],
        "name": "Brand Impersonation",
        "description": "URL may be impersonating a legitimate brand",
        "severity": "critical",
        "mitre": "T1583.001",
    },
    "credential_harvesting": {
        "patterns": [
            r"/login", r"/signin", r"/verify", r"/confirm", r"update.*account",
            r"secure.*form", r"/password", r"/credential", r"/authenticate",
        ],
        "name": "Credential Harvesting",
        "description": "URL contains keywords associated with phishing",
        "severity": "high",
        "mitre": "T1056.004",
    },
    "data_exfil": {
        "patterns": [
            r"\.php\?.*=", r"\.asp\?.*=", r"/collect", r"/submit", r"/form",
            r"/data", r"/upload", r"/send",
        ],
        "name": "Data Exfiltration Endpoint",
        "description": "URL appears to be a data collection endpoint",
        "severity": "medium",
        "mitre": "T1041",
    },
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    urls = []
    
    # First check if the entire input is a single URL/domain (common for URL mode)
    text_stripped = text.strip()
    if text_stripped and ' ' not in text_stripped and '\n' not in text_stripped:
        # Single token - might be a URL or domain
        if re.match(r'^(?:https?://)?(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?:/[^\s]*)?$', text_stripped, re.IGNORECASE):
            url = text_stripped
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            return [url]
    
    # For text with multiple tokens, use pattern matching
    # Match URLs with protocol
    url_with_protocol = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+(?:\.[^\s<>"\']+)*'
    
    # For bare domains in text, match complete domains (word boundaries on both sides)
    # This pattern matches: subdomain.subdomain.domain.tld
    bare_domain = r'(?<![a-zA-Z0-9.\-])(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?:/[^\s]*)?(?![a-zA-Z0-9.\-])'
    
    # Extract URLs with protocol first
    protocol_matches = re.findall(url_with_protocol, text, re.IGNORECASE)
    urls.extend(protocol_matches)
    
    # Then extract bare domains from remaining text
    remaining_text = text
    for match in protocol_matches:
        remaining_text = remaining_text.replace(match, ' ')
    
    bare_matches = re.findall(bare_domain, remaining_text, re.IGNORECASE)
    urls.extend(bare_matches)
    
    cleaned = []
    for url in urls:
        url = re.sub(r'[.,;:!?\)]+$', '', url)
        if url and len(url) > 4:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            cleaned.append(url)
    
    # Deduplicate while preserving order
    seen = set()
    result = []
    for url in cleaned:
        if url not in seen:
            seen.add(url)
            result.append(url)
    
    return result


def extract_domains(urls: List[str]) -> List[str]:
    """Extract domains from URLs."""
    domains = []
    for url in urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.netloc:
                domains.append(parsed.netloc.lower())
        except:
            pass
    return list(set(domains))


def extract_ips(text: str) -> List[str]:
    """Extract IP addresses from text."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return list(set(valid_ips))


def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text."""
    patterns = [
        r'\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        r'\b\d{10,11}\b',
        r'\+\d{1,3}[-.\s]?\d{6,14}',
    ]
    phones = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        phones.extend(matches)
    
    cleaned = []
    for phone in phones:
        clean = re.sub(r'[^\d+]', '', phone)
        if len(clean) >= 10:
            cleaned.append(phone)
    return list(set(cleaned))


def detect_sms_patterns(text: str) -> List[ScamPattern]:
    """Detect SMS scam patterns."""
    text_lower = text.lower()
    matches = []
    
    for pattern_id, config in SMS_SCAM_PATTERNS.items():
        for regex in config["patterns"]:
            match = re.search(regex, text_lower)
            if match:
                matches.append(ScamPattern(
                    pattern_id=pattern_id,
                    name=config["name"],
                    description=config["description"],
                    severity=config["severity"],
                    matched_text=match.group(0)[:100],
                    mitre_technique=config.get("mitre"),
                ))
                break
    
    return matches


def detect_url_patterns(urls: List[str]) -> List[ScamPattern]:
    """Detect URL threat patterns."""
    patterns = []
    seen = set()
    
    for url in urls:
        url_lower = url.lower()
        for pattern_id, config in URL_THREAT_PATTERNS.items():
            if pattern_id in seen:
                continue
            for regex in config["patterns"]:
                if re.search(regex, url_lower, re.I):
                    patterns.append(ScamPattern(
                        pattern_id=f"url_{pattern_id}",
                        name=config["name"],
                        description=config["description"],
                        severity=config["severity"],
                        matched_text=url[:100],
                        mitre_technique=config.get("mitre"),
                    ))
                    seen.add(pattern_id)
                    break
    
    return patterns


def calculate_risk_score(
    patterns: List[ScamPattern],
    urls: List[str],
    url_enrichment: List[URLEnrichmentResult],
    url_sandbox: List[Any] = None,
    ai_analysis: Any = None,
) -> int:
    """
    Calculate overall risk score using fully dynamic weighted scoring.
    
    Score Components:
    1. Pattern Detection Score (0-40 points) - Based on pattern severity
    2. URL Enrichment Score (0-30 points) - From VirusTotal, PhishTank, URLhaus
    3. URL Sandbox Score (0-20 points) - From URLScan.io dynamic analysis
    4. AI Analysis Score (0-10 points) - From AI threat assessment
    
    All weights are derived from the actual data, not hardcoded thresholds.
    """
    component_scores = []
    component_weights = []
    
    # =========================================================================
    # COMPONENT 1: Pattern Detection Score (weight: 0.4)
    # =========================================================================
    pattern_score = 0
    if patterns:
        severity_weights = {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
        }
        
        # Calculate normalized pattern score
        pattern_contributions = []
        for pattern in patterns:
            weight = severity_weights.get(pattern.severity, 0.25)
            pattern_contributions.append(weight)
        
        if pattern_contributions:
            # Use exponential decay to prevent score explosion with many patterns
            # First pattern gets full weight, subsequent patterns get diminishing returns
            sorted_contributions = sorted(pattern_contributions, reverse=True)
            weighted_sum = 0
            for i, contribution in enumerate(sorted_contributions):
                decay_factor = 0.7 ** i  # Each subsequent pattern contributes 70% of previous
                weighted_sum += contribution * decay_factor
            
            # Normalize to 0-100 scale, cap at ~4 critical patterns worth
            max_possible = sum(0.7 ** i for i in range(4))  # ~2.8
            pattern_score = min(100, (weighted_sum / max_possible) * 100)
    
    if patterns:  # Only add if we have patterns to evaluate
        component_scores.append(pattern_score)
        component_weights.append(0.4)
    
    # =========================================================================
    # COMPONENT 2: URL Enrichment Score (weight: 0.3)
    # =========================================================================
    enrichment_score = 0
    if url_enrichment:
        enrichment_contributions = []
        
        for enrichment in url_enrichment:
            # Use actual threat_score from enrichment sources
            if enrichment.is_malicious:
                # If marked malicious by any source, high contribution
                enrichment_contributions.append(90)
            elif enrichment.threat_score > 0:
                # Use actual threat score from VirusTotal/other sources
                enrichment_contributions.append(enrichment.threat_score)
            elif enrichment.categories:
                # Has categories but not scored - moderate contribution
                malicious_categories = ['phishing', 'malware', 'spam', 'scam', 'suspicious']
                if any(cat.lower() in malicious_categories for cat in enrichment.categories):
                    enrichment_contributions.append(60)
                else:
                    enrichment_contributions.append(20)
        
        if enrichment_contributions:
            # Take weighted average favoring highest scores
            sorted_scores = sorted(enrichment_contributions, reverse=True)
            weighted_sum = sum(score * (0.8 ** i) for i, score in enumerate(sorted_scores))
            weight_sum = sum(0.8 ** i for i in range(len(sorted_scores)))
            enrichment_score = weighted_sum / weight_sum if weight_sum > 0 else 0
    
    if url_enrichment:  # Only add if we have enrichment data
        component_scores.append(enrichment_score)
        component_weights.append(0.3)
    
    # =========================================================================
    # COMPONENT 3: URL Sandbox Score (weight: 0.2)
    # =========================================================================
    sandbox_score = 0
    if url_sandbox:
        sandbox_contributions = []
        
        for sandbox in url_sandbox:
            # Handle both dict and object formats
            if isinstance(sandbox, dict):
                is_malicious = sandbox.get('is_malicious', False)
                threat_score = sandbox.get('threat_score', 0)
                threat_level = sandbox.get('threat_level', 'unknown')
            else:
                is_malicious = getattr(sandbox, 'is_malicious', False)
                threat_score = getattr(sandbox, 'threat_score', 0)
                threat_level = getattr(sandbox, 'threat_level', 'unknown')
            
            if is_malicious:
                sandbox_contributions.append(95)
            elif threat_score > 0:
                # Use actual URLScan.io/Cuckoo threat score directly
                sandbox_contributions.append(threat_score)
            elif threat_level == 'suspicious':
                sandbox_contributions.append(50)
            elif threat_level == 'malicious':
                sandbox_contributions.append(90)
        
        if sandbox_contributions:
            # Average of all sandbox results
            sandbox_score = sum(sandbox_contributions) / len(sandbox_contributions)
    
    if url_sandbox and len(url_sandbox) > 0:  # Only add if we have sandbox data
        component_scores.append(sandbox_score)
        component_weights.append(0.2)
    
    # =========================================================================
    # COMPONENT 4: AI Analysis Score (weight: 0.1)
    # =========================================================================
    ai_score = 0
    if ai_analysis:
        # Handle both dict and object formats
        if isinstance(ai_analysis, dict):
            enabled = ai_analysis.get('enabled', False)
            threat_assessment = ai_analysis.get('threat_assessment', '')
            confidence = ai_analysis.get('confidence', 0)
        else:
            enabled = getattr(ai_analysis, 'enabled', False)
            threat_assessment = getattr(ai_analysis, 'threat_assessment', '')
            confidence = getattr(ai_analysis, 'confidence', 0)
        
        if enabled:
            # Map AI assessment to score
            assessment_scores = {
                'MALICIOUS': 95,
                'SUSPICIOUS': 60,
                'LIKELY_SAFE': 25,
                'SAFE': 10,
            }
            base_score = assessment_scores.get(threat_assessment.upper(), 50)
            
            # Weight by AI confidence
            ai_score = base_score * confidence if confidence > 0 else base_score * 0.5
    
    if ai_analysis and (isinstance(ai_analysis, dict) and ai_analysis.get('enabled')) or (hasattr(ai_analysis, 'enabled') and ai_analysis.enabled):
        component_scores.append(ai_score)
        component_weights.append(0.1)
    
    # =========================================================================
    # FINAL SCORE CALCULATION
    # =========================================================================
    if not component_scores:
        # Fallback: Basic URL risk heuristics if no other data
        base_score = 0
        for url in urls:
            if len(url) > 150:
                base_score += 5
            if url.count('.') > 4:
                base_score += 5
            if re.search(r':\d{4,5}/', url):
                base_score += 8
            if '%' in url and url.count('%') > 3:
                base_score += 5
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                base_score += 10  # IP in URL
        return min(100, base_score)
    
    # Normalize weights to sum to 1.0
    weight_sum = sum(component_weights)
    normalized_weights = [w / weight_sum for w in component_weights]
    
    # Calculate weighted average
    final_score = sum(score * weight for score, weight in zip(component_scores, normalized_weights))
    
    return min(100, max(0, int(round(final_score))))


def get_risk_level(score: int) -> str:
    """Convert score to risk level."""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    return "clean"


def classify_threat(score: int, patterns: List[ScamPattern], is_url_mode: bool) -> ScamCategory:
    """Classify the threat type."""
    if score < 20:
        return ScamCategory.LEGITIMATE
    
    # Check for specific categories from patterns
    for pattern in patterns:
        if pattern.severity in ["critical", "high"]:
            for pid, config in SMS_SCAM_PATTERNS.items():
                if pid == pattern.pattern_id:
                    return config.get("category", ScamCategory.SUSPICIOUS)
    
    if is_url_mode:
        if score >= 70:
            return ScamCategory.MALICIOUS_URL
        elif score >= 40:
            return ScamCategory.PHISHING_URL
    
    return ScamCategory.SUSPICIOUS


def build_threat_indicators(
    patterns: List[ScamPattern],
    urls: List[str],
    score: int,
    url_enrichment: List[URLEnrichmentResult],
) -> List[str]:
    """Build list of threat indicators."""
    indicators = []
    
    # Score indicator
    if score >= 80:
        indicators.append(f"🔴 CRITICAL risk score: {score}/100")
    elif score >= 60:
        indicators.append(f"🟠 HIGH risk score: {score}/100")
    elif score >= 40:
        indicators.append(f"🟡 MEDIUM risk score: {score}/100")
    elif score >= 20:
        indicators.append(f"🟢 LOW risk score: {score}/100")
    else:
        indicators.append(f"✅ Clean: {score}/100")
    
    # Pattern indicators
    for pattern in patterns:
        icon = "🔴" if pattern.severity == "critical" else "🟠" if pattern.severity == "high" else "🟡"
        indicators.append(f"{icon} {pattern.name}")
    
    # URL indicators
    if urls:
        indicators.append(f"🔗 {len(urls)} URL(s) detected")
    
    # Enrichment indicators
    for enrichment in url_enrichment:
        if enrichment.is_malicious:
            indicators.append(f"⚠️ {enrichment.domain} flagged as MALICIOUS")
        if enrichment.categories:
            indicators.append(f"📁 Categories: {', '.join(enrichment.categories[:3])}")
    
    return indicators


def generate_recommendations(classification: ScamCategory, is_url_mode: bool) -> List[str]:
    """Generate actionable recommendations."""
    if classification == ScamCategory.LEGITIMATE:
        return ["✅ No immediate action required", "🔍 Always verify sender identity before acting"]
    
    recs = [
        "🚫 DO NOT click any links",
        "🚫 DO NOT reply or provide information",
        "📱 Block and report the sender",
    ]
    
    if is_url_mode:
        recs.extend([
            "🔍 Check URL in VirusTotal before visiting",
            "🛡️ Use sandbox/VM if investigation required",
            "📧 Report phishing to Google Safe Browsing",
        ])
    
    if classification == ScamCategory.SMISHING_FINANCIAL:
        recs.append("🏦 Contact your bank directly using official number")
    elif classification == ScamCategory.SMISHING_DELIVERY:
        recs.append("📦 Track packages only on official carrier websites")
    elif classification == ScamCategory.SMISHING_GOVERNMENT:
        recs.append("🏛️ Contact agency directly via .gov website")
    
    recs.append("🗑️ Delete the message")
    
    return recs


def build_mitre_techniques(patterns: List[ScamPattern]) -> List[Dict[str, str]]:
    """Extract MITRE ATT&CK techniques from patterns."""
    techniques = []
    seen = set()
    
    technique_names = {
        "T1566.001": "Spearphishing Attachment",
        "T1566.002": "Spearphishing Link",
        "T1566.003": "Spearphishing via Service",
        "T1583.001": "Domains",
        "T1583.003": "Virtual Private Server",
        "T1608.005": "Link Target",
        "T1204.001": "Malicious Link",
        "T1056.004": "Web Portal Capture",
        "T1041": "Exfiltration Over C2 Channel",
    }
    
    for pattern in patterns:
        if pattern.mitre_technique and pattern.mitre_technique not in seen:
            techniques.append({
                "id": pattern.mitre_technique,
                "name": technique_names.get(pattern.mitre_technique, pattern.mitre_technique),
                "tactic": "Initial Access" if "T1566" in pattern.mitre_technique else "Resource Development",
            })
            seen.add(pattern.mitre_technique)
    
    return techniques


# ============================================================================
# URL ENRICHMENT
# ============================================================================

async def enrich_urls(urls: List[str]) -> List[URLEnrichmentResult]:
    """
    Enrich URLs with threat intelligence from multiple sources.
    
    Sources (in order of reliability):
    1. IPQualityScore - Comprehensive URL scanning  
    2. URLhaus - Free, no rate limits, malware database
    3. PhishTank - Free, no rate limits, phishing database  
    4. VirusTotal - Has rate limits (4/min free tier), reputation check
    
    Note: Google Safe Browsing disabled (slow, redundant with IPQS)
    
    The function gracefully handles when any source fails or is unavailable.
    """
    results = []
    
    if not urls:
        logger.info("No URLs to enrich")
        return results
    
    logger.info(f"Starting URL enrichment for {len(urls)} URLs")
    
    # Try to import enrichment services
    try:
        from app.services.enrichment.virustotal import VirusTotalProvider
        from app.services.enrichment.phishtank import PhishTankProvider
        from app.services.enrichment.urlhaus import URLhausProvider
        from app.services.enrichment.ipqualityscore import IPQualityScoreClient
        from app.api.dependencies import get_settings
        
        settings = get_settings()
        
        # Initialize providers WITH API keys from settings
        vt_key = getattr(settings, 'virustotal_api_key', None)
        vt = VirusTotalProvider(vt_key) if vt_key else None
        
        pt = PhishTankProvider()  # Free, no key needed
        uh = URLhausProvider()   # Free, no key needed
        
        # Initialize IPQS provider
        ipqs_key = getattr(settings, 'ipqualityscore_api_key', '') or ''
        ipqs = IPQualityScoreClient(ipqs_key) if ipqs_key else None
        
        # Google Safe Browsing - DISABLED (slow, redundant with IPQS)
        gsb = None
        gsb_available = False
        
        # Log which services are available
        vt_available = vt is not None and vt.is_configured
        ipqs_available = ipqs is not None and bool(ipqs.api_key)
        
        logger.info(f"=== URL ENRICHMENT CONFIG ===")
        logger.info(f"  VirusTotal: {'CONFIGURED' if vt_available else 'NO API KEY'}")
        logger.info(f"  IPQualityScore: {'CONFIGURED' if ipqs_available else 'NO API KEY'}")
        logger.info(f"  URLhaus: AVAILABLE (free)")
        logger.info(f"  PhishTank: AVAILABLE (free)")
        logger.info(f"  Google Safe Browsing: DISABLED")
        
        for url in urls[:5]:  # Limit to 5 URLs
            logger.info(f"Enriching URL: {url}")
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                
                enrichment = URLEnrichmentResult(
                    url=url,
                    domain=domain,
                )
                
                sources = []
                errors = []
                
                # IPQualityScore check (comprehensive)
                if ipqs_available:
                    try:
                        ipqs_result = await ipqs.scan_url(url)
                        if ipqs_result and ipqs_result.get('success'):
                            risk_score = ipqs_result.get('risk_score', 0)
                            
                            # Store IPQS-specific data
                            enrichment.ipqs_score = risk_score
                            enrichment.ipqs_phishing = ipqs_result.get('is_phishing', False)
                            enrichment.ipqs_malware = ipqs_result.get('is_malware', False)
                            
                            # Always use IPQS risk_score as the threat_score if it's higher
                            if risk_score > enrichment.threat_score:
                                enrichment.threat_score = risk_score
                            
                            if ipqs_result.get('is_phishing') or ipqs_result.get('is_malware'):
                                enrichment.is_malicious = True
                                sources.append("IPQualityScore")
                                if ipqs_result.get('is_phishing'):
                                    enrichment.categories.append("IPQS: phishing")
                                if ipqs_result.get('is_malware'):
                                    enrichment.categories.append("IPQS: malware")
                                logger.info(f"IPQualityScore: {url} flagged - risk={risk_score}, phishing={ipqs_result.get('is_phishing')}, malware={ipqs_result.get('is_malware')}")
                            elif risk_score >= 75:
                                enrichment.is_malicious = True
                                sources.append("IPQualityScore")
                                logger.info(f"IPQualityScore: {url} high risk ({risk_score})")
                            elif risk_score >= 50:
                                sources.append("IPQualityScore")
                                logger.info(f"IPQualityScore: {url} medium risk ({risk_score})")
                            else:
                                sources.append("IPQualityScore")
                                logger.debug(f"IPQualityScore: {url} low risk ({risk_score})")
                        else:
                            error = ipqs_result.get('error', 'Unknown error') if ipqs_result else 'No response'
                            logger.warning(f"IPQualityScore: {url} check failed - {error}")
                    except Exception as e:
                        logger.warning(f"IPQualityScore check failed for {url}: {e}")
                
                # URLhaus check (free, no limits, most reliable for malware)
                urlhaus_checked = False
                try:
                    uh_result = await uh.check_url(url)
                    urlhaus_checked = True
                    sources.append("URLhaus")  # Always add - it's free and was checked
                    if uh_result and uh_result.get('threat'):
                        enrichment.is_malicious = True
                        enrichment.threat_score = max(enrichment.threat_score, 90)
                        enrichment.categories.append(uh_result.get('threat_type', 'malware'))
                        logger.info(f"URLhaus: {url} flagged as {uh_result.get('threat_type', 'malware')}")
                    else:
                        logger.info(f"URLhaus: {url} - clean (not in database)")
                except Exception as e:
                    logger.warning(f"URLhaus check failed for {url}: {e}")
                
                # PhishTank check (free, no limits)
                phishtank_checked = False
                try:
                    pt_result = await pt.check_url(url)
                    phishtank_checked = True
                    sources.append("PhishTank")  # Always add - it's free and was checked
                    if pt_result and pt_result.get('is_phish'):
                        enrichment.is_malicious = True
                        enrichment.threat_score = max(enrichment.threat_score, 80)
                        enrichment.categories.append("phishing")
                        logger.info(f"PhishTank: {url} flagged as phishing")
                    else:
                        logger.info(f"PhishTank: {url} - clean (not in database)")
                except Exception as e:
                    logger.warning(f"PhishTank check failed for {url}: {e}")
                
                # VirusTotal check LAST (has rate limits, may fail)
                if vt_available:
                    try:
                        vt_result = await vt.check_url(url)
                        if vt_result:
                            malicious_count = vt_result.get('malicious', 0)
                            enrichment.vt_malicious = malicious_count
                            if malicious_count > 0:
                                enrichment.is_malicious = True
                                enrichment.threat_score = max(enrichment.threat_score, min(100, malicious_count * 10))
                                logger.info(f"VirusTotal: {url} flagged by {malicious_count} engines")
                            sources.append("VirusTotal")
                            enrichment.categories.extend(vt_result.get('categories', []))
                    except Exception as e:
                        # Log but continue - VT is optional
                        logger.warning(f"VirusTotal check skipped for {url}: {e}")
                
                enrichment.sources = sources
                
                # Log final enrichment result
                logger.info(f"=== ENRICHMENT RESULT: {url} ===")
                logger.info(f"  Sources checked: {sources if sources else 'none (APIs not configured)'}")
                logger.info(f"  Threat score: {enrichment.threat_score}")
                logger.info(f"  Is malicious: {enrichment.is_malicious}")
                logger.info(f"  Categories: {enrichment.categories}")
                
                # Always return result even if no TI data found
                results.append(enrichment)
                
            except Exception as e:
                logger.error(f"Error enriching URL {url}: {e}", exc_info=True)
                # Still return basic result
                results.append(URLEnrichmentResult(url=url, domain=urlparse(url).netloc if url else "unknown"))
        
    except ImportError as e:
        logger.error(f"Enrichment services import failed: {e}", exc_info=True)
        # Return basic results without enrichment
        for url in urls[:5]:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                results.append(URLEnrichmentResult(url=url, domain=domain, sources=["import_error"]))
            except:
                results.append(URLEnrichmentResult(url=url, domain="unknown", sources=["import_error"]))
    except Exception as e:
        logger.error(f"Enrichment failed: {e}", exc_info=True)
        for url in urls[:5]:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                results.append(URLEnrichmentResult(url=url, domain=domain, sources=["error"]))
            except:
                results.append(URLEnrichmentResult(url=url, domain="unknown", sources=["error"]))
    
    logger.info(f"URL enrichment complete: {len(results)} results")
    return results


# ============================================================================
# AI ANALYSIS
# ============================================================================

async def get_ai_analysis(
    text: str,
    source: TextSource,
    patterns: List[ScamPattern],
    urls: List[str],
    score: int,
    url_enrichment: List[Dict] = None,
    url_sandbox: List[Dict] = None,
) -> AIAnalysisResult:
    """
    Get AI-powered analysis with full threat intelligence context.
    
    Args:
        text: The message/URL content
        source: Source type (SMS, URL, etc.)
        patterns: Detected scam patterns
        urls: URLs found in content
        score: Current risk score
        url_enrichment: TI results from VirusTotal, IPQS, GSB, etc.
        url_sandbox: Dynamic analysis results
    """
    logger.info("=== AI ANALYSIS START ===")
    
    try:
        from app.services.ai.openai_provider import OpenAIProvider
        from app.services.ai.anthropic_provider import AnthropicProvider
        import os
        
        # Try OpenAI first, then Anthropic
        provider = None
        provider_name = None
        
        openai_key = os.getenv("OPENAI_API_KEY")
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        
        logger.info(f"  OpenAI API Key: {'CONFIGURED' if openai_key else 'NOT SET'}")
        logger.info(f"  Anthropic API Key: {'CONFIGURED' if anthropic_key else 'NOT SET'}")
        
        if openai_key:
            provider = OpenAIProvider(api_key=openai_key)
            provider_name = "openai"
            logger.info(f"  Using provider: OpenAI")
        elif anthropic_key:
            provider = AnthropicProvider(api_key=anthropic_key)
            provider_name = "anthropic"
            logger.info(f"  Using provider: Anthropic")
        
        if not provider or not provider.is_configured():
            logger.warning("  AI provider not configured - analysis disabled")
            return AIAnalysisResult(
                enabled=False, 
                summary="AI analysis not configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY environment variable."
            )
        
        # Build prompt with full context
        source_type = "URL" if source == TextSource.URL else f"{source.value.upper()} message"
        patterns_text = "\n".join([f"- {p.name}: {p.description}" for p in patterns]) if patterns else "None detected"
        urls_text = "\n".join(urls[:5]) if urls else "None"
        
        # Build threat intelligence summary
        ti_findings = []
        if url_enrichment:
            for enrichment in url_enrichment:
                url = enrichment.get('url', 'Unknown URL')
                sources = enrichment.get('sources', [])
                is_malicious = enrichment.get('is_malicious', False)
                threat_score = enrichment.get('threat_score', 0)
                categories = enrichment.get('categories', [])
                
                if is_malicious or threat_score >= 50:
                    ti_findings.append(f"⚠️ {url}: MALICIOUS (score: {threat_score}, sources: {', '.join(sources)}, categories: {', '.join(categories)})")
                elif threat_score > 0:
                    ti_findings.append(f"⚡ {url}: Suspicious (score: {threat_score}, sources: {', '.join(sources)})")
                elif sources:
                    ti_findings.append(f"✓ {url}: Clean (checked by: {', '.join(sources)})")
        
        ti_text = "\n".join(ti_findings) if ti_findings else "No threat intelligence data available"
        
        # Build sandbox summary
        sandbox_findings = []
        if url_sandbox:
            for sandbox in url_sandbox:
                url = sandbox.get('url', 'Unknown URL')
                is_malicious = sandbox.get('is_malicious', False)
                threat_level = sandbox.get('threat_level', 'unknown')
                threat_score = sandbox.get('threat_score', 0)
                
                if is_malicious:
                    sandbox_findings.append(f"🔴 {url}: MALICIOUS (level: {threat_level}, score: {threat_score})")
                elif threat_score > 50:
                    sandbox_findings.append(f"🟡 {url}: Suspicious (level: {threat_level}, score: {threat_score})")
        
        sandbox_text = "\n".join(sandbox_findings) if sandbox_findings else "No sandbox analysis performed"
        
        prompt = f"""Analyze this {source_type} for security threats. Use ALL the intelligence data provided.

=== CONTENT ===
{text[:1500]}

=== DETECTED PATTERNS ===
{patterns_text}

=== URLs FOUND ===
{urls_text}

=== THREAT INTELLIGENCE FINDINGS ===
{ti_text}

=== SANDBOX ANALYSIS ===
{sandbox_text}

=== CURRENT RISK SCORE ===
{score}/100

Based on ALL the above intelligence, provide:
1. SUMMARY: 2-3 sentence assessment incorporating TI findings
2. THREAT_ASSESSMENT: One of [MALICIOUS, SUSPICIOUS, LIKELY_SAFE, SAFE]
3. KEY_FINDINGS: 3-5 bullet points (reference specific TI sources if they found threats)
4. INTENT: What is the attacker trying to achieve? (credential theft, malware delivery, financial fraud, etc.)
5. SOCIAL_ENGINEERING: Tactics used (urgency, fear, authority, etc.)
6. RECOMMENDATIONS: 3-5 actionable steps for SOC analyst

IMPORTANT: If threat intelligence APIs flagged URLs as malicious, this should heavily influence your threat assessment.

Format response as valid JSON."""

        system_prompt = """You are a senior SOC analyst specializing in SMS smishing, phishing URLs, and social engineering attacks.
You have access to threat intelligence from multiple sources: VirusTotal, IPQualityScore, Google Safe Browsing, PhishTank, URLhaus.
Analyze the content AND the threat intelligence findings to provide accurate threat assessment.
Always weight confirmed TI findings heavily in your assessment.
Respond in valid JSON format only."""

        response = await provider.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.3,
            max_tokens=1000,
        )
        
        # Parse response
        import json
        try:
            # Try to extract JSON from response
            content = response.content.strip()
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            data = json.loads(content)
            
            # Safely extract list fields (AI sometimes returns strings instead of lists)
            key_findings = _ensure_list(data.get("KEY_FINDINGS", data.get("key_findings")))
            social_eng = _ensure_list(data.get("SOCIAL_ENGINEERING", data.get("social_engineering")))
            recommendations = _ensure_list(data.get("RECOMMENDATIONS", data.get("recommendations")))
            
            # Extract intent
            intent = data.get("INTENT", data.get("intent", ""))
            if isinstance(intent, list):
                intent = ", ".join(intent)
            
            # Adjust confidence based on TI data availability
            base_confidence = 0.7
            if url_enrichment:
                base_confidence += 0.1  # Higher confidence with TI data
                if any(e.get('is_malicious') for e in url_enrichment):
                    base_confidence += 0.1  # Even higher if TI confirms malicious
            if url_sandbox:
                base_confidence += 0.05
            
            return AIAnalysisResult(
                enabled=True,
                provider=provider_name,
                summary=str(data.get("SUMMARY", data.get("summary", "")))[:1000],
                threat_assessment=str(data.get("THREAT_ASSESSMENT", data.get("threat_assessment", "UNKNOWN"))),
                key_findings=key_findings,
                social_engineering_tactics=social_eng,
                recommendations=recommendations,
                confidence=min(0.95, base_confidence),
                intent=intent,
            )
        except json.JSONDecodeError:
            # Return raw response if JSON parsing fails
            return AIAnalysisResult(
                enabled=True,
                provider=provider_name,
                summary=response.content[:500],
                confidence=0.6,
            )
    
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return AIAnalysisResult(enabled=False, summary=f"AI analysis unavailable: {str(e)[:100]}")


# ============================================================================
# URL SANDBOX (DYNAMIC ANALYSIS)
# ============================================================================

async def run_url_sandbox(urls: List[str]) -> List[URLSandboxResult]:
    """Run dynamic URL analysis using URLScan.io or Cuckoo."""
    results = []
    
    try:
        from app.services.sandbox.url_sandbox import get_url_sandbox_service, SandboxProvider
        
        service = get_url_sandbox_service()
        status = service.get_status()
        
        # Check if any provider is configured
        if not any(p.get("configured") for p in status.values()):
            logger.info("No URL sandbox providers configured")
            return results
        
        for url in urls[:3]:  # Limit to 3 URLs for sandbox
            try:
                logger.info(f"Submitting URL to sandbox: {url}")
                sandbox_result = await service.analyze_url(
                    url=url,
                    provider=SandboxProvider.AUTO,
                    wait_for_result=True,
                    max_wait=60  # 60 second timeout
                )
                
                results.append(URLSandboxResult(
                    url=sandbox_result.url,
                    provider=sandbox_result.provider,
                    status=sandbox_result.status.value,
                    is_malicious=sandbox_result.is_malicious,
                    threat_score=sandbox_result.threat_score,
                    threat_level=sandbox_result.threat_level,
                    categories=sandbox_result.categories,
                    indicators=sandbox_result.indicators,
                    contacted_ips=sandbox_result.contacted_ips,
                    contacted_domains=sandbox_result.contacted_domains,
                    redirects=sandbox_result.redirects,
                    final_url=sandbox_result.final_url,
                    page_title=sandbox_result.page_title,
                    screenshot_url=sandbox_result.screenshot_url,
                    report_url=sandbox_result.report_url,
                    analysis_time_ms=sandbox_result.analysis_time_ms,
                ))
                
            except Exception as e:
                logger.error(f"Sandbox analysis failed for {url}: {e}")
                results.append(URLSandboxResult(
                    url=url,
                    provider="error",
                    status="failed",
                ))
    
    except ImportError as e:
        logger.warning(f"URL sandbox service not available: {e}")
    except Exception as e:
        logger.error(f"URL sandbox error: {e}")
    
    return results


# ============================================================================
# API ENDPOINT
# ============================================================================

@router.post("/text", response_model=TextAnalysisResponse)
async def analyze_text(
    request: TextAnalysisRequest,
    analysis_store = Depends(get_analysis_store),
) -> TextAnalysisResponse:
    """
    Analyze text message, SMS, or URLs for threats.
    
    Supports:
    - SMS/WhatsApp/Telegram smishing detection
    - URL phishing analysis
    - AI-powered threat assessment
    - Threat intelligence enrichment
    """
    text = request.text.strip()
    is_url_mode = request.source == TextSource.URL
    
    # Generate analysis ID
    analysis_id = hashlib.sha256(
        f"{text}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:16]
    
    analysis_type = "url" if is_url_mode else "sms" if request.source == TextSource.SMS else "message"
    logger.info(f"Analyzing {analysis_type}: {analysis_id} ({len(text)} chars)")
    
    # Extract IOCs
    urls = extract_urls(text)
    domains = extract_domains(urls)
    ips = extract_ips(text)
    phones = extract_phone_numbers(text) if not is_url_mode else []
    
    # Detect patterns
    patterns = []
    if not is_url_mode:
        patterns.extend(detect_sms_patterns(text))
    patterns.extend(detect_url_patterns(urls))
    
    # URL enrichment
    url_enrichment = []
    if urls and request.enable_url_enrichment:
        try:
            url_enrichment = await enrich_urls(urls)
        except Exception as e:
            logger.error(f"URL enrichment failed: {e}")
    
    # URL Sandbox (Dynamic Analysis) - Run BEFORE scoring to include in calculation
    url_sandbox = []
    if urls and request.enable_url_sandbox:
        try:
            url_sandbox = await run_url_sandbox(urls)
        except Exception as e:
            logger.error(f"URL sandbox failed: {e}")
    
    # Convert enrichment to dict format BEFORE AI analysis
    enrichment_dicts = [
        {
            "url": e.url,
            "domain": e.domain,
            "is_malicious": e.is_malicious,
            "threat_score": e.threat_score,
            "sources": e.sources,
            "categories": e.categories,
            # IPQS-specific fields
            "ipqs_score": e.ipqs_score,
            "ipqs_phishing": e.ipqs_phishing,
            "ipqs_malware": e.ipqs_malware,
            "vt_malicious": e.vt_malicious,
            "gsb_malicious": e.gsb_malicious,
        }
        for e in url_enrichment
    ] if url_enrichment else []
    
    # Convert sandbox results to dict format
    sandbox_dicts = [
        {
            "url": s.url,
            "is_malicious": s.is_malicious,
            "threat_score": s.threat_score,
            "threat_level": s.threat_level,
            "categories": s.categories,
        }
        for s in url_sandbox
    ] if url_sandbox else []
    
    # AI Analysis - Run AFTER enrichment to include TI findings
    ai_result = AIAnalysisResult(enabled=False)
    if request.enable_ai_analysis:
        try:
            # Pass ALL threat intelligence data to AI
            ai_result = await get_ai_analysis(
                text=text,
                source=request.source,
                patterns=patterns,
                urls=urls,
                score=0,  # Preliminary score
                url_enrichment=enrichment_dicts,
                url_sandbox=sandbox_dicts,
            )
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
    
    # =========================================================================
    # DYNAMIC INTELLIGENT SCORING (DIDA)
    # All scoring is now evidence-based with zero hardcoding
    # =========================================================================
    try:
        from app.services.detection.sms_dynamic_scorer import calculate_sms_dynamic_score
        
        # enrichment_dicts and sandbox_dicts already created above
        
        # Convert AI result to dict
        ai_dict = None
        if ai_result.enabled:
            ai_dict = {
                "enabled": ai_result.enabled,
                "provider": ai_result.provider,
                "confidence": ai_result.confidence,
                "key_findings": ai_result.key_findings,
                "social_engineering_tactics": ai_result.social_engineering_tactics,
                "threat_assessment": getattr(ai_result, 'threat_assessment', None),
                "intent": getattr(ai_result, 'intent', None),
            }
        
        # Calculate using Dynamic Intelligent Detection Architecture
        dynamic_result = calculate_sms_dynamic_score(
            text=text,
            urls=urls,
            sender=request.sender,
            url_enrichment=enrichment_dicts,
            url_sandbox=sandbox_dicts,
            ai_analysis=ai_dict,
        )
        
        # Use dynamic results
        score = dynamic_result.value
        level = dynamic_result.level
        confidence = dynamic_result.confidence
        
        # Map classification from dynamic result
        classification_mapping = {
            "financial_smishing": ScamCategory.SMISHING_FINANCIAL,
            "delivery_smishing": ScamCategory.SMISHING_DELIVERY,
            "prize_scam": ScamCategory.SMISHING_PRIZE,
            "brand_impersonation_smishing": ScamCategory.PHISHING_URL,
            "credential_phishing": ScamCategory.PHISHING_URL,
            "financial scam": ScamCategory.SMISHING_FINANCIAL,
            "credential phishing": ScamCategory.PHISHING_URL,
            "prize scam": ScamCategory.SMISHING_PRIZE,
            "fear-based scam": ScamCategory.SUSPICIOUS,
            "brand impersonation": ScamCategory.PHISHING_URL,
            "suspicious": ScamCategory.SUSPICIOUS,
        }
        
        dynamic_class = dynamic_result.classification.lower()
        classification = classification_mapping.get(dynamic_class, ScamCategory.SUSPICIOUS)
        
        if score < 20:
            classification = ScamCategory.LEGITIMATE
        elif is_url_mode and score >= 60:
            classification = ScamCategory.MALICIOUS_URL if score >= 75 else ScamCategory.PHISHING_URL
        
        # Use dynamic explanation as indicators
        indicators = dynamic_result.explanation.copy()
        
        # Add attack chain info
        for chain in dynamic_result.attack_chains:
            if chain.name not in str(indicators):
                chain_conf = int(chain.confidence * 100)
                indicators.append(f"⛓️ Attack Pattern: {chain.description} ({chain_conf}% match)")
        
        # Use dynamic MITRE mapping
        mitre = dynamic_result.mitre_techniques
        
        # Use dynamic recommendation
        recommendations = [dynamic_result.recommended_action]
        
        # Add standard recommendations based on level
        if level in ["critical", "high"]:
            recommendations.extend([
                "🚫 DO NOT click any links",
                "🚫 DO NOT reply or provide information",
                "📱 Block and report the sender",
            ])
        
        # Add AI recommendations if available
        if ai_result.enabled and ai_result.recommendations:
            recommendations.extend(ai_result.recommendations[:3])
        
        # Log dynamic scoring result
        logger.info(f"Dynamic score: {score} ({level}) confidence={confidence:.2f} chains={len(dynamic_result.attack_chains)}")
        
    except Exception as e:
        # Fallback to legacy scoring if dynamic scoring fails
        logger.warning(f"Dynamic scoring failed, using legacy: {e}")
        score = calculate_risk_score(
            patterns=patterns,
            urls=urls,
            url_enrichment=url_enrichment,
            url_sandbox=url_sandbox,
            ai_analysis=ai_result,
        )
        level = get_risk_level(score)
        classification = classify_threat(score, patterns, is_url_mode)
        indicators = build_threat_indicators(patterns, urls, score, url_enrichment)
        recommendations = generate_recommendations(classification, is_url_mode)
        if ai_result.enabled and ai_result.recommendations:
            recommendations = ai_result.recommendations + recommendations[:3]
        mitre = build_mitre_techniques(patterns)
        confidence = min(0.95, score / 100 + 0.15) if score >= 30 else max(0.7, 1 - score / 100)
    
    # Add sandbox indicators if not already present
    for sr in url_sandbox:
        if sr.is_malicious:
            msg = "🔴 URL confirmed MALICIOUS by sandbox"
            if msg not in indicators:
                indicators.insert(0, msg)
        elif sr.threat_score and sr.threat_score > 50:
            msg = f"⚠️ Sandbox score: {sr.threat_score}/100"
            if msg not in indicators:
                indicators.append(msg)
    
    is_threat = classification != ScamCategory.LEGITIMATE and score >= 25
    
    response = TextAnalysisResponse(
        analysis_id=analysis_id,
        analyzed_at=datetime.utcnow().isoformat(),
        analysis_type=analysis_type,
        source=request.source,
        original_text=text[:2000],
        message_length=len(text),
        overall_score=score,
        overall_level=level,
        classification=classification,
        is_threat=is_threat,
        confidence=round(confidence, 2),
        urls_found=urls,
        domains_found=domains,
        ips_found=ips,
        phone_numbers_found=phones,
        url_enrichment=url_enrichment,
        url_sandbox=url_sandbox,
        patterns_matched=patterns,
        threat_indicators=indicators,
        ai_analysis=ai_result,
        recommendations=recommendations,
        mitre_techniques=mitre,
    )
    
    # Save to history as a pseudo-email analysis
    if analysis_store:
        try:
            from app.models.analysis import AnalysisResult, ExtractedIOCs
            from app.models.email import ParsedEmail, EmailAddress, ExtractedURL
            from app.models.detection import DetectionResults, DetectionRule, RiskLevel, EmailClassification
            from app.models.enrichment import EnrichmentResults
            
            # Map classification to EmailClassification
            classification_map = {
                ScamCategory.LEGITIMATE: EmailClassification.BENIGN,
                ScamCategory.SMISHING_FINANCIAL: EmailClassification.PHISHING,
                ScamCategory.SMISHING_DELIVERY: EmailClassification.PHISHING,
                ScamCategory.SMISHING_PRIZE: EmailClassification.PHISHING,
                ScamCategory.SMISHING_GOVERNMENT: EmailClassification.PHISHING,
                ScamCategory.SMISHING_TECH_SUPPORT: EmailClassification.PHISHING,
                ScamCategory.PHISHING_URL: EmailClassification.PHISHING,
                ScamCategory.MALICIOUS_URL: EmailClassification.MALWARE_DELIVERY,
                ScamCategory.SUSPICIOUS: EmailClassification.SPAM,
            }
            email_classification = classification_map.get(classification, EmailClassification.UNKNOWN)
            
            # Map level to RiskLevel
            level_map = {
                "low": RiskLevel.LOW,
                "medium": RiskLevel.MEDIUM,
                "high": RiskLevel.HIGH,
                "critical": RiskLevel.CRITICAL,
            }
            risk_level_enum = level_map.get(level.lower(), RiskLevel.LOW)
            
            # Create detection rules from patterns
            detection_rules = [
                DetectionRule(
                    rule_id=p.pattern_id,
                    rule_name=p.name,
                    category="url_threat" if is_url_mode else "smishing",
                    description=p.description,
                    severity=level_map.get(p.severity, RiskLevel.MEDIUM),
                    score_impact=20,
                    triggered=True,
                    evidence=[p.matched_text] if p.matched_text else [],
                    mitre_technique=p.mitre_technique,
                )
                for p in patterns
            ]
            
            # Create sender EmailAddress
            sender_type = "url" if is_url_mode else "sms"
            sender_email_addr = f"{sender_type}@analysis.local"
            sender_address = EmailAddress(
                raw=sender_email_addr,
                email=sender_email_addr,
                display_name=f"{'URL Scanner' if is_url_mode else 'SMS Scanner'}",
                domain="analysis.local",
                local_part=sender_type,
            )
            
            # Create recipient EmailAddress
            recipient_address = EmailAddress(
                raw="security@analysis.local",
                email="security@analysis.local",
                display_name="Security Team",
                domain="analysis.local",
                local_part="security",
            )
            
            # Create ExtractedURL objects
            extracted_urls = []
            for u in urls[:10]:  # Limit to first 10
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(u)
                    extracted_urls.append(ExtractedURL(
                        url=u,
                        normalized_url=u.lower(),
                        domain=parsed.netloc or "unknown",
                        scheme=parsed.scheme or "https",
                        path=parsed.path or "/",
                        source="body_text",
                    ))
                except Exception:
                    pass
            
            # Create proper models
            parsed_email = ParsedEmail(
                message_id=f"text-{analysis_id}",
                subject=f"{'URL' if is_url_mode else 'SMS'} Analysis: {classification.value}",
                sender=sender_address,
                to_recipients=[recipient_address],
                cc_recipients=[],
                bcc_recipients=[],
                body_text=text[:500],
                urls=extracted_urls,
                attachments=[],
                phone_numbers=phones,
            )
            
            detection_results = DetectionResults(
                rules_triggered=detection_rules,
                rules_passed=[],
                risk_score=score,
                risk_level=risk_level_enum,
                confidence=confidence,
                primary_classification=email_classification,
                secondary_classifications=[],
            )
            
            enrichment_results = EnrichmentResults(
                sender_domain=None,
                reply_to_domain=None,
                url_domains=[],
                originating_ip=None,
                all_ips=[],
                urls=[],
                attachments=[],
            )
            
            iocs_model = ExtractedIOCs(
                domains=domains,
                urls=urls,
                ips=ips,
                email_addresses=[],
                file_hashes_md5=[],
                file_hashes_sha256=[],
                phone_numbers=phones,
            )
            
            # Convert to AnalysisResult for storage compatibility
            pseudo_result = AnalysisResult(
                analysis_id=analysis_id,
                analyzed_at=datetime.utcnow(),
                analysis_duration_ms=500,
                email=parsed_email,
                detection=detection_results,
                enrichment=enrichment_results,
                iocs=iocs_model,
                overall_score=score,
                overall_level=level,
                classification=classification.value,
                ai_triage=None,
            )
            
            await analysis_store.save(pseudo_result)
            logger.info(f"Saved {analysis_type} analysis to history: {analysis_id}")
        except Exception as e:
            logger.error(f"Failed to save to history: {e}", exc_info=True)
    
    return response
