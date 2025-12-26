"""
NiksES Text/SMS Analysis Route

Endpoint for analyzing SMS, WhatsApp, Telegram and other text messages
for smishing and scam detection.
"""

import re
import logging
import hashlib
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analysis"])


class TextSource(str, Enum):
    """Source of the text message."""
    SMS = "sms"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    OTHER = "other"


class ScamCategory(str, Enum):
    """Categories of detected scams."""
    LEGITIMATE = "legitimate"
    SMISHING_FINANCIAL = "smishing_financial"
    SMISHING_DELIVERY = "smishing_delivery"
    SMISHING_PRIZE = "smishing_prize"
    SMISHING_GOVERNMENT = "smishing_government"
    SMISHING_TECH_SUPPORT = "smishing_tech_support"
    SUSPICIOUS = "suspicious"


class TextAnalysisRequest(BaseModel):
    """Request model for text analysis."""
    text: str = Field(..., min_length=1, max_length=5000, description="Message text to analyze")
    sender: Optional[str] = Field(None, description="Sender phone number or ID")
    source: TextSource = Field(TextSource.SMS, description="Source platform")


class ScamPattern(BaseModel):
    """A detected scam pattern."""
    pattern_id: str
    name: str
    description: str
    severity: str  # low, medium, high, critical
    matched_text: Optional[str] = None


class TextAnalysisResponse(BaseModel):
    """Response model for text analysis."""
    analysis_id: str
    analyzed_at: str
    source: TextSource
    
    # Risk assessment
    overall_score: int = Field(..., ge=0, le=100)
    overall_level: str
    classification: ScamCategory
    is_likely_scam: bool
    confidence: float = Field(..., ge=0, le=1)
    
    # Extracted IOCs
    urls_found: List[str]
    phone_numbers_found: List[str]
    
    # Pattern matches
    scam_patterns_matched: List[ScamPattern]
    indicators: List[str]
    
    # Recommendations
    recommendations: List[str]
    
    # Original message info
    message_length: int
    has_url: bool
    has_phone: bool


# ============================================================================
# SCAM DETECTION PATTERNS
# ============================================================================

SMS_SCAM_PATTERNS = {
    # Package/Delivery Scams
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
    },
    
    # Banking/Financial Scams
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
    },
    
    # Prize/Lottery Scams
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
    },
    
    # Government Impersonation
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
    },
    
    # Tech Support Scams
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
    },
    
    # Urgency Indicators
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
    },
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s]*)?'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    
    # Clean up URLs
    cleaned = []
    for url in urls:
        # Remove trailing punctuation
        url = re.sub(r'[.,;:!?\)]+$', '', url)
        if url and len(url) > 4:
            cleaned.append(url)
    
    return list(set(cleaned))


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
    
    # Clean and deduplicate
    cleaned = []
    for phone in phones:
        clean = re.sub(r'[^\d+]', '', phone)
        if len(clean) >= 10:
            cleaned.append(phone)
    
    return list(set(cleaned))


def detect_scam_patterns(text: str) -> List[ScamPattern]:
    """Detect scam patterns in text."""
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
                    matched_text=match.group(0)[:100] if match.group(0) else None
                ))
                break  # One match per category is enough
    
    return matches


def calculate_risk_score(
    text: str,
    urls: List[str],
    phones: List[str],
    patterns: List[ScamPattern]
) -> int:
    """Calculate overall risk score (0-100)."""
    score = 0
    
    # Pattern-based scoring
    for pattern in patterns:
        if pattern.severity == "critical":
            score += 35
        elif pattern.severity == "high":
            score += 25
        elif pattern.severity == "medium":
            score += 15
        else:
            score += 10
    
    # URL analysis
    if urls:
        score += 10
        for url in urls:
            # Suspicious URL indicators
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 15  # IP address in URL
            if len(url) > 100:
                score += 5  # Very long URL
            if re.search(r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly', url, re.I):
                score += 10  # URL shortener
    
    # Sender analysis
    if phones:
        score += 5  # Has phone numbers (not necessarily bad)
    
    # Text analysis
    text_lower = text.lower()
    
    # Check for suspicious patterns not in main patterns
    if re.search(r'click\s*(?:here|link|below)', text_lower):
        score += 10
    if re.search(r'act\s*(?:fast|now|immediately)', text_lower):
        score += 10
    if re.search(r'\$\d+', text):  # Money amounts
        score += 5
    
    # Cap at 100
    return min(100, score)


def classify_message(score: int, patterns: List[ScamPattern]) -> ScamCategory:
    """Classify message based on score and patterns."""
    if not patterns and score < 20:
        return ScamCategory.LEGITIMATE
    
    # Check for specific categories
    for pattern in patterns:
        if pattern.severity in ["critical", "high"]:
            # Return the specific category from the pattern config
            for pid, config in SMS_SCAM_PATTERNS.items():
                if pid == pattern.pattern_id:
                    return config.get("category", ScamCategory.SUSPICIOUS)
    
    if score >= 40:
        return ScamCategory.SUSPICIOUS
    
    return ScamCategory.LEGITIMATE


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


def generate_recommendations(
    classification: ScamCategory,
    urls: List[str],
    patterns: List[ScamPattern]
) -> List[str]:
    """Generate actionable recommendations."""
    recommendations = []
    
    if classification == ScamCategory.LEGITIMATE:
        recommendations.append("✅ Message appears legitimate, but always verify sender identity")
    else:
        recommendations.append("🚫 DO NOT click any links in this message")
        recommendations.append("🚫 DO NOT reply or call any numbers provided")
        recommendations.append("🚫 DO NOT provide personal or financial information")
        
        if classification == ScamCategory.SMISHING_FINANCIAL:
            recommendations.append("📞 Contact your bank directly using official channels")
            recommendations.append("🔐 Check your accounts through official banking apps only")
        
        if classification == ScamCategory.SMISHING_DELIVERY:
            recommendations.append("📦 Track packages only through official carrier websites")
            recommendations.append("🔍 Verify delivery status using official tracking numbers")
        
        if classification == ScamCategory.SMISHING_GOVERNMENT:
            recommendations.append("🏛️ Government agencies don't request personal info via text")
            recommendations.append("📞 Contact agencies directly using official .gov websites")
        
        if urls:
            recommendations.append("🔗 Report suspicious URLs to phishing databases")
        
        recommendations.append("📱 Block and report the sender")
        recommendations.append("🗑️ Delete the message")
    
    return recommendations


def build_indicators(
    text: str,
    urls: List[str],
    phones: List[str],
    patterns: List[ScamPattern],
    score: int
) -> List[str]:
    """Build list of threat indicators."""
    indicators = []
    
    # Score indicator
    if score >= 80:
        indicators.append(f"🔴 Critical risk score: {score}/100")
    elif score >= 60:
        indicators.append(f"🟠 High risk score: {score}/100")
    elif score >= 40:
        indicators.append(f"🟡 Medium risk score: {score}/100")
    elif score >= 20:
        indicators.append(f"🟢 Low risk score: {score}/100")
    
    # Pattern indicators
    for pattern in patterns:
        if pattern.severity == "critical":
            indicators.append(f"🔴 {pattern.name}")
        elif pattern.severity == "high":
            indicators.append(f"🟠 {pattern.name}")
        else:
            indicators.append(f"🟡 {pattern.name}")
    
    # URL indicators
    if urls:
        indicators.append(f"🔗 Contains {len(urls)} URL(s)")
        for url in urls[:3]:
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                indicators.append("⚠️ URL contains raw IP address")
            if re.search(r'bit\.ly|tinyurl|t\.co', url, re.I):
                indicators.append("⚠️ Uses URL shortener (hides destination)")
    
    # Phone indicators
    if phones:
        indicators.append(f"📱 Contains {len(phones)} phone number(s)")
    
    # Text analysis indicators
    text_lower = text.lower()
    if re.search(r'urgent|immediately|right away|asap', text_lower):
        indicators.append("⏰ Uses urgency tactics")
    if re.search(r'click|tap|open', text_lower) and urls:
        indicators.append("👆 Requests clicking a link")
    if re.search(r'verify|confirm|update.*(?:info|account)', text_lower):
        indicators.append("🔐 Requests personal information")
    
    return indicators


# ============================================================================
# API ENDPOINT
# ============================================================================

@router.post("/text", response_model=TextAnalysisResponse)
async def analyze_text(request: TextAnalysisRequest) -> TextAnalysisResponse:
    """
    Analyze a text message (SMS, WhatsApp, Telegram) for smishing/scam indicators.
    
    Returns risk assessment, extracted IOCs, and recommendations.
    """
    text = request.text.strip()
    
    # Generate analysis ID
    analysis_id = hashlib.sha256(
        f"{text}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:16]
    
    logger.info(f"Analyzing text message: {analysis_id} ({len(text)} chars)")
    
    # Extract IOCs
    urls = extract_urls(text)
    phones = extract_phone_numbers(text)
    
    # Detect patterns
    patterns = detect_scam_patterns(text)
    
    # Calculate risk
    score = calculate_risk_score(text, urls, phones, patterns)
    level = get_risk_level(score)
    classification = classify_message(score, patterns)
    
    # Build response
    indicators = build_indicators(text, urls, phones, patterns, score)
    recommendations = generate_recommendations(classification, urls, patterns)
    
    # Determine if likely scam
    is_scam = classification != ScamCategory.LEGITIMATE and score >= 40
    confidence = min(0.95, score / 100 + 0.2) if is_scam else max(0.6, 1 - score / 100)
    
    return TextAnalysisResponse(
        analysis_id=analysis_id,
        analyzed_at=datetime.utcnow().isoformat(),
        source=request.source,
        overall_score=score,
        overall_level=level,
        classification=classification,
        is_likely_scam=is_scam,
        confidence=round(confidence, 2),
        urls_found=urls,
        phone_numbers_found=phones,
        scam_patterns_matched=patterns,
        indicators=indicators,
        recommendations=recommendations,
        message_length=len(text),
        has_url=len(urls) > 0,
        has_phone=len(phones) > 0,
    )
