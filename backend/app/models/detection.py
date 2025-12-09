"""
NiksES Detection Data Models

Pydantic models for detection engine results.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level classification."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EmailClassification(str, Enum):
    """Email threat classification."""
    BENIGN = "benign"
    SPAM = "spam"
    MARKETING = "marketing"
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BEC = "bec"
    INVOICE_FRAUD = "invoice_fraud"
    GIFT_CARD_SCAM = "gift_card_scam"
    CALLBACK_PHISHING = "callback_phishing"
    MALWARE_DELIVERY = "malware_delivery"
    RANSOMWARE = "ransomware"
    QR_PHISHING = "qr_phishing"
    BRAND_IMPERSONATION = "brand_impersonation"
    ACCOUNT_TAKEOVER = "account_takeover"
    UNKNOWN = "unknown"


class DetectionRule(BaseModel):
    """Individual detection rule result."""
    rule_id: str = Field(..., description="Unique rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    category: str = Field(..., description="Rule category")
    description: str = Field(..., description="Rule description")
    severity: RiskLevel = Field(..., description="Rule severity")
    score_impact: int = Field(..., description="Points added to risk score")
    triggered: bool = Field(..., description="Whether rule was triggered")
    evidence: List[str] = Field(default_factory=list, description="Evidence items")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique ID")


class DetectionResults(BaseModel):
    """Aggregated detection results."""
    rules_triggered: List[DetectionRule] = Field(default_factory=list)
    rules_passed: List[DetectionRule] = Field(default_factory=list)
    
    # Scoring
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    risk_level: RiskLevel = Field(..., description="Risk level classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence 0-1")
    
    # Classification
    primary_classification: EmailClassification = Field(..., description="Primary threat classification")
    secondary_classifications: List[EmailClassification] = Field(default_factory=list)
    
    # Social engineering indicators
    urgency_score: int = Field(0, ge=0, le=10, description="Urgency indicator score")
    authority_score: int = Field(0, ge=0, le=10, description="Authority indicator score")
    fear_score: int = Field(0, ge=0, le=10, description="Fear indicator score")
    reward_score: int = Field(0, ge=0, le=10, description="Reward indicator score")
    
    # Brand impersonation
    impersonated_brand: Optional[str] = Field(None, description="Detected brand impersonation")
    brand_confidence: Optional[float] = Field(None, description="Brand detection confidence")
