"""
NiksES Analysis Data Models

Pydantic models for complete analysis results.
This is the main output schema.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from .email import ParsedEmail
from .enrichment import EnrichmentResults
from .detection import DetectionResults


class RecommendedAction(BaseModel):
    """Recommended remediation action."""
    action: str = Field(..., description="Short action name")
    priority: int = Field(..., ge=1, description="Priority (1 = highest)")
    description: str = Field(..., description="Detailed description")
    automated: bool = Field(False, description="Can be automated via SOAR")


class AITriageResult(BaseModel):
    """AI-generated triage output."""
    
    # Pydantic v2 config - allow model_ prefix
    model_config = {"protected_namespaces": ()}
    
    summary: str = Field(..., description="2-3 sentence incident summary")
    detailed_analysis: str = Field(..., description="Full analysis paragraph")
    classification_reasoning: str = Field(..., description="Why this classification")
    risk_reasoning: str = Field(..., description="Why this risk score")
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    
    # Key findings - critical evidence for analyst review
    key_findings: List[str] = Field(default_factory=list, description="Key evidence and indicators found")
    
    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    
    # Metadata
    model_used: str = Field(..., description="LLM model used")
    tokens_used: int = Field(..., description="Tokens consumed")
    analysis_timestamp: datetime = Field(..., description="When analysis was performed")


class HeaderAnalysisResult(BaseModel):
    """Comprehensive header analysis results."""
    originating_ip: Optional[str] = Field(None, description="Originating IP address")
    hop_count: int = Field(0, description="Number of mail server hops")
    total_delay_seconds: int = Field(0, description="Total delivery delay")
    
    # Authentication results
    spf_result: Optional[str] = Field(None, description="SPF result")
    dkim_result: Optional[str] = Field(None, description="DKIM result")
    dmarc_result: Optional[str] = Field(None, description="DMARC result")
    
    # Anomalies detected
    anomalies: List[str] = Field(default_factory=list, description="Header anomalies")
    
    # Security indicators
    has_arc: bool = Field(False, description="Has ARC headers")
    has_dkim_signature: bool = Field(False, description="Has DKIM signature")
    has_list_unsubscribe: bool = Field(False, description="Has List-Unsubscribe")
    suspicious_timing: bool = Field(False, description="Suspicious delivery timing")
    
    # GeoIP data for originating IP
    geoip: Optional[Dict[str, Any]] = Field(None, description="GeoIP data")


class ExtractedIOCs(BaseModel):
    """All IOCs extracted for export/blocking."""
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    file_hashes_md5: List[str] = Field(default_factory=list)
    file_hashes_sha256: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)


class SocialEngineeringAnalysis(BaseModel):
    """Social engineering analysis result for frontend display."""
    se_score: int = Field(0, description="Overall SE score 0-100")
    se_level: str = Field("low", description="SE risk level")
    confidence: float = Field(0.0, description="Analysis confidence")
    primary_intent: str = Field("unknown", description="Primary attack intent")
    secondary_intents: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list, description="Detected techniques")
    technique_scores: Dict[str, int] = Field(default_factory=dict, description="Scores per technique")
    heuristic_breakdown: Dict[str, int] = Field(default_factory=dict, description="Heuristic scores")
    explanation: str = Field("", description="Human readable explanation")
    key_indicators: List[str] = Field(default_factory=list)
    used_llm: bool = Field(False)
    llm_error: Optional[str] = None


class ContentAnalysis(BaseModel):
    """Content analysis result for frontend display."""
    intent: str = Field("unknown", description="Attack intent classification")
    intent_score: int = Field(0, description="Calculated intent risk score")
    confidence: float = Field(0.0)
    requested_actions: List[str] = Field(default_factory=list)
    target_data: List[str] = Field(default_factory=list)
    business_process_abused: str = Field("none")
    spoofed_brand: Optional[str] = None
    spoofed_entity_type: Optional[str] = None
    potential_impact: List[str] = Field(default_factory=list)
    mentioned_amounts: List[str] = Field(default_factory=list)
    mentioned_deadlines: List[str] = Field(default_factory=list)
    mentioned_organizations: List[str] = Field(default_factory=list)
    primary_intent: Optional[str] = None  # Alias for frontend
    target: Optional[str] = None  # First target_data item
    action_requested: Optional[str] = None  # First requested_action


class LookalikeMatch(BaseModel):
    """Single lookalike domain match."""
    domain: str = Field(..., description="Suspicious domain")
    target_brand: str = Field(..., description="Target brand being impersonated")
    brand: Optional[str] = None  # Alias for target_brand
    legitimate_domain: str = Field(..., description="Legitimate domain")
    confidence: float = Field(0.0)
    detection_methods: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    homoglyphs_found: List[str] = Field(default_factory=list)


class LookalikeAnalysis(BaseModel):
    """Lookalike domain analysis result."""
    is_lookalike: bool = Field(False)
    highest_confidence: float = Field(0.0)
    primary_target: Optional[str] = None
    matches: List[LookalikeMatch] = Field(default_factory=list)


class ThreatIntelSource(BaseModel):
    """Single TI source result."""
    source: str = Field(...)
    verdict: str = Field("clean")
    score: int = Field(0)
    details: Optional[str] = None


class ThreatIntelResults(BaseModel):
    """Threat intelligence fusion results."""
    fused_score: int = Field(0, description="Fused TI score 0-100")
    fused_verdict: str = Field("clean", description="Overall verdict")
    sources_checked: int = Field(0)
    sources_available: int = Field(0)
    sources_flagged: int = Field(0)
    confidence: float = Field(0.0)
    findings: List[str] = Field(default_factory=list)
    api_status: Dict[str, str] = Field(default_factory=dict)
    sources: Dict[str, ThreatIntelSource] = Field(default_factory=dict)


class RiskDimension(BaseModel):
    """Single risk dimension with score and indicators."""
    score: int = Field(0)
    level: str = Field("low")
    indicators: List[str] = Field(default_factory=list)


class MultiDimensionalRiskScore(BaseModel):
    """Multi-dimensional risk scoring result."""
    overall_score: int = Field(0)
    overall_level: str = Field("low")
    primary_classification: str = Field("unknown")
    dimensions: Dict[str, RiskDimension] = Field(default_factory=dict)
    top_indicators: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """
    Complete analysis output - THE MAIN OUTPUT SCHEMA.
    
    This is the primary response format for the /api/analyze endpoint.
    """
    # Identification
    analysis_id: str = Field(..., description="Unique analysis identifier")
    analyzed_at: datetime = Field(..., description="Analysis timestamp")
    analysis_duration_ms: int = Field(..., description="Analysis duration in milliseconds")
    
    # Parsed email
    email: ParsedEmail = Field(..., description="Parsed email data")
    
    # Enrichment
    enrichment: EnrichmentResults = Field(..., description="Threat intelligence enrichment")
    
    # Detection
    detection: DetectionResults = Field(..., description="Detection engine results")
    
    # AI Triage (optional - may be disabled or fail)
    ai_triage: Optional[AITriageResult] = Field(None, description="AI triage results")
    
    # Header Analysis (new)
    header_analysis: Optional[HeaderAnalysisResult] = Field(None, description="Detailed header analysis")
    
    # Enhanced Analysis Fields (for Advanced Insights)
    se_analysis: Optional[SocialEngineeringAnalysis] = Field(None, description="Social engineering analysis")
    content_analysis: Optional[ContentAnalysis] = Field(None, description="Content deconstruction analysis")
    lookalike_analysis: Optional[LookalikeAnalysis] = Field(None, description="Lookalike domain analysis")
    ti_results: Optional[ThreatIntelResults] = Field(None, description="Threat intelligence fusion results")
    risk_score: Optional[MultiDimensionalRiskScore] = Field(None, description="Multi-dimensional risk score")
    
    # Extracted IOCs for export
    iocs: ExtractedIOCs = Field(..., description="Extracted IOCs")
    
    # Metadata
    api_keys_used: List[str] = Field(default_factory=list, description="API services used")
    enrichment_errors: List[str] = Field(default_factory=list, description="Enrichment errors")


class AnalysisSummary(BaseModel):
    """Abbreviated analysis for list views."""
    analysis_id: str
    analyzed_at: datetime
    subject: Optional[str]
    sender_email: Optional[str]
    sender_domain: Optional[str]
    risk_score: int
    risk_level: str
    classification: str
    has_attachments: bool
    has_urls: bool
    attachment_count: int
    url_count: int
    ai_summary: Optional[str]


class AnalysisListResponse(BaseModel):
    """Response for list analyses endpoint."""
    total: int = Field(..., description="Total number of analyses")
    page: int = Field(..., description="Current page")
    page_size: int = Field(..., description="Items per page")
    analyses: List[AnalysisSummary] = Field(default_factory=list)
