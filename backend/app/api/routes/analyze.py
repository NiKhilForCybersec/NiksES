"""
NiksES Unified Analyze API

Single comprehensive analysis endpoint combining:
- 61 detection rules (including spam/romance scam detection)
- Social Engineering analysis (AI-powered)
- Content deconstruction (AI-powered)
- Lookalike domain detection
- Threat Intelligence fusion (VirusTotal, AbuseIPDB, URLhaus)
- GeoIP enrichment for IP geolocation
- Multi-dimensional risk scoring
- Detailed AI-generated descriptions
"""

import logging
import time
import re
from datetime import datetime
from typing import Optional, Dict, Any, List, Set
from uuid import uuid4

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse

from app.models.email import ParsedEmail, EmailAddress
from app.models.enrichment import EnrichmentResults, ThreatIntelVerdict, IPEnrichment
from app.models.detection import DetectionResults, RiskLevel, EmailClassification, DetectionRule
from app.models.analysis import (
    AnalysisResult, AITriageResult, ExtractedIOCs, RecommendedAction, HeaderAnalysisResult,
    SocialEngineeringAnalysis, ContentAnalysis, LookalikeAnalysis, LookalikeMatch,
    ThreatIntelResults, ThreatIntelSource, MultiDimensionalRiskScore, RiskDimension
)
from app.api.dependencies import get_settings, get_analysis_store
from app.services.enrichment.geoip import GeoIPProvider, get_geoip_provider

# Sandbox integration (optional - gracefully handles if not configured)
try:
    from app.services.sandbox import get_sandbox_service
    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False
    def get_sandbox_service():
        return None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("")
async def analyze_email(
    file: UploadFile = File(..., description="Email file (.eml or .msg)"),
    background_tasks: BackgroundTasks = None,
    settings = Depends(get_settings),
    analysis_store = Depends(get_analysis_store),
):
    """
    Comprehensive email security analysis.
    
    Returns complete AnalysisResult compatible with exports.
    """
    start_time = time.time()
    analysis_id = str(uuid4())
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    filename = file.filename.lower()
    if not filename.endswith(('.eml', '.msg')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .eml and .msg files are supported.")
    
    # Read file content
    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read file: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")
    
    if len(content) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 50MB.")
    
    # Parse email
    try:
        parsed_email = await parse_email_file(content, file.filename)
    except Exception as e:
        logger.error(f"Failed to parse email: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to parse email: {str(e)}")
    
    # Run unified analysis and build AnalysisResult
    try:
        analysis_result = await run_unified_analysis(
            email=parsed_email,
            settings=settings,
            analysis_id=analysis_id,
            start_time=start_time,
        )
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    
    # Run sandbox analysis on attachments (non-blocking)
    sandbox_analysis = None
    logger.info(f"Sandbox check: SANDBOX_AVAILABLE={SANDBOX_AVAILABLE}, attachments={len(parsed_email.attachments) if parsed_email.attachments else 0}")
    
    if SANDBOX_AVAILABLE and parsed_email.attachments:
        try:
            sandbox_service = get_sandbox_service()
            logger.info(f"Sandbox service: exists={sandbox_service is not None}, enabled={sandbox_service.is_enabled if sandbox_service else 'N/A'}")
            
            if sandbox_service and sandbox_service.is_enabled:
                # Re-extract attachment content from original email for sandbox
                # (AttachmentInfo model only stores metadata, not content)
                attachment_payloads = await _extract_attachment_payloads(content)
                
                if attachment_payloads:
                    sandbox_analysis = await sandbox_service.analyze_attachments(
                        attachment_payloads,
                        wait_for_results=False  # Don't wait - results appear async
                    )
                    logger.info(f"Sandbox analysis initiated for {len(attachment_payloads)} attachments")
                else:
                    logger.warning("Sandbox: No attachment payloads extracted")
                    sandbox_analysis = {
                        "analyzed": False,
                        "reason": "no_content",
                        "results": [],
                        "summary": {"total": len(parsed_email.attachments), "analyzed": 0, "malicious": 0, "suspicious": 0, "clean": 0, "skipped": len(parsed_email.attachments)}
                    }
            else:
                logger.info(f"Sandbox skipped: service_exists={sandbox_service is not None}, is_enabled={sandbox_service.is_enabled if sandbox_service else False}")
        except Exception as e:
            logger.error(f"Sandbox analysis error: {e}")
            sandbox_analysis = {
                "analyzed": False,
                "reason": "error",
                "error": str(e),
                "results": [],
                "summary": {"total": len(parsed_email.attachments), "analyzed": 0, "malicious": 0, "suspicious": 0, "clean": 0, "skipped": len(parsed_email.attachments)}
            }
    
    # Store in memory cache FIRST (for immediate export access)
    from app.api.dependencies import cache_analysis
    cache_analysis(analysis_id, analysis_result)
    
    # Store to database SYNCHRONOUSLY (ensures export works immediately)
    if analysis_store:
        try:
            await analysis_store.save(analysis_result)
            logger.info(f"Analysis {analysis_id} stored to database")
        except Exception as e:
            logger.error(f"Failed to store analysis {analysis_id}: {e}")
            # Continue even if storage fails - we have the in-memory cache
    else:
        logger.warning(f"Analysis {analysis_id} - no database store available, using cache only")
    
    duration_ms = int((time.time() - start_time) * 1000)
    logger.info(f"Analysis {analysis_id} completed in {duration_ms}ms")
    
    # Build response and add sandbox analysis
    response = build_response_dict(analysis_result)
    
    # Add sandbox analysis to response
    if sandbox_analysis:
        response['sandbox_analysis'] = sandbox_analysis
    else:
        # Provide empty sandbox structure for frontend consistency
        attachment_count = len(parsed_email.attachments) if parsed_email.attachments else 0
        response['sandbox_analysis'] = {
            "analyzed": False,
            "reason": "no_attachments" if attachment_count == 0 else "sandbox_not_configured",
            "results": [],
            "summary": {
                "total": attachment_count,
                "analyzed": 0,
                "malicious": 0,
                "suspicious": 0,
                "clean": 0,
                "skipped": attachment_count
            }
        }
    
    return response


async def parse_email_file(content: bytes, filename: str) -> ParsedEmail:
    """Parse email file content."""
    from app.services.parser import parse_eml_bytes, parse_msg_bytes
    
    if filename.lower().endswith('.msg'):
        return await parse_msg_bytes(content)
    else:
        return await parse_eml_bytes(content)


async def _extract_attachment_payloads(email_content: bytes) -> List[Dict[str, Any]]:
    """
    Extract attachment payloads (actual file content) from raw email.
    
    Returns list of dicts with:
    - filename: str
    - content: bytes (raw file content)
    - content_type: str
    - size: int
    """
    import email
    from email import policy
    from email.message import EmailMessage
    import base64
    
    attachments = []
    
    try:
        msg = email.message_from_bytes(email_content, policy=policy.default)
        
        for part in msg.walk():
            content_disposition = str(part.get('Content-Disposition', ''))
            
            # Check if this is an attachment
            if 'attachment' in content_disposition or part.get_filename():
                filename = part.get_filename()
                if not filename:
                    continue
                
                # Get the payload
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        content_type = part.get_content_type() or 'application/octet-stream'
                        attachments.append({
                            'filename': filename,
                            'content': payload,  # This is bytes
                            'content_type': content_type,
                            'size': len(payload)
                        })
                        logger.debug(f"Extracted attachment: {filename} ({len(payload)} bytes)")
                except Exception as e:
                    logger.warning(f"Failed to extract payload for {filename}: {e}")
                    continue
    except Exception as e:
        logger.error(f"Failed to extract attachment payloads: {e}")
    
    return attachments


async def run_unified_analysis(
    email: ParsedEmail,
    settings,
    analysis_id: str,
    start_time: float,
) -> AnalysisResult:
    """
    Run complete unified analysis and return AnalysisResult model.
    """
    from app.services.detection import DetectionEngine, RiskScorer
    from app.services.detection.multi_scorer import MultiDimensionalScorer
    from app.services.detection.lookalike import LookalikeDetector
    from app.services.ai.se_analyzer import SocialEngineeringAnalyzer
    from app.services.ai.content_analyzer import ContentAnalyzer
    from app.services.enrichment.ti_fusion import ThreatIntelFusion
    from app.services.enrichment.virustotal import VirusTotalProvider
    from app.services.enrichment.abuseipdb import AbuseIPDBProvider
    from app.services.enrichment.urlhaus import URLhausProvider
    from app.services.analysis.orchestrator import AnalysisOrchestrator
    from app.services.parser.header_analyzer import analyze_headers
    from app.services.ai.description_generator import generate_ai_description, generate_fallback_description
    
    apis_configured = []
    apis_errors = []
    geoip_data = {}
    header_analysis = {}
    
    # 1. Initialize Detection Engine (always runs)
    detection_engine = DetectionEngine()
    logger.info(f"Detection engine ready with {len(detection_engine.rules)} rules")
    
    # 2. Run Header Analysis
    try:
        if email.raw_headers:
            header_analysis = analyze_headers(email.raw_headers)
            logger.info(f"Header analysis complete: {len(header_analysis.get('anomalies', []))} anomalies found")
    except Exception as e:
        logger.warning(f"Header analysis failed: {e}")
        apis_errors.append(f"Header analysis: {str(e)}")
    
    # 3. GeoIP lookup for originating IP
    originating_ip = header_analysis.get("originating_ip")
    if originating_ip:
        try:
            geoip_provider = get_geoip_provider()
            geoip_data = await geoip_provider.lookup_ip(originating_ip)
            if geoip_data:
                apis_configured.append("geoip")
                logger.info(f"GeoIP: {originating_ip} -> {geoip_data.get('country', 'Unknown')}")
        except Exception as e:
            logger.warning(f"GeoIP lookup failed: {e}")
            apis_errors.append(f"GeoIP: {str(e)}")
    
    # 4. Initialize AI analyzers (if OpenAI key available)
    openai_client = None
    se_analyzer = None
    content_analyzer = None
    
    openai_key = getattr(settings, 'openai_api_key', None)
    if openai_key:
        try:
            import openai
            openai_client = openai.AsyncOpenAI(api_key=openai_key)
            se_analyzer = SocialEngineeringAnalyzer(openai_client)
            content_analyzer = ContentAnalyzer(openai_client)
            apis_configured.append("openai")
            logger.info("OpenAI client initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize OpenAI: {e}")
            apis_errors.append(f"OpenAI: {str(e)}")
    
    # 5. Initialize TI providers individually
    vt_provider = None
    abuseipdb_provider = None
    urlhaus_provider = None
    
    vt_key = getattr(settings, 'virustotal_api_key', None)
    if vt_key:
        vt_provider = VirusTotalProvider(vt_key)
        apis_configured.append("virustotal")
        logger.info("VirusTotal provider configured")
    
    abuseipdb_key = getattr(settings, 'abuseipdb_api_key', None)
    if abuseipdb_key:
        abuseipdb_provider = AbuseIPDBProvider(abuseipdb_key)
        apis_configured.append("abuseipdb")
        logger.info("AbuseIPDB provider configured")
    
    # URLhaus is free
    urlhaus_provider = URLhausProvider()
    apis_configured.append("urlhaus")
    logger.info("URLhaus provider configured (free)")
    
    # 6. Initialize TI Fusion with individual providers
    ti_fusion = ThreatIntelFusion(
        virustotal_provider=vt_provider,
        abuseipdb_provider=abuseipdb_provider,
        urlhaus_provider=urlhaus_provider,
    )
    
    # 7. Initialize Lookalike detector
    lookalike_detector = LookalikeDetector()
    
    # 8. Initialize orchestrator
    orchestrator = AnalysisOrchestrator(
        detection_engine=detection_engine,
        se_analyzer=se_analyzer,
        content_analyzer=content_analyzer,
        lookalike_detector=lookalike_detector,
        ti_fusion=ti_fusion,
        openai_client=openai_client,
    )
    
    # 9. Run analysis
    options = {
        "use_llm": bool(openai_client),
        "run_ti": bool(ti_fusion),
        "run_detection": True,
        "timeout": 120.0,
    }
    
    logger.info(f"Starting unified analysis: LLM={options['use_llm']}, TI={options['run_ti']}, Detection=True")
    
    result = await orchestrator.analyze_email(email, options)
    
    logger.info(f"Analysis complete: score={result.overall_score}, level={result.overall_level}")
    
    # 10. Generate AI description
    ai_description = None
    if openai_client:
        try:
            # Build analysis dict for description generator
            analysis_dict = {
                "overall_score": result.overall_score,
                "overall_level": result.overall_level,
                "classification": result.classification,
                "detection_results": result.detection_results,
                "se_analysis": result.se_analysis,
                "ti_results": result.ti_results,
                "geoip": geoip_data,
                "header_analysis": header_analysis,
            }
            email_dict = {
                "sender": email.sender.model_dump() if email.sender else {},
                "subject": email.subject,
                "body_text": (email.body_text or "")[:500],  # Limit body size
            }
            ai_description = await generate_ai_description(openai_client, email_dict, analysis_dict)
            if ai_description:
                logger.info("AI description generated successfully")
        except Exception as e:
            logger.warning(f"Failed to generate AI description: {e}")
    
    # Fallback description if AI not available
    if not ai_description:
        analysis_dict = {
            "overall_score": result.overall_score,
            "overall_level": result.overall_level,
            "classification": result.classification,
            "detection_results": result.detection_results,
        }
        ai_description = generate_fallback_description({}, analysis_dict)
    
    # 11. Build proper AnalysisResult model
    duration_ms = int((time.time() - start_time) * 1000)
    
    analysis_result = build_analysis_result(
        analysis_id=analysis_id,
        email=email,
        orchestrator_result=result,
        duration_ms=duration_ms,
        apis_configured=apis_configured,
        apis_errors=apis_errors,
        geoip_data=geoip_data,
        header_analysis=header_analysis,
        ai_description=ai_description,
    )
    
    return analysis_result


def build_analysis_result(
    analysis_id: str,
    email: ParsedEmail,
    orchestrator_result,
    duration_ms: int,
    apis_configured: List[str],
    apis_errors: List[str],
    geoip_data: Optional[Dict[str, Any]] = None,
    header_analysis: Optional[Dict[str, Any]] = None,
    ai_description: Optional[str] = None,
) -> AnalysisResult:
    """Build proper AnalysisResult model from orchestrator result."""
    
    # Build DetectionResults
    detection = build_detection_results(orchestrator_result)
    
    # Build EnrichmentResults with GeoIP
    enrichment = build_enrichment_results(orchestrator_result, geoip_data)
    
    # Build AITriageResult with description
    ai_triage = build_ai_triage_result(orchestrator_result, ai_description, header_analysis)
    
    # Build HeaderAnalysisResult
    header_result = build_header_analysis_result(header_analysis, geoip_data)
    
    # Build ExtractedIOCs
    iocs = extract_iocs(email)
    
    # Build Enhanced Analysis Fields
    se_analysis_model = build_se_analysis(orchestrator_result)
    content_analysis_model = build_content_analysis(orchestrator_result)
    lookalike_analysis_model = build_lookalike_analysis(orchestrator_result)
    ti_results_model = build_ti_results(orchestrator_result)
    risk_score_model = build_risk_score(orchestrator_result)
    
    return AnalysisResult(
        analysis_id=analysis_id,
        analyzed_at=datetime.utcnow(),
        analysis_duration_ms=duration_ms,
        email=email,
        enrichment=enrichment,
        detection=detection,
        ai_triage=ai_triage,
        header_analysis=header_result,
        se_analysis=se_analysis_model,
        content_analysis=content_analysis_model,
        lookalike_analysis=lookalike_analysis_model,
        ti_results=ti_results_model,
        risk_score=risk_score_model,
        iocs=iocs,
        api_keys_used=apis_configured,
        enrichment_errors=apis_errors,
    )


def build_se_analysis(orchestrator_result) -> Optional[SocialEngineeringAnalysis]:
    """Build SocialEngineeringAnalysis from orchestrator result."""
    se = orchestrator_result.se_analysis
    if not se:
        return None
    
    # Convert to dict if needed
    se_dict = se.to_dict() if hasattr(se, 'to_dict') else (se.model_dump() if hasattr(se, 'model_dump') else se)
    
    if not isinstance(se_dict, dict):
        return None
    
    return SocialEngineeringAnalysis(
        se_score=se_dict.get('se_score', 0),
        se_level=se_dict.get('se_level', 'low'),
        confidence=se_dict.get('confidence', 0.0),
        primary_intent=se_dict.get('primary_intent', 'unknown'),
        secondary_intents=se_dict.get('secondary_intents', []),
        techniques=se_dict.get('techniques', []),
        technique_scores=se_dict.get('technique_scores', {}),
        heuristic_breakdown=se_dict.get('heuristic_breakdown', {}),
        explanation=se_dict.get('explanation', ''),
        key_indicators=se_dict.get('key_indicators', []),
        used_llm=se_dict.get('used_llm', False),
        llm_error=se_dict.get('llm_error'),
    )


def build_content_analysis(orchestrator_result) -> Optional[ContentAnalysis]:
    """Build ContentAnalysis from orchestrator result."""
    ca = orchestrator_result.content_analysis
    if not ca:
        return None
    
    # Convert to dict if needed
    ca_dict = ca.to_dict() if hasattr(ca, 'to_dict') else (ca.model_dump() if hasattr(ca, 'model_dump') else ca)
    
    if not isinstance(ca_dict, dict):
        return None
    
    # Calculate intent_score based on confidence and intent severity
    intent = ca_dict.get('intent', 'unknown')
    confidence = ca_dict.get('confidence', 0.5)
    
    intent_severity = {
        'credential_harvest': 90,
        'payment_fraud': 85,
        'malware_delivery': 85,
        'account_takeover': 80,
        'bec': 80,
        'invoice_fraud': 75,
        'gift_card_scam': 70,
        'callback_phishing': 65,
        'data_theft': 75,
        'reconnaissance': 50,
        'spam': 30,
        'marketing': 10,
        'legitimate': 5,
        'unknown': 25,
    }
    
    base_score = intent_severity.get(intent, 25)
    intent_score = int(base_score * confidence)
    
    requested_actions = ca_dict.get('requested_actions', [])
    target_data = ca_dict.get('target_data', [])
    
    return ContentAnalysis(
        intent=intent,
        intent_score=intent_score,
        confidence=confidence,
        requested_actions=requested_actions,
        target_data=target_data,
        business_process_abused=ca_dict.get('business_process_abused', 'none'),
        spoofed_brand=ca_dict.get('spoofed_brand'),
        spoofed_entity_type=ca_dict.get('spoofed_entity_type'),
        potential_impact=ca_dict.get('potential_impact', []),
        mentioned_amounts=ca_dict.get('mentioned_amounts', []),
        mentioned_deadlines=ca_dict.get('mentioned_deadlines', []),
        mentioned_organizations=ca_dict.get('mentioned_organizations', []),
        primary_intent=intent,  # Alias
        target=target_data[0] if target_data else None,  # First item
        action_requested=requested_actions[0] if requested_actions else None,  # First item
    )


def build_lookalike_analysis(orchestrator_result) -> Optional[LookalikeAnalysis]:
    """Build LookalikeAnalysis from orchestrator result."""
    la = orchestrator_result.lookalike_analysis
    if not la:
        return None
    
    # Convert to dict if needed
    la_dict = la.to_dict() if hasattr(la, 'to_dict') else (la.model_dump() if hasattr(la, 'model_dump') else la)
    
    if not isinstance(la_dict, dict):
        return None
    
    matches = []
    for match in la_dict.get('matches', []):
        if isinstance(match, dict):
            matches.append(LookalikeMatch(
                domain=match.get('domain', ''),
                target_brand=match.get('target_brand', match.get('target', '')),
                brand=match.get('target_brand', match.get('target', '')),  # Alias
                legitimate_domain=match.get('legitimate_domain', ''),
                confidence=match.get('confidence', 0.0),
                detection_methods=match.get('detection_methods', []),
                description=match.get('description'),
                homoglyphs_found=match.get('homoglyphs_found', []),
            ))
    
    return LookalikeAnalysis(
        is_lookalike=la_dict.get('is_lookalike', False),
        highest_confidence=la_dict.get('highest_confidence', 0.0),
        primary_target=la_dict.get('primary_target'),
        matches=matches,
    )


def build_ti_results(orchestrator_result) -> Optional[ThreatIntelResults]:
    """Build ThreatIntelResults from orchestrator result."""
    ti = orchestrator_result.ti_results
    if not ti:
        return None
    
    # Convert to dict if needed
    ti_dict = ti.to_dict() if hasattr(ti, 'to_dict') else (ti.model_dump() if hasattr(ti, 'model_dump') else ti)
    
    if not isinstance(ti_dict, dict):
        return None
    
    sources = {}
    for source_name, source_data in ti_dict.get('sources', {}).items():
        if isinstance(source_data, dict):
            sources[source_name] = ThreatIntelSource(
                source=source_name,
                verdict=source_data.get('verdict', 'clean'),
                score=source_data.get('score', 0),
                details=source_data.get('details'),
            )
    
    return ThreatIntelResults(
        fused_score=ti_dict.get('fused_score', 0),
        fused_verdict=ti_dict.get('fused_verdict', 'clean'),
        sources_checked=ti_dict.get('sources_checked', 0),
        sources_available=ti_dict.get('sources_available', 0),
        sources_flagged=ti_dict.get('sources_flagged', 0),
        confidence=ti_dict.get('confidence', 0.0),
        findings=ti_dict.get('findings', []),
        api_status=ti_dict.get('api_status', {}),
        sources=sources,
    )


def build_risk_score(orchestrator_result) -> Optional[MultiDimensionalRiskScore]:
    """Build MultiDimensionalRiskScore from orchestrator result."""
    rs = orchestrator_result.risk_score
    if not rs:
        return None
    
    # Convert to dict if needed
    rs_dict = rs.to_dict() if hasattr(rs, 'to_dict') else (rs.model_dump() if hasattr(rs, 'model_dump') else rs)
    
    if not isinstance(rs_dict, dict):
        return None
    
    # Build dimensions with all fields
    dimensions = {}
    for dim_name, dim_data in rs_dict.get('dimensions', {}).items():
        if isinstance(dim_data, dict):
            dimensions[dim_name] = RiskDimension(
                score=dim_data.get('score', 0),
                level=dim_data.get('level', 'low'),
                weight=dim_data.get('weight', 0.0),
                indicators=dim_data.get('indicators', []),
                details=dim_data.get('details', {}),
            )
    
    # Get primary classification
    primary_class = rs_dict.get('primary_classification', 'unknown')
    if hasattr(primary_class, 'value'):
        primary_class = primary_class.value
    
    # Get secondary classifications
    secondary = rs_dict.get('secondary_classifications', [])
    secondary_list = [c.value if hasattr(c, 'value') else str(c) for c in secondary]
    
    return MultiDimensionalRiskScore(
        overall_score=rs_dict.get('overall_score', 0),
        overall_level=rs_dict.get('overall_level', 'low'),
        confidence=rs_dict.get('confidence', 0.0),
        primary_classification=str(primary_class),
        secondary_classifications=secondary_list,
        dimensions=dimensions,
        top_indicators=rs_dict.get('top_indicators', []),
        summary=rs_dict.get('summary', ''),
        detailed_explanation=rs_dict.get('detailed_explanation', ''),
        recommended_actions=rs_dict.get('recommended_actions', []),
        mitre_techniques=rs_dict.get('mitre_techniques', []),
        rules_triggered=rs_dict.get('rules_triggered', 0),
        data_sources_available=rs_dict.get('data_sources_available', 0),
    )


def build_detection_results(result) -> DetectionResults:
    """Build DetectionResults from orchestrator result."""
    
    # Get detection_results from orchestrator
    det = result.detection_results
    
    # Determine risk level
    level_str = result.overall_level or "low"
    if isinstance(level_str, str):
        level_str = level_str.lower()
    
    # Determine classification
    class_str = result.classification or "unknown"
    if isinstance(class_str, str):
        class_str = class_str.lower()
    
    if det is None:
        # Return default
        return DetectionResults(
            rules_triggered=[],
            rules_passed=[],
            risk_score=result.overall_score or 0,
            risk_level=RiskLevel(level_str),
            confidence=0.5,
            primary_classification=EmailClassification(class_str),
        )
    
    # If det is already a DetectionResults model, update it with unified score
    if isinstance(det, DetectionResults):
        # CRITICAL: Override the detection engine's raw score with the orchestrator's unified score
        det.risk_score = result.overall_score or det.risk_score
        det.risk_level = RiskLevel(level_str)
        return det
    
    # If det is a Pydantic model with model_dump
    if hasattr(det, 'model_dump'):
        det = det.model_dump()
    
    # If det is a dict, convert
    if isinstance(det, dict):
        rules_triggered = []
        for r in det.get('rules_triggered', []):
            if isinstance(r, dict):
                try:
                    rules_triggered.append(DetectionRule(**r))
                except Exception as e:
                    logger.warning(f"Failed to parse rule: {e}")
            elif isinstance(r, DetectionRule):
                rules_triggered.append(r)
            elif hasattr(r, 'model_dump'):
                try:
                    rules_triggered.append(DetectionRule(**r.model_dump()))
                except:
                    pass
        
        # Get risk level
        risk_level_val = det.get('risk_level', level_str)
        if hasattr(risk_level_val, 'value'):
            risk_level_val = risk_level_val.value
        if isinstance(risk_level_val, str):
            risk_level_val = risk_level_val.lower()
        
        # Get classification
        class_val = det.get('primary_classification', class_str)
        if hasattr(class_val, 'value'):
            class_val = class_val.value
        if isinstance(class_val, str):
            class_val = class_val.lower()
        
        return DetectionResults(
            rules_triggered=rules_triggered,
            rules_passed=[],
            # CRITICAL: Use orchestrator's unified score, not detection engine's raw score
            # The unified score applies multi-dimensional analysis and false positive suppression
            risk_score=result.overall_score or det.get('risk_score', 0),
            risk_level=RiskLevel(risk_level_val),
            confidence=det.get('confidence', 0.5),
            primary_classification=EmailClassification(class_val),
            secondary_classifications=[],
            urgency_score=det.get('urgency_score', 0),
            authority_score=det.get('authority_score', 0),
            fear_score=det.get('fear_score', 0),
            reward_score=det.get('reward_score', 0),
        )
    
    # Fallback
    return DetectionResults(
        rules_triggered=[],
        rules_passed=[],
        risk_score=result.overall_score or 0,
        risk_level=RiskLevel(level_str),
        confidence=0.5,
        primary_classification=EmailClassification(class_str),
    )


def build_enrichment_results(result, geoip_data: Optional[Dict[str, Any]] = None) -> EnrichmentResults:
    """Build EnrichmentResults from TI results and GeoIP data."""
    # Start with empty enrichment
    enrichment = EnrichmentResults()
    
    # Add GeoIP data to originating IP
    if geoip_data:
        enrichment.originating_ip = IPEnrichment(
            ip_address=geoip_data.get('ip', ''),
            country=geoip_data.get('country'),
            country_code=geoip_data.get('country_code'),
            city=geoip_data.get('city'),
            region=geoip_data.get('region'),
            asn=geoip_data.get('asn'),
            as_org=geoip_data.get('as_org'),
            isp=geoip_data.get('isp'),
            is_proxy=geoip_data.get('is_proxy', False),
            is_datacenter=geoip_data.get('is_datacenter', False),
        )
    
    # If we have TI results from orchestrator, populate from there
    ti_results = result.ti_results if hasattr(result, 'ti_results') else None
    if ti_results:
        # Could populate URL/domain enrichments from TI
        pass
    
    return enrichment


def build_header_analysis_result(
    header_analysis: Optional[Dict[str, Any]],
    geoip_data: Optional[Dict[str, Any]],
) -> Optional[HeaderAnalysisResult]:
    """Build HeaderAnalysisResult from header analysis and GeoIP data."""
    
    if not header_analysis:
        return None
    
    # Extract authentication results
    auth = header_analysis.get("auth_results", {})
    
    spf_result = None
    dkim_result = None
    dmarc_result = None
    
    if auth.get("spf"):
        spf_result = auth["spf"].result if hasattr(auth["spf"], 'result') else str(auth["spf"])
    if auth.get("dkim"):
        dkim_result = auth["dkim"].result if hasattr(auth["dkim"], 'result') else str(auth["dkim"])
    if auth.get("dmarc"):
        dmarc_result = auth["dmarc"].result if hasattr(auth["dmarc"], 'result') else str(auth["dmarc"])
    
    # Extract timing analysis
    timing = header_analysis.get("timing_analysis", {})
    
    # Extract security headers
    security = header_analysis.get("security_headers", {})
    
    return HeaderAnalysisResult(
        originating_ip=header_analysis.get("originating_ip"),
        hop_count=timing.get("total_hops", 0),
        total_delay_seconds=int(timing.get("total_delay_seconds", 0)),
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        anomalies=header_analysis.get("anomalies", []),
        has_arc=security.get("has_arc", False),
        has_dkim_signature=security.get("has_dkim_signature", False),
        has_list_unsubscribe=security.get("has_list_unsubscribe", False),
        suspicious_timing=timing.get("suspicious_timing", False),
        geoip=geoip_data,
    )


def build_ai_triage_result(
    result,
    ai_description: Optional[str] = None,
    header_analysis: Optional[Dict[str, Any]] = None,
) -> Optional[AITriageResult]:
    """Build AITriageResult from SE and content analysis with AI description."""
    
    se = result.se_analysis
    content = result.content_analysis
    
    # Even if no SE/content, we might have AI description
    if not se and not content and not ai_description:
        return None
    
    summary_parts = []
    key_findings = []
    recommendations = []
    
    # From SE analysis
    if se:
        se_dict = se.to_dict() if hasattr(se, 'to_dict') else {}
        level = se_dict.get('se_level', 'unknown')
        score = se_dict.get('se_score', 0)
        
        summary_parts.append(f"Social engineering risk: {str(level).upper()} ({score}/100)")
        
        techniques = se_dict.get('techniques', [])
        if techniques:
            key_findings.append(f"SE techniques detected: {', '.join(str(t) for t in techniques[:3])}")
        
        indicators = se_dict.get('key_indicators', [])
        key_findings.extend([str(i) for i in indicators[:3]])
    
    # From content analysis
    if content:
        content_dict = content.to_dict() if hasattr(content, 'to_dict') else {}
        intent = content_dict.get('intent', '')
        
        if intent:
            summary_parts.append(f"Intent: {str(intent).replace('_', ' ')}")
        
        actions = content_dict.get('requested_actions', [])
        if actions:
            key_findings.append(f"Requested actions: {', '.join(str(a) for a in actions[:2])}")
    
    # From header analysis
    if header_analysis:
        anomalies = header_analysis.get('anomalies', [])
        if anomalies:
            key_findings.append(f"Header anomalies: {', '.join(str(a) for a in anomalies[:3])}")
        
        timing = header_analysis.get('timing_analysis', {})
        if timing.get('suspicious_timing'):
            key_findings.append(f"Suspicious delivery timing detected ({timing.get('total_hops', 0)} hops)")
        
        security = header_analysis.get('security_headers', {})
        if security.get('x_spam_status'):
            key_findings.append(f"Spam status: {security.get('x_spam_status')}")
    
    # Build recommendations based on risk
    score = result.overall_score or 0
    recommended_actions = []
    
    if score >= 70:
        recommended_actions = [
            RecommendedAction(action="quarantine", priority=1, description="Quarantine immediately", automated=True),
            RecommendedAction(action="block_sender", priority=2, description="Block sender domain", automated=True),
            RecommendedAction(action="alert", priority=3, description="Alert security team", automated=False),
        ]
        recommendations = ["Quarantine immediately", "Block sender", "Investigate sender domain"]
    elif score >= 40:
        recommended_actions = [
            RecommendedAction(action="review", priority=1, description="Manual review recommended", automated=False),
            RecommendedAction(action="warn_user", priority=2, description="Warn user before interaction", automated=True),
        ]
        recommendations = ["Review manually", "Warn user", "Monitor for similar emails"]
    else:
        recommended_actions = [
            RecommendedAction(action="monitor", priority=1, description="Continue monitoring", automated=False),
        ]
        recommendations = ["Low risk - continue monitoring"]
    
    # Use AI description if available, otherwise build from findings
    detailed_analysis = ai_description if ai_description else "\n".join(key_findings) if key_findings else "No significant findings"
    
    return AITriageResult(
        summary=" | ".join(summary_parts) if summary_parts else "Analysis complete",
        detailed_analysis=detailed_analysis,
        classification_reasoning=f"Based on {result.overall_score or 0}/100 risk score",
        risk_reasoning=f"Risk level: {result.overall_level or 'low'}",
        key_findings=key_findings,  # Include key findings!
        recommended_actions=recommended_actions,
        mitre_tactics=[],
        mitre_techniques=[],
        model_used="openai" if (result.se_analysis or ai_description) else "rules-only",
        tokens_used=0,
        analysis_timestamp=datetime.utcnow(),
    )


def extract_iocs(email: ParsedEmail) -> ExtractedIOCs:
    """Extract IOCs from parsed email."""
    domains: Set[str] = set()
    urls: Set[str] = set()
    ips: Set[str] = set()
    email_addresses: Set[str] = set()
    hashes_md5: Set[str] = set()
    hashes_sha256: Set[str] = set()
    
    # Extract sender domain
    if email.sender and email.sender.domain:
        domains.add(email.sender.domain)
    if email.sender and email.sender.email:
        email_addresses.add(email.sender.email)
    
    # Extract from recipients
    for r in (email.to_recipients or []):
        if r.domain:
            domains.add(r.domain)
        if r.email:
            email_addresses.add(r.email)
    
    # Extract from URLs
    for url_obj in (email.urls or []):
        if hasattr(url_obj, 'url') and url_obj.url:
            urls.add(url_obj.url)
        if hasattr(url_obj, 'domain') and url_obj.domain:
            domains.add(url_obj.domain)
    
    # Extract from received chain
    for hop in (email.received_chain or []):
        if hasattr(hop, 'from_ip') and hop.from_ip:
            ips.add(hop.from_ip)
    
    # Extract from attachments
    for att in (email.attachments or []):
        if hasattr(att, 'md5') and att.md5:
            hashes_md5.add(att.md5)
        if hasattr(att, 'sha256') and att.sha256:
            hashes_sha256.add(att.sha256)
    
    return ExtractedIOCs(
        domains=sorted(list(domains)),
        urls=sorted(list(urls)),
        ips=sorted(list(ips)),
        email_addresses=sorted(list(email_addresses)),
        file_hashes_md5=sorted(list(hashes_md5)),
        file_hashes_sha256=sorted(list(hashes_sha256)),
        phone_numbers=[],
    )


def build_response_dict(analysis: AnalysisResult) -> Dict[str, Any]:
    """Build response dict from AnalysisResult for frontend."""
    
    # Get base model dump
    response = analysis.model_dump()
    
    # Convert datetime objects
    def convert_datetimes(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: convert_datetimes(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_datetimes(item) for item in obj]
        return obj
    
    response = convert_datetimes(response)
    
    # Add top-level fields frontend expects
    # CRITICAL: Use the multi-dimensional risk_score (unified score), NOT detection.risk_score (raw detection engine score)
    # The risk_score applies multi-dimensional analysis, weighted averaging, and false positive suppression
    if analysis.risk_score:
        response['overall_score'] = analysis.risk_score.overall_score
        response['overall_level'] = analysis.risk_score.overall_level
        response['classification'] = analysis.risk_score.primary_classification.value if hasattr(analysis.risk_score.primary_classification, 'value') else str(analysis.risk_score.primary_classification)
    else:
        # Fallback to detection if risk_score not available
        response['overall_score'] = analysis.detection.risk_score
        response['overall_level'] = analysis.detection.risk_level.value
        response['classification'] = analysis.detection.primary_classification.value
    
    # Add detection_results for backward compatibility
    response['detection_results'] = response.get('detection', {})
    
    # Get authentication results from multiple possible sources
    spf_result = 'none'
    dkim_result = 'none'
    dmarc_result = 'none'
    spf_details = None
    dkim_details = None
    dmarc_details = None
    
    # Try header_analysis first (from analyze_headers)
    if analysis.header_analysis:
        if analysis.header_analysis.spf_result:
            spf_result = analysis.header_analysis.spf_result
        if analysis.header_analysis.dkim_result:
            dkim_result = analysis.header_analysis.dkim_result
        if analysis.header_analysis.dmarc_result:
            dmarc_result = analysis.header_analysis.dmarc_result
    
    # Try email's auth results if header_analysis didn't have them
    if analysis.email.spf_result and spf_result == 'none':
        spf_result = analysis.email.spf_result.result
        spf_details = analysis.email.spf_result.details
    if analysis.email.dkim_result and dkim_result == 'none':
        dkim_result = analysis.email.dkim_result.result
        dkim_details = analysis.email.dkim_result.details
    if analysis.email.dmarc_result and dmarc_result == 'none':
        dmarc_result = analysis.email.dmarc_result.result
        dmarc_details = analysis.email.dmarc_result.details
    
    # Build top-level authentication dict (for Overview tab)
    response['authentication'] = {
        'spf': {
            'result': spf_result,
            'details': spf_details,
        },
        'dkim': {
            'result': dkim_result,
            'details': dkim_details,
        },
        'dmarc': {
            'result': dmarc_result,
            'details': dmarc_details,
        },
    }
    
    # Also add auth to email.header_analysis for Advanced Insights tab
    if 'email' not in response:
        response['email'] = {}
    if 'header_analysis' not in response['email'] or response['email']['header_analysis'] is None:
        response['email']['header_analysis'] = {}
    
    # Add authentication in the format Advanced Insights expects
    response['email']['header_analysis']['spf'] = {'result': spf_result, 'details': spf_details}
    response['email']['header_analysis']['dkim'] = {'result': dkim_result, 'details': dkim_details}
    response['email']['header_analysis']['dmarc'] = {'result': dmarc_result, 'details': dmarc_details}
    
    # Also set string versions for simpler access
    response['email']['header_analysis']['spf_result'] = spf_result
    response['email']['header_analysis']['dkim_result'] = dkim_result
    response['email']['header_analysis']['dmarc_result'] = dmarc_result
    
    # Add apis info
    response['apis_configured'] = analysis.api_keys_used
    response['apis_errors'] = analysis.enrichment_errors
    
    # Convert enum values in nested dicts
    if 'detection' in response:
        det = response['detection']
        if isinstance(det.get('risk_level'), str) == False and hasattr(det.get('risk_level'), 'value'):
            det['risk_level'] = det['risk_level'].value
        if isinstance(det.get('primary_classification'), str) == False and hasattr(det.get('primary_classification'), 'value'):
            det['primary_classification'] = det['primary_classification'].value
    
    return response


async def store_analysis(store, analysis: AnalysisResult):
    """Store analysis result in background."""
    try:
        await store.save(analysis)
        logger.info(f"Analysis {analysis.analysis_id} stored successfully")
    except Exception as e:
        logger.error(f"Failed to store analysis {analysis.analysis_id}: {e}")


# ==============================================================================
# HEALTH CHECK ENDPOINT
# ==============================================================================

@router.get("/health")
async def analyze_health():
    """Check analyze endpoint health."""
    return {"status": "ok", "endpoint": "analyze"}
