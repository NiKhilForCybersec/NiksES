"""
NiksES Master Analysis Orchestrator

Coordinates all analysis components to produce a unified email assessment:
- Email parsing
- Header analysis
- Detection rules
- Social engineering analysis
- Content deconstruction
- Lookalike domain detection
- Threat intelligence fusion
- Multi-dimensional scoring

Handles graceful degradation when components fail or APIs are unavailable.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field

from app.models.email import ParsedEmail
from app.services.ai.se_analyzer import SocialEngineeringAnalyzer, SEAnalysisResult
from app.services.ai.content_analyzer import ContentAnalyzer, ContentAnalysisResult
from app.services.detection.lookalike import LookalikeDetector, LookalikeAnalysisResult
from app.services.enrichment.ti_fusion import ThreatIntelFusion, FusedTIResult
from app.services.detection.multi_scorer import MultiDimensionalScorer, UnifiedRiskScore

logger = logging.getLogger(__name__)


@dataclass
class AnalysisMetadata:
    """Metadata about the analysis run."""
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_ms: int = 0
    
    # Component status
    components_run: List[str] = field(default_factory=list)
    components_failed: List[str] = field(default_factory=list)
    components_skipped: List[str] = field(default_factory=list)
    
    # API status
    api_status: Dict[str, str] = field(default_factory=dict)
    apis_rate_limited: List[str] = field(default_factory=list)
    
    # Warnings/errors
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "components_run": self.components_run,
            "components_failed": self.components_failed,
            "components_skipped": self.components_skipped,
            "api_status": self.api_status,
            "apis_rate_limited": self.apis_rate_limited,
            "warnings": self.warnings,
            "errors": self.errors,
        }


@dataclass
class CompleteAnalysisResult:
    """Complete analysis result from all components."""
    
    # Core results
    risk_score: Optional[UnifiedRiskScore] = None
    se_analysis: Optional[SEAnalysisResult] = None
    content_analysis: Optional[ContentAnalysisResult] = None
    lookalike_analysis: Optional[LookalikeAnalysisResult] = None
    ti_results: Optional[FusedTIResult] = None
    
    # Detection engine results
    detection_results: Optional[Dict[str, Any]] = None
    header_analysis: Optional[Dict[str, Any]] = None
    
    # Metadata
    metadata: AnalysisMetadata = field(default_factory=AnalysisMetadata)
    
    # Quick access fields
    overall_score: int = 0
    overall_level: str = "unknown"
    classification: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        # Handle detection_results - it's a Pydantic model
        detection_dict = None
        if self.detection_results:
            if hasattr(self.detection_results, 'model_dump'):
                detection_dict = self.detection_results.model_dump()
            elif hasattr(self.detection_results, 'dict'):
                detection_dict = self.detection_results.dict()
            else:
                detection_dict = self.detection_results
        
        return {
            "overall_score": self.overall_score,
            "overall_level": self.overall_level,
            "classification": self.classification,
            "risk_score": self.risk_score.to_dict() if self.risk_score else None,
            "se_analysis": self.se_analysis.to_dict() if self.se_analysis else None,
            "content_analysis": self.content_analysis.to_dict() if self.content_analysis else None,
            "lookalike_analysis": self.lookalike_analysis.to_dict() if self.lookalike_analysis else None,
            "ti_results": self.ti_results.to_dict() if self.ti_results else None,
            "detection_results": detection_dict,
            "header_analysis": self.header_analysis,
            "metadata": self.metadata.to_dict(),
        }


class AnalysisOrchestrator:
    """
    Master orchestrator for email analysis.
    
    Coordinates all analysis components and handles:
    - Parallel execution where possible
    - Graceful degradation on failures
    - API rate limit handling
    - Result aggregation
    """
    
    def __init__(
        self,
        # Detection engine
        detection_engine=None,
        # AI analyzers
        se_analyzer: Optional[SocialEngineeringAnalyzer] = None,
        content_analyzer: Optional[ContentAnalyzer] = None,
        # Lookalike detector
        lookalike_detector: Optional[LookalikeDetector] = None,
        # TI fusion
        ti_fusion: Optional[ThreatIntelFusion] = None,
        # Scorer
        scorer: Optional[MultiDimensionalScorer] = None,
        # OpenAI client for AI features
        openai_client=None,
    ):
        self.detection_engine = detection_engine
        self.se_analyzer = se_analyzer or SocialEngineeringAnalyzer(openai_client)
        self.content_analyzer = content_analyzer or ContentAnalyzer(openai_client)
        self.lookalike_detector = lookalike_detector or LookalikeDetector()
        self.ti_fusion = ti_fusion
        self.scorer = scorer or MultiDimensionalScorer()
        self.openai_client = openai_client
        
        self.logger = logging.getLogger(__name__)
    
    async def analyze_email(
        self,
        email: ParsedEmail,
        options: Optional[Dict[str, Any]] = None,
    ) -> CompleteAnalysisResult:
        """
        Perform complete analysis on an email.
        
        Args:
            email: Parsed email to analyze
            options: Analysis options
                - use_llm: bool - Whether to use LLM analysis (default: True)
                - run_ti: bool - Whether to run threat intel (default: True)
                - run_detection: bool - Whether to run detection rules (default: True)
                - timeout: float - Overall timeout in seconds (default: 60)
                
        Returns:
            CompleteAnalysisResult with all analysis data
        """
        options = options or {}
        use_llm = options.get("use_llm", True)
        run_ti = options.get("run_ti", True)
        run_detection = options.get("run_detection", True)
        timeout = options.get("timeout", 60.0)
        
        result = CompleteAnalysisResult()
        result.metadata.started_at = datetime.utcnow()
        
        try:
            # Run all analyses with overall timeout
            await asyncio.wait_for(
                self._run_all_analyses(email, result, use_llm, run_ti, run_detection),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            result.metadata.errors.append(f"Analysis timed out after {timeout}s")
            self.logger.error(f"Analysis timed out after {timeout}s")
        except Exception as e:
            result.metadata.errors.append(f"Analysis error: {str(e)}")
            self.logger.error(f"Analysis error: {e}", exc_info=True)
        
        # Calculate final score even if some components failed
        try:
            result = self._calculate_final_score(result, email)
        except Exception as e:
            self.logger.error(f"Scoring error: {e}")
            result.metadata.errors.append(f"Scoring error: {str(e)}")
        
        # Finalize metadata
        result.metadata.completed_at = datetime.utcnow()
        result.metadata.duration_ms = int(
            (result.metadata.completed_at - result.metadata.started_at).total_seconds() * 1000
        )
        
        return result
    
    async def _run_all_analyses(
        self,
        email: ParsedEmail,
        result: CompleteAnalysisResult,
        use_llm: bool,
        run_ti: bool,
        run_detection: bool,
    ):
        """Run all analysis components."""
        
        # Phase 1: Quick local analyses (can run in parallel)
        phase1_tasks = {}
        
        # Social Engineering Analysis
        phase1_tasks["se_analysis"] = self._run_se_analysis(email, use_llm)
        
        # Content Analysis
        phase1_tasks["content_analysis"] = self._run_content_analysis(email, use_llm)
        
        # Lookalike Domain Detection
        phase1_tasks["lookalike_analysis"] = self._run_lookalike_analysis(email)
        
        # Detection Rules (if available)
        if run_detection and self.detection_engine:
            phase1_tasks["detection_results"] = self._run_detection_rules(email)
        
        # Run phase 1 in parallel
        phase1_results = await asyncio.gather(
            *phase1_tasks.values(),
            return_exceptions=True
        )
        
        # Process phase 1 results
        for i, (task_name, task_result) in enumerate(zip(phase1_tasks.keys(), phase1_results)):
            if isinstance(task_result, Exception):
                result.metadata.components_failed.append(task_name)
                result.metadata.errors.append(f"{task_name}: {str(task_result)}")
                self.logger.warning(f"{task_name} failed: {task_result}")
            else:
                result.metadata.components_run.append(task_name)
                setattr(result, task_name, task_result)
        
        # Phase 2: TI lookups (depends on extracted IOCs)
        if run_ti and self.ti_fusion:
            try:
                result.ti_results = await self._run_ti_analysis(email, result)
                result.metadata.components_run.append("ti_analysis")
                
                # Record API status
                if result.ti_results:
                    result.metadata.api_status = result.ti_results.api_status
                    for source, status in result.ti_results.api_status.items():
                        if "limited" in status.lower():
                            result.metadata.apis_rate_limited.append(source)
                            
            except Exception as e:
                result.metadata.components_failed.append("ti_analysis")
                result.metadata.errors.append(f"TI analysis: {str(e)}")
                self.logger.warning(f"TI analysis failed: {e}")
        else:
            result.metadata.components_skipped.append("ti_analysis")
    
    async def _run_se_analysis(
        self,
        email: ParsedEmail,
        use_llm: bool,
    ) -> Optional[SEAnalysisResult]:
        """Run social engineering analysis."""
        try:
            return await self.se_analyzer.analyze(email, use_llm=use_llm)
        except Exception as e:
            self.logger.error(f"SE analysis error: {e}")
            raise
    
    async def _run_content_analysis(
        self,
        email: ParsedEmail,
        use_llm: bool,
    ) -> Optional[ContentAnalysisResult]:
        """Run content deconstruction analysis."""
        try:
            return await self.content_analyzer.analyze(email, use_llm=use_llm)
        except Exception as e:
            self.logger.error(f"Content analysis error: {e}")
            raise
    
    async def _run_lookalike_analysis(
        self,
        email: ParsedEmail,
    ) -> Optional[LookalikeAnalysisResult]:
        """Run lookalike domain detection."""
        try:
            # Extract domains to check
            domains_to_check = set()
            
            # Sender domain - email.sender is an EmailAddress object
            if email.sender:
                if email.sender.domain:
                    domains_to_check.add(email.sender.domain.lower())
                elif email.sender.email and "@" in email.sender.email:
                    domains_to_check.add(email.sender.email.split("@")[1].lower())
            
            # Reply-to domain - email.reply_to is a list of EmailAddress objects
            if email.reply_to:
                for reply_addr in email.reply_to:
                    if hasattr(reply_addr, 'domain') and reply_addr.domain:
                        domains_to_check.add(reply_addr.domain.lower())
                    elif hasattr(reply_addr, 'email') and reply_addr.email and "@" in reply_addr.email:
                        domains_to_check.add(reply_addr.email.split("@")[1].lower())
            
            # URL domains
            if email.urls:
                for url_info in email.urls:
                    url = url_info.url if hasattr(url_info, 'url') else str(url_info)
                    # Extract domain from URL
                    import re
                    match = re.search(r'https?://([^/]+)', url)
                    if match:
                        domain = match.group(1).lower()
                        # Remove port if present
                        domain = domain.split(':')[0]
                        domains_to_check.add(domain)
            
            # Analyze each domain
            combined_result = LookalikeAnalysisResult()
            
            for domain in domains_to_check:
                domain_result = self.lookalike_detector.analyze_domain(domain)
                if domain_result.has_lookalikes:
                    combined_result.has_lookalikes = True
                    combined_result.matches.extend(domain_result.matches)
                    if domain_result.highest_confidence > combined_result.highest_confidence:
                        combined_result.highest_confidence = domain_result.highest_confidence
                        combined_result.primary_target = domain_result.primary_target
            
            return combined_result
            
        except Exception as e:
            self.logger.error(f"Lookalike analysis error: {e}")
            raise
    
    async def _run_detection_rules(
        self,
        email: ParsedEmail,
    ) -> Optional[Dict[str, Any]]:
        """Run detection engine rules."""
        try:
            if self.detection_engine:
                # Assuming detection engine has an async analyze method
                if asyncio.iscoroutinefunction(self.detection_engine.analyze):
                    return await self.detection_engine.analyze(email)
                else:
                    return self.detection_engine.analyze(email)
            return None
        except Exception as e:
            self.logger.error(f"Detection rules error: {e}")
            raise
    
    async def _run_ti_analysis(
        self,
        email: ParsedEmail,
        current_result: CompleteAnalysisResult,
    ) -> Optional[FusedTIResult]:
        """Run threat intelligence analysis on extracted IOCs."""
        try:
            if not self.ti_fusion:
                return None
            
            # Collect IOCs to check
            urls_to_check = []
            domains_to_check = []
            ips_to_check = []
            hashes_to_check = []
            
            # Extract URLs
            if email.urls:
                for url_info in email.urls:
                    url = url_info.url if hasattr(url_info, 'url') else str(url_info)
                    urls_to_check.append(url)
            
            # Extract IPs from headers
            if email.received_chain:
                for hop in email.received_chain:
                    if hasattr(hop, 'from_ip') and hop.from_ip:
                        ips_to_check.append(hop.from_ip)
            
            # Extract attachment hashes
            if email.attachments:
                for att in email.attachments:
                    if hasattr(att, 'sha256') and att.sha256:
                        hashes_to_check.append(att.sha256)
                    elif hasattr(att, 'md5') and att.md5:
                        hashes_to_check.append(att.md5)
            
            # Run TI checks (limit to avoid API abuse)
            ti_tasks = []
            
            # Check first 3 URLs
            for url in urls_to_check[:3]:
                ti_tasks.append(("url", url, self.ti_fusion.check_url(url)))
            
            # Check first 3 IPs
            for ip in ips_to_check[:3]:
                ti_tasks.append(("ip", ip, self.ti_fusion.check_ip(ip)))
            
            # Check first 2 hashes
            for file_hash in hashes_to_check[:2]:
                ti_tasks.append(("hash", file_hash, self.ti_fusion.check_hash(file_hash)))
            
            if not ti_tasks:
                return None
            
            # Run checks in parallel
            results = await asyncio.gather(
                *[task[2] for task in ti_tasks],
                return_exceptions=True
            )
            
            # Aggregate results into single FusedTIResult
            aggregated = FusedTIResult()
            
            for i, (ioc_type, ioc_value, _) in enumerate(ti_tasks):
                ti_result = results[i]
                
                if isinstance(ti_result, Exception):
                    self.logger.warning(f"TI check failed for {ioc_type} {ioc_value}: {ti_result}")
                    continue
                
                if isinstance(ti_result, FusedTIResult):
                    # Merge results
                    aggregated.sources_checked += ti_result.sources_checked
                    aggregated.sources_available += ti_result.sources_available
                    aggregated.sources_flagged += ti_result.sources_flagged
                    
                    # Take highest score
                    if ti_result.fused_score > aggregated.fused_score:
                        aggregated.fused_score = ti_result.fused_score
                        aggregated.fused_verdict = ti_result.fused_verdict
                    
                    # Merge findings
                    for finding in ti_result.findings:
                        aggregated.findings.append(f"[{ioc_type}:{ioc_value[:30]}] {finding}")
                    
                    # Merge API status
                    aggregated.api_status.update(ti_result.api_status)
            
            # Calculate confidence
            if aggregated.sources_checked > 0:
                aggregated.confidence = aggregated.sources_available / aggregated.sources_checked
            
            return aggregated
            
        except Exception as e:
            self.logger.error(f"TI analysis error: {e}")
            raise
    
    def _calculate_final_score(
        self,
        result: CompleteAnalysisResult,
        email: Optional[ParsedEmail] = None,
    ) -> CompleteAnalysisResult:
        """Calculate final unified score from all components."""
        
        # Prepare inputs for scorer - all must be dicts
        detection_results = None
        if result.detection_results:
            # Convert Pydantic model to dict
            if hasattr(result.detection_results, 'model_dump'):
                detection_results = result.detection_results.model_dump()
            elif hasattr(result.detection_results, 'dict'):
                detection_results = result.detection_results.dict()
            elif isinstance(result.detection_results, dict):
                detection_results = result.detection_results
            else:
                self.logger.warning(f"Could not convert detection_results: {type(result.detection_results)}")
        
        se_analysis = None
        if result.se_analysis:
            se_analysis = result.se_analysis.to_dict()
        
        content_analysis = None
        if result.content_analysis:
            content_analysis = result.content_analysis.to_dict()
        
        lookalike_results = None
        if result.lookalike_analysis:
            lookalike_results = result.lookalike_analysis.to_dict()
        
        ti_results = None
        if result.ti_results:
            ti_results = result.ti_results.to_dict()
        
        # Extract sender domain for legitimacy checks
        sender_domain = None
        if email and email.sender and email.sender.domain:
            sender_domain = email.sender.domain
        
        # Calculate unified score
        result.risk_score = self.scorer.calculate_unified_score(
            detection_results=detection_results,
            se_analysis=se_analysis,
            content_analysis=content_analysis,
            lookalike_results=lookalike_results,
            ti_results=ti_results,
            header_analysis=result.header_analysis,
            sender_domain=sender_domain,
        )
        
        # Set quick access fields
        if result.risk_score:
            result.overall_score = result.risk_score.overall_score
            result.overall_level = result.risk_score.overall_level
            result.classification = result.risk_score.primary_classification.value
        
        return result


# Factory function
def create_orchestrator(
    detection_engine=None,
    openai_client=None,
    ti_providers: Optional[Dict[str, Any]] = None,
) -> AnalysisOrchestrator:
    """
    Create an analysis orchestrator with all components.
    
    Args:
        detection_engine: Detection rule engine
        openai_client: OpenAI client for AI features
        ti_providers: Dict of TI provider instances
        
    Returns:
        Configured AnalysisOrchestrator
    """
    ti_fusion = None
    if ti_providers:
        ti_fusion = ThreatIntelFusion(**ti_providers)
    
    return AnalysisOrchestrator(
        detection_engine=detection_engine,
        openai_client=openai_client,
        ti_fusion=ti_fusion,
    )
