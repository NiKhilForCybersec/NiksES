"""
NiksES Unified Threat Intelligence Fusion

Combines results from multiple TI sources:
- AbuseIPDB
- VirusTotal
- URLhaus
- PhishTank
- WHOIS/Domain Age

Features:
- Parallel API calls with timeout
- 4-retry logic per API
- Weighted score fusion
- Graceful degradation when APIs are unavailable
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from app.services.enrichment.base import APIStatus, APIStatusInfo, EnrichmentResult

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    """Unified threat level."""
    CLEAN = "clean"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class TISourceResult:
    """Result from a single TI source."""
    source: str
    available: bool = True
    verdict: ThreatLevel = ThreatLevel.UNKNOWN
    score: Optional[int] = None  # 0-100
    raw_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    attempts: int = 0
    was_rate_limited: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "available": self.available,
            "verdict": self.verdict.value,
            "score": self.score,
            "error": self.error,
            "attempts": self.attempts,
            "was_rate_limited": self.was_rate_limited,
            "raw_data": self.raw_data,
        }


@dataclass
class FusedTIResult:
    """Fused result from all TI sources."""
    # Overall assessment
    fused_score: int = 0  # 0-100
    fused_verdict: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: float = 0.0  # Based on how many sources responded
    
    # Individual source results
    sources: Dict[str, TISourceResult] = field(default_factory=dict)
    
    # Summary
    sources_checked: int = 0
    sources_available: int = 0
    sources_flagged: int = 0  # How many flagged as malicious/suspicious
    
    # API status for display
    api_status: Dict[str, str] = field(default_factory=dict)  # source -> status message
    
    # Detailed findings
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fused_score": self.fused_score,
            "fused_verdict": self.fused_verdict.value,
            "confidence": self.confidence,
            "sources_checked": self.sources_checked,
            "sources_available": self.sources_available,
            "sources_flagged": self.sources_flagged,
            "api_status": self.api_status,
            "findings": self.findings,
            "source_details": {k: v.to_dict() for k, v in self.sources.items()},
        }


# Source weights for score fusion
# Import centralized scoring configuration
try:
    from app.config.scoring import get_scoring_config
    USE_CENTRALIZED_CONFIG = True
except ImportError:
    USE_CENTRALIZED_CONFIG = False

# Fallback weights (used if config not available)
SOURCE_WEIGHTS = {
    "virustotal": 0.25,  # Multi-engine scanner
    "google_safebrowsing": 0.20,  # Google's real-time threat list
    "ipqualityscore": 0.20,  # Comprehensive URL/domain analysis
    "abuseipdb": 0.15,  # IP reputation
    "urlhaus": 0.10,  # Malware URL database
    "phishtank": 0.05,  # Phishing database
    "whois": 0.05,  # Domain age is supplementary
}

def get_source_weight(source: str) -> float:
    """Get weight for a TI source from config or fallback."""
    if USE_CENTRALIZED_CONFIG:
        config = get_scoring_config()
        return config.ti_weights.get_weight(source)
    return SOURCE_WEIGHTS.get(source, 0.1)


class ThreatIntelFusion:
    """
    Fuses threat intelligence from multiple sources.
    
    Handles:
    - Parallel API calls
    - Retry logic (4 attempts per source)
    - Rate limit detection
    - Score fusion with weighted consensus
    - Graceful degradation (continues even if APIs fail)
    
    IMPORTANT: If any API fails after 4 retries, analysis continues
    with available data. No single API failure blocks the analysis.
    
    Supported Sources:
    - VirusTotal (URL, domain, IP, hash)
    - Google Safe Browsing (URL)
    - IPQualityScore (URL, domain)
    - AbuseIPDB (IP)
    - URLhaus (URL)
    - PhishTank (URL)
    - WHOIS (domain age)
    """
    
    # Per-source timeout (seconds) - after this, move on
    DEFAULT_TIMEOUT = 15.0
    
    def __init__(
        self,
        virustotal_provider=None,
        abuseipdb_provider=None,
        urlhaus_provider=None,
        phishtank_provider=None,
        whois_provider=None,
        ipqualityscore_provider=None,
        google_safebrowsing_provider=None,
        timeout: float = None,
    ):
        """Initialize with enrichment providers."""
        self.providers = {
            "virustotal": virustotal_provider,
            "abuseipdb": abuseipdb_provider,
            "urlhaus": urlhaus_provider,
            "phishtank": phishtank_provider,
            "whois": whois_provider,
            "ipqualityscore": ipqualityscore_provider,
            "google_safebrowsing": google_safebrowsing_provider,
        }
        self.timeout = timeout or self.DEFAULT_TIMEOUT  # Per-source timeout
        self.logger = logging.getLogger(__name__)
    
    async def check_url(self, url: str) -> FusedTIResult:
        """
        Check URL against all TI sources.
        
        Args:
            url: URL to check
            
        Returns:
            FusedTIResult with combined assessment
        """
        result = FusedTIResult()
        
        # Define tasks for each source
        tasks = {}
        
        if self.providers.get("google_safebrowsing"):
            tasks["google_safebrowsing"] = self._check_google_safebrowsing(url)
        
        if self.providers.get("ipqualityscore"):
            tasks["ipqualityscore"] = self._check_ipqualityscore_url(url)
        
        if self.providers.get("virustotal"):
            tasks["virustotal"] = self._check_virustotal_url(url)
        
        if self.providers.get("urlhaus"):
            tasks["urlhaus"] = self._check_urlhaus(url)
        
        if self.providers.get("phishtank"):
            tasks["phishtank"] = self._check_phishtank(url)
        
        # Run all checks in parallel
        result = await self._run_checks(tasks, result)
        
        return result
    
    async def check_domain(self, domain: str) -> FusedTIResult:
        """Check domain against all TI sources."""
        result = FusedTIResult()
        
        tasks = {}
        
        if self.providers.get("virustotal"):
            tasks["virustotal"] = self._check_virustotal_domain(domain)
        
        if self.providers.get("whois"):
            tasks["whois"] = self._check_whois(domain)
        
        result = await self._run_checks(tasks, result)
        
        return result
    
    async def check_ip(self, ip: str) -> FusedTIResult:
        """Check IP address against all TI sources."""
        result = FusedTIResult()
        
        tasks = {}
        
        if self.providers.get("abuseipdb"):
            tasks["abuseipdb"] = self._check_abuseipdb(ip)
        
        if self.providers.get("virustotal"):
            tasks["virustotal"] = self._check_virustotal_ip(ip)
        
        result = await self._run_checks(tasks, result)
        
        return result
    
    async def check_hash(self, file_hash: str) -> FusedTIResult:
        """Check file hash against TI sources."""
        result = FusedTIResult()
        
        tasks = {}
        
        if self.providers.get("virustotal"):
            tasks["virustotal"] = self._check_virustotal_hash(file_hash)
        
        result = await self._run_checks(tasks, result)
        
        return result
    
    async def _run_checks(
        self,
        tasks: Dict[str, Any],
        result: FusedTIResult,
    ) -> FusedTIResult:
        """
        Run all TI checks in parallel and fuse results.
        
        Graceful degradation: If any API fails, we continue with 
        whatever data we have. Analysis is never blocked by API failures.
        """
        
        result.sources_checked = len(tasks)
        
        if not tasks:
            result.api_status["general"] = "No TI providers configured"
            return result
        
        self.logger.info(f"Running {len(tasks)} TI checks: {list(tasks.keys())}")
        
        # Run all tasks with timeout - return_exceptions=True ensures
        # we continue even if some tasks fail
        try:
            gathered = await asyncio.gather(
                *tasks.values(),
                return_exceptions=True,
            )
        except Exception as e:
            self.logger.error(f"TI fusion gather error: {e}")
            gathered = [e] * len(tasks)
        
        # Process results - graceful degradation
        source_names = list(tasks.keys())
        for i, source_result in enumerate(gathered):
            source = source_names[i]
            
            if isinstance(source_result, Exception):
                # API failed - log and continue
                self.logger.warning(f"TI source {source} failed: {source_result} - continuing with other sources")
                result.sources[source] = TISourceResult(
                    source=source,
                    available=False,
                    error=str(source_result),
                )
                result.api_status[source] = f"Error: {str(source_result)[:50]}"
            elif isinstance(source_result, TISourceResult):
                result.sources[source] = source_result
                
                if source_result.available:
                    result.sources_available += 1
                    self.logger.info(f"TI source {source}: available, score={source_result.score}, verdict={source_result.verdict}")
                    
                    if source_result.verdict in [ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS]:
                        result.sources_flagged += 1
                    
                    # Add to findings
                    if source_result.verdict == ThreatLevel.MALICIOUS:
                        result.findings.append(f"{source}: MALICIOUS (score: {source_result.score})")
                    elif source_result.verdict == ThreatLevel.SUSPICIOUS:
                        result.findings.append(f"{source}: Suspicious (score: {source_result.score})")
                    
                    result.api_status[source] = "OK"
                else:
                    if source_result.was_rate_limited:
                        # Rate limits expected on free tiers - log as INFO not WARNING
                        self.logger.info(f"TI source {source}: rate limited (attempt {source_result.attempts}) - using other sources")
                        result.api_status[source] = f"Rate limited (tried {source_result.attempts}x)"
                    elif source_result.error == "Timeout":
                        # Timeouts expected on free tier APIs like VT - log as INFO
                        self.logger.info(f"TI source {source}: timeout - using other sources")
                        result.api_status[source] = "Timeout (free tier)"
                    else:
                        self.logger.warning(f"TI source {source}: unavailable - {source_result.error}")
                        result.api_status[source] = f"Unavailable: {source_result.error}"
        
        # Log summary with source details
        available_sources = [s for s, r in result.sources.items() if r.available]
        unavailable_sources = [s for s, r in result.sources.items() if not r.available]
        
        if unavailable_sources:
            self.logger.info(f"TI fusion: {result.sources_available}/{result.sources_checked} sources (used: {', '.join(available_sources) or 'none'}, skipped: {', '.join(unavailable_sources)})")
        else:
            self.logger.info(f"TI fusion: {result.sources_available}/{result.sources_checked} sources available, {result.sources_flagged} flagged")
        
        # Fuse scores from available sources
        result = self._fuse_scores(result)
        
        return result
    
    def _fuse_scores(self, result: FusedTIResult) -> FusedTIResult:
        """Calculate fused score from individual source scores."""
        
        if result.sources_available == 0:
            result.fused_score = 0
            result.fused_verdict = ThreatLevel.UNKNOWN
            result.confidence = 0.0
            return result
        
        # Get dynamic config
        if USE_CENTRALIZED_CONFIG:
            config = get_scoring_config()
            ti_thresholds = config.ti_thresholds
            thresholds = config.thresholds
        else:
            # Fallback defaults
            ti_thresholds = None
            thresholds = None
        
        # Weighted score calculation
        weighted_sum = 0.0
        weight_sum = 0.0
        
        for source, source_result in result.sources.items():
            if source_result.available and source_result.score is not None:
                weight = get_source_weight(source)
                weighted_sum += source_result.score * weight
                weight_sum += weight
        
        if weight_sum > 0:
            result.fused_score = int(weighted_sum / weight_sum)
        else:
            result.fused_score = 0
        
        # Determine verdict from fused score using dynamic thresholds
        malicious_threshold = thresholds.high if thresholds else 70
        suspicious_threshold = thresholds.medium if thresholds else 40
        
        if result.fused_score >= malicious_threshold:
            result.fused_verdict = ThreatLevel.MALICIOUS
        elif result.fused_score >= suspicious_threshold:
            result.fused_verdict = ThreatLevel.SUSPICIOUS
        elif result.fused_score > 0:
            result.fused_verdict = ThreatLevel.CLEAN
        else:
            result.fused_verdict = ThreatLevel.UNKNOWN
        
        # Consensus boost: if multiple sources agree on malicious, boost score
        consensus_threshold = ti_thresholds.sources_flagged_for_malicious if ti_thresholds else 2
        high_consensus = ti_thresholds.sources_flagged_for_consensus if ti_thresholds else 3
        
        if result.sources_flagged >= consensus_threshold:
            result.fused_score = min(100, result.fused_score + 10)
            if result.sources_flagged >= high_consensus:
                result.fused_verdict = ThreatLevel.MALICIOUS
        
        # Calculate confidence based on source availability
        result.confidence = result.sources_available / max(1, result.sources_checked)
        
        return result
    
    # ==========================================================================
    # Individual source check methods
    # ==========================================================================
    
    async def _check_virustotal_url(self, url: str) -> TISourceResult:
        """Check URL on VirusTotal."""
        source_result = TISourceResult(source="virustotal")
        
        try:
            provider = self.providers.get("virustotal")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            # Use provider's retry-enabled method
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_url", provider.check_url, url),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                source_result.attempts = result.attempts
                
                # Parse VT result
                stats = result.data.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1
                
                # Calculate score (0-100)
                if total > 0:
                    source_result.score = int((malicious * 100 + suspicious * 50) / total)
                else:
                    source_result.score = 0
                
                # Determine verdict
                if malicious >= 3:
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif malicious >= 1 or suspicious >= 2:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.attempts = result.attempts
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_virustotal_domain(self, domain: str) -> TISourceResult:
        """Check domain on VirusTotal."""
        source_result = TISourceResult(source="virustotal")
        
        try:
            provider = self.providers.get("virustotal")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_domain", provider.check_domain, domain),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                source_result.attempts = result.attempts
                
                stats = result.data.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 1
                
                if total > 0:
                    source_result.score = int((malicious * 100 + suspicious * 50) / total)
                else:
                    source_result.score = 0
                
                if malicious >= 3:
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif malicious >= 1 or suspicious >= 2:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.attempts = result.attempts
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_virustotal_ip(self, ip: str) -> TISourceResult:
        """Check IP on VirusTotal."""
        source_result = TISourceResult(source="virustotal")
        
        try:
            provider = self.providers.get("virustotal")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_ip", provider.check_ip, ip),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                source_result.attempts = result.attempts
                
                stats = result.data.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                source_result.score = min(100, malicious * 15 + suspicious * 5)
                
                if malicious >= 3:
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif malicious >= 1 or suspicious >= 2:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_virustotal_hash(self, file_hash: str) -> TISourceResult:
        """Check file hash on VirusTotal."""
        source_result = TISourceResult(source="virustotal")
        
        try:
            provider = self.providers.get("virustotal")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_file_hash", provider.check_file_hash, file_hash),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                
                stats = result.data.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = stats.get("total", 1)
                
                if total > 0:
                    source_result.score = int((malicious * 100) / total)
                
                if malicious >= 5:
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif malicious >= 1:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.was_rate_limited = result.was_rate_limited
                
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_abuseipdb(self, ip: str) -> TISourceResult:
        """Check IP on AbuseIPDB."""
        source_result = TISourceResult(source="abuseipdb")
        
        try:
            provider = self.providers.get("abuseipdb")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_ip", provider.check_ip, ip),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                source_result.attempts = result.attempts
                
                # AbuseIPDB returns abuse confidence score 0-100
                score = result.data.get("abuseConfidenceScore", 0)
                source_result.score = score
                
                if score >= 75:
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif score >= 25:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_urlhaus(self, url: str) -> TISourceResult:
        """Check URL on URLhaus."""
        source_result = TISourceResult(source="urlhaus")
        
        try:
            provider = self.providers.get("urlhaus")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_url", provider.check_url, url),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                
                status = result.data.get("query_status", "")
                
                if status == "listed":
                    source_result.score = 100
                    source_result.verdict = ThreatLevel.MALICIOUS
                    
                    threat = result.data.get("threat", "unknown")
                    source_result.raw_data["threat_type"] = threat
                elif status == "no_results":
                    source_result.score = 0
                    source_result.verdict = ThreatLevel.CLEAN
                else:
                    source_result.score = 0
                    source_result.verdict = ThreatLevel.UNKNOWN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_phishtank(self, url: str) -> TISourceResult:
        """Check URL on PhishTank."""
        source_result = TISourceResult(source="phishtank")
        
        try:
            provider = self.providers.get("phishtank")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_url", provider.check_url, url),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                
                in_database = result.data.get("in_database", False)
                verified = result.data.get("verified", False)
                
                if in_database and verified:
                    source_result.score = 100
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif in_database:
                    source_result.score = 75
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.score = 0
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_whois(self, domain: str) -> TISourceResult:
        """Check domain age via WHOIS."""
        source_result = TISourceResult(source="whois")
        
        try:
            provider = self.providers.get("whois")
            if not provider or not provider.is_configured:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider._execute_with_retry("check_domain", provider.check_domain, domain),
                timeout=self.timeout
            )
            
            if result.success:
                source_result.available = True
                source_result.raw_data = result.data
                
                # Check domain age
                creation_date = result.data.get("creation_date")
                age_days = result.data.get("age_days", 0)
                
                # Newly registered domains are suspicious
                if age_days is not None:
                    if age_days < 7:
                        source_result.score = 80
                        source_result.verdict = ThreatLevel.SUSPICIOUS
                    elif age_days < 30:
                        source_result.score = 50
                        source_result.verdict = ThreatLevel.SUSPICIOUS
                    elif age_days < 90:
                        source_result.score = 25
                        source_result.verdict = ThreatLevel.UNKNOWN
                    else:
                        source_result.score = 0
                        source_result.verdict = ThreatLevel.CLEAN
                else:
                    source_result.score = 0
                    source_result.verdict = ThreatLevel.UNKNOWN
            else:
                source_result.available = False
                source_result.error = result.error
                source_result.was_rate_limited = result.was_rate_limited
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_ipqualityscore_url(self, url: str) -> TISourceResult:
        """Check URL on IPQualityScore."""
        source_result = TISourceResult(source="ipqualityscore")
        
        try:
            provider = self.providers.get("ipqualityscore")
            if not provider:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            # Check if provider is configured
            if hasattr(provider, 'is_configured') and not provider.is_configured():
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider.scan_url(url),
                timeout=self.timeout
            )
            
            if result and result.get("success", False):
                source_result.available = True
                source_result.raw_data = result
                
                # IPQualityScore returns risk_score 0-100
                risk_score = result.get("risk_score", 0)
                source_result.score = risk_score
                
                is_phishing = result.get("is_phishing", False)
                is_malware = result.get("is_malware", False)
                is_suspicious = result.get("is_suspicious", False)
                
                if is_phishing or is_malware or risk_score >= 85:
                    source_result.verdict = ThreatLevel.MALICIOUS
                elif is_suspicious or risk_score >= 75:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                elif risk_score >= 50:
                    source_result.verdict = ThreatLevel.SUSPICIOUS
                else:
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = result.get("message", "Unknown error") if result else "No response"
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result
    
    async def _check_google_safebrowsing(self, url: str) -> TISourceResult:
        """Check URL on Google Safe Browsing."""
        source_result = TISourceResult(source="google_safebrowsing")
        
        try:
            provider = self.providers.get("google_safebrowsing")
            if not provider:
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            # Check if provider is configured
            if hasattr(provider, 'is_configured') and not provider.is_configured():
                source_result.available = False
                source_result.error = "Not configured"
                return source_result
            
            result = await asyncio.wait_for(
                provider.check_url(url),
                timeout=self.timeout
            )
            
            if result:
                source_result.available = True
                source_result.raw_data = result
                
                is_safe = result.get("safe", True)
                threats = result.get("threats", [])
                
                if not is_safe or threats:
                    source_result.score = 100  # GSB is binary - if flagged, it's bad
                    source_result.verdict = ThreatLevel.MALICIOUS
                    
                    # Store threat types
                    threat_types = [t.get("threatType", "unknown") for t in threats]
                    source_result.raw_data["threat_types"] = threat_types
                else:
                    source_result.score = 0
                    source_result.verdict = ThreatLevel.CLEAN
            else:
                source_result.available = False
                source_result.error = "No response"
                
        except asyncio.TimeoutError:
            source_result.available = False
            source_result.error = "Timeout"
        except Exception as e:
            source_result.available = False
            source_result.error = str(e)
        
        return source_result


# Singleton
_ti_fusion: Optional[ThreatIntelFusion] = None


def get_ti_fusion(**providers) -> ThreatIntelFusion:
    """Get or create TI fusion singleton."""
    global _ti_fusion
    if _ti_fusion is None:
        _ti_fusion = ThreatIntelFusion(**providers)
    return _ti_fusion
