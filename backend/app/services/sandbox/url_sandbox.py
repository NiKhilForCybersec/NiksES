"""
NiksES URL Sandbox Service

Dynamic URL analysis using URLScan.io and Cuckoo sandbox environments.
Provides real-time URL detonation and behavioral analysis.
"""

import os
import logging
import hashlib
import asyncio
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import aiohttp

logger = logging.getLogger(__name__)


class SandboxProvider(str, Enum):
    """Available sandbox providers."""
    URLSCAN = "urlscan"
    CUCKOO = "cuckoo"
    AUTO = "auto"


class AnalysisStatus(str, Enum):
    """Status of sandbox analysis."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CACHED = "cached"


@dataclass
class URLAnalysisResult:
    """Result from URL sandbox analysis."""
    url: str
    provider: str
    task_id: Optional[str] = None
    status: AnalysisStatus = AnalysisStatus.PENDING
    
    # Threat assessment
    is_malicious: bool = False
    is_suspicious: bool = False
    threat_score: int = 0
    threat_level: str = "unknown"
    
    # Analysis details
    categories: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Network behavior
    contacted_ips: List[str] = field(default_factory=list)
    contacted_domains: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    final_url: Optional[str] = None
    
    # Page info
    page_title: Optional[str] = None
    page_ip: Optional[str] = None
    page_country: Optional[str] = None
    server: Optional[str] = None
    
    # Screenshots and reports
    screenshot_url: Optional[str] = None
    report_url: Optional[str] = None
    
    # Metadata
    submitted_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    analysis_time_ms: int = 0
    error_message: Optional[str] = None
    
    # Raw data for debugging
    raw_response: Optional[Dict[str, Any]] = None


class URLScanClient:
    """Client for URLScan.io API."""
    
    BASE_URL = "https://urlscan.io/api/v1"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
    
    def _refresh_api_key(self):
        """Refresh API key from environment if not set."""
        if not self.api_key:
            self.api_key = os.getenv("URLSCAN_API_KEY")
            if self.api_key:
                logger.info(f"Refreshed URLScan.io API key from environment ({len(self.api_key)} chars)")
    
    def is_configured(self) -> bool:
        self._refresh_api_key()
        return bool(self.api_key)
    
    async def submit_url(self, url: str, visibility: str = "unlisted") -> Optional[str]:
        """Submit URL for scanning. Returns task UUID."""
        if not self.api_key:
            logger.warning("URLScan.io API key not configured")
            return None
        
        session = await self._get_session()
        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "url": url,
            "visibility": visibility  # public, unlisted, or private
        }
        
        try:
            async with session.post(
                f"{self.BASE_URL}/scan/",
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("uuid")
                elif response.status == 429:
                    logger.warning("URLScan.io rate limit exceeded")
                    return None
                else:
                    error = await response.text()
                    logger.error(f"URLScan.io submit error: {response.status} - {error}")
                    return None
        except Exception as e:
            logger.error(f"URLScan.io submit exception: {e}")
            return None
    
    async def get_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get scan result by task UUID."""
        session = await self._get_session()
        
        try:
            async with session.get(
                f"{self.BASE_URL}/result/{task_id}/",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    # Not ready yet
                    return None
                else:
                    logger.error(f"URLScan.io result error: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"URLScan.io result exception: {e}")
            return None
    
    async def analyze_url(
        self,
        url: str,
        wait_for_result: bool = True,
        max_wait: int = 120,
        poll_interval: int = 5
    ) -> URLAnalysisResult:
        """Submit URL and optionally wait for results."""
        result = URLAnalysisResult(
            url=url,
            provider="urlscan.io",
            submitted_at=datetime.utcnow()
        )
        
        # Submit URL
        task_id = await self.submit_url(url)
        if not task_id:
            result.status = AnalysisStatus.FAILED
            result.error_message = "Failed to submit URL to URLScan.io"
            return result
        
        result.task_id = task_id
        result.status = AnalysisStatus.RUNNING
        result.report_url = f"https://urlscan.io/result/{task_id}/"
        
        if not wait_for_result:
            return result
        
        # Poll for results
        start_time = datetime.utcnow()
        while (datetime.utcnow() - start_time).seconds < max_wait:
            await asyncio.sleep(poll_interval)
            
            data = await self.get_result(task_id)
            if data:
                result = self._parse_result(result, data)
                result.completed_at = datetime.utcnow()
                result.analysis_time_ms = int((result.completed_at - result.submitted_at).total_seconds() * 1000)
                return result
        
        # Timeout
        result.status = AnalysisStatus.TIMEOUT
        result.error_message = f"Analysis timed out after {max_wait} seconds"
        return result
    
    def _parse_result(self, result: URLAnalysisResult, data: Dict[str, Any]) -> URLAnalysisResult:
        """Parse URLScan.io result data."""
        result.status = AnalysisStatus.COMPLETED
        result.raw_response = data
        
        # Verdicts
        verdicts = data.get("verdicts", {})
        overall = verdicts.get("overall", {})
        result.is_malicious = overall.get("malicious", False)
        result.threat_score = overall.get("score", 0)
        result.categories = overall.get("categories", [])
        result.tags = overall.get("tags", [])
        
        # Determine threat level
        if result.is_malicious or result.threat_score >= 80:
            result.threat_level = "critical"
            result.is_suspicious = True
        elif result.threat_score >= 50:
            result.threat_level = "high"
            result.is_suspicious = True
        elif result.threat_score >= 30:
            result.threat_level = "medium"
            result.is_suspicious = True
        elif result.threat_score >= 10:
            result.threat_level = "low"
        else:
            result.threat_level = "clean"
        
        # Page info
        page = data.get("page", {})
        result.page_title = page.get("title")
        result.page_ip = page.get("ip")
        result.page_country = page.get("country")
        result.server = page.get("server")
        result.final_url = page.get("url")
        
        # Lists
        lists = data.get("lists", {})
        result.contacted_ips = lists.get("ips", [])[:20]
        result.contacted_domains = lists.get("domains", [])[:20]
        
        # Redirects
        data_section = data.get("data", {})
        requests = data_section.get("requests", [])
        redirects = []
        for req in requests[:10]:
            req_url = req.get("request", {}).get("request", {}).get("url")
            if req_url and req_url != result.url:
                redirects.append(req_url)
        result.redirects = redirects[:5]
        
        # Screenshot
        task = data.get("task", {})
        result.screenshot_url = task.get("screenshotURL")
        
        # Build indicators
        indicators = []
        if result.is_malicious:
            indicators.append("🔴 Flagged as MALICIOUS")
        if result.categories:
            indicators.append(f"Categories: {', '.join(result.categories[:3])}")
        if len(result.redirects) > 2:
            indicators.append(f"⚠️ {len(result.redirects)} redirects detected")
        if result.page_country and result.page_country in ["RU", "CN", "KP", "IR"]:
            indicators.append(f"⚠️ Hosted in high-risk country: {result.page_country}")
        result.indicators = indicators
        
        return result


class CuckooClient:
    """Client for Cuckoo Sandbox API."""
    
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = base_url or os.getenv("CUCKOO_API_URL", "http://localhost:8090")
        self.api_key = api_key or os.getenv("CUCKOO_API_KEY")
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
    
    def is_configured(self) -> bool:
        return bool(self.base_url)
    
    async def submit_url(self, url: str) -> Optional[int]:
        """Submit URL for analysis. Returns task ID."""
        session = await self._get_session()
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            async with session.post(
                f"{self.base_url}/tasks/create/url",
                headers=headers,
                data={"url": url},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("task_id")
                else:
                    logger.error(f"Cuckoo submit error: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Cuckoo submit exception: {e}")
            return None
    
    async def get_status(self, task_id: int) -> Optional[str]:
        """Get task status."""
        session = await self._get_session()
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            async with session.get(
                f"{self.base_url}/tasks/view/{task_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("task", {}).get("status")
                return None
        except Exception as e:
            logger.error(f"Cuckoo status exception: {e}")
            return None
    
    async def get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """Get analysis report."""
        session = await self._get_session()
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            async with session.get(
                f"{self.base_url}/tasks/report/{task_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except Exception as e:
            logger.error(f"Cuckoo report exception: {e}")
            return None
    
    async def analyze_url(
        self,
        url: str,
        wait_for_result: bool = True,
        max_wait: int = 300,
        poll_interval: int = 10
    ) -> URLAnalysisResult:
        """Submit URL and optionally wait for results."""
        result = URLAnalysisResult(
            url=url,
            provider="cuckoo",
            submitted_at=datetime.utcnow()
        )
        
        # Submit URL
        task_id = await self.submit_url(url)
        if not task_id:
            result.status = AnalysisStatus.FAILED
            result.error_message = "Failed to submit URL to Cuckoo"
            return result
        
        result.task_id = str(task_id)
        result.status = AnalysisStatus.RUNNING
        
        if not wait_for_result:
            return result
        
        # Poll for completion
        start_time = datetime.utcnow()
        while (datetime.utcnow() - start_time).seconds < max_wait:
            await asyncio.sleep(poll_interval)
            
            status = await self.get_status(task_id)
            if status == "reported":
                report = await self.get_report(task_id)
                if report:
                    result = self._parse_report(result, report)
                    result.completed_at = datetime.utcnow()
                    result.analysis_time_ms = int((result.completed_at - result.submitted_at).total_seconds() * 1000)
                    return result
            elif status in ["failed", "failed_analysis"]:
                result.status = AnalysisStatus.FAILED
                result.error_message = "Cuckoo analysis failed"
                return result
        
        result.status = AnalysisStatus.TIMEOUT
        result.error_message = f"Analysis timed out after {max_wait} seconds"
        return result
    
    def _parse_report(self, result: URLAnalysisResult, report: Dict[str, Any]) -> URLAnalysisResult:
        """Parse Cuckoo report data."""
        result.status = AnalysisStatus.COMPLETED
        result.raw_response = report
        
        # Get info section
        info = report.get("info", {})
        result.threat_score = info.get("score", 0)
        
        # Determine threat level
        if result.threat_score >= 8:
            result.threat_level = "critical"
            result.is_malicious = True
            result.is_suspicious = True
        elif result.threat_score >= 5:
            result.threat_level = "high"
            result.is_suspicious = True
        elif result.threat_score >= 3:
            result.threat_level = "medium"
            result.is_suspicious = True
        elif result.threat_score >= 1:
            result.threat_level = "low"
        else:
            result.threat_level = "clean"
        
        # Network data
        network = report.get("network", {})
        
        # Contacted hosts
        hosts = network.get("hosts", [])
        result.contacted_ips = [h.get("ip") for h in hosts if h.get("ip")][:20]
        
        # DNS requests
        dns = network.get("dns", [])
        result.contacted_domains = [d.get("request") for d in dns if d.get("request")][:20]
        
        # HTTP requests for redirects
        http = network.get("http", [])
        result.redirects = [h.get("uri") for h in http if h.get("uri")][:5]
        
        # Signatures
        signatures = report.get("signatures", [])
        indicators = []
        for sig in signatures[:10]:
            severity = sig.get("severity", 0)
            name = sig.get("name", "")
            if severity >= 3:
                indicators.append(f"🔴 {name}")
            elif severity >= 2:
                indicators.append(f"🟠 {name}")
        result.indicators = indicators
        
        return result


class URLSandboxService:
    """
    Main URL Sandbox Service.
    
    Provides unified interface for URL analysis across multiple sandbox providers.
    Includes caching to avoid redundant analyses.
    """
    
    def __init__(self):
        self.urlscan = URLScanClient()
        self.cuckoo = CuckooClient()
        self._cache: Dict[str, URLAnalysisResult] = {}
        self._cache_ttl = timedelta(hours=1)
    
    async def close(self):
        """Close all client sessions."""
        await self.urlscan.close()
        await self.cuckoo.close()
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all sandbox providers."""
        return {
            "urlscan": {
                "configured": self.urlscan.is_configured(),
                "provider": "urlscan.io",
                "description": "Cloud-based URL scanner"
            },
            "cuckoo": {
                "configured": self.cuckoo.is_configured(),
                "provider": "Cuckoo Sandbox",
                "description": "Self-hosted malware sandbox"
            }
        }
    
    def _get_cache_key(self, url: str) -> str:
        """Generate cache key for URL."""
        return hashlib.sha256(url.encode()).hexdigest()
    
    def _get_cached(self, url: str) -> Optional[URLAnalysisResult]:
        """Get cached result if still valid."""
        key = self._get_cache_key(url)
        if key in self._cache:
            result = self._cache[key]
            if result.completed_at:
                age = datetime.utcnow() - result.completed_at
                if age < self._cache_ttl:
                    cached_result = URLAnalysisResult(
                        url=result.url,
                        provider=result.provider,
                        task_id=result.task_id,
                        status=AnalysisStatus.CACHED,
                        is_malicious=result.is_malicious,
                        is_suspicious=result.is_suspicious,
                        threat_score=result.threat_score,
                        threat_level=result.threat_level,
                        categories=result.categories,
                        indicators=result.indicators,
                        tags=result.tags,
                        contacted_ips=result.contacted_ips,
                        contacted_domains=result.contacted_domains,
                        redirects=result.redirects,
                        final_url=result.final_url,
                        page_title=result.page_title,
                        screenshot_url=result.screenshot_url,
                        report_url=result.report_url,
                        submitted_at=result.submitted_at,
                        completed_at=result.completed_at,
                    )
                    return cached_result
            del self._cache[key]
        return None
    
    def _cache_result(self, url: str, result: URLAnalysisResult):
        """Cache analysis result."""
        if result.status == AnalysisStatus.COMPLETED:
            key = self._get_cache_key(url)
            self._cache[key] = result
    
    async def analyze_url(
        self,
        url: str,
        provider: SandboxProvider = SandboxProvider.AUTO,
        wait_for_result: bool = True,
        max_wait: int = 120
    ) -> URLAnalysisResult:
        """
        Analyze a URL using sandbox.
        
        Args:
            url: URL to analyze
            provider: Which sandbox to use (auto selects best available)
            wait_for_result: Whether to wait for analysis to complete
            max_wait: Maximum wait time in seconds
            
        Returns:
            URLAnalysisResult with analysis findings
        """
        # Check cache first
        cached = self._get_cached(url)
        if cached:
            logger.info(f"Returning cached result for {url}")
            return cached
        
        # Select provider
        if provider == SandboxProvider.AUTO:
            if self.urlscan.is_configured():
                provider = SandboxProvider.URLSCAN
            elif self.cuckoo.is_configured():
                provider = SandboxProvider.CUCKOO
            else:
                return URLAnalysisResult(
                    url=url,
                    provider="none",
                    status=AnalysisStatus.FAILED,
                    error_message="No sandbox provider configured"
                )
        
        # Run analysis
        if provider == SandboxProvider.URLSCAN:
            result = await self.urlscan.analyze_url(url, wait_for_result, max_wait)
        elif provider == SandboxProvider.CUCKOO:
            result = await self.cuckoo.analyze_url(url, wait_for_result, max_wait)
        else:
            return URLAnalysisResult(
                url=url,
                provider=str(provider),
                status=AnalysisStatus.FAILED,
                error_message=f"Unknown provider: {provider}"
            )
        
        # Cache successful results
        self._cache_result(url, result)
        
        return result
    
    async def analyze_urls(
        self,
        urls: List[str],
        provider: SandboxProvider = SandboxProvider.AUTO,
        wait_for_result: bool = True,
        max_wait: int = 120
    ) -> List[URLAnalysisResult]:
        """Analyze multiple URLs concurrently."""
        tasks = [
            self.analyze_url(url, provider, wait_for_result, max_wait)
            for url in urls[:10]  # Limit to 10 URLs
        ]
        return await asyncio.gather(*tasks)


# Global singleton instance
_sandbox_service: Optional[URLSandboxService] = None


def get_url_sandbox_service() -> URLSandboxService:
    """Get or create the URL sandbox service instance."""
    global _sandbox_service
    if _sandbox_service is None:
        _sandbox_service = URLSandboxService()
    return _sandbox_service
