"""
NiksES Sandbox Integration Service - Hybrid Analysis

Provides dynamic analysis of email attachments through Hybrid Analysis API.
Gracefully handles cases with no attachments or no API key configured.
"""

import asyncio
import hashlib
import httpx
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
import logging
import os
import base64

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    """Unified sandbox analysis result."""
    provider: str
    submission_id: str
    status: str  # pending, running, completed, error, skipped, not_configured
    filename: Optional[str] = None
    file_hash: Optional[str] = None
    verdict: Optional[str] = None  # malicious, suspicious, clean, unknown
    threat_score: Optional[int] = None  # 0-100
    threat_level: Optional[str] = None  # high, medium, low, none
    malware_families: List[str] = None
    signatures: List[Dict[str, Any]] = None
    mitre_attacks: List[Dict[str, str]] = None
    network_iocs: Dict[str, List[str]] = None
    file_iocs: List[Dict[str, str]] = None
    processes: List[Dict[str, Any]] = None
    registry_keys: List[str] = None
    report_url: Optional[str] = None
    analysis_time: Optional[int] = None
    environment: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.malware_families is None:
            self.malware_families = []
        if self.signatures is None:
            self.signatures = []
        if self.mitre_attacks is None:
            self.mitre_attacks = []
        if self.network_iocs is None:
            self.network_iocs = {"domains": [], "ips": [], "urls": []}
        if self.file_iocs is None:
            self.file_iocs = []
        if self.processes is None:
            self.processes = []
        if self.registry_keys is None:
            self.registry_keys = []

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HybridAnalysisClient:
    """
    Hybrid Analysis API Client
    
    Free tier: 100 submissions/month, 200 searches/month
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """
    
    BASE_URL = "https://www.hybrid-analysis.com/api/v2"
    
    ENVIRONMENTS = {
        "win10_64": 120,
        "win7_64": 110,
        "win7_32": 100,
        "android": 200,
        "linux": 300,
    }
    
    ANALYZABLE_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse',
        '.wsf', '.wsh', '.msc', '.cpl', '.com', '.pif',
        '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.xlsb',
        '.ppt', '.pptx', '.pptm', '.rtf', '.pdf',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img', '.cab',
        '.hta', '.jar', '.lnk', '.msi', '.msix', '.appx',
        '.html', '.htm', '.svg', '.swf',
    }
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("HYBRID_ANALYSIS_API_KEY", "")
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "NiksES/1.0 (Email Security Analyzer)",
            "Accept": "application/json"
        }
        self._configured = bool(self.api_key)
    
    @property
    def is_configured(self) -> bool:
        return self._configured
    
    def update_api_key(self, api_key: str):
        """Update API key at runtime."""
        self.api_key = api_key
        self.headers["api-key"] = api_key
        self._configured = bool(api_key)
    
    def should_analyze(self, filename: str) -> bool:
        """Check if file type is worth analyzing in sandbox."""
        if not filename:
            return False
        ext = os.path.splitext(filename.lower())[1]
        return ext in self.ANALYZABLE_EXTENSIONS
    
    async def get_quota(self) -> Dict[str, Any]:
        """Get current API quota status."""
        if not self.is_configured:
            return {"error": "API key not configured", "configured": False}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/key/current",
                    headers=self.headers
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "configured": True,
                        "api_key_valid": True,
                        "limits": {
                            "submissions_limit": data.get("api_key_data", {}).get("limit_submission", 0),
                            "search_limit": data.get("api_key_data", {}).get("limit_search", 0),
                        },
                        "used": {
                            "submissions_used": data.get("api_key_data", {}).get("used_submission", 0),
                            "search_used": data.get("api_key_data", {}).get("used_search", 0),
                        }
                    }
                else:
                    return {"error": f"API error: {response.status_code}", "configured": True, "api_key_valid": False}
            except Exception as e:
                return {"error": str(e), "configured": True}
    
    async def search_hash(self, file_hash: str) -> SandboxResult:
        """Search for existing analysis by hash."""
        if not self.is_configured:
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id="",
                status="not_configured",
                error="Hybrid Analysis API key not configured"
            )
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/search/hash",
                    headers=self.headers,
                    data={"hash": file_hash}
                )
                
                if response.status_code == 200:
                    results = response.json()
                    if results and len(results) > 0:
                        report = results[0]
                        return self._parse_search_result(report, file_hash)
                    else:
                        return SandboxResult(
                            provider="hybrid_analysis",
                            submission_id=file_hash,
                            file_hash=file_hash,
                            status="not_found",
                            verdict="unknown"
                        )
                elif response.status_code == 403:
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id="",
                        status="error",
                        error="API key invalid or quota exceeded"
                    )
                else:
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id="",
                        status="error",
                        error=f"Search failed: {response.status_code}"
                    )
            except Exception as e:
                logger.error(f"Hybrid Analysis search error: {e}")
                return SandboxResult(
                    provider="hybrid_analysis",
                    submission_id="",
                    status="error",
                    error=str(e)
                )
    
    async def submit_file(
        self, 
        file_content: bytes, 
        filename: str,
        environment: str = "win10_64"
    ) -> SandboxResult:
        """Submit file for analysis."""
        if not self.is_configured:
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id="",
                filename=filename,
                status="not_configured",
                error="Hybrid Analysis API key not configured"
            )
        
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Check if already analyzed
        existing = await self.search_hash(file_hash)
        if existing.status == "completed":
            logger.info(f"Found existing analysis for {filename} ({file_hash[:16]}...)")
            existing.filename = filename
            return existing
        
        env_id = self.ENVIRONMENTS.get(environment, 120)
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/submit/file",
                    headers=self.headers,
                    files={"file": (filename, file_content)},
                    data={
                        "environment_id": env_id,
                        "allow_community_access": "true"
                    }
                )
                
                if response.status_code == 201:
                    data = response.json()
                    sha256 = data.get("sha256", file_hash)
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id=data.get("job_id", sha256),
                        filename=filename,
                        file_hash=sha256,
                        status="submitted",
                        environment=environment,
                        report_url=f"https://www.hybrid-analysis.com/sample/{sha256}"
                    )
                elif response.status_code == 429:
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id="",
                        filename=filename,
                        file_hash=file_hash,
                        status="rate_limited",
                        error="API quota exceeded. Try again later."
                    )
                else:
                    error_detail = ""
                    try:
                        error_detail = response.json().get("message", "")
                    except:
                        pass
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id="",
                        filename=filename,
                        file_hash=file_hash,
                        status="error",
                        error=f"Submission failed ({response.status_code}): {error_detail}"
                    )
            except Exception as e:
                logger.error(f"Hybrid Analysis submission error: {e}")
                return SandboxResult(
                    provider="hybrid_analysis",
                    submission_id="",
                    filename=filename,
                    file_hash=file_hash,
                    status="error",
                    error=str(e)
                )
    
    async def get_report(self, submission_id: str) -> SandboxResult:
        """Get detailed analysis report."""
        if not self.is_configured:
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id=submission_id,
                status="not_configured",
                error="API key not configured"
            )
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/report/{submission_id}/summary",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_full_report(data, submission_id)
                elif response.status_code == 404:
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id=submission_id,
                        status="pending",
                        error="Analysis still in progress"
                    )
                else:
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id=submission_id,
                        status="error",
                        error=f"Report fetch failed: {response.status_code}"
                    )
            except Exception as e:
                return SandboxResult(
                    provider="hybrid_analysis",
                    submission_id=submission_id,
                    status="error",
                    error=str(e)
                )
    
    def _parse_search_result(self, report: Dict, file_hash: str) -> SandboxResult:
        """Parse search result into SandboxResult."""
        verdict = self._map_verdict(report.get("verdict"))
        threat_score = report.get("threat_score", 0)
        
        families = []
        if report.get("vx_family"):
            families = [f.strip() for f in report["vx_family"].split(",") if f.strip()]
        
        mitre = []
        for technique in report.get("mitre_attcks", []):
            mitre.append({
                "tactic": technique.get("tactic", ""),
                "technique": technique.get("technique", ""),
                "attck_id": technique.get("attck_id", "")
            })
        
        return SandboxResult(
            provider="hybrid_analysis",
            submission_id=report.get("sha256", file_hash),
            file_hash=report.get("sha256", file_hash),
            status="completed",
            verdict=verdict,
            threat_score=threat_score,
            threat_level=self._score_to_level(threat_score),
            malware_families=families,
            mitre_attacks=mitre,
            environment=report.get("environment_description", ""),
            report_url=f"https://www.hybrid-analysis.com/sample/{report.get('sha256', file_hash)}"
        )
    
    def _parse_full_report(self, data: Dict, submission_id: str) -> SandboxResult:
        """Parse full report into SandboxResult."""
        state = data.get("state", "").upper()
        
        if state != "SUCCESS":
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id=submission_id,
                status="running" if state == "IN_PROGRESS" else "pending"
            )
        
        verdict = self._map_verdict(data.get("verdict"))
        threat_score = data.get("threat_score", 0)
        
        families = []
        if data.get("vx_family"):
            families = [f.strip() for f in data["vx_family"].split(",") if f.strip()]
        
        signatures = []
        for sig in data.get("signatures", []):
            signatures.append({
                "name": sig.get("name", ""),
                "description": sig.get("description", ""),
                "severity": sig.get("severity", ""),
                "category": sig.get("category", "")
            })
        
        mitre = []
        for technique in data.get("mitre_attcks", []):
            mitre.append({
                "tactic": technique.get("tactic", ""),
                "technique": technique.get("technique", ""),
                "attck_id": technique.get("attck_id", "")
            })
        
        network_iocs = {
            "domains": data.get("domains", []),
            "ips": data.get("hosts", []),
            "urls": data.get("extracted_urls", [])
        }
        
        file_iocs = []
        for dropped in data.get("dropped_files", []):
            file_iocs.append({
                "filename": dropped.get("name", ""),
                "sha256": dropped.get("sha256", ""),
                "type": dropped.get("type", ""),
                "malicious": dropped.get("threat_level", 0) > 0
            })
        
        processes = []
        for proc in data.get("processes", [])[:20]:
            processes.append({
                "name": proc.get("name", ""),
                "command_line": proc.get("command_line", ""),
                "pid": proc.get("pid", 0)
            })
        
        registry = data.get("registry_keys_modified", [])[:20]
        
        return SandboxResult(
            provider="hybrid_analysis",
            submission_id=submission_id,
            file_hash=data.get("sha256", submission_id),
            status="completed",
            verdict=verdict,
            threat_score=threat_score,
            threat_level=self._score_to_level(threat_score),
            malware_families=families,
            signatures=signatures,
            mitre_attacks=mitre,
            network_iocs=network_iocs,
            file_iocs=file_iocs,
            processes=processes,
            registry_keys=registry,
            environment=data.get("environment_description", ""),
            report_url=f"https://www.hybrid-analysis.com/sample/{data.get('sha256', submission_id)}"
        )
    
    def _map_verdict(self, verdict: str) -> str:
        if not verdict:
            return "unknown"
        verdict_lower = verdict.lower()
        mapping = {
            "malicious": "malicious",
            "suspicious": "suspicious",
            "whitelisted": "clean",
            "no specific threat": "clean",
            "no verdict": "unknown",
            "clean": "clean"
        }
        return mapping.get(verdict_lower, "unknown")
    
    def _score_to_level(self, score: int) -> str:
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 10:
            return "low"
        return "none"


class SandboxService:
    """High-level sandbox service for NiksES integration."""
    
    def __init__(self):
        self.client = HybridAnalysisClient()
        self._enabled = False
    
    @property
    def is_enabled(self) -> bool:
        return self._enabled and self.client.is_configured
    
    def configure(self, api_key: str = None, enabled: bool = True):
        """Configure sandbox service."""
        if api_key:
            self.client.update_api_key(api_key)
        self._enabled = enabled
        logger.info(f"Sandbox service configured: enabled={enabled}, api_configured={self.client.is_configured}")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get sandbox service status and quota."""
        if not self.client.is_configured:
            return {
                "enabled": self._enabled,
                "configured": False,
                "provider": "hybrid_analysis",
                "message": "API key not configured"
            }
        
        quota = await self.client.get_quota()
        return {
            "enabled": self._enabled,
            "configured": True,
            "provider": "hybrid_analysis",
            "quota": quota
        }
    
    async def analyze_attachments(
        self, 
        attachments: List[Dict[str, Any]],
        wait_for_results: bool = False,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """Analyze email attachments through sandbox."""
        
        # No attachments
        if not attachments:
            return {
                "analyzed": False,
                "reason": "no_attachments",
                "results": [],
                "summary": {
                    "total": 0,
                    "analyzed": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "clean": 0,
                    "skipped": 0
                }
            }
        
        # Not configured
        if not self.is_enabled:
            return {
                "analyzed": False,
                "reason": "sandbox_not_configured",
                "results": [],
                "summary": {
                    "total": len(attachments),
                    "analyzed": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "clean": 0,
                    "skipped": len(attachments)
                }
            }
        
        results = []
        analyzed = 0
        skipped = 0
        
        for attachment in attachments:
            filename = attachment.get('filename') or attachment.get('name') or 'unknown'
            content = attachment.get('content_bytes') or attachment.get('content') or attachment.get('data')
            
            # Skip non-analyzable files
            if not self.client.should_analyze(filename):
                logger.info(f"Skipping {filename} - not analyzable")
                results.append(SandboxResult(
                    provider="hybrid_analysis",
                    submission_id="",
                    filename=filename,
                    status="skipped",
                    error="File type not suitable for dynamic analysis"
                ).to_dict())
                skipped += 1
                continue
            
            # Skip if no content
            if not content:
                logger.warning(f"Skipping {filename} - no content")
                results.append(SandboxResult(
                    provider="hybrid_analysis",
                    submission_id="",
                    filename=filename,
                    status="skipped",
                    error="No file content available"
                ).to_dict())
                skipped += 1
                continue
            
            # Convert to bytes if base64
            if isinstance(content, str):
                try:
                    content = base64.b64decode(content)
                except:
                    skipped += 1
                    continue
            
            # Submit for analysis
            result = await self.client.submit_file(content, filename)
            
            # Optionally wait for results
            if wait_for_results and result.status == "submitted":
                result = await self._wait_for_result(result.submission_id, timeout)
            
            results.append(result.to_dict())
            analyzed += 1
        
        summary = self._calculate_summary(results)
        summary["total"] = len(attachments)
        summary["analyzed"] = analyzed
        summary["skipped"] = skipped
        
        return {
            "analyzed": analyzed > 0,
            "reason": "success" if analyzed > 0 else "all_skipped",
            "results": results,
            "summary": summary
        }
    
    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check hash against existing analyses."""
        if not self.is_enabled:
            return {"found": False, "reason": "sandbox_not_configured", "result": None}
        
        result = await self.client.search_hash(file_hash)
        return {
            "found": result.status == "completed",
            "reason": "success",
            "result": result.to_dict()
        }
    
    async def get_report(self, submission_id: str) -> Dict[str, Any]:
        """Get detailed report for a submission."""
        if not self.is_enabled:
            return {"success": False, "reason": "sandbox_not_configured", "result": None}
        
        result = await self.client.get_report(submission_id)
        return {
            "success": result.status == "completed",
            "reason": "success",
            "result": result.to_dict()
        }
    
    async def _wait_for_result(self, submission_id: str, timeout: int) -> SandboxResult:
        """Poll for results until complete or timeout."""
        poll_interval = 15
        elapsed = 0
        
        while elapsed < timeout:
            result = await self.client.get_report(submission_id)
            if result.status in ["completed", "error"]:
                return result
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        
        return SandboxResult(
            provider="hybrid_analysis",
            submission_id=submission_id,
            status="timeout",
            error=f"Analysis did not complete within {timeout} seconds"
        )
    
    def _calculate_summary(self, results: List[Dict]) -> Dict[str, int]:
        """Calculate summary statistics."""
        malicious = 0
        suspicious = 0
        clean = 0
        
        for r in results:
            if r.get("status") == "completed":
                verdict = r.get("verdict", "unknown")
                if verdict == "malicious":
                    malicious += 1
                elif verdict == "suspicious":
                    suspicious += 1
                elif verdict == "clean":
                    clean += 1
        
        return {"malicious": malicious, "suspicious": suspicious, "clean": clean}


# Global singleton
_sandbox_service = None


def get_sandbox_service() -> SandboxService:
    """Get the global sandbox service instance."""
    global _sandbox_service
    if _sandbox_service is None:
        _sandbox_service = SandboxService()
        # Auto-configure from environment
        api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
        if api_key:
            _sandbox_service.configure(api_key=api_key, enabled=True)
    return _sandbox_service
