"""
NiksES Sandbox Integration Service - Hybrid Analysis

Provides dynamic analysis of email attachments through Hybrid Analysis API.
Gracefully handles cases with no attachments or no API key configured.

Version: 2.3.0 (2025-12-11) - Added screenshots, fixed None comparisons, response format parsing
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

SANDBOX_VERSION = "2.3.0"
logger.info(f"Sandbox service module loaded - version {SANDBOX_VERSION}")


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
    
    # Additional Hybrid Analysis fields
    av_detect: Optional[int] = None  # Number of AV engines detecting as malicious
    vt_detect: Optional[int] = None  # VirusTotal detections
    total_signatures: Optional[int] = None
    total_processes: Optional[int] = None
    total_network_connections: Optional[int] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    classification_tags: List[str] = None
    submit_name: Optional[str] = None
    type_short: Optional[str] = None  # e.g., "script", "peexe", "document"
    contacted_hosts: List[Dict[str, Any]] = None  # IP + port + protocol

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
        if self.classification_tags is None:
            self.classification_tags = []
        if self.contacted_hosts is None:
            self.contacted_hosts = []

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HybridAnalysisClient:
    """
    Hybrid Analysis API Client
    
    Free tier: 100 submissions/month, 200 searches/month
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """
    
    BASE_URL = "https://hybrid-analysis.com/api/v2"
    
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
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
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
    
    async def search_hash(self, file_hash: str, fetch_full_report: bool = True) -> SandboxResult:
        """Search for existing analysis by hash. Optionally fetches full report."""
        if not self.is_configured:
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id="",
                status="not_configured",
                error="Hybrid Analysis API key not configured"
            )
        
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            try:
                # API v2.35.0: Changed from POST to GET for hash search
                response = await client.get(
                    f"{self.BASE_URL}/search/hash",
                    headers=self.headers,
                    params={"hash": file_hash}
                )
                
                logger.info(f"Hash search response: {response.status_code} for {file_hash[:16]}...")
                
                if response.status_code == 200:
                    try:
                        results = response.json()
                        logger.info(f"Hash search response type: {type(results)}, content: {str(results)[:200]}")
                    except Exception as json_err:
                        logger.error(f"Failed to parse search response: {json_err}")
                        return SandboxResult(
                            provider="hybrid_analysis",
                            submission_id=file_hash,
                            file_hash=file_hash,
                            status="error",
                            error=f"Invalid response format: {json_err}"
                        )
                    
                    # Handle different response formats
                    if results is None:
                        results = []
                    elif isinstance(results, dict):
                        # Hybrid Analysis uses 'reports' key
                        results = results.get("reports", results.get("result", results.get("results", [])))
                        if not isinstance(results, list):
                            results = [results] if results else []
                    
                    logger.info(f"Hash search returned {len(results) if isinstance(results, list) else 'non-list'} results")
                    
                    if results and len(results) > 0:
                        report = results[0]
                        # 'id' in reports is the job_id, sha256 may be at top level or in report
                        sha256 = report.get("sha256", file_hash)
                        # If sha256 not in report, check parent dict
                        if sha256 == file_hash and isinstance(response.json(), dict):
                            sha256s = response.json().get("sha256s", [])
                            if sha256s:
                                sha256 = sha256s[0]
                        
                        # 'id' field is the job_id  
                        job_id = report.get("id", report.get("job_id", ""))
                        env_id = report.get("environment_id", 120)
                        
                        # Use sha256:env_id format for report URL (job_id alone doesn't work)
                        report_id = f"{sha256}:{env_id}"
                        
                        logger.info(f"Hash found: sha256={sha256[:16]}..., job_id={job_id}, report_id={report_id}")
                        
                        # Fetch full report for comprehensive details
                        if fetch_full_report:
                            logger.info(f"Fetching full report for {report_id}")
                            return await self.get_report(report_id)
                        else:
                            return self._parse_search_result(report, file_hash)
                    else:
                        logger.info(f"No existing analysis found for {file_hash[:16]}...")
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
        
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
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
                    job_id = data.get("job_id", "")  # Format: {sha256}:{env_id}
                    
                    # Use job_id for report lookups (contains environment_id)
                    # Fall back to sha256:env_id if job_id not provided
                    report_id = job_id if job_id else f"{sha256}:{env_id}"
                    
                    logger.info(f"Submission successful: sha256={sha256[:16]}..., job_id={job_id}, report_id={report_id}")
                    
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id=report_id,  # Use job_id format for report lookups
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
        """Get detailed analysis report.
        
        submission_id can be:
        - {sha256}:{environment_id} format (from job_id)
        - Just {sha256} (will try common environments)
        """
        if not self.is_configured:
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id=submission_id,
                status="not_configured",
                error="API key not configured"
            )
        
        # If submission_id already has environment, use it directly
        if ":" in submission_id:
            report_id = submission_id
            logger.info(f"Fetching report for: {report_id}")
        else:
            # Try with default environment (Windows 10 64-bit)
            report_id = f"{submission_id}:120"
            logger.info(f"Fetching report for: {report_id} (added default env)")
        
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/report/{report_id}/summary",
                    headers=self.headers
                )
                
                logger.info(f"Report response: {response.status_code}")
                
                # If 400/404 with default env, try other common environments
                if response.status_code in [400, 404] and ":" not in submission_id:
                    for env_id in [110, 100, 160]:  # Win10 32-bit, Win7 32-bit, Linux
                        alt_report_id = f"{submission_id}:{env_id}"
                        logger.info(f"Trying alternate environment: {alt_report_id}")
                        response = await client.get(
                            f"{self.BASE_URL}/report/{alt_report_id}/summary",
                            headers=self.headers
                        )
                        if response.status_code == 200:
                            report_id = alt_report_id
                            break
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Log all available fields for debugging
                    logger.info(f"=== HYBRID ANALYSIS RAW RESPONSE ===")
                    logger.info(f"Keys: {list(data.keys())}")
                    logger.info(f"verdict: {data.get('verdict')}")
                    logger.info(f"threat_score: {data.get('threat_score')}")
                    logger.info(f"av_detect: {data.get('av_detect')}")
                    logger.info(f"vx_family: {data.get('vx_family')}")
                    logger.info(f"state: {data.get('state')}")
                    logger.info(f"environment_description: {data.get('environment_description')}")
                    logger.info(f"total_signatures: {data.get('total_signatures')}")
                    logger.info(f"total_processes: {data.get('total_processes')}")
                    logger.info(f"total_network_connections: {data.get('total_network_connections')}")
                    logger.info(f"mitre_attcks count: {len(data.get('mitre_attcks', []))}")
                    logger.info(f"signatures count: {len(data.get('signatures', []))}")
                    logger.info(f"domains: {data.get('domains', [])[:5]}")
                    logger.info(f"hosts: {data.get('hosts', [])[:5]}")
                    logger.info(f"processes count: {len(data.get('processes', []))}")
                    logger.info(f"extracted_files count: {len(data.get('extracted_files', []))}")
                    logger.info(f"classification_tags: {data.get('classification_tags')}")
                    logger.info(f"=== END RAW RESPONSE ===")
                    
                    result = self._parse_full_report(data, submission_id)
                    logger.info(f"Report parsed: status={result.status}, verdict={result.verdict}")
                    return result
                elif response.status_code == 404:
                    logger.info(f"Report not ready yet for {report_id}")
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id=submission_id,
                        status="pending",
                        error="Analysis still in progress"
                    )
                else:
                    logger.warning(f"Report fetch failed: {response.status_code}")
                    return SandboxResult(
                        provider="hybrid_analysis",
                        submission_id=submission_id,
                        status="error",
                        error=f"Report fetch failed: {response.status_code}"
                    )
            except Exception as e:
                logger.error(f"Report fetch error: {e}")
                return SandboxResult(
                    provider="hybrid_analysis",
                    submission_id=submission_id,
                    status="error",
                    error=str(e)
                )
    
    async def get_screenshots(self, report_id: str) -> Dict[str, Any]:
        """Get screenshots from sandbox analysis.
        
        Args:
            report_id: Format {sha256}:{environment_id}
            
        Returns:
            Dict with 'screenshots' key containing list of base64 images
        """
        if not self.is_configured:
            return {"success": False, "error": "API not configured", "screenshots": []}
        
        # Ensure report_id has environment
        if ":" not in report_id:
            report_id = f"{report_id}:120"
        
        logger.info(f"Fetching screenshots for: {report_id}")
        
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/report/{report_id}/screenshots",
                    headers=self.headers
                )
                
                logger.info(f"Screenshots response: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    screenshots = []
                    
                    # Response is array of base64 strings or objects
                    if isinstance(data, list):
                        for i, item in enumerate(data):
                            if isinstance(item, str):
                                # Direct base64 string
                                screenshots.append({
                                    "index": i,
                                    "image": item,
                                    "format": "png"
                                })
                            elif isinstance(item, dict):
                                # Object with image data
                                screenshots.append({
                                    "index": i,
                                    "image": item.get("image", item.get("data", "")),
                                    "format": item.get("format", "png"),
                                    "name": item.get("name", f"screenshot_{i}")
                                })
                    
                    logger.info(f"Retrieved {len(screenshots)} screenshots")
                    return {
                        "success": True,
                        "screenshots": screenshots,
                        "count": len(screenshots)
                    }
                elif response.status_code == 404:
                    return {"success": True, "screenshots": [], "count": 0, "message": "No screenshots available"}
                else:
                    return {"success": False, "error": f"Failed: {response.status_code}", "screenshots": []}
                    
            except Exception as e:
                logger.error(f"Screenshots fetch error: {e}")
                return {"success": False, "error": str(e), "screenshots": []}
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
        """Parse full report into SandboxResult with comprehensive details."""
        state = data.get("state", "").upper()
        
        logger.info(f"Parsing report - state: {state}, keys: {list(data.keys())[:20]}")
        
        if state not in ["SUCCESS", "ERROR"] and state != "":
            return SandboxResult(
                provider="hybrid_analysis",
                submission_id=submission_id,
                status="running" if state == "IN_PROGRESS" else "pending"
            )
        
        verdict = self._map_verdict(data.get("verdict"))
        # Handle None values explicitly
        threat_score = data.get("threat_score")
        if threat_score is None:
            threat_score = data.get("av_detect") or 0
        threat_score = int(threat_score) if threat_score else 0
        
        # Malware families
        families = []
        if data.get("vx_family"):
            families = [f.strip() for f in str(data["vx_family"]).split(",") if f.strip()]
        
        # Classification tags  
        tags = data.get("classification_tags", []) or []
        if tags and isinstance(tags, list):
            families.extend([t for t in tags if t not in families])
        
        # Behavioral signatures
        signatures = []
        for sig in data.get("signatures", []) or []:
            if isinstance(sig, dict):
                signatures.append({
                    "name": sig.get("name", ""),
                    "description": sig.get("description", ""),
                    "severity": sig.get("severity", sig.get("threat_level_human", "")),
                    "category": sig.get("category", "")
                })
        
        # MITRE ATT&CK techniques
        mitre = []
        mitre_data = data.get("mitre_attcks", []) or data.get("mitre_attacks", []) or []
        for technique in mitre_data:
            if isinstance(technique, dict):
                mitre.append({
                    "tactic": technique.get("tactic", ""),
                    "technique": technique.get("technique", ""),
                    "attck_id": technique.get("attck_id", technique.get("id", ""))
                })
        
        # Network IOCs - comprehensive extraction
        domains = data.get("domains", []) or []
        hosts = data.get("hosts", []) or []
        urls = data.get("extracted_urls", []) or data.get("compromised_hosts", []) or []
        
        # Also check for contacted hosts
        contacted = data.get("contacted_hosts", []) or []
        for host in contacted:
            if isinstance(host, dict):
                if host.get("ip") and host.get("ip") not in hosts:
                    hosts.append(host.get("ip"))
                if host.get("hostname") and host.get("hostname") not in domains:
                    domains.append(host.get("hostname"))
        
        network_iocs = {
            "domains": domains[:50],  # Limit to 50
            "ips": hosts[:50],
            "urls": urls[:50]
        }
        
        # Dropped files
        file_iocs = []
        dropped = data.get("dropped_files", []) or data.get("extracted_files", []) or []
        for f in dropped[:30]:
            if isinstance(f, dict):
                threat_level = f.get("threat_level") or 0
                av_matched = f.get("av_matched") or 0
                file_iocs.append({
                    "filename": f.get("name", f.get("filename", "unknown")),
                    "sha256": f.get("sha256", ""),
                    "type": f.get("type", f.get("file_type", "")),
                    "size": f.get("size") or f.get("file_size") or 0,
                    "malicious": (threat_level > 0) or (av_matched > 0)
                })
        
        # Processes
        processes = []
        proc_data = data.get("processes", []) or data.get("process_list", []) or []
        for proc in proc_data[:30]:
            if isinstance(proc, dict):
                processes.append({
                    "name": proc.get("name") or proc.get("process_name") or "",
                    "command_line": proc.get("command_line") or proc.get("cmd") or "",
                    "pid": proc.get("pid") or proc.get("process_id") or 0,
                    "parent_pid": proc.get("parentuid") or proc.get("parent_pid") or 0,
                    "file_accesses": proc.get("file_accesses") or 0,
                    "registry_accesses": proc.get("registry_accesses") or 0
                })
        
        # Registry modifications
        registry = []
        reg_data = data.get("registry_keys_modified", []) or data.get("registry", []) or []
        for reg in reg_data[:30]:
            if isinstance(reg, str):
                registry.append(reg)
            elif isinstance(reg, dict):
                registry.append(reg.get("key", str(reg)))
        
        # Additional metadata
        environment = data.get("environment_description", "") or data.get("environment", "")
        analysis_time = data.get("analysis_start_time", "")
        total_processes = data.get("total_processes", len(processes))
        total_network = data.get("total_network_connections", len(hosts) + len(domains))
        
        # AV detections
        av_detect = data.get("av_detect", 0) or 0
        vt_detect = data.get("vt_detect", 0) or 0
        total_signatures = data.get("total_signatures", len(signatures))
        
        # File metadata
        file_type = data.get("type", "") or data.get("type_short", "")
        type_short = data.get("type_short", "")
        file_size = data.get("size", 0) or 0
        submit_name = data.get("submit_name", "")
        
        # Classification tags (separate from families)
        classification_tags = data.get("classification_tags", []) or []
        
        # Contacted hosts with details
        contacted_hosts = []
        for host in data.get("contacted_hosts", []) or []:
            if isinstance(host, dict):
                contacted_hosts.append({
                    "ip": host.get("ip", ""),
                    "port": host.get("port", 0),
                    "protocol": host.get("protocol", ""),
                    "hostname": host.get("hostname", ""),
                    "country": host.get("country", "")
                })
        
        sha256 = data.get("sha256", submission_id)
        
        logger.info(f"Parsed report: verdict={verdict}, score={threat_score}, av_detect={av_detect}, "
                   f"families={families}, mitre={len(mitre)}, signatures={len(signatures)}, "
                   f"network_iocs={len(domains)+len(hosts)}, processes={len(processes)}")
        
        return SandboxResult(
            provider="hybrid_analysis",
            submission_id=sha256,
            file_hash=sha256,
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
            environment=environment,
            report_url=f"https://www.hybrid-analysis.com/sample/{sha256}",
            # New fields
            av_detect=av_detect,
            vt_detect=vt_detect,
            total_signatures=total_signatures,
            total_processes=total_processes,
            total_network_connections=total_network,
            file_type=file_type,
            file_size=file_size,
            classification_tags=classification_tags,
            submit_name=submit_name,
            type_short=type_short,
            contacted_hosts=contacted_hosts
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
        if score is None:
            score = 0
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
        
        # Try to get API key from multiple sources
        api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
        
        # Also try to load from settings if env var not set
        if not api_key:
            try:
                from app.api.dependencies import get_settings
                settings = get_settings()
                api_key = getattr(settings, 'hybrid_analysis_api_key', '') or ''
                if api_key:
                    logger.info("Loaded Hybrid Analysis API key from settings")
            except Exception as e:
                logger.debug(f"Could not load settings for sandbox: {e}")
        
        if api_key:
            _sandbox_service.configure(api_key=api_key, enabled=True)
            logger.info(f"Sandbox service auto-configured: enabled=True")
        else:
            logger.info("Sandbox service: No API key found (env or settings)")
            
    return _sandbox_service
