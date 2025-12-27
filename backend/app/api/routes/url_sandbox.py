"""
NiksES URL Sandbox API Routes

Provides endpoints for URL dynamic analysis using URLScan.io and Cuckoo.
Separate from file sandbox (Hybrid Analysis).
"""

from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel, Field
import logging

from app.services.sandbox.url_sandbox import (
    get_url_sandbox_service,
    SandboxProvider,
    AnalysisStatus,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/url-sandbox", tags=["url-sandbox"])


class URLAnalysisRequest(BaseModel):
    """Request to analyze a URL."""
    url: str = Field(..., description="URL to analyze")
    provider: str = Field("auto", description="Provider: auto, urlscan, cuckoo")
    wait_for_result: bool = Field(True, description="Wait for analysis to complete")
    max_wait: int = Field(120, ge=10, le=300, description="Max wait time in seconds")


class BatchURLRequest(BaseModel):
    """Request to analyze multiple URLs."""
    urls: List[str] = Field(..., max_length=10, description="URLs to analyze (max 10)")
    provider: str = Field("auto", description="Provider: auto, urlscan, cuckoo")
    wait_for_result: bool = Field(True, description="Wait for results")


@router.get("/status")
async def get_url_sandbox_status():
    """
    Get URL sandbox service status.
    
    Returns configuration status for URLScan.io and Cuckoo providers.
    """
    service = get_url_sandbox_service()
    status = service.get_status()
    
    # Add overall status
    any_configured = any(p["configured"] for p in status.values())
    
    return {
        "service": "url-sandbox",
        "available": any_configured,
        "providers": status,
        "message": "URL sandbox ready" if any_configured else "No URL sandbox providers configured"
    }


@router.get("/providers")
async def get_providers():
    """Get list of available URL sandbox providers."""
    return {
        "providers": [
            {
                "id": "urlscan",
                "name": "URLScan.io",
                "description": "Cloud-based URL scanner with screenshot capture",
                "free_tier": "50 scans/day",
                "signup_url": "https://urlscan.io/user/signup/"
            },
            {
                "id": "cuckoo",
                "name": "Cuckoo Sandbox",
                "description": "Self-hosted malware analysis sandbox",
                "free_tier": "Self-hosted (free)",
                "signup_url": "https://cuckoosandbox.org/"
            }
        ]
    }


@router.post("/analyze")
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a single URL using sandbox.
    
    Submits URL to configured sandbox provider and optionally waits for results.
    Returns threat assessment, screenshots, and behavioral indicators.
    """
    service = get_url_sandbox_service()
    
    # Check if any provider is configured
    status = service.get_status()
    if not any(p["configured"] for p in status.values()):
        raise HTTPException(
            status_code=503,
            detail="No URL sandbox providers configured. Add URLSCAN_API_KEY to enable."
        )
    
    # Map provider string to enum
    provider_map = {
        "auto": SandboxProvider.AUTO,
        "urlscan": SandboxProvider.URLSCAN,
        "cuckoo": SandboxProvider.CUCKOO,
    }
    provider = provider_map.get(request.provider.lower(), SandboxProvider.AUTO)
    
    logger.info(f"Analyzing URL: {request.url} with provider: {provider}")
    
    try:
        result = await service.analyze_url(
            url=request.url,
            provider=provider,
            wait_for_result=request.wait_for_result,
            max_wait=request.max_wait
        )
        
        return {
            "success": True,
            "result": {
                "url": result.url,
                "provider": result.provider,
                "task_id": result.task_id,
                "status": result.status.value,
                "is_malicious": result.is_malicious,
                "is_suspicious": result.is_suspicious,
                "threat_score": result.threat_score,
                "threat_level": result.threat_level,
                "categories": result.categories,
                "indicators": result.indicators,
                "tags": result.tags,
                "contacted_ips": result.contacted_ips,
                "contacted_domains": result.contacted_domains,
                "redirects": result.redirects,
                "final_url": result.final_url,
                "page_title": result.page_title,
                "page_ip": result.page_ip,
                "page_country": result.page_country,
                "screenshot_url": result.screenshot_url,
                "report_url": result.report_url,
                "analysis_time_ms": result.analysis_time_ms,
                "error": result.error_message,
            }
        }
    except Exception as e:
        logger.error(f"URL analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-batch")
async def analyze_urls_batch(request: BatchURLRequest):
    """
    Analyze multiple URLs concurrently.
    
    Submits up to 10 URLs for analysis. Results are returned as an array.
    """
    service = get_url_sandbox_service()
    
    # Check configuration
    status = service.get_status()
    if not any(p["configured"] for p in status.values()):
        raise HTTPException(
            status_code=503,
            detail="No URL sandbox providers configured"
        )
    
    if not request.urls:
        raise HTTPException(status_code=400, detail="No URLs provided")
    
    if len(request.urls) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 URLs per batch")
    
    provider_map = {
        "auto": SandboxProvider.AUTO,
        "urlscan": SandboxProvider.URLSCAN,
        "cuckoo": SandboxProvider.CUCKOO,
    }
    provider = provider_map.get(request.provider.lower(), SandboxProvider.AUTO)
    
    logger.info(f"Batch analyzing {len(request.urls)} URLs")
    
    try:
        results = await service.analyze_urls(
            urls=request.urls,
            provider=provider,
            wait_for_result=request.wait_for_result
        )
        
        return {
            "success": True,
            "total": len(results),
            "results": [
                {
                    "url": r.url,
                    "provider": r.provider,
                    "status": r.status.value,
                    "is_malicious": r.is_malicious,
                    "threat_score": r.threat_score,
                    "threat_level": r.threat_level,
                    "report_url": r.report_url,
                    "error": r.error_message,
                }
                for r in results
            ]
        }
    except Exception as e:
        logger.error(f"Batch analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/check/{task_id}")
async def check_analysis_status(task_id: str, provider: str = "urlscan"):
    """
    Check status of a previously submitted URL analysis.
    
    Use this to poll for results when wait_for_result was False.
    """
    service = get_url_sandbox_service()
    
    # For now, just return that we need the full URL to check
    # In a real implementation, we'd store task_id -> URL mapping
    return {
        "task_id": task_id,
        "provider": provider,
        "message": "Use the report_url from the initial submission to check status",
        "report_url": f"https://urlscan.io/result/{task_id}/" if provider == "urlscan" else None
    }
