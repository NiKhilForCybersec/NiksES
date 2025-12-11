"""
NiksES Sandbox API Routes

Provides endpoints for sandbox analysis:
- GET /sandbox/status - Check sandbox configuration status
- POST /sandbox/analyze/file - Submit file for analysis
- POST /sandbox/analyze/url - Submit URL for analysis  
- GET /sandbox/report/{submission_id} - Get analysis report
- POST /sandbox/hash - Check hash against existing analyses
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Optional
from pydantic import BaseModel
import logging

from app.services.sandbox import get_sandbox_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sandbox", tags=["sandbox"])


class HashCheckRequest(BaseModel):
    hash: str


class UrlAnalysisRequest(BaseModel):
    url: str
    wait_for_results: bool = False


class SandboxConfigRequest(BaseModel):
    api_key: Optional[str] = None
    enabled: bool = True


@router.get("/status")
async def get_sandbox_status():
    """Get sandbox service status including configuration and quota."""
    service = get_sandbox_service()
    status = await service.get_status()
    return status


@router.post("/configure")
async def configure_sandbox(config: SandboxConfigRequest):
    """Configure sandbox service settings."""
    service = get_sandbox_service()
    service.configure(api_key=config.api_key, enabled=config.enabled)
    return {"success": True, "message": "Sandbox configuration updated"}


@router.post("/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    wait_for_results: bool = Form(default=False),
    timeout: int = Form(default=120)
):
    """Submit a file for sandbox analysis."""
    service = get_sandbox_service()
    
    if not service.is_enabled:
        raise HTTPException(
            status_code=503,
            detail="Sandbox service not configured. Please add HYBRID_ANALYSIS_API_KEY."
        )
    
    content = await file.read()
    filename = file.filename or "unknown"
    
    if not service.client.should_analyze(filename):
        return {
            "analyzed": False,
            "reason": "unsupported_file_type",
            "message": f"File type not suitable for dynamic analysis: {filename}",
            "supported_types": list(service.client.ANALYZABLE_EXTENSIONS)
        }
    
    result = await service.client.submit_file(content, filename)
    
    if wait_for_results and result.status == "submitted":
        result = await service._wait_for_result(result.submission_id, timeout)
    
    return {"analyzed": True, "result": result.to_dict()}


@router.post("/analyze/url")
async def analyze_url(request: UrlAnalysisRequest):
    """Submit a URL for sandbox analysis."""
    service = get_sandbox_service()
    
    if not service.is_enabled:
        raise HTTPException(status_code=503, detail="Sandbox service not configured")
    
    result = await service.client.submit_url(request.url)
    return {"analyzed": True, "result": result.to_dict()}


@router.post("/hash")
async def check_hash(request: HashCheckRequest):
    """Check if a file hash has existing sandbox analysis."""
    service = get_sandbox_service()
    
    if not service.is_enabled:
        raise HTTPException(status_code=503, detail="Sandbox service not configured")
    
    result = await service.check_hash(request.hash)
    return result


@router.get("/report/{submission_id}")
async def get_report(submission_id: str):
    """Get detailed analysis report for a submission."""
    service = get_sandbox_service()
    
    if not service.is_enabled:
        raise HTTPException(status_code=503, detail="Sandbox service not configured")
    
    result = await service.get_report(submission_id)
    
    if result.get("result", {}).get("status") == "error":
        raise HTTPException(
            status_code=404,
            detail=result.get("result", {}).get("error", "Report not found")
        )
    
    return result


@router.get("/environments")
async def get_environments():
    """Get available sandbox analysis environments."""
    return {
        "environments": [
            {"id": "win10_64", "name": "Windows 10 64-bit", "default": True},
            {"id": "win7_64", "name": "Windows 7 64-bit", "default": False},
            {"id": "win7_32", "name": "Windows 7 32-bit", "default": False},
            {"id": "linux", "name": "Linux Ubuntu 16.04", "default": False},
            {"id": "android", "name": "Android", "default": False},
        ]
    }


@router.get("/supported-types")
async def get_supported_types():
    """Get list of file types suitable for sandbox analysis."""
    service = get_sandbox_service()
    extensions = sorted(service.client.ANALYZABLE_EXTENSIONS)
    
    return {
        "extensions": extensions,
        "categories": {
            "executables": [e for e in extensions if e in {'.exe', '.dll', '.scr', '.msi', '.com'}],
            "scripts": [e for e in extensions if e in {'.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta'}],
            "documents": [e for e in extensions if e in {'.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.pdf', '.rtf'}],
            "archives": [e for e in extensions if e in {'.zip', '.rar', '.7z', '.tar', '.gz', '.iso'}],
        }
    }
