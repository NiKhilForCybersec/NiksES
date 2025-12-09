"""
NiksES Analyses API Routes

Endpoints for retrieving and managing past analyses.
"""

import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Query

from app.models.analysis import AnalysisResult, AnalysisSummary, AnalysisListResponse
from app.api.dependencies import get_analysis_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyses", tags=["analyses"])


# NOTE: Stats routes MUST come before /{analysis_id} routes to avoid path conflicts

@router.get("/stats/summary")
async def get_stats_summary(
    days: int = Query(7, ge=1, le=90, description="Number of days"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Get summary statistics for recent analyses.
    
    Returns:
        Statistics including counts, risk distribution, etc.
    """
    if not analysis_store:
        return {
            "total_analyses": 0,
            "risk_distribution": {},
            "classification_distribution": {},
            "average_risk_score": 0,
        }
    
    stats = await analysis_store.get_stats(days=days)
    return stats


@router.get("/stats/timeline")
async def get_stats_timeline(
    days: int = Query(7, ge=1, le=90, description="Number of days"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Get timeline data for visualizations.
    
    Returns:
        Daily analysis counts and risk trends
    """
    if not analysis_store:
        return {"timeline": []}
    
    timeline = await analysis_store.get_timeline(days=days)
    return {"timeline": timeline}


@router.get("/stats")
async def get_dashboard_stats(
    analysis_store = Depends(get_analysis_store),
):
    """
    Get dashboard statistics - simplified version for UI.
    
    Returns:
        Statistics including counts by verdict, avg score, etc.
    """
    from datetime import datetime, timedelta
    
    if not analysis_store:
        return {
            "total_analyses": 0,
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "avg_risk_score": 0.0,
            "analyses_today": 0,
            "analyses_this_week": 0,
            "top_threat_categories": [],
        }
    
    try:
        # Get all analyses for stats
        analyses, total = await analysis_store.list(page=1, page_size=1000)
        
        malicious = 0
        suspicious = 0
        clean = 0
        total_score = 0
        today_count = 0
        week_count = 0
        category_counts = {}
        
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        
        for analysis in analyses:
            # AnalysisSummary has risk_score directly, not nested under detection
            score = getattr(analysis, 'risk_score', 0)
            if hasattr(analysis, 'detection') and analysis.detection:
                score = analysis.detection.risk_score
            total_score += score
            
            # Categorize by risk
            if score >= 60:
                malicious += 1
            elif score >= 20:
                suspicious += 1
            else:
                clean += 1
            
            # Time-based counts
            analyzed = analysis.analyzed_at
            if isinstance(analyzed, str):
                analyzed = datetime.fromisoformat(analyzed.replace('Z', '+00:00'))
            
            if analyzed >= today_start:
                today_count += 1
            if analyzed >= week_start:
                week_count += 1
            
            # Category counts - AnalysisSummary has classification directly
            classification = getattr(analysis, 'classification', 'unknown')
            if hasattr(analysis, 'detection') and analysis.detection:
                classification = str(analysis.detection.primary_classification.value) if hasattr(analysis.detection.primary_classification, 'value') else str(analysis.detection.primary_classification)
            category_counts[classification] = category_counts.get(classification, 0) + 1
        
        # Top categories
        top_categories = sorted(
            [{"category": k, "count": v} for k, v in category_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:5]
        
        return {
            "total_analyses": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "avg_risk_score": round(total_score / total, 1) if total > 0 else 0.0,
            "analyses_today": today_count,
            "analyses_this_week": week_count,
            "top_threat_categories": top_categories,
        }
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return {
            "total_analyses": 0,
            "malicious": 0,
            "suspicious": 0,
            "clean": 0,
            "avg_risk_score": 0.0,
            "analyses_today": 0,
            "analyses_this_week": 0,
            "top_threat_categories": [],
        }


@router.get("", response_model=AnalysisListResponse)
async def list_analyses(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    classification: Optional[str] = Query(None, description="Filter by classification"),
    search: Optional[str] = Query(None, description="Search in subject/sender"),
    sender_domain: Optional[str] = Query(None, description="Filter by sender domain"),
    start_date: Optional[datetime] = Query(None, description="Filter by start date"),
    end_date: Optional[datetime] = Query(None, description="Filter by end date"),
    sort_by: str = Query("analyzed_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    analysis_store = Depends(get_analysis_store),
):
    """
    List all analyses with pagination and filtering.
    
    Returns:
        Paginated list of analysis summaries
    """
    if not analysis_store:
        return AnalysisListResponse(
            total=0,
            page=page,
            page_size=page_size,
            analyses=[],
        )
    
    # Get analyses with filters
    analyses, total = await analysis_store.list(
        page=page,
        page_size=page_size,
        risk_level=risk_level,
        classification=classification,
        search=search,
        sender_domain=sender_domain,
        date_from=start_date,
        date_to=end_date,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    
    # SQLite store returns AnalysisSummary directly
    # In-memory store returns AnalysisResult, convert if needed
    summaries = []
    for analysis in analyses:
        if isinstance(analysis, AnalysisSummary):
            summaries.append(analysis)
        else:
            # Convert AnalysisResult to AnalysisSummary
            summaries.append(AnalysisSummary(
                analysis_id=analysis.analysis_id,
                analyzed_at=analysis.analyzed_at,
                subject=analysis.email.subject,
                sender_email=analysis.email.sender.email if analysis.email.sender else None,
                sender_domain=analysis.email.sender.domain if analysis.email.sender else None,
                risk_score=analysis.detection.risk_score,
                risk_level=analysis.detection.risk_level.value if hasattr(analysis.detection.risk_level, 'value') else str(analysis.detection.risk_level),
                classification=analysis.detection.primary_classification.value if hasattr(analysis.detection.primary_classification, 'value') else str(analysis.detection.primary_classification),
                has_attachments=len(analysis.email.attachments) > 0,
                has_urls=len(analysis.email.urls) > 0,
                attachment_count=len(analysis.email.attachments),
                url_count=len(analysis.email.urls),
                ai_summary=analysis.ai_triage.summary if analysis.ai_triage else None,
            ))
    
    return AnalysisListResponse(
        total=total,
        page=page,
        page_size=page_size,
        analyses=summaries,
    )


@router.get("/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(
    analysis_id: str,
    analysis_store = Depends(get_analysis_store),
):
    """
    Get a specific analysis by ID.
    
    Returns:
        Complete analysis result
    """
    if not analysis_store:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    analysis = await analysis_store.get(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis


@router.delete("/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    analysis_store = Depends(get_analysis_store),
):
    """
    Delete an analysis by ID.
    
    Returns:
        Success message
    """
    if not analysis_store:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    deleted = await analysis_store.delete(analysis_id)
    
    if not deleted:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return {"message": "Analysis deleted", "analysis_id": analysis_id}


@router.delete("")
async def delete_all_analyses(
    analysis_store = Depends(get_analysis_store),
):
    """
    Delete all analyses.
    
    Returns:
        Count of deleted analyses
    """
    if not analysis_store:
        return {"message": "No analyses to delete", "count": 0}
    
    count = await analysis_store.delete_all()
    
    return {"message": f"Deleted {count} analyses", "count": count}


@router.get("/{analysis_id}/iocs")
async def get_analysis_iocs(
    analysis_id: str,
    analysis_store = Depends(get_analysis_store),
):
    """
    Get IOCs from a specific analysis.
    
    Returns:
        Extracted IOCs
    """
    if not analysis_store:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    analysis = await analysis_store.get(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis.iocs


@router.get("/{analysis_id}/detection")
async def get_analysis_detection(
    analysis_id: str,
    analysis_store = Depends(get_analysis_store),
):
    """
    Get detection results from a specific analysis.
    
    Returns:
        Detection engine results
    """
    if not analysis_store:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    analysis = await analysis_store.get(analysis_id)
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis.detection
