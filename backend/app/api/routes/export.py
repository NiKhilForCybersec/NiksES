"""
NiksES Export API Routes

Endpoints for exporting analysis results.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import Response, StreamingResponse
import io

from app.api.dependencies import get_analysis_store
from app.services.export import (
    export_to_json,
    export_to_markdown,
    export_to_stix,
    export_iocs_simple,
    export_iocs_to_csv,
    export_rules_to_csv,
    export_to_pdf,
    is_pdf_available,
)
from app.services.export.executive_pdf import generate_executive_pdf, generate_summary_pdf

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/{analysis_id}/json")
async def export_json(
    analysis_id: str,
    pretty: bool = Query(True, description="Pretty print JSON"),
    include_raw: bool = Query(False, description="Include raw email content"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export analysis to JSON format.
    
    Returns:
        JSON file download
    """
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    content = export_to_json(analysis, pretty=pretty, include_raw=include_raw)
    
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=analysis_{analysis_id}.json"
        }
    )


@router.get("/{analysis_id}/markdown")
async def export_markdown(
    analysis_id: str,
    include_evidence: bool = Query(True, description="Include rule evidence"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export analysis to Markdown format.
    
    Returns:
        Markdown file download
    """
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    content = export_to_markdown(analysis, include_evidence=include_evidence)
    
    return Response(
        content=content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=analysis_{analysis_id}.md"
        }
    )


@router.get("/{analysis_id}/pdf")
async def export_pdf(
    analysis_id: str,
    page_size: str = Query("letter", description="Page size (letter/a4)"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export analysis to PDF format.
    
    Returns:
        PDF file download
    """
    if not is_pdf_available():
        raise HTTPException(
            status_code=501,
            detail="PDF export not available. Install reportlab: pip install reportlab"
        )
    
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    try:
        pdf_bytes = export_to_pdf(analysis, page_size=page_size)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=analysis_{analysis_id}.pdf"
        }
    )


@router.get("/{analysis_id}/executive-pdf")
async def export_executive_pdf(
    analysis_id: str,
    page_size: str = Query("letter", description="Page size (letter/a4)"),
    include_technical: bool = Query(True, description="Include technical appendix"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export analysis to Executive PDF format.
    
    Professional PDF report designed for executive forwarding with:
    - Clear executive summary with risk explanation
    - Visual risk score gauge
    - Business-friendly threat explanations
    - Recommended actions
    - Optional technical appendix
    
    Returns:
        PDF file download
    """
    if not is_pdf_available():
        raise HTTPException(
            status_code=501,
            detail="PDF export not available. Install reportlab: pip install reportlab"
        )
    
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    try:
        pdf_bytes = generate_executive_pdf(
            analysis, 
            page_size=page_size,
            include_technical=include_technical
        )
    except Exception as e:
        logger.error(f"Executive PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=executive_report_{analysis_id}.pdf"
        }
    )


@router.get("/{analysis_id}/summary-pdf")
async def export_summary_pdf(
    analysis_id: str,
    page_size: str = Query("letter", description="Page size (letter/a4)"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export analysis to one-page Summary PDF.
    
    Quick overview PDF for rapid review without technical details.
    
    Returns:
        PDF file download
    """
    if not is_pdf_available():
        raise HTTPException(
            status_code=501,
            detail="PDF export not available. Install reportlab: pip install reportlab"
        )
    
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    try:
        pdf_bytes = generate_summary_pdf(analysis, page_size=page_size)
    except Exception as e:
        logger.error(f"Summary PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=summary_{analysis_id}.pdf"
        }
    )


@router.get("/{analysis_id}/stix")
async def export_stix(
    analysis_id: str,
    include_indicators: bool = Query(True, description="Include STIX indicators"),
    include_observables: bool = Query(True, description="Include STIX observables"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export IOCs to STIX 2.1 format.
    
    Returns:
        STIX bundle JSON download
    """
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    content = export_to_stix(
        analysis,
        include_indicators=include_indicators,
        include_observables=include_observables,
    )
    
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=iocs_{analysis_id}.stix.json"
        }
    )


@router.get("/{analysis_id}/iocs")
async def export_iocs(
    analysis_id: str,
    format: str = Query("txt", description="Format: txt, csv, or stix"),
    analysis_store = Depends(get_analysis_store),
):
    """
    Export IOCs in various formats.
    
    Formats:
    - txt: Simple newline-separated list
    - csv: CSV format with metadata
    - stix: STIX 2.1 bundle
    
    Returns:
        IOC file download
    """
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    if format == "csv":
        content = export_iocs_to_csv(analysis)
        media_type = "text/csv"
        ext = "csv"
    elif format == "stix":
        content = export_to_stix(analysis)
        media_type = "application/json"
        ext = "stix.json"
    else:  # txt
        content = export_iocs_simple(analysis)
        media_type = "text/plain"
        ext = "txt"
    
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename=iocs_{analysis_id}.{ext}"
        }
    )


@router.get("/{analysis_id}/rules")
async def export_rules(
    analysis_id: str,
    analysis_store = Depends(get_analysis_store),
):
    """
    Export triggered detection rules to CSV.
    
    Returns:
        CSV file with rule details
    """
    analysis = await get_analysis_or_404(analysis_id, analysis_store)
    
    content = export_rules_to_csv(analysis)
    
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=rules_{analysis_id}.csv"
        }
    )


# Helper function
async def get_analysis_or_404(analysis_id: str, analysis_store):
    """Get analysis from cache first, then database, or raise 404."""
    # Check in-memory cache first (for recent analyses)
    from app.api.dependencies import get_cached_analysis
    
    cached = get_cached_analysis(analysis_id)
    if cached:
        logger.info(f"Export: Found analysis {analysis_id} in memory cache")
        return cached
    
    logger.info(f"Export: Analysis {analysis_id} not in cache, checking database")
    
    # Try database
    if not analysis_store:
        logger.error(f"Export: No analysis store available for {analysis_id}")
        raise HTTPException(status_code=404, detail="Analysis not found - no storage available")
    
    analysis = await analysis_store.get(analysis_id)
    
    if not analysis:
        logger.error(f"Export: Analysis {analysis_id} not found in database")
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    logger.info(f"Export: Found analysis {analysis_id} in database")
    return analysis
