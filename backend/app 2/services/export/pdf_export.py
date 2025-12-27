"""
NiksES PDF Export

Generate PDF reports from analysis results.
Uses ReportLab for PDF generation.
"""

import io
import logging
from datetime import datetime
from typing import Optional, List

from app.models.analysis import AnalysisResult
from app.models.detection import RiskLevel

logger = logging.getLogger(__name__)

# Try to import reportlab
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
    
    # Color scheme - only define when ReportLab is available
    COLORS = {
        'critical': colors.Color(0.8, 0.1, 0.1),  # Dark red
        'high': colors.Color(0.9, 0.3, 0.2),      # Red-orange
        'medium': colors.Color(0.95, 0.6, 0.1),   # Orange
        'low': colors.Color(0.2, 0.6, 0.3),       # Green
        'informational': colors.Color(0.3, 0.5, 0.7),  # Blue
        'header': colors.Color(0.2, 0.3, 0.4),    # Dark blue-gray
        'border': colors.Color(0.7, 0.7, 0.7),    # Light gray
    }
    
    def get_risk_color(risk_level: RiskLevel):
        """Get color for risk level."""
        return COLORS.get(risk_level.value, COLORS['informational'])
        
except ImportError:
    REPORTLAB_AVAILABLE = False
    COLORS = {}
    logger.warning("ReportLab not installed. PDF export will not be available.")
    
    def get_risk_color(risk_level: RiskLevel):
        """Stub when ReportLab not available."""
        return None


def export_to_pdf(
    analysis: AnalysisResult,
    output_path: Optional[str] = None,
    page_size: str = "letter",
) -> bytes:
    """
    Export analysis result to PDF.
    
    Args:
        analysis: Complete analysis result
        output_path: Optional file path to save PDF
        page_size: Page size ("letter" or "a4")
        
    Returns:
        PDF content as bytes
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for PDF export. Install with: pip install reportlab")
    
    # Create buffer
    buffer = io.BytesIO()
    
    # Page size
    size = letter if page_size.lower() == "letter" else A4
    
    # Create document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=size,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=COLORS['header'],
        spaceAfter=20,
        alignment=TA_CENTER,
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=COLORS['header'],
        spaceBefore=15,
        spaceAfter=10,
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
    )
    
    # Build content
    elements = []
    
    # Title
    elements.append(Paragraph("Email Security Analysis Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    # Summary box
    risk_color = get_risk_color(analysis.detection.risk_level)
    classification = analysis.detection.primary_classification.value.replace('_', ' ').title()
    
    summary_data = [
        ['Analysis ID:', analysis.analysis_id],
        ['Date:', analysis.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Risk Score:', f"{analysis.detection.risk_score}/100"],
        ['Risk Level:', analysis.detection.risk_level.value.upper()],
        ['Classification:', classification],
    ]
    
    summary_table = Table(summary_data, colWidths=[1.5 * inch, 4.5 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.Color(0.95, 0.95, 0.95)),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, COLORS['border']),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3 * inch))
    
    # Email Details
    elements.append(Paragraph("Email Details", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['border']))
    
    email = analysis.email
    sender = email.sender.email if email.sender else "Unknown"
    sender_name = email.sender.display_name if email.sender and email.sender.display_name else ""
    
    email_data = [
        ['From:', f"{sender_name} <{sender}>" if sender_name else sender],
        ['Subject:', email.subject or "(No subject)"],
        ['Date:', str(email.date) if email.date else "Unknown"],
        ['Attachments:', str(len(email.attachments))],
        ['URLs:', str(len(email.urls))],
    ]
    
    email_table = Table(email_data, colWidths=[1.2 * inch, 4.8 * inch])
    email_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(email_table)
    elements.append(Spacer(1, 0.2 * inch))
    
    # Detection Results
    elements.append(Paragraph("Detection Results", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['border']))
    
    triggered_rules = analysis.detection.rules_triggered
    if triggered_rules:
        elements.append(Paragraph(f"<b>{len(triggered_rules)} detection rules triggered:</b>", normal_style))
        
        rule_data = [['Rule', 'Severity', 'Category']]
        for rule in triggered_rules[:15]:  # Limit to 15 rules
            rule_data.append([
                rule.rule_name[:40],
                rule.severity.value.upper() if hasattr(rule.severity, 'value') else str(rule.severity),
                rule.category,
            ])
        
        rule_table = Table(rule_data, colWidths=[3 * inch, 1.2 * inch, 1.5 * inch])
        rule_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['header']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, COLORS['border']),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(rule_table)
    else:
        elements.append(Paragraph("No detection rules triggered.", normal_style))
    
    elements.append(Spacer(1, 0.2 * inch))
    
    # IOCs
    elements.append(Paragraph("Indicators of Compromise (IOCs)", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['border']))
    
    iocs = analysis.iocs
    ioc_counts = [
        ('Domains', len(iocs.domains)),
        ('URLs', len(iocs.urls)),
        ('IP Addresses', len(iocs.ips)),
        ('Email Addresses', len(iocs.email_addresses)),
        ('File Hashes (SHA256)', len(iocs.file_hashes_sha256)),
        ('File Hashes (MD5)', len(iocs.file_hashes_md5)),
    ]
    
    ioc_data = [['IOC Type', 'Count']]
    for ioc_type, count in ioc_counts:
        if count > 0:
            ioc_data.append([ioc_type, str(count)])
    
    if len(ioc_data) > 1:
        ioc_table = Table(ioc_data, colWidths=[3 * inch, 1 * inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['header']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, COLORS['border']),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(ioc_table)
    else:
        elements.append(Paragraph("No IOCs extracted.", normal_style))
    
    elements.append(Spacer(1, 0.2 * inch))
    
    # Attachment Analysis (Static Analysis)
    if analysis.email.attachments:
        threat_attachments = [
            att for att in analysis.email.attachments 
            if getattr(att, 'threat_score', 0) > 0 or 
               getattr(att, 'has_macros', False) or 
               getattr(att, 'has_javascript', False) or
               getattr(att, 'is_executable', False)
        ]
        
        if threat_attachments:
            elements.append(Paragraph("Attachment Analysis", heading_style))
            elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['border']))
            
            att_data = [['Filename', 'Threat Score', 'Indicators']]
            for att in threat_attachments[:10]:  # Limit to 10
                indicators = []
                if getattr(att, 'is_executable', False):
                    indicators.append('EXECUTABLE')
                if getattr(att, 'has_macros', False):
                    indicators.append('MACROS')
                if getattr(att, 'has_auto_exec_macros', False):
                    indicators.append('AUTO-EXEC')
                if getattr(att, 'has_dde', False):
                    indicators.append('DDE')
                if getattr(att, 'has_javascript', False):
                    indicators.append('JAVASCRIPT')
                if getattr(att, 'has_embedded_files', False):
                    indicators.append('EMBEDDED')
                if getattr(att, 'is_packed', False):
                    indicators.append('PACKED')
                if getattr(att, 'has_suspicious_imports', False):
                    indicators.append('SUS IMPORTS')
                if getattr(att, 'type_mismatch', False):
                    indicators.append('TYPE MISMATCH')
                if getattr(att, 'has_double_extension', False):
                    indicators.append('DOUBLE EXT')
                
                threat_score = getattr(att, 'threat_score', 0)
                threat_level = getattr(att, 'threat_level', 'unknown')
                score_display = f"{threat_score}/100 ({threat_level.upper()})" if threat_score > 0 else "Clean"
                
                att_data.append([
                    att.filename[:35] if len(att.filename) > 35 else att.filename,
                    score_display,
                    ', '.join(indicators[:4]) or 'None'
                ])
            
            att_table = Table(att_data, colWidths=[2.5 * inch, 1.3 * inch, 2 * inch])
            att_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLORS['header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, COLORS['border']),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(att_table)
            
            # Add threat summaries for critical attachments
            for att in threat_attachments[:3]:
                if getattr(att, 'threat_summary', ''):
                    elements.append(Spacer(1, 0.1 * inch))
                    elements.append(Paragraph(
                        f"<b>{att.filename}:</b> {att.threat_summary[:200]}", 
                        normal_style
                    ))
                if getattr(att, 'sha256', ''):
                    elements.append(Paragraph(
                        f"<font size='8'>SHA256: {att.sha256}</font>", 
                        normal_style
                    ))
            
            elements.append(Spacer(1, 0.2 * inch))
    
    # AI Analysis (if available)
    if analysis.ai_triage:
        elements.append(Paragraph("AI Analysis", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['border']))
        
        elements.append(Paragraph(f"<b>Summary:</b> {analysis.ai_triage.summary}", normal_style))
        elements.append(Spacer(1, 0.1 * inch))
        
        if analysis.ai_triage.recommended_actions:
            elements.append(Paragraph("<b>Recommended Actions:</b>", normal_style))
            for i, action in enumerate(analysis.ai_triage.recommended_actions[:5], 1):
                elements.append(Paragraph(f"{i}. {action.action}: {action.description}", normal_style))
    
    # Footer
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(HRFlowable(width="100%", thickness=1, color=COLORS['border']))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.gray)
    elements.append(Paragraph(f"Generated by NiksES on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", footer_style))
    
    # Build PDF
    doc.build(elements)
    
    # Get bytes
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    # Save to file if path provided
    if output_path:
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
    
    return pdf_bytes


def is_pdf_available() -> bool:
    """Check if PDF export is available."""
    return REPORTLAB_AVAILABLE
